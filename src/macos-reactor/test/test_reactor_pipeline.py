"""End-to-end test of the reactor's event → verify → reaction pipeline.

Injects synthetic auth-event lines through an iterator instead of a
real `log stream` subprocess. Stands up the same AF_UNIX mock daemon
used by test_lavalamp_client. All reactions run in dry_run mode.

Reaction model (2026-05-31): a single wall-clock grace window. REJECT /
STALE / UNREACHABLE / TIMEOUT all share one bad-since timer; the
lock+kill reaction fires only after the substrate has been continuously
bad for >= grace_seconds. Any ACCEPT resets the timer. BAD_SIG bypasses
the grace and fires immediately (true tamper signal).
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ecdsa import SigningKey
from ecdsa.curves import NIST256p
from ecdsa.util import sigencode_string

import pharos_reactor
from lavalamp_client import IPC_VERSION


def _spawn_persistent_mock(
    sock_path: Path,
    *,
    sk: SigningKey,
    result_byte_provider,
) -> None:
    """Mock that handles many connections; calls result_byte_provider() each."""
    def _serve():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(8)
        srv.settimeout(0.5)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                req = b""
                while len(req) < 17:
                    chunk = conn.recv(17 - len(req))
                    if not chunk:
                        break
                    req += chunk
                if len(req) < 17:
                    conn.close()
                    continue
                nonce = req[1:17]
                rb = result_byte_provider()
                ts_le = struct.pack("<Q", int(time.time()))
                signed = nonce + rb + ts_le
                sig = sk.sign(signed, hashfunc=hashlib.sha256,
                              sigencode=sigencode_string)
                conn.sendall(bytes([IPC_VERSION]) + rb + ts_le + sig)
            finally:
                conn.close()
        srv.close()
        try:
            sock_path.unlink()
        except FileNotFoundError:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    time.sleep(0.1)


class ReactorPipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ph019-pipe-"))
        self.sk = SigningKey.generate(curve=NIST256p)
        self.sock = self.tmp / "verify.sock"
        self.pub = self.tmp / "verify.pub"
        self.pub.write_bytes(
            self.sk.get_verifying_key().to_string("compressed")
        )

        # Patch lavalamp_client._resolve_paths so verify uses our temp
        # paths instead of touching ~/.lavalamp/.
        import lavalamp_client
        self._orig_resolve = lavalamp_client._resolve_paths
        lavalamp_client._resolve_paths = lambda: (self.sock, self.pub)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        import lavalamp_client
        lavalamp_client._resolve_paths = self._orig_resolve
        logging.disable(logging.NOTSET)
        for p in [self.sock, self.pub]:
            if p.exists():
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass

    def _now_seq(self, values):
        """Return a now_fn yielding `values` in order (last value repeats).

        Drives reactor_loop's wall-clock grace deterministically. Values
        should start above REACTION_THROTTLE_S so the first event is not
        throttled (real time.monotonic is always large; tests mimic that
        with values like 1000+).
        """
        it = iter(values)
        last = {"v": values[-1]}

        def _fn():
            try:
                last["v"] = next(it)
            except StopIteration:
                pass
            return last["v"]

        return _fn

    def test_accept_event_no_reaction(self):
        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=lambda: b"A")
        events = ["authentication completed for user aaron"]
        # Should run without raising; no reaction fires (ACCEPT path).
        pharos_reactor.reactor_loop(
            event_source=iter(events),
            dry_run=True,
        )

    def test_non_auth_lines_ignored(self):
        # Lines that don't match AUTH_EVENT_PATTERNS must not trigger
        # any verify call — useful as a no-mock-needed smoke test.
        events = [
            "some unrelated log line",
            "another unrelated line",
        ]
        pharos_reactor.reactor_loop(
            event_source=iter(events),
            dry_run=True,
        )

    def test_reject_within_grace_does_not_fire(self):
        # Grace model (2026-05-31): a REJECT only STARTS the bad-since
        # timer. Two REJECTs 30s apart (< 60s grace) must NOT fire —
        # this is the load-induced nuisance-REJECT case the grace window
        # exists to absorb.
        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=lambda: b"R")
        events = ["authentication completed (reject 1)",
                  "authentication completed (reject 2)"]
        with mock.patch.object(pharos_reactor, "react_to_reject") as spy:
            pharos_reactor.reactor_loop(
                event_source=iter(events),
                dry_run=True,
                grace_seconds=60.0,
                now_fn=self._now_seq([1000.0, 1030.0]),
            )
        spy.assert_not_called()

    def test_reject_continuous_past_grace_fires_once(self):
        # A REJECT that persists across the grace window fires exactly
        # once: first event starts the timer (t=1000), second event at
        # t=1120 (elapsed 120 >= 60s grace) fires.
        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=lambda: b"R")
        events = ["authentication completed (reject 1)",
                  "authentication completed (reject 2)"]
        with mock.patch.object(pharos_reactor, "react_to_reject") as spy:
            pharos_reactor.reactor_loop(
                event_source=iter(events),
                dry_run=True,
                grace_seconds=60.0,
                now_fn=self._now_seq([1000.0, 1120.0]),
            )
        spy.assert_called_once()

    def test_accept_then_reject_starts_grace_no_immediate_fire(self):
        # ACCEPT -> REJECT transition (stolen-credential takeover): the
        # first REJECT after a clean ACCEPT must NOT fire immediately —
        # it starts the grace timer. Only a REJECT that then persists
        # past the window fires. Provider: ACCEPT, then REJECT forever.
        calls = {"n": 0}

        def _provider():
            calls["n"] += 1
            return b"A" if calls["n"] == 1 else b"R"

        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=_provider)
        events = [
            "authentication completed (pre-compromise)",     # ACCEPT
            "authentication completed (post-compromise 1)",  # REJECT, starts timer
            "authentication completed (post-compromise 2)",  # REJECT, past grace
        ]
        with mock.patch.object(pharos_reactor, "react_to_reject") as spy:
            pharos_reactor.reactor_loop(
                event_source=iter(events),
                dry_run=True,
                grace_seconds=60.0,
                # ACCEPT@1000, REJECT@1001 (timer start), REJECT@1062 (fire).
                now_fn=self._now_seq([1000.0, 1001.0, 1062.0]),
            )
        # Exactly one fire, and not on the first REJECT.
        spy.assert_called_once()


class DispatchGraceTest(unittest.TestCase):
    """Direct unit tests for _dispatch_reaction's wall-clock grace model
    (2026-05-31, replacing the consecutive-UNREACHABLE-count model).

    Bypasses the event source / verify pipeline; exercises the
    cross-event bad-since state machine in isolation. `now` and
    `bad_since` are passed explicitly so the grace window is fully
    deterministic. All reactions run dry_run=True.
    """

    GRACE = 60.0

    def setUp(self):
        logging.disable(logging.CRITICAL)
        # Spy on react_to_reject so "fired" is asserted at the call
        # site, not just via the return flag.
        self._patcher = mock.patch.object(pharos_reactor, "react_to_reject")
        self.spy = self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        logging.disable(logging.NOTSET)

    def _dispatch(self, result, *, now, bad_since):
        return pharos_reactor._dispatch_reaction(
            result, kill=True, dry_run=True,
            now=now, bad_since=bad_since, grace_seconds=self.GRACE,
        )

    def test_accept_clears_bad_since(self):
        from lavalamp_client import DaemonResult
        fired, bad_since = self._dispatch(
            DaemonResult.ACCEPT, now=1000.0, bad_since=900.0)
        self.assertFalse(fired)
        self.assertIsNone(bad_since)
        self.spy.assert_not_called()

    def test_first_bad_starts_timer_no_fire(self):
        from lavalamp_client import DaemonResult
        for state in (DaemonResult.REJECT, DaemonResult.STALE,
                      DaemonResult.TIMEOUT, DaemonResult.UNREACHABLE):
            self.spy.reset_mock()
            fired, bad_since = self._dispatch(state, now=1000.0,
                                              bad_since=None)
            self.assertFalse(fired, f"{state} should not fire on first bad")
            self.assertEqual(bad_since, 1000.0)
            self.spy.assert_not_called()

    def test_bad_within_grace_does_not_fire(self):
        from lavalamp_client import DaemonResult
        fired, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1030.0, bad_since=1000.0)  # 30s < 60s
        self.assertFalse(fired)
        self.assertEqual(bad_since, 1000.0)  # timer preserved
        self.spy.assert_not_called()

    def test_bad_at_grace_boundary_fires(self):
        from lavalamp_client import DaemonResult
        fired, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1060.0, bad_since=1000.0)  # exactly 60s
        self.assertTrue(fired)
        self.assertIsNone(bad_since)  # reset after fire
        self.spy.assert_called_once()

    def test_bad_past_grace_fires(self):
        from lavalamp_client import DaemonResult
        fired, bad_since = self._dispatch(
            DaemonResult.UNREACHABLE, now=1200.0, bad_since=1000.0)
        self.assertTrue(fired)
        self.assertIsNone(bad_since)
        self.spy.assert_called_once()

    def test_accept_midstream_resets_then_bad_restarts_timer(self):
        from lavalamp_client import DaemonResult
        # Bad at t=1000 (timer start), ACCEPT at t=1030 (clears), bad
        # again at t=1040 (NEW timer), bad at t=1080 (only 40s into the
        # new streak — must NOT fire even though 80s since first bad).
        _, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1000.0, bad_since=None)
        self.assertEqual(bad_since, 1000.0)
        _, bad_since = self._dispatch(
            DaemonResult.ACCEPT, now=1030.0, bad_since=bad_since)
        self.assertIsNone(bad_since)
        _, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1040.0, bad_since=bad_since)
        self.assertEqual(bad_since, 1040.0)
        fired, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1080.0, bad_since=bad_since)  # 40s < 60s
        self.assertFalse(fired)
        self.spy.assert_not_called()

    def test_mixed_bad_states_share_one_timer(self):
        from lavalamp_client import DaemonResult
        # UNREACHABLE starts the timer; a later TIMEOUT then REJECT
        # continue the SAME timer (do not reset it) and fire once past
        # grace.
        _, bad_since = self._dispatch(
            DaemonResult.UNREACHABLE, now=1000.0, bad_since=None)
        self.assertEqual(bad_since, 1000.0)
        _, bad_since = self._dispatch(
            DaemonResult.TIMEOUT, now=1030.0, bad_since=bad_since)  # 30s
        self.assertEqual(bad_since, 1000.0)  # unchanged
        fired, bad_since = self._dispatch(
            DaemonResult.REJECT, now=1061.0, bad_since=bad_since)  # 61s
        self.assertTrue(fired)
        self.assertIsNone(bad_since)
        self.spy.assert_called_once()

    def test_bad_sig_fires_immediately_bypassing_grace(self):
        from lavalamp_client import DaemonResult
        # BAD_SIG is a true tamper signal — fires with no grace, even
        # from a clean prior state.
        fired, bad_since = self._dispatch(
            DaemonResult.BAD_SIG, now=1000.0, bad_since=None)
        self.assertTrue(fired)
        self.assertIsNone(bad_since)
        self.spy.assert_called_once()


if __name__ == "__main__":
    unittest.main()
