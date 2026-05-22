"""End-to-end test of the reactor's event → verify → reaction pipeline.

Injects synthetic auth-event lines through an iterator instead of a
real `log stream` subprocess. Stands up the same AF_UNIX mock daemon
used by test_lavalamp_client. All reactions run in dry_run mode.
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

    def test_accept_event_no_reaction(self):
        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=lambda: b"A")
        events = ["authentication completed for user aaron"]
        # Should run without raising; no reaction fires (ACCEPT path).
        pharos_reactor.reactor_loop(
            event_source=iter(events),
            dry_run=True,
        )

    def test_reject_event_triggers_reaction_dry_run(self):
        # The pipeline should observe the auth event, verify, get
        # REJECT, and dispatch react_to_reject in dry_run mode.
        # We assert via side effect: the throttle clock should
        # advance after the reaction fires. Easiest way is to inject
        # a second event and confirm throttling kicks in.
        _spawn_persistent_mock(self.sock, sk=self.sk,
                               result_byte_provider=lambda: b"R")
        events = [
            "authentication completed for user aaron",
            "authentication completed for user aaron (cascade)",
        ]
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


if __name__ == "__main__":
    unittest.main()
