#!/usr/bin/env python3
"""PharOS macOS post-authentication reactor — PH-019 MVP-1.

Subscribes to macOS authentication events via `log stream`, runs the
LL-043 v4 ECDSA P-256 verify against the LavaLamp daemon on each
event, and dispatches a reaction primitive if the substrate verify
returns REJECT / STALE / UNREACHABLE.

Run modes:

  python3 pharos_reactor.py --foreground          (interactive)
  python3 pharos_reactor.py --foreground --dry-run (validation only)
  python3 pharos_reactor.py                       (LaunchAgent target)

Event source backend is selected by env LL_REACTOR_SOURCE:
  log_stream  — default; MVP-1, no Apple entitlement required.
  es_client   — MVP-2 stub; requires the Endpoint Security
                entitlement and a separate Swift binary (out of
                scope for this Python scaffold).

See README.md for the full posture, threat model, and safety
practices.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import time
from typing import Iterator, Optional

from lavalamp_client import DaemonResult, verify_lavalamp_substrate
# Only react_to_reject is wired into dispatch now: the unified grace
# model (2026-05-31) routes every bad substrate state through the single
# lock+kill reaction. react_to_stale / react_to_timeout remain defined
# and unit-tested in reactions.py for possible future differentiated
# responses, but are intentionally not imported here.
from reactions import react_to_reject

log = logging.getLogger("pharos_reactor")


# Patterns we treat as "an authentication event just occurred".
# Conservative set — false positives cost us a verify round-trip
# (cheap, <100ms), false negatives leave a session unreacted-to
# (expensive, the whole point of this reactor).
AUTH_EVENT_PATTERNS = [
    re.compile(r"authentication completed", re.IGNORECASE),
    re.compile(r"authentication succeeded", re.IGNORECASE),
    re.compile(r"SecurityAgent[^[]*\[[^]]*\] EVALUATE", re.IGNORECASE),
    re.compile(r"loginwindow[^[]*\[[^]]*\] login completed", re.IGNORECASE),
    re.compile(r"copy_rights.*succeeded", re.IGNORECASE),
    re.compile(r"AgentMechanism.*invoke", re.IGNORECASE),
    re.compile(r"engine \d+: PERFORM .*invoke", re.IGNORECASE),
]

# Log-stream subscription predicate. Narrow enough to keep the event
# volume sane on a busy laptop; wide enough to catch every auth path
# we care about (sudo, screen-unlock, settings privileged panes,
# loginwindow login).
LOG_STREAM_PREDICATE = (
    'subsystem == "com.apple.Authorization" '
    'OR process == "loginwindow" '
    'OR process == "SecurityAgent" '
    'OR process == "authd" '
    'OR process == "authorizationhost" '
    'OR process == "sudo"'
)

# Throttle: after firing a reaction, suppress further reactions for
# this many seconds (a single REJECT triggers many cascading auth
# events; one reaction per cluster is correct).
REACTION_THROTTLE_S = 5.0

# Wall-clock grace window before any lock+kill reaction fires.
#
# Design (2026-05-31, replacing the earlier instant-REJECT +
# consecutive-UNREACHABLE-count model). The lock+kill reaction is
# *expensive to recover from* on a personal machine: the user must
# physically log back in AND remember to unload the reactor, which
# takes real wall-clock time. So the reactor must be slow to pull the
# trigger and forgiving of transient badness.
#
# Unified rule: REJECT, STALE, UNREACHABLE, and TIMEOUT all start a
# single wall-clock "bad-since" timer. The lock+kill reaction fires
# only once the substrate has been *continuously* bad for at least
# GRACE_SECONDS. Any ACCEPT clears the timer. This absorbs:
#   - daemon restarts (socket gone ~1-2s → UNREACHABLE → the next poll
#     after restart returns ACCEPT and clears the timer);
#   - load-induced nuisance REJECTs (empirically 2 in 9,790 verifies
#     over 10 days, both single transient spikes under heavy load —
#     neither would survive a 60s continuous-bad requirement).
#
# BAD_SIG is the ONE exception: it bypasses the grace and fires
# immediately. It is a true tamper signal (the daemon's signature
# failed verification — the daemon was replaced or the socket MITM'd),
# never a nuisance (0 occurrences in 9,790 verifies), so there is no
# reason to grant it grace.
#
# Default 60s. Override via env LL_REACTOR_GRACE_SECONDS or CLI
# --grace-seconds. Set very large (e.g. 86400) to keep the reactor
# observing without ever locking.
GRACE_SECONDS_DEFAULT = 60.0


def _iter_log_stream() -> Iterator[str]:
    """Yield each line of `log stream` output as the events arrive.

    Spawns the system `log` binary as a subprocess and streams its
    stdout line by line. Exits if the subprocess dies (the wrapper
    re-launches us via LaunchAgent KeepAlive).
    """
    argv = [
        "/usr/bin/log", "stream",
        "--predicate", LOG_STREAM_PREDICATE,
        "--level", "info",
        "--style", "compact",
    ]
    log.info("subscribing: %s", " ".join(argv))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def _matches_auth_event(line: str) -> bool:
    return any(pat.search(line) for pat in AUTH_EVENT_PATTERNS)


# Bad substrate states that share the wall-clock grace window before
# lock+kill. BAD_SIG is deliberately excluded — it fires immediately.
_GRACE_BAD_STATES = (
    DaemonResult.REJECT,
    DaemonResult.STALE,
    DaemonResult.TIMEOUT,
    DaemonResult.UNREACHABLE,
)


def _dispatch_reaction(
    result: DaemonResult,
    *,
    kill: bool,
    dry_run: bool,
    now: float,
    bad_since: Optional[float],
    grace_seconds: float,
) -> tuple[bool, Optional[float]]:
    """Dispatch the reaction matching `result` under the grace model.

    `now` is a monotonic timestamp; `bad_since` is the monotonic time
    the current unbroken bad streak began (None if the last observed
    state was good). Returns (fired, new_bad_since); the caller threads
    new_bad_since back in on the next event — the grace window is
    cross-event wall-clock state.

    Rule: REJECT / STALE / UNREACHABLE / TIMEOUT all start (or continue)
    one shared bad-since timer; lock+kill fires only once the substrate
    has been continuously bad for >= grace_seconds. ACCEPT clears the
    timer. BAD_SIG bypasses the grace entirely (true tamper signal).
    """
    if result == DaemonResult.ACCEPT:
        if bad_since is not None:
            log.info("substrate ACCEPT — clearing bad-state grace timer")
        else:
            log.debug("substrate ACCEPT — no reaction")
        return (False, None)

    if result == DaemonResult.BAD_SIG:
        # True tamper signal — no grace.
        log.error("substrate BAD_SIG — daemon response failed signature "
                  "check; locking and killing session immediately")
        react_to_reject(kill=kill, dry_run=dry_run)
        return (True, None)

    if result in _GRACE_BAD_STATES:
        if bad_since is None:
            log.warning(
                "substrate %s — starting %.0fs grace timer (no reaction "
                "yet; an ACCEPT before then clears it)",
                result.name, grace_seconds,
            )
            return (False, now)
        elapsed = now - bad_since
        if elapsed >= grace_seconds:
            log.error(
                "substrate bad (%s) continuously for %.0fs (grace %.0fs) "
                "— locking and killing session",
                result.name, elapsed, grace_seconds,
            )
            react_to_reject(kill=kill, dry_run=dry_run)
            # Reset; the loop's throttle prevents an immediate re-fire.
            return (True, None)
        log.warning(
            "substrate %s for %.0fs / %.0fs grace — no reaction yet",
            result.name, elapsed, grace_seconds,
        )
        return (False, bad_since)

    log.error("unhandled DaemonResult: %r", result)
    return (False, bad_since)


def reactor_loop(
    *,
    kill_on_reject: bool = True,
    dry_run: bool = False,
    grace_seconds: float = GRACE_SECONDS_DEFAULT,
    event_source: Optional[Iterator[str]] = None,
    now_fn=time.monotonic,
) -> None:
    """Main loop. Subscribes to events, verifies on each, reacts.

    `now_fn` is injectable so tests can drive the wall-clock grace
    window deterministically.
    """
    if event_source is None:
        event_source = _iter_log_stream()

    last_reaction_at = 0.0
    # Monotonic time the current unbroken bad streak began; None when
    # the last observed substrate state was good (or never-yet-bad).
    bad_since: Optional[float] = None

    for line in event_source:
        if not _matches_auth_event(line):
            continue

        log.debug("auth event: %s", line[:200])
        now = now_fn()
        if now - last_reaction_at < REACTION_THROTTLE_S:
            log.debug("throttled — last reaction %.1fs ago",
                      now - last_reaction_at)
            continue

        result = verify_lavalamp_substrate()
        log.info("verify result: %s", result.name)

        fired, bad_since = _dispatch_reaction(
            result,
            kill=kill_on_reject,
            dry_run=dry_run,
            now=now,
            bad_since=bad_since,
            grace_seconds=grace_seconds,
        )
        if fired:
            last_reaction_at = now


def _install_signal_handlers() -> None:
    def _handle(signum: int, _frame) -> None:
        log.info("received signal %d — shutting down", signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PharOS macOS post-authentication reactor (PH-019).",
    )
    parser.add_argument(
        "--foreground", action="store_true",
        help="Run in foreground with verbose logging (default: daemon mode).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Log reactions that would fire without executing them.",
    )
    parser.add_argument(
        "--no-kill", action="store_true",
        help="On REJECT, lock screen only; do NOT kill the GUI session.",
    )
    parser.add_argument(
        "--grace-seconds", type=float,
        default=float(os.environ.get(
            "LL_REACTOR_GRACE_SECONDS",
            str(GRACE_SECONDS_DEFAULT),
        )),
        help=(
            "Seconds the substrate must be CONTINUOUSLY bad "
            "(REJECT/STALE/UNREACHABLE/TIMEOUT) before the lock+kill "
            f"reaction fires. Default: {GRACE_SECONDS_DEFAULT:.0f}. Any "
            "ACCEPT resets the timer; BAD_SIG bypasses it. Set very "
            "large (e.g. 86400) to keep observing without ever locking."
        ),
    )
    parser.add_argument(
        "--log-level", default=os.environ.get("LL_REACTOR_LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG/INFO/WARNING/ERROR). Default: INFO.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr if args.foreground else sys.stdout,
    )

    source = os.environ.get("LL_REACTOR_SOURCE", "log_stream")
    if source != "log_stream":
        log.error(
            "event source %r not supported in MVP-1 (Python scaffold). "
            "Use the default (log_stream) or upgrade to the MVP-2 Swift "
            "binary with com.apple.developer.endpoint-security.client.",
            source,
        )
        return 2

    if args.grace_seconds <= 0:
        log.error("--grace-seconds must be > 0 (got %s)", args.grace_seconds)
        return 2

    log.info(
        "starting PharOS reactor — PH-019 MVP-1 (log stream source); "
        "dry_run=%s, kill_on_reject=%s, grace_seconds=%.0f",
        args.dry_run, not args.no_kill, args.grace_seconds,
    )
    _install_signal_handlers()

    try:
        reactor_loop(
            kill_on_reject=not args.no_kill,
            dry_run=args.dry_run,
            grace_seconds=args.grace_seconds,
        )
    except KeyboardInterrupt:
        log.info("interrupted — exiting")
        return 0
    except Exception:
        log.exception("reactor loop crashed")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
