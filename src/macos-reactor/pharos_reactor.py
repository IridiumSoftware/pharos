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
from reactions import (
    react_to_reject,
    react_to_stale,
    react_to_timeout,
)

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

# Escalation threshold for persistent UNREACHABLE.
#
# react_to_timeout is intentionally a no-op on a single miss — a
# legitimate `lavalampd` restart is a normal event and we don't want
# to evict the user's session for it. But an attacker who kills the
# daemon and stays logged in is the exact gap this reactor exists to
# close. Compromise: after N consecutive UNREACHABLE / TIMEOUT
# results, treat the substrate as effectively REJECT and dispatch the
# full lock+kill reaction. Reset to 0 on any non-unreachable result.
#
# Default 5: at ~5s throttle ≈ 25s elapsed, comfortably longer than a
# clean daemon restart (LL-039 daemon comes up in <2s) but short
# enough to catch malicious shutdown before the attacker can
# accomplish much. Override via env LL_REACTOR_UNREACHABLE_LIMIT or
# CLI --unreachable-limit.
UNREACHABLE_ESCALATION_DEFAULT = 5


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


def _dispatch_reaction(
    result: DaemonResult,
    *,
    kill: bool,
    dry_run: bool,
    unreachable_count: int,
    unreachable_limit: int,
) -> tuple[bool, int]:
    """Dispatch the reaction matching `result`.

    Returns (fired, new_unreachable_count). The caller threads
    new_unreachable_count back in on the next event — escalation of
    persistent UNREACHABLE / TIMEOUT requires cross-event state.
    """
    if result == DaemonResult.ACCEPT:
        log.debug("substrate ACCEPT — no reaction")
        return (False, 0)
    if result == DaemonResult.REJECT:
        log.warning("substrate REJECT — locking and killing session")
        react_to_reject(kill=kill, dry_run=dry_run)
        return (True, 0)
    if result == DaemonResult.STALE:
        log.warning("substrate STALE — forcing re-auth")
        react_to_stale(dry_run=dry_run)
        return (True, 0)
    if result in (DaemonResult.TIMEOUT, DaemonResult.UNREACHABLE):
        new_count = unreachable_count + 1
        if new_count >= unreachable_limit:
            log.error(
                "substrate %s for %d consecutive events (limit %d) — "
                "escalating to REJECT-equivalent reaction (attacker "
                "may have killed lavalampd to evade detection)",
                result.name, new_count, unreachable_limit,
            )
            react_to_reject(kill=kill, dry_run=dry_run)
            # Reset so a stuck-unreachable state fires one reaction
            # per throttle window, not continuously.
            return (True, 0)
        log.warning(
            "substrate %s (%d/%d consecutive) — no reaction yet",
            result.name, new_count, unreachable_limit,
        )
        react_to_timeout(dry_run=dry_run)
        return (False, new_count)
    if result == DaemonResult.BAD_SIG:
        log.error("substrate BAD_SIG — daemon response failed signature check")
        react_to_reject(kill=kill, dry_run=dry_run)
        return (True, 0)
    log.error("unhandled DaemonResult: %r", result)
    return (False, unreachable_count)


def reactor_loop(
    *,
    kill_on_reject: bool = True,
    dry_run: bool = False,
    unreachable_limit: int = UNREACHABLE_ESCALATION_DEFAULT,
    event_source: Optional[Iterator[str]] = None,
) -> None:
    """Main loop. Subscribes to events, verifies on each, reacts."""
    if event_source is None:
        event_source = _iter_log_stream()

    last_reaction_at = 0.0
    consecutive_unreachable = 0

    for line in event_source:
        if not _matches_auth_event(line):
            continue

        log.debug("auth event: %s", line[:200])
        now = time.monotonic()
        if now - last_reaction_at < REACTION_THROTTLE_S:
            log.debug("throttled — last reaction %.1fs ago",
                      now - last_reaction_at)
            continue

        result = verify_lavalamp_substrate()
        log.info("verify result: %s", result.name)

        # Log substrate recovery (informational; not a reaction).
        if consecutive_unreachable > 0 and result not in (
            DaemonResult.TIMEOUT, DaemonResult.UNREACHABLE,
        ):
            log.info("substrate reachable again after %d consecutive misses",
                     consecutive_unreachable)

        fired, consecutive_unreachable = _dispatch_reaction(
            result,
            kill=kill_on_reject,
            dry_run=dry_run,
            unreachable_count=consecutive_unreachable,
            unreachable_limit=unreachable_limit,
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
        "--unreachable-limit", type=int,
        default=int(os.environ.get(
            "LL_REACTOR_UNREACHABLE_LIMIT",
            str(UNREACHABLE_ESCALATION_DEFAULT),
        )),
        help=(
            "Consecutive UNREACHABLE/TIMEOUT events before escalating "
            f"to a REJECT-equivalent reaction. Default: "
            f"{UNREACHABLE_ESCALATION_DEFAULT}. Set to a very large "
            "number (e.g. 10000) to effectively disable escalation."
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

    if args.unreachable_limit < 1:
        log.error("--unreachable-limit must be ≥ 1 (got %d)",
                  args.unreachable_limit)
        return 2

    log.info(
        "starting PharOS reactor — PH-019 MVP-1 (log stream source); "
        "dry_run=%s, kill_on_reject=%s, unreachable_limit=%d",
        args.dry_run, not args.no_kill, args.unreachable_limit,
    )
    _install_signal_handlers()

    try:
        reactor_loop(
            kill_on_reject=not args.no_kill,
            dry_run=args.dry_run,
            unreachable_limit=args.unreachable_limit,
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
