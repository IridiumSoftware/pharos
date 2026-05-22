"""Reaction primitives for the PharOS macOS post-auth reactor (PH-019).

Each reaction is a pure subprocess wrapper. No side-channel inputs:
the reactor's reaction is a function of `DaemonResult` only, preserving
LL-017 membrane-no-oracle at the OS layer.

All reactions support a `dry_run` mode that logs what would be run
without executing — used by `pharos_reactor.py --dry-run` during install
validation.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional

log = logging.getLogger(__name__)


def _run(argv: list[str], *, dry_run: bool) -> int:
    """Execute argv (or log + skip if dry_run). Returns process exit code."""
    if dry_run:
        log.info("DRY-RUN would execute: %s", " ".join(argv))
        return 0
    log.info("executing: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv, check=False, capture_output=True, timeout=5,
        )
        if proc.returncode != 0:
            log.warning(
                "%s exited %d: stderr=%s",
                argv[0], proc.returncode, proc.stderr.decode(errors="replace"),
            )
        return proc.returncode
    except subprocess.TimeoutExpired:
        log.warning("%s timed out", argv[0])
        return -1
    except FileNotFoundError:
        log.warning("%s not found on PATH", argv[0])
        return -1


def lock_screen(*, dry_run: bool = False) -> int:
    """Lock the screen via pmset (puts display to sleep, lock-on-sleep policy)."""
    return _run(["/usr/bin/pmset", "displaysleepnow"], dry_run=dry_run)


def kill_gui_session(uid: Optional[int] = None, *, dry_run: bool = False) -> int:
    """Kill the user's loginwindow, returning the seat to the login window.

    Uses launchctl kickstart -k against the user's per-UID loginwindow
    job. uid defaults to os.getuid().
    """
    if uid is None:
        uid = os.getuid()
    target = f"user/{uid}/com.apple.loginwindow"
    return _run(
        ["/bin/launchctl", "kickstart", "-k", target],
        dry_run=dry_run,
    )


def force_reauth(*, dry_run: bool = False) -> int:
    """Force the user to re-authenticate at the next privileged operation.

    Lighter-weight than killing the session: invalidates the cached
    authorization timeout window via `security authorizationdb` ACL
    flush. On macOS 26+, this is best-effort — the exact mechanism
    Apple exposes for invalidating cached auth varies by release.
    For MVP-1 we approximate via a non-destructive `security
    authorize -u` against a privileged right we don't have, which
    forces authd to drop any cached grants for the current process
    chain. Falls back to a no-op if the binary isn't present.
    """
    return _run(
        ["/usr/bin/security", "authorize", "-u",
         "com.apple.uikit.AppFairProvisioning"],
        dry_run=dry_run,
    )


def revoke_keychain_item(service: str, *, dry_run: bool = False) -> int:
    """Delete a generic keychain item by service name.

    Scoped reaction for MVP-2. Use case: a stolen credential that
    persists in keychain (e.g. a refresh token) is revoked when the
    substrate verify flips to REJECT.
    """
    # Whitelist: alphanumeric, dot, dash, underscore. Refuses anything
    # with shell metacharacters, path separators, whitespace, or the
    # empty string. We pass the value to /usr/bin/security as an argv
    # element (not through a shell), but a strict whitelist makes the
    # safety property local to this function and survives accidental
    # refactor.
    import string
    allowed = set(string.ascii_letters + string.digits + "._-")
    if not service or any(c not in allowed for c in service):
        log.warning("revoke_keychain_item: refusing suspicious service=%r",
                    service)
        return -1
    return _run(
        ["/usr/bin/security", "delete-generic-password", "-s", service],
        dry_run=dry_run,
    )


# ─── Reaction policies (compositions of primitives) ──────────────────

def react_to_reject(*, kill: bool = True, dry_run: bool = False) -> None:
    """Default reaction to `DaemonResult.REJECT`.

    Order of operations:
      1. Lock screen immediately (cheap, fast, always succeeds).
      2. If `kill`, kill the GUI session — forces a return to the
         login window. Default-on for MVP-1; the configuration file
         can disable this for low-confidence deployments.
    """
    lock_screen(dry_run=dry_run)
    if kill:
        kill_gui_session(dry_run=dry_run)


def react_to_stale(*, dry_run: bool = False) -> None:
    """Default reaction to `DaemonResult.STALE`.

    STALE means the daemon's verify cache is older than the freshness
    threshold (LL-043 v4 IPC_TS_SKEW_S = 30s). Treat as soft signal:
    force re-auth at next privileged operation but don't kill the
    session.
    """
    force_reauth(dry_run=dry_run)


def react_to_timeout(*, dry_run: bool = False) -> None:
    """Default reaction to `DaemonResult.TIMEOUT` / `UNREACHABLE`.

    Substrate daemon is not responding. Conservative posture: do NOT
    kill the session (the daemon may be transiently down for legitimate
    reasons — restart, swap, hardware change). Log only. The reactor's
    next event-source tick will re-poll; persistent unreachability
    will be visible in the log stream for operator follow-up.
    """
    log.warning("LavaLamp substrate unreachable — no reaction fired")


__all__ = [
    "lock_screen",
    "kill_gui_session",
    "force_reauth",
    "revoke_keychain_item",
    "react_to_reject",
    "react_to_stale",
    "react_to_timeout",
]
