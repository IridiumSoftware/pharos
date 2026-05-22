"""LavaLamp daemon client — LL-043 v4 ECDSA P-256 protocol.

Mirrors the Security.framework verify path implemented in C/ObjC
at ../macos/LavaLampMechanism.m. The wire format is byte-identical;
this module re-implements the protocol on top of the Python `ecdsa`
package + stdlib `socket` / `os.urandom`.

LL-043 v4 wire format (must match LavaLamp daemon):

  Request  (17 bytes):  version(1) || nonce(16)
                        version = 0x04

  Response (74 bytes):  version(1) || result(1) || ts_le(8) || sig(64)
                        version = 0x04
                        result  = 'A' | 'R' | 'S' (ACCEPT / REJECT / STALE)
                        ts_le   = 8-byte little-endian Unix timestamp
                        sig     = 64-byte raw r||s P-256 signature

The signed payload is:   nonce(16) || result(1) || ts_le(8) = 25 bytes
Hash:                    SHA-256(signed_payload)
Curve:                   secp256r1 (a.k.a. P-256, prime256v1)
Pubkey on disk:          33-byte SEC1-compressed (0x02|0x03 prefix +
                         32-byte X coordinate)

Public key & socket paths (system-mode daemon first, then user-mode):

  System:  /var/run/lavalamp/verify.sock   /var/run/lavalamp/verify.pub
  User:    ~/.lavalamp/verify.sock         ~/.lavalamp/verify.pub
"""

from __future__ import annotations

import enum
import hashlib
import os
import socket
import struct
import time
from pathlib import Path
from typing import Optional

try:
    from ecdsa import VerifyingKey, BadSignatureError
    from ecdsa.curves import NIST256p
    from ecdsa.util import sigdecode_string
except ImportError as e:
    raise ImportError(
        "lavalamp_client requires the 'ecdsa' package. "
        "Install with: pip3 install --user ecdsa"
    ) from e


# ─── LL-043 v4 protocol constants (must match LavaLampMechanism.m) ─

IPC_VERSION = 0x04
IPC_REQUEST_LEN = 17
IPC_RESPONSE_LEN = 74
IPC_NONCE_LEN = 16
IPC_SIG_LEN = 64
IPC_RAW_FIELD_LEN = 32
IPC_PUB_LEN = 33
IPC_TIMEOUT_S = 2.0
IPC_TS_SKEW_S = 30

SYSTEM_VERIFY_SOCK = "/var/run/lavalamp/verify.sock"
SYSTEM_VERIFY_PUB = "/var/run/lavalamp/verify.pub"
USER_VERIFY_SOCK_REL = ".lavalamp/verify.sock"
USER_VERIFY_PUB_REL = ".lavalamp/verify.pub"


class DaemonResult(enum.Enum):
    """3-state outcome of the substrate verify.

    Maps directly to the LL-040 result byte ('A'/'R'/'S') in the
    LL-043 v4 response. The membrane (PH-004) collapses STALE and
    REJECT into a single deny per LL-017 / `Membrane.lean`; this
    module preserves the 3-state distinction for diagnostics.
    """
    ACCEPT = "A"
    REJECT = "R"
    STALE = "S"
    # Locally-generated (not from daemon):
    TIMEOUT = "T"
    UNREACHABLE = "U"
    BAD_SIG = "B"


class VerifyError(Exception):
    """Raised when the verify path fails in a way the reactor should log."""


def _resolve_paths() -> tuple[Path, Path]:
    """Return (socket_path, pubkey_path), preferring system-mode daemon."""
    if Path(SYSTEM_VERIFY_SOCK).exists():
        return Path(SYSTEM_VERIFY_SOCK), Path(SYSTEM_VERIFY_PUB)
    home = Path.home()
    return home / USER_VERIFY_SOCK_REL, home / USER_VERIFY_PUB_REL


def _load_pubkey(pub_path: Path) -> VerifyingKey:
    """Load a 33-byte SEC1-compressed P-256 pubkey from disk."""
    data = pub_path.read_bytes()
    if len(data) != IPC_PUB_LEN:
        raise VerifyError(
            f"pubkey at {pub_path}: expected {IPC_PUB_LEN} bytes, "
            f"got {len(data)}"
        )
    if data[0] not in (0x02, 0x03):
        raise VerifyError(
            f"pubkey at {pub_path}: not SEC1-compressed "
            f"(leading byte 0x{data[0]:02x})"
        )
    return VerifyingKey.from_string(data, curve=NIST256p)


def verify_lavalamp_substrate(
    *,
    sock_path: Optional[Path] = None,
    pub_path: Optional[Path] = None,
    now: Optional[int] = None,
) -> DaemonResult:
    """Run the full LL-043 v4 challenge-response. Returns DaemonResult.

    Mirrors verify_lavalamp_substrate in LavaLampMechanism.m, including
    the 30-second timestamp skew window and the nonce-binding check.

    `now` is injectable for tests; defaults to time.time().
    `sock_path` / `pub_path` are injectable for tests; default to the
    resolved system-or-user pair.
    """
    if sock_path is None or pub_path is None:
        rsock, rpub = _resolve_paths()
        sock_path = sock_path or rsock
        pub_path = pub_path or rpub

    if not sock_path.exists():
        return DaemonResult.UNREACHABLE
    if not pub_path.exists():
        return DaemonResult.UNREACHABLE

    try:
        vk = _load_pubkey(pub_path)
    except VerifyError:
        return DaemonResult.BAD_SIG

    nonce = os.urandom(IPC_NONCE_LEN)
    request = bytes([IPC_VERSION]) + nonce
    assert len(request) == IPC_REQUEST_LEN

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(IPC_TIMEOUT_S)
            s.connect(str(sock_path))
            s.sendall(request)
            response = b""
            while len(response) < IPC_RESPONSE_LEN:
                chunk = s.recv(IPC_RESPONSE_LEN - len(response))
                if not chunk:
                    return DaemonResult.UNREACHABLE
                response += chunk
    except socket.timeout:
        return DaemonResult.TIMEOUT
    except (FileNotFoundError, ConnectionRefusedError, OSError):
        return DaemonResult.UNREACHABLE

    if len(response) != IPC_RESPONSE_LEN:
        return DaemonResult.BAD_SIG
    if response[0] != IPC_VERSION:
        return DaemonResult.BAD_SIG

    result_byte = response[1:2]
    ts_le = response[2:10]
    sig = response[10:74]

    try:
        ts = struct.unpack("<Q", ts_le)[0]
    except struct.error:
        return DaemonResult.BAD_SIG

    current = now if now is not None else int(time.time())
    if abs(current - ts) > IPC_TS_SKEW_S:
        return DaemonResult.STALE

    signed_msg = nonce + result_byte + ts_le
    assert len(signed_msg) == IPC_NONCE_LEN + 1 + 8

    try:
        vk.verify(
            sig, signed_msg, hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string,
        )
    except BadSignatureError:
        return DaemonResult.BAD_SIG

    try:
        return DaemonResult(result_byte.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return DaemonResult.BAD_SIG


__all__ = [
    "DaemonResult",
    "VerifyError",
    "verify_lavalamp_substrate",
    "IPC_VERSION",
    "IPC_NONCE_LEN",
    "IPC_TS_SKEW_S",
]
