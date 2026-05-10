#!/usr/bin/env python3
"""
mock_lavalamp_daemon.py — minimal AF_UNIX socket server that
mimics the LavaLamp daemon's LL-042 v3 IPC contract (Ed25519
asymmetric-signature challenge-response).

Used by test_pam_lavalamp.sh to exercise the MVP-4 IPC
protocol without requiring a running Julia LavaLamp daemon.
On each connection, reads a 17-byte v3 request (version 0x03 +
nonce), responds with 74 bytes (version + result + 8-byte LE
timestamp + 64-byte Ed25519 signature over
`nonce ‖ result ‖ timestamp`).

Usage:
    mock_lavalamp_daemon.py <socket-path> <pubkey-path> <response-char> [--ts-skew SECONDS]

  socket-path     path to AF_UNIX listener (created mode 0600).
  pubkey-path     path to write the 32-byte raw Ed25519
                  public key (created mode 0644 — world-
                  readable; matches LL-042 contract).
  response-char   one of 'A' / 'R' / 'S' (LL-040/041/042
                  protocol).
  --ts-skew N     (optional) bias daemon timestamp by N seconds
                  for testing client freshness checks. Default 0.

Runs until killed (SIGINT/SIGTERM). Cleans up socket + pubkey
files on exit.

Requires: cryptography library (`pip install cryptography`).
ubuntu-latest: `python3 -m pip install cryptography` (typically
pre-installed in 24.04+).
"""

import argparse
import os
import signal
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_path")
    parser.add_argument("pubkey_path")
    parser.add_argument("response_char")
    parser.add_argument("--ts-skew", type=int, default=0,
                        help="bias daemon timestamp by N seconds (test)")
    args = parser.parse_args()

    if args.response_char not in ("A", "R", "S"):
        sys.exit(f"response must be 'A' / 'R' / 'S'; got '{args.response_char}'")

    response_byte = args.response_char.encode("ascii")

    # Generate Ed25519 keypair.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert len(pub_raw) == 32

    # Write public key (mode 0644 — world-readable; clients verify
    # without needing any secret).
    fd = os.open(args.pubkey_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, pub_raw)
    finally:
        os.close(fd)

    # Bind listener (mode 0600 — only owner UID can connect).
    if os.path.exists(args.socket_path):
        os.unlink(args.socket_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(args.socket_path)
    os.chmod(args.socket_path, 0o600)
    server.listen(8)

    def cleanup(*_):
        try:
            server.close()
        except Exception:
            pass
        for path in (args.socket_path, args.pubkey_path):
            if os.path.exists(path):
                os.unlink(path)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    print(f"mock daemon v3: socket={args.socket_path}, "
          f"pubkey={args.pubkey_path}, response='{args.response_char}', "
          f"ts_skew={args.ts_skew}s", flush=True)

    try:
        while True:
            client, _ = server.accept()
            try:
                client.settimeout(2.0)
                # Read 17-byte v3 request.
                request = b""
                while len(request) < 17:
                    chunk = client.recv(17 - len(request))
                    if not chunk:
                        break
                    request += chunk
                if len(request) != 17:
                    continue
                if request[0] != 0x03:
                    continue   # unsupported version
                nonce = request[1:17]

                # Build signed response.
                ts = int(time.time()) + args.ts_skew
                ts_bytes = struct.pack("<q", ts)
                signed = nonce + response_byte + ts_bytes
                sig = priv.sign(signed)
                assert len(sig) == 64

                response = bytes([0x03]) + response_byte + ts_bytes + sig
                assert len(response) == 74
                client.sendall(response)
            except (socket.timeout, BlockingIOError, ConnectionError):
                pass
            finally:
                client.close()
    except KeyboardInterrupt:
        cleanup()
    except OSError:
        cleanup()


if __name__ == "__main__":
    main()
