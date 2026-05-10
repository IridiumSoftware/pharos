#!/usr/bin/env python3
"""
mock_lavalamp_daemon.py — minimal AF_UNIX socket server that
mimics the LavaLamp daemon's LL-041 v2 IPC contract (HMAC-
SHA256 anti-replay).

Used by test_pam_lavalamp.sh to exercise the MVP-3 IPC
protocol without requiring a running Julia LavaLamp daemon.
On each connection, reads a 17-byte v2 request (version +
nonce), responds with 42 bytes (version + result + 8-byte LE
timestamp + 32-byte HMAC over nonce ‖ result ‖ timestamp).

Usage:
    mock_lavalamp_daemon.py <socket-path> <secret-path> <response-char> [--ts-skew SECONDS]

  socket-path     path to AF_UNIX listener (created mode 0600).
  secret-path     path to write the 32-byte shared secret
                  (created mode 0600).
  response-char   one of 'A' / 'R' / 'S' (LL-040/041 protocol).
  --ts-skew N     (optional) bias daemon timestamp by N seconds
                  for testing client freshness checks. Default 0.

Runs until killed (SIGINT/SIGTERM). Cleans up socket + secret
files on exit.
"""

import argparse
import hashlib
import hmac
import os
import secrets
import signal
import socket
import struct
import sys
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_path")
    parser.add_argument("secret_path")
    parser.add_argument("response_char")
    parser.add_argument("--ts-skew", type=int, default=0,
                        help="bias daemon timestamp by N seconds (test)")
    args = parser.parse_args()

    if args.response_char not in ("A", "R", "S"):
        sys.exit(f"response must be 'A' / 'R' / 'S'; got '{args.response_char}'")

    response_byte = args.response_char.encode("ascii")

    # Generate 32-byte secret + write with mode 0600.
    shared_secret = secrets.token_bytes(32)
    fd = os.open(args.secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, shared_secret)
    finally:
        os.close(fd)

    # Bind listener.
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
        for path in (args.socket_path, args.secret_path):
            if os.path.exists(path):
                os.unlink(path)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    print(f"mock daemon v2: socket={args.socket_path}, "
          f"secret={args.secret_path}, response='{args.response_char}', "
          f"ts_skew={args.ts_skew}s", flush=True)

    try:
        while True:
            client, _ = server.accept()
            try:
                client.settimeout(2.0)
                # Read 17-byte v2 request.
                request = b""
                while len(request) < 17:
                    chunk = client.recv(17 - len(request))
                    if not chunk:
                        break
                    request += chunk
                if len(request) != 17:
                    continue
                if request[0] != 0x02:
                    continue   # unsupported version
                nonce = request[1:17]

                # Build signed response.
                ts = int(time.time()) + args.ts_skew
                ts_bytes = struct.pack("<q", ts)
                signed = nonce + response_byte + ts_bytes
                mac = hmac.new(shared_secret, signed, hashlib.sha256).digest()

                response = bytes([0x02]) + response_byte + ts_bytes + mac
                assert len(response) == 42
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
