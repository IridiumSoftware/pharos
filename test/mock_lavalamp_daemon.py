#!/usr/bin/env python3
"""
mock_lavalamp_daemon.py — minimal AF_UNIX socket server that
mimics the LavaLamp daemon's LL-040 IPC contract.

Used by test_pam_lavalamp.sh to exercise the MVP-2 IPC protocol
without requiring a running Julia LavaLamp daemon. Listens on a
provided socket path; on each connection, optionally consumes
one request byte and writes a configured response byte.

Usage:
    mock_lavalamp_daemon.py <socket-path> <response-char>

  socket-path    path to AF_UNIX listener (created with mode 0600).
  response-char  one of 'A' / 'R' / 'S' (LL-040 protocol).

Runs until killed (SIGINT/SIGTERM). Cleans up the socket file on exit.
"""

import os
import signal
import socket
import sys


def main(sock_path: str, response_char: str) -> None:
    if response_char not in ("A", "R", "S"):
        sys.exit(f"response must be 'A' / 'R' / 'S'; got '{response_char}'")

    if os.path.exists(sock_path):
        os.unlink(sock_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o600)
    server.listen(8)

    response_byte = response_char.encode("ascii")

    def cleanup(*_):
        try:
            server.close()
        except Exception:
            pass
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    print(f"mock daemon: listening on {sock_path}, responding '{response_char}'", flush=True)
    try:
        while True:
            client, _ = server.accept()
            try:
                # Optional: consume one request byte (timeout-protected).
                client.settimeout(0.5)
                try:
                    client.recv(1)
                except (socket.timeout, BlockingIOError):
                    pass
                client.send(response_byte)
            finally:
                client.close()
    except KeyboardInterrupt:
        cleanup()
    except OSError:
        cleanup()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <socket-path> <response-char>")
    main(sys.argv[1], sys.argv[2])
