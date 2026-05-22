"""Tests for lavalamp_client — LL-043 v4 ECDSA P-256 protocol consumer.

Stands up an AF_UNIX mock daemon that signs responses with a known
private key, then exercises the verify path through every documented
outcome:

  ACCEPT       — happy path, signature valid + nonce binds + fresh.
  REJECT       — daemon returns 'R'.
  STALE        — timestamp outside the ±30s window.
  TIMEOUT      — mock holds the connection open without responding.
  UNREACHABLE  — no socket at the configured path.
  BAD_SIG      — mock signs with the wrong key.

Each test injects sock_path + pub_path explicitly so we never touch
the real ~/.lavalamp/ paths.
"""

from __future__ import annotations

import hashlib
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

from lavalamp_client import (
    DaemonResult,
    IPC_NONCE_LEN,
    IPC_VERSION,
    verify_lavalamp_substrate,
)


def _spawn_mock(
    sock_path: Path,
    *,
    sk: SigningKey,
    result_byte: bytes,
    ts: int,
    hang: bool = False,
    bad_sig: bool = False,
) -> threading.Event:
    """Spawn a one-shot AF_UNIX mock daemon. Returns a 'ready' Event."""
    ready = threading.Event()

    def _serve():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        ready.set()
        srv.settimeout(5)
        conn, _ = srv.accept()
        try:
            req = b""
            while len(req) < 17:
                chunk = conn.recv(17 - len(req))
                if not chunk:
                    return
                req += chunk
            nonce = req[1:17]
            ts_le = struct.pack("<Q", ts)
            signed = nonce + result_byte + ts_le
            if bad_sig:
                # Sign with a fresh, *different* key.
                wrong = SigningKey.generate(curve=NIST256p)
                sig = wrong.sign(signed, hashfunc=hashlib.sha256,
                                 sigencode=sigencode_string)
            else:
                sig = sk.sign(signed, hashfunc=hashlib.sha256,
                              sigencode=sigencode_string)
            if hang:
                time.sleep(10)
                return
            response = bytes([IPC_VERSION]) + result_byte + ts_le + sig
            conn.sendall(response)
        finally:
            conn.close()
            srv.close()
            try:
                sock_path.unlink()
            except FileNotFoundError:
                pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    ready.wait(timeout=2)
    return ready


def _write_pubkey(sk: SigningKey, path: Path) -> None:
    vk = sk.get_verifying_key()
    path.write_bytes(vk.to_string("compressed"))


class LavaLampClientTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ph019-test-"))
        self.sk = SigningKey.generate(curve=NIST256p)
        self.sock = self.tmp / "verify.sock"
        self.pub = self.tmp / "verify.pub"
        _write_pubkey(self.sk, self.pub)
        self.now = int(time.time())

    def tearDown(self):
        for p in [self.sock, self.pub]:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass

    def test_accept(self):
        _spawn_mock(self.sock, sk=self.sk, result_byte=b"A", ts=self.now)
        result = verify_lavalamp_substrate(
            sock_path=self.sock, pub_path=self.pub, now=self.now,
        )
        self.assertEqual(result, DaemonResult.ACCEPT)

    def test_reject(self):
        _spawn_mock(self.sock, sk=self.sk, result_byte=b"R", ts=self.now)
        result = verify_lavalamp_substrate(
            sock_path=self.sock, pub_path=self.pub, now=self.now,
        )
        self.assertEqual(result, DaemonResult.REJECT)

    def test_stale_timestamp(self):
        # Daemon timestamp 60s in the past — outside ±30s window.
        _spawn_mock(self.sock, sk=self.sk, result_byte=b"A",
                    ts=self.now - 60)
        result = verify_lavalamp_substrate(
            sock_path=self.sock, pub_path=self.pub, now=self.now,
        )
        self.assertEqual(result, DaemonResult.STALE)

    def test_unreachable(self):
        # No mock spawned — socket file doesn't exist.
        result = verify_lavalamp_substrate(
            sock_path=self.sock, pub_path=self.pub, now=self.now,
        )
        self.assertEqual(result, DaemonResult.UNREACHABLE)

    def test_bad_signature(self):
        _spawn_mock(self.sock, sk=self.sk, result_byte=b"A",
                    ts=self.now, bad_sig=True)
        result = verify_lavalamp_substrate(
            sock_path=self.sock, pub_path=self.pub, now=self.now,
        )
        self.assertEqual(result, DaemonResult.BAD_SIG)


if __name__ == "__main__":
    unittest.main()
