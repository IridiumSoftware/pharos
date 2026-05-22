"""Smoke test: every reaction primitive in --dry-run mode is a no-op.

If this test ever fails by actually side-effecting (locking the
screen during CI, killing a session), the dry_run kill-switch is
broken and PH-019 should not ship.
"""

from __future__ import annotations

import logging
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reactions


class DryRunTest(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_lock_screen_dry_run_returns_0(self):
        self.assertEqual(reactions.lock_screen(dry_run=True), 0)

    def test_kill_gui_session_dry_run_returns_0(self):
        self.assertEqual(reactions.kill_gui_session(dry_run=True), 0)

    def test_force_reauth_dry_run_returns_0(self):
        self.assertEqual(reactions.force_reauth(dry_run=True), 0)

    def test_revoke_keychain_item_dry_run_returns_0(self):
        self.assertEqual(
            reactions.revoke_keychain_item("test.service", dry_run=True),
            0,
        )

    def test_revoke_keychain_item_rejects_suspicious_service(self):
        # Service names with shell metacharacters or path separators
        # must be refused even in dry_run mode.
        for bad in ["foo bar", "../etc/passwd", "foo;rm", ""]:
            with self.subTest(service=bad):
                self.assertEqual(
                    reactions.revoke_keychain_item(bad, dry_run=True),
                    -1,
                )

    def test_react_to_reject_dry_run_does_not_raise(self):
        # Should not raise; should not actually lock or kill anything.
        reactions.react_to_reject(dry_run=True)
        reactions.react_to_reject(kill=False, dry_run=True)

    def test_react_to_stale_dry_run_does_not_raise(self):
        reactions.react_to_stale(dry_run=True)

    def test_react_to_timeout_does_not_raise(self):
        # No subprocess at all — just a log line.
        reactions.react_to_timeout(dry_run=True)
        reactions.react_to_timeout(dry_run=False)


if __name__ == "__main__":
    unittest.main()
