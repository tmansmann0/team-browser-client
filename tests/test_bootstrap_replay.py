import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from team_browser.contracts.replay import SQLiteReplayGuard
from team_browser.contracts.bootstrap import BootstrapRejected


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "synthetic.db"
        self.connections = lambda: sqlite3.connect(self.path, timeout=5)
        self.guard = SQLiteReplayGuard(self.connections)
        self.expiry = datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp.cleanup()

    def test_consumed_state_survives_new_guard(self):
        self.assertIs(self.guard.consume("org", "device", "command", self.expiry), True)
        second = SQLiteReplayGuard(self.connections)
        self.assertIs(second.consume("org", "device", "command", self.expiry), False)

    def test_competing_consumers_are_exclusive(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(
                pool.map(
                    lambda _: self.guard.consume("org", "device", "same-command", self.expiry),
                    range(8),
                )
            )
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 7)

    def test_scope_is_part_of_key(self):
        self.assertTrue(self.guard.consume("org-a", "device", "command", self.expiry))
        self.assertTrue(self.guard.consume("org-b", "device", "command", self.expiry))
        self.assertTrue(self.guard.consume("org-a", "other-device", "command", self.expiry))

    def test_invalid_scope_never_inserts(self):
        with self.assertRaises(BootstrapRejected):
            self.guard.consume("../invalid", "device", "command", self.expiry)
        with self.connections() as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM bootstrap_replay_v1").fetchone()[0], 0
            )

    def test_no_cookie_columns(self):
        with self.connections() as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(bootstrap_replay_v1)")
            }
        self.assertEqual(columns, {"organization_id", "device_id", "command_id", "expires_at"})
