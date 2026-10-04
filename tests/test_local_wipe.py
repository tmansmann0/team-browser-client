from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from team_browser.local.storage import ProfileStore
from team_browser.local.wipe import WipeRejected, wipe_profile_data


class LocalWipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "profiles"
        self.store = ProfileStore(self.root)
        self.lease = self.store.acquire("synthetic-profile")
        self.data = self.lease.paths.browser_data
        (self.data / "synthetic-session.txt").write_text("invented-test-data")

    def tearDown(self):
        self.lease.release()
        self.temp.cleanup()

    def test_removes_only_own_data_and_preserves_lock(self):
        sibling = self.store.prepare("other-synthetic-profile").browser_data / "keep.txt"
        sibling.write_text("keep")
        before = os.stat(self.lease.paths.directory / ".lease.lock").st_ino
        result = wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue(result.local_data_removed)
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertEqual(sibling.read_text(), "keep")
        self.assertEqual(os.stat(self.lease.paths.directory / ".lease.lock").st_ino, before)
        self.assertTrue(self.lease.active)
        self.assertIn("not revoked", result.limitation)

    def test_live_unknown_or_nonboolean_stop_denied(self):
        for result in (False, None, "yes", 1):
            with self.assertRaises(WipeRejected):
                wipe_profile_data(self.lease, confirm_stopped=lambda lease: result)
        self.assertTrue((self.data / "synthetic-session.txt").exists())

    def test_released_lease_denied(self):
        self.lease.release()
        with self.assertRaises(WipeRejected):
            wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)

    def test_symlink_inside_data_does_not_follow_target(self):
        target = Path(self.temp.name) / "outside.txt"
        target.write_text("keep-outside")
        (self.data / "linked.txt").symlink_to(target)
        wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertEqual(target.read_text(), "keep-outside")

    def test_root_symlink_rejected_without_deleting_target(self):
        moved = self.data.with_name("original-data")
        self.data.rename(moved)
        self.data.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(WipeRejected):
            wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue((moved / "synthetic-session.txt").exists())

    def test_interrupted_removal_is_not_success_and_retry_cleans_tombstone(self):
        with patch(
            "team_browser.local.wipe.shutil.rmtree", side_effect=OSError("synthetic I/O failure")
        ):
            with self.assertRaises(WipeRejected):
                wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue(
            any(p.name.startswith(".wipe-") for p in self.lease.paths.directory.iterdir())
        )
        result = wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue(result.local_data_removed)
        self.assertFalse(
            any(p.name.startswith(".wipe-") for p in self.lease.paths.directory.iterdir())
        )
