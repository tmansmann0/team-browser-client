"""Local-only tests. Never open a browser or contact a credential provider."""

import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from pathlib import Path

from team_browser.local import ProfileInUseError, ProfileStore, UnsafePathError, validate_identifier


def _crash_with_lease(root: str, profile_id: str) -> None:
    store = ProfileStore(Path(root))
    lease = store.acquire(profile_id)
    assert lease.active
    os._exit(0)  # Deliberately skip cleanup to simulate supervisor process death.


def _try_competing_lease(root: str, result: object) -> None:
    try:
        with ProfileStore(Path(root)).acquire("profile-1"):
            result.put("acquired")
    except ProfileInUseError:
        result.put("blocked")


class ProfileStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS /var can be a symlink; pass the deliberate canonical test root.
        self.root = Path(self.temp.name).resolve() / "profiles"
        self.store = ProfileStore(self.root)

    def test_persistent_data_survives_lease_reopen(self) -> None:
        with self.store.acquire("profile-1") as lease:
            (lease.paths.browser_data / "synthetic.txt").write_text("synthetic test data")
        with self.store.acquire("profile-1") as lease:
            self.assertEqual(
                (lease.paths.browser_data / "synthetic.txt").read_text(), "synthetic test data"
            )
            self.assertFalse(lease.recovered_unclean_lease)

    def test_directories_are_private(self) -> None:
        paths = self.store.prepare("profile-1")
        for path in (self.root, paths.directory, paths.browser_data):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_invalid_identifiers_are_rejected(self) -> None:
        for invalid in (
            "",
            "..",
            "../escape",
            "/absolute",
            "a/b",
            "a\\b",
            "A",
            ".hidden",
            "é",
            "a\n",
            "a" * 65,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.store.prepare(invalid)
        self.assertEqual(validate_identifier("a-0_test"), "a-0_test")

    def test_profile_symlink_is_rejected(self) -> None:
        outside = Path(self.temp.name).resolve() / "outside"
        outside.mkdir(mode=0o700)
        (self.root / "profile-1").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(UnsafePathError):
            self.store.prepare("profile-1")
        self.assertFalse((outside / "browser-data").exists())

    def test_root_symlink_is_rejected(self) -> None:
        link = Path(self.temp.name).resolve() / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(UnsafePathError):
            ProfileStore(link)

    def test_unsafe_permissions_fail_without_changing_them(self) -> None:
        self.root.chmod(0o755)
        with self.assertRaises(UnsafePathError):
            ProfileStore(self.root)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)

    def test_relative_root_is_rejected(self) -> None:
        with self.assertRaises(UnsafePathError):
            ProfileStore(Path("relative"))

    def test_competing_lease_same_process_is_rejected(self) -> None:
        with self.store.acquire("profile-1"):
            with self.assertRaises(ProfileInUseError):
                self.store.acquire("profile-1")

    def test_competing_lease_other_process_is_rejected(self) -> None:
        context = multiprocessing.get_context("spawn")
        result = context.Queue()
        self.addCleanup(result.close)
        with self.store.acquire("profile-1"):
            process = context.Process(target=_try_competing_lease, args=(str(self.root), result))
            process.start()
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join()
                self.fail("Competing process did not finish")
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(result.get(timeout=2), "blocked")

    def test_crash_recovery_uses_kernel_lock(self) -> None:
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=_crash_with_lease, args=(str(self.root), "profile-1"))
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("Crash simulation did not finish")
        self.assertEqual(process.exitcode, 0)
        with self.store.acquire("profile-1") as lease:
            self.assertTrue(lease.recovered_unclean_lease)

    def test_malformed_stale_metadata_does_not_prevent_recovery(self) -> None:
        paths = self.store.prepare("profile-1")
        lock = paths.directory / ".lease.lock"
        lock.write_text('{"incomplete":')
        lock.chmod(0o600)
        with self.store.acquire("profile-1") as lease:
            self.assertIsNone(lease.previous_metadata)
        self.assertEqual(json.loads(lock.read_text())["state"], "released")

    def test_lock_inode_is_retained_between_leases(self) -> None:
        with self.store.acquire("profile-1") as lease:
            lock = lease.paths.directory / ".lease.lock"
            inode = lock.stat().st_ino
        with self.store.acquire("profile-1"):
            self.assertEqual(lock.stat().st_ino, inode)

    def test_lock_symlink_is_rejected(self) -> None:
        paths = self.store.prepare("profile-1")
        target = Path(self.temp.name).resolve() / "target"
        target.write_text("unchanged")
        (paths.directory / ".lease.lock").symlink_to(target)
        with self.assertRaises(UnsafePathError):
            self.store.acquire("profile-1")
        self.assertEqual(target.read_text(), "unchanged")

    def test_lock_hardlink_is_rejected(self) -> None:
        paths = self.store.prepare("profile-1")
        target = Path(self.temp.name).resolve() / "target"
        target.write_text("unchanged")
        target.chmod(0o600)
        os.link(target, paths.directory / ".lease.lock")
        with self.assertRaises(UnsafePathError):
            self.store.acquire("profile-1")
        self.assertEqual(target.read_text(), "unchanged")

    def test_release_is_idempotent(self) -> None:
        lease = self.store.acquire("profile-1")
        lease.release()
        lease.release()
        self.assertFalse(lease.active)

    def test_fifo_lock_is_rejected_without_blocking(self) -> None:
        paths = self.store.prepare("profile-1")
        os.mkfifo(paths.directory / ".lease.lock", mode=0o600)
        with self.assertRaises(UnsafePathError):
            self.store.acquire("profile-1")
