"""Independent signed-deployment tests using only ephemeral keys and inert files.

Positive protected-layout tests emulate administrator ownership at the stat
boundary. Real descriptor traversal, hashes, parsing and Ed25519 verification
remain active. This fixture does not grant any real filesystem authority.
"""

import copy
import hashlib
import json
import os
import stat
import unittest
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_client_camoufox_setup_deployment as fixtures
from team_browser.client import camoufox_deployment as deployment


def _as_root(info, *, safe_ancestor=False):
    values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
    values["st_uid"] = 0
    if safe_ancestor:
        values["st_mode"] &= ~0o022
    return SimpleNamespace(**values)


class IndependentDeploymentTests(unittest.TestCase):
    setUp = fixtures.DeploymentTests.setUp
    tearDown = fixtures.DeploymentTests.tearDown
    write_receipt = fixtures.DeploymentTests.write_receipt
    load = fixtures.DeploymentTests.load

    @contextmanager
    def protected_layout(self):
        original_read, original_fstat, original_lstat = deployment._read, os.fstat, Path.lstat

        def simulated_read(path, **kwargs):
            if not kwargs.get("protected"):
                return original_read(path, **kwargs)

            def owned_stat(fd):
                info = original_fstat(fd)
                fd_path = Path(os.readlink(f"/proc/self/fd/{fd}"))
                ancestor = (
                    stat.S_ISDIR(info.st_mode)
                    and fd_path != self.native
                    and self.native not in fd_path.parents
                )
                return _as_root(info, safe_ancestor=ancestor)

            with patch.object(deployment.os, "fstat", side_effect=owned_stat):
                return original_read(path, **kwargs)

        def owned_lstat(path):
            return _as_root(original_lstat(path))

        with (
            patch.object(deployment, "_read", side_effect=simulated_read),
            patch.object(Path, "lstat", owned_lstat),
            patch.object(deployment.os, "geteuid", return_value=1000),
        ):
            yield

    @staticmethod
    def verify(selected):
        return selected.verify(
            selected.executable, observed_version=selected.policy.version, policy=selected.policy
        )

    def test_exact_complete_signed_synthetic_inventory_verifies(self):
        with self.protected_layout():
            selected = self.load()
            observed = self.verify(selected)
        self.assertEqual(observed.sha256, self.payload["files"]["camoufox-bin"])
        self.assertIsNone(selected.acceptance())

    def test_unknown_unsigned_resource_is_rejected(self):
        with self.protected_layout():
            selected = self.load()
            (self.native / "unlisted-library.so").write_bytes(b"inert")
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_missing_signed_resource_is_rejected(self):
        with self.protected_layout():
            selected = self.load()
            (self.native / "properties.json").unlink()
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_nested_resources_are_covered_and_change_is_rejected(self):
        directory = self.native / "resources"
        directory.mkdir()
        path = directory / "locale.pack"
        path.write_bytes(b"inert locale resource")
        self.payload["files"]["resources/locale.pack"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        self.write_receipt()
        with self.protected_layout():
            selected = self.load()
            self.verify(selected)
            path.write_bytes(b"changed locale resource")
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_symlink_root_parent_file_and_directory_are_rejected(self):
        with self.protected_layout():
            selected = self.load()
            real = self.root / "real-distribution"
            self.native.rename(real)
            self.native.symlink_to(real, target_is_directory=True)
            with self.assertRaises(Exception):
                self.verify(selected)
            self.native.unlink()
            real.rename(self.native)
            path = self.native / "properties.json"
            path.unlink()
            path.symlink_to(self.native / "application.ini")
            with self.assertRaises(Exception):
                self.verify(selected)
            path.unlink()
            path.write_text("[]")
            (self.native / "foreign-dir").symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_hard_link_and_fifo_are_rejected_without_blocking(self):
        with self.protected_layout():
            selected = self.load()
            path = self.native / "properties.json"
            backup = self.root / "same-inode"
            os.link(path, backup)
            with self.assertRaises(Exception):
                self.verify(selected)
            backup.unlink()
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_writable_root_and_resource_and_subdirectory_are_rejected(self):
        with self.protected_layout():
            selected = self.load()
            self.native.chmod(0o777)
            with self.assertRaises(Exception):
                self.verify(selected)
            self.native.chmod(0o700)
            path = self.native / "properties.json"
            path.chmod(0o666)
            with self.assertRaises(Exception):
                self.verify(selected)
            path.chmod(0o600)
            directory = self.native / "unsafe"
            directory.mkdir()
            directory.chmod(0o777)
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_execution_bit_is_required(self):
        with self.protected_layout():
            selected = self.load()
            selected.executable.chmod(0o600)
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_no_follow_private_configuration_and_receipt(self):
        for path in (self.config, self.receipt):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                saved = self.root / (path.name + ".real")
                path.rename(saved)
                path.symlink_to(saved)
                with self.protected_layout(), self.assertRaises(Exception):
                    self.load()
                path.unlink()
                path.write_bytes(original)
                path.chmod(0o600)
                saved.unlink()

    def test_path_traversal_and_noncanonical_inventory_entries_fail(self):
        original = copy.deepcopy(self.payload)
        for key in (
            "../outside",
            "/absolute",
            "a//b",
            "a/./b",
            "a/../b",
            "a/",
            "bad\x00name",
            "bad\nname",
        ):
            with self.subTest(key=key):
                self.payload = copy.deepcopy(original)
                self.payload["files"][key] = "a" * 64
                self.write_receipt()
                with self.protected_layout(), self.assertRaises(Exception):
                    self.load()

    def test_valid_signature_does_not_allow_noncanonical_payload_json(self):
        text = json.dumps(self.payload, indent=2)
        self.receipt.write_text(
            fixtures.canonical(
                {"payload": text, "signature_hex": self.key.sign(text.encode("ascii")).hex()}
            )
        )
        with self.protected_layout(), self.assertRaises(Exception):
            self.load()

    def test_duplicate_json_fields_and_nonfinite_numbers_fail(self):
        original = self.config.read_text()
        for raw in ('{"schema_version":1,"schema_version":1}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(raw=raw):
                self.config.write_text(raw)
                with self.protected_layout(), self.assertRaises(Exception):
                    self.load()
        self.config.write_text(original)

    def test_expiry_naive_future_and_overlong_windows_fail(self):
        original = copy.deepcopy(self.payload)
        cases = (
            {"issued_at": (self.now + timedelta(minutes=1)).isoformat()},
            {"valid_until": self.now.replace(tzinfo=None).isoformat()},
            {"issued_at": self.now.replace(tzinfo=None).isoformat()},
            {"valid_until": (self.now + timedelta(days=31)).isoformat()},
            {"valid_until": (self.now - timedelta(hours=1)).isoformat()},
        )
        for updates in cases:
            with self.subTest(updates=updates):
                self.payload = {**copy.deepcopy(original), **updates}
                self.write_receipt()
                with self.protected_layout(), self.assertRaises(Exception):
                    self.load()

    def test_duplicate_profile_bindings_fail(self):
        selection = {
            "profile_id": "synthetic-one",
            "profile_binding_sha256": "a" * 64,
            **self.payload["profile_defaults"],
        }
        config = json.loads(self.config.read_text())
        config["profiles"] = [selection, selection]
        self.config.write_text(fixtures.canonical(config))
        with self.protected_layout(), self.assertRaises(Exception):
            self.load()

    def test_bounded_read_rejects_oversize_before_parsing(self):
        self.config.write_bytes(b" " * (deployment.MAX_BYTES + 1))
        with self.protected_layout(), self.assertRaises(Exception):
            self.load()

    def test_independent_key_signature_host_platform_and_authority_are_bound(self):
        original = copy.deepcopy(self.payload)
        for key, value in (
            ("host_id", "other-host-00000001"),
            ("authority_id", "other-reviewer"),
            ("platform", "darwin"),
        ):
            with self.subTest(key=key):
                self.payload = {**copy.deepcopy(original), key: value}
                self.write_receipt()
                with self.protected_layout(), self.assertRaises(Exception):
                    self.load()

    def test_metadata_version_cannot_be_substituted_by_receipt_string(self):
        path = self.native / "application.ini"
        path.write_text("[App]\nVersion=156.0.1\nBuildID=20260901000000\n")
        self.payload["files"]["application.ini"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_receipt()
        with self.protected_layout():
            selected = self.load()
            with self.assertRaises(Exception):
                self.verify(selected)

    def test_receipt_bytes_change_during_hashing_fails_closed(self):
        original = deployment._hash_regular_file
        changed = False

        def revoke(path):
            nonlocal changed
            observed = original(path)
            if not changed:
                changed = True
                self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
            return observed

        with self.protected_layout():
            selected = self.load()
            with (
                patch.object(deployment, "_hash_regular_file", side_effect=revoke),
                self.assertRaises(Exception),
            ):
                self.verify(selected)

    def test_changed_signed_resource_after_its_hash_cannot_verify(self):
        path = self.native / "accepted-library.so"
        path.write_bytes(b"original reviewed library")
        self.payload["files"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_receipt()
        original = deployment._hash_regular_file

        def changed_after_read(file):
            result = original(file)
            if file == path:
                path.write_bytes(b"changed after its signed hash was checked")
            return result

        with self.protected_layout():
            selected = self.load()
            with (
                patch.object(deployment, "_hash_regular_file", side_effect=changed_after_read),
                self.assertRaises(Exception),
            ):
                self.verify(selected)

    def test_extra_resource_created_after_walk_snapshot_cannot_verify(self):
        original = deployment._hash_regular_file

        def add_after_walk(file):
            result = original(file)
            (self.native / "late-unlisted-library.so").write_bytes(b"late resource")
            return result

        with self.protected_layout():
            selected = self.load()
            with (
                patch.object(deployment, "_hash_regular_file", side_effect=add_after_walk),
                self.assertRaises(Exception),
            ):
                self.verify(selected)

    def test_verified_support_resource_change_invalidates_native_metadata_guard(self):
        path = self.native / "accepted-library.so"
        path.write_bytes(b"original reviewed library")
        self.payload["files"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_receipt()
        with self.protected_layout():
            selected = self.load()
            self.verify(selected)
            path.write_bytes(b"modified support library")
            with self.assertRaises(Exception):
                selected.metadata(selected.executable)

    def test_new_file_after_verification_invalidates_native_metadata_guard(self):
        with self.protected_layout():
            selected = self.load()
            self.verify(selected)
            (self.native / "new-support-resource").write_bytes(b"unreviewed")
            with self.assertRaises(Exception):
                selected.metadata(selected.executable)

    def test_native_metadata_guard_observes_resources_without_byte_rehash(self):
        with self.protected_layout():
            selected = self.load()
            self.verify(selected)
            with patch.object(
                deployment,
                "_hash_regular_file",
                side_effect=AssertionError("No full bytes at metadata fence"),
            ):
                self.assertEqual(
                    selected.metadata(selected.executable).version, selected.policy.version
                )

    def test_hardlink_created_after_verification_invalidates_native_guard(self):
        with self.protected_layout():
            selected = self.load()
            self.verify(selected)
            os.link(self.native / "properties.json", self.root / "new-link")
            with self.assertRaises(Exception):
                selected.metadata(selected.executable)

    def test_inventory_entry_count_is_bounded_before_stat(self):
        with self.protected_layout():
            selected = self.load()
            entries = [f"synthetic-dir-{number}" for number in range(32768)]
            with (
                patch.object(
                    deployment.os, "walk", return_value=iter([(str(self.native), entries, [])])
                ),
                self.assertRaises(Exception),
            ):
                self.verify(selected)

    def test_native_qualification_requires_exact_boolean_true_for_every_claim(self):
        claims = (
            "normal_sandbox_and_security_defaults",
            "controlled_updates",
            "owned_launch_close_and_two_profile_persistence",
            "fixed_probe_and_identity_surfaces",
            "accepted_unrestricted_local_direct_egress",
        )
        record = {
            "report_id": "synthetic-independent-report",
            **dict.fromkeys(claims, True),
            "generator": {
                "generator_version": "synthetic",
                "implementation_sha256": "a" * 64,
                "packages_sha256": "b" * 64,
                "catalogue_name": "synthetic",
                "catalogue_sha256": "c" * 64,
            },
            "probe_id": "synthetic-fixed-probe",
        }
        accepted = deployment.NativeQualification.model_validate(record)
        self.assertIs(accepted.controlled_updates, True)
        for claim in claims:
            for value in (1, 1.0, "true", "True", "1", False, 0, None):
                with self.subTest(claim=claim, value=repr(value)), self.assertRaises(Exception):
                    deployment.NativeQualification.model_validate({**record, claim: value})

    def test_schema_version_requires_exact_integer_one_for_every_record(self):
        records = (
            (deployment.TrustAnchor, self.anchor),
            (deployment.SetupConfiguration, json.loads(self.config.read_text())),
            (deployment.DistributionRecord, self.payload),
        )
        for model, record in records:
            self.assertEqual(model.model_validate(record).schema_version, 1)
            for value in (True, 1.0, "1", False, 0, None):
                with (
                    self.subTest(model=model.__name__, value=repr(value)),
                    self.assertRaises(Exception),
                ):
                    model.model_validate({**record, "schema_version": value})
