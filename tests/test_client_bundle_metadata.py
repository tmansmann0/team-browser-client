"""Synthetic signed-bundle observation/cache contracts; no browser execution."""

import hashlib
import json
import os
import plistlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from team_browser.client import LifecycleCoordinator, WorkspaceStore
from team_browser.client.installed_browser import (
    InstalledBrowserAdapter,
    load_installed_adapter,
    read_macos_bundle_metadata,
)
from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence
from test_client_installed_browser import FixtureSupervisor


class BundleMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "Synthetic Chrome.app"
        (self.bundle / "Contents" / "MacOS").mkdir(parents=True)
        self.binary = self.bundle / "Contents" / "MacOS" / "Synthetic Chrome"
        self.binary.write_bytes(b"Synthetic browser fixture; never execute")
        self.binary.chmod(0o700)
        self.info = self.bundle / "Contents" / "Info.plist"
        self.metadata = {
            "CFBundleExecutable": "Synthetic Chrome",
            "CFBundleShortVersionString": "12.34.56.78",
        }
        self.write_info()
        self.store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(self.store.close)
        self.policy = RuntimePolicy(
            "chromium",
            "12.34.56.78",
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "fixture-team:fixture-bundle",
        )
        self.verifications = []
        parent = self

        class Verifier:
            def verify(self, executable, digest):
                parent.verifications.append(executable)
                return SignatureEvidence(
                    digest, parent.policy.signer_identity, True, True, datetime.now(timezone.utc)
                )

        self.verifier = Verifier()
        self.adapter = InstalledBrowserAdapter(
            profile_store=self.store.profiles,
            executable=self.binary,
            observed_version=None,
            policy=self.policy,
            runtime_gate=RuntimeGate(self.verifier),
            supervisor=FixtureSupervisor(),
            metadata_observer=read_macos_bundle_metadata,
        )

    def write_info(self, metadata=None, *, fmt=plistlib.FMT_XML):
        self.info.write_bytes(
            plistlib.dumps(self.metadata if metadata is None else metadata, fmt=fmt)
        )
        self.info.chmod(0o644)

    def test_reads_xml_and_binary_version_without_executing_browser(self):
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            self.write_info(fmt=fmt)
            with patch("subprocess.run", side_effect=AssertionError("Must not execute browser")):
                evidence = read_macos_bundle_metadata(self.binary)
            self.assertEqual(evidence.version, self.policy.version)
            self.assertEqual(evidence.executable_name, self.binary.name)
            self.assertEqual(
                evidence.info_sha256, hashlib.sha256(self.info.read_bytes()).hexdigest()
            )

    def test_rejects_missing_invalid_version_or_wrong_executable(self):
        for version in (None, "", 123, True, ["12.34.56.78"], "12.34.56.78 ", "12\n34"):
            self.write_info(
                {**self.metadata, "CFBundleShortVersionString": version}
            ) if version is not None else self.write_info({"CFBundleExecutable": self.binary.name})
            with self.subTest(version=version), self.assertRaises(RuntimeVerificationError):
                read_macos_bundle_metadata(self.binary)
        self.write_info({**self.metadata, "CFBundleExecutable": "Other Browser"})
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.binary)

    def test_rejects_malformed_oversized_and_non_dictionary_plist(self):
        for raw in (b"not a plist", b"x" * (1024 * 1024 + 1), plistlib.dumps(["not-a-dictionary"])):
            self.info.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(RuntimeVerificationError):
                read_macos_bundle_metadata(self.binary)

    def test_refuses_symlink_file_and_symlink_parent_without_reading_target(self):
        target = self.root / "outside.plist"
        target.write_bytes(self.info.read_bytes())
        self.info.unlink()
        self.info.symlink_to(target)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.binary)
        self.info.unlink()
        self.write_info()
        alias = self.root / "Alias.app"
        alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(alias / "Contents" / "MacOS" / self.binary.name)

    def test_rejects_nonregular_and_group_writable_metadata(self):
        self.info.chmod(0o664)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.binary)
        self.info.unlink()
        os.mkfifo(self.info, mode=0o600)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.binary)

    def test_actual_bundle_version_mismatch_fails_even_if_policy_claim_matches(self):
        self.write_info({**self.metadata, "CFBundleShortVersionString": "99.0.0.0"})
        self.adapter.observed_version = (
            self.policy.version
        )  # Not authority when observation is enabled.
        self.assertIn("version does not match", self.adapter.global_blockers()[0])
        self.assertEqual(self.verifications, [])

    def test_info_digest_change_invalidates_status_cache_with_same_browser_binary(self):
        first = self.adapter._runtime()
        self.assertIs(self.adapter._runtime(), first)
        self.assertEqual(len(self.verifications), 1)
        old = self.info.stat()
        self.write_info({**self.metadata, "FixtureResource": "changed"})
        os.utime(self.info, ns=(old.st_atime_ns, old.st_mtime_ns))
        second = self.adapter._runtime()
        self.assertIsNot(second, first)
        self.assertEqual(len(self.verifications), 2)
        self.assertEqual(first.file_identity, second.file_identity)

    def test_each_new_start_freshly_verifies_whole_bundle_but_focus_does_not(self):
        profile = self.store.create("Fixture", network_policy="local_direct")["id"]
        coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.addCleanup(coordinator.shutdown)
        self.adapter.global_blockers()  # A status-only cache must not authorize launch.
        self.assertEqual(len(self.verifications), 1)
        coordinator.action(profile, "start")
        self.assertEqual(len(self.verifications), 2)
        coordinator.action(profile, "select")
        coordinator.action(profile, "start")  # Focus existing profile.
        self.assertEqual(len(self.verifications), 2)
        coordinator.action(profile, "stop")
        coordinator.action(profile, "start")
        self.assertEqual(len(self.verifications), 3)

    def test_changed_framework_cannot_reuse_status_only_signature_cache(self):
        self.assertEqual(self.adapter.global_blockers(), ())
        self.assertEqual(len(self.verifications), 1)

        def reject_changed_bundle(executable, digest):
            self.verifications.append(executable)
            return SignatureEvidence(
                digest, self.policy.signer_identity, False, True, datetime.now(timezone.utc)
            )

        # Simulate system codesign rejecting a changed framework/resource while
        # the main executable and Info.plist bytes remain identical.
        self.verifier.verify = reject_changed_bundle
        profile = self.store.create("Changed bundle", network_policy="local_direct")
        self.assertTrue(self.adapter.blockers(profile))
        self.assertEqual(len(self.verifications), 2)
        self.assertEqual(self.adapter.supervisor.launches, [])

    def test_metadata_change_after_preflight_rejects_launch(self):
        from team_browser.client.lifecycle import LaunchContext
        from team_browser.client import WorkspaceError

        profile = self.store.create("Fixture", network_policy="local_direct")
        self.assertEqual(self.adapter.blockers(profile), ())
        self.write_info({**self.metadata, "FixtureResource": "changed after preflight"})
        with self.store.profiles.acquire(profile["id"]) as lease:
            context = LaunchContext(
                profile["id"], "chromium", lease.paths.browser_data, 1, "about:blank", lease
            )
            with self.assertRaises(WorkspaceError) as caught:
                self.adapter.start(context)
            self.assertEqual(caught.exception.code, "runtime_changed")
        self.assertEqual(self.adapter.supervisor.launches, [])

    def test_metadata_mutation_during_signing_is_rejected(self):
        original = self.verifier.verify

        def mutate(executable, digest):
            result = original(executable, digest)
            self.write_info({**self.metadata, "FixtureResource": "changed while signing"})
            return result

        self.verifier.verify = mutate
        self.assertIn("metadata changed during signature", self.adapter.global_blockers()[0])
        self.assertIsNone(self.adapter._runtime_cache)

    def test_cli_loader_observes_version_instead_of_copying_policy_claim(self):
        path = self.root / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "executable": str(self.binary),
                    "version": self.policy.version,
                    "sha256": self.policy.sha256,
                    "signer_identity": self.policy.signer_identity,
                }
            )
        )
        path.chmod(0o600)
        loaded = load_installed_adapter(path, self.store.profiles)
        self.assertIsNone(loaded.observed_version)
        self.assertIs(loaded.metadata_observer, read_macos_bundle_metadata)
        self.write_info({**self.metadata, "CFBundleShortVersionString": "99.0.0.0"})
        self.assertIn("version does not match", loaded.global_blockers()[0])
        self.write_info()
        with patch("team_browser.client.installed_browser.sys.platform", "linux"):
            self.assertIn("requires macOS", loaded.global_blockers()[0])
