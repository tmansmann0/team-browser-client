"""Owner-approved artifact gate contracts using inert synthetic bytes only."""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from team_browser.client import WorkspaceError, WorkspaceStore
from team_browser.client.installed_browser import load_installed_adapter
from team_browser.client.linux_pilot import (
    PILOT_PROVENANCE,
    LinuxPilotRuntimeGate,
    _protected,
    manifest_digest,
    observe_artifact,
    read_private_manifest,
)
from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimePolicy


MODULE = "team_browser.client.linux_pilot"


class LinuxPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        for name in (
            "chromium",
            "chrome-sandbox",
            "chrome_crashpad_handler",
            "icudtl.dat",
            "libEGL.so",
        ):
            (self.runtime / name).write_bytes(b"\x7fELFsynthetic inert fixture " + name.encode())
            (self.runtime / name).chmod(0o700)
        for target, value in (
            ("ROOT", self.runtime),
            ("EXECUTABLE", self.runtime / "chromium"),
            ("sys.platform", "linux"),
        ):
            p = patch(f"{MODULE}.{target}", value)
            p.start()
            self.addCleanup(p.stop)
        p = patch(f"{MODULE}._protected")
        p.start()
        self.addCleanup(p.stop)
        p = patch(f"{MODULE}.os.geteuid", return_value=1000)
        p.start()
        self.addCleanup(p.stop)
        self.manifest = observe_artifact(version="154.0-synthetic")
        self.now = datetime.now(timezone.utc)
        self.gate_args = dict(
            manifest=self.manifest,
            approved_manifest_sha256=manifest_digest(self.manifest),
            approval_reference="synthetic-test-only-not-human-approval",
            approved_at=self.now - timedelta(seconds=1),
            expires_at=self.now + timedelta(minutes=10),
            workspace=self.root / "workspace",
        )
        self.gate = LinuxPilotRuntimeGate(**self.gate_args)
        self.policy = RuntimePolicy(
            "chromium",
            "154.0-synthetic",
            hashlib.sha256((self.runtime / "chromium").read_bytes()).hexdigest(),
            PILOT_PROVENANCE,
            False,
        )

    def verify(self):
        return self.gate.verify(
            self.runtime / "chromium", observed_version=self.policy.version, policy=self.policy
        )

    def test_observation_grants_no_approval_and_covers_support_files(self):
        self.assertEqual(len(self.manifest["entries"]), 6)
        self.assertNotIn("approval_reference", self.manifest)
        self.assertTrue(all("sha256" in e for e in self.manifest["entries"] if e["kind"] == "file"))
        self.assertNotIn("signature_valid", json.dumps(self.manifest))

    def test_pilot_gate_is_distinct_from_vendor_evidence(self):
        runtime = self.verify()
        self.assertEqual(runtime.signer_identity, PILOT_PROVENANCE)
        self.assertEqual(runtime.sha256, self.policy.sha256)

    def test_no_approval_wrong_manifest_or_excessive_lifetime_rejected(self):
        for change in (
            {"approval_reference": ""},
            {"approved_manifest_sha256": "0" * 64},
            {"expires_at": self.now + timedelta(hours=3)},
            {"approved_at": self.now.replace(tzinfo=None)},
            {"workspace": Path("relative")},
        ):
            with self.subTest(change=change):
                with self.assertRaises(RuntimeVerificationError):
                    LinuxPilotRuntimeGate(**{**self.gate_args, **change})

    def test_inactive_and_expired_approval_block(self):
        for now in (self.now - timedelta(days=1), self.now + timedelta(days=1)):
            with self.assertRaisesRegex(RuntimeVerificationError, "inactive or expired"):
                self.gate.verify(
                    self.runtime / "chromium",
                    observed_version=self.policy.version,
                    policy=self.policy,
                    now=now,
                )

    def test_support_change_addition_or_removal_blocks(self):
        support = self.runtime / "libEGL.so"
        support.write_bytes(b"changed support bytes")
        with self.assertRaisesRegex(RuntimeVerificationError, "metadata has changed"):
            self.verify()
        support.unlink()
        with self.assertRaises(RuntimeVerificationError):
            self.verify()

    def test_exact_bytes_change_cannot_hide_behind_mocked_metadata(self):
        with patch.object(
            self.gate, "observe", return_value=SimpleNamespace(version=self.policy.version)
        ):
            (self.runtime / "libEGL.so").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeVerificationError, "bytes or support"):
                self.verify()

    def test_other_executable_mac_policy_and_wrong_sha_rejected(self):
        with self.assertRaises(RuntimeVerificationError):
            self.gate.observe(Path("/tmp/another"))
        for signer, notarized, digest in (
            ("APPLE:signature", True, self.policy.sha256),
            (PILOT_PROVENANCE, False, "0" * 64),
        ):
            policy = RuntimePolicy("chromium", self.policy.version, digest, signer, notarized)
            with self.assertRaises(RuntimeVerificationError):
                self.gate.verify(
                    self.runtime / "chromium", observed_version=policy.version, policy=policy
                )

    def test_real_path_checks_reject_writable_or_symlinked_artifacts(self):
        with self.assertRaisesRegex(RuntimeVerificationError, "writable by the client"):
            _protected(self.runtime / "chromium")
        symlink = self.root / "runtime-link"
        symlink.symlink_to(self.runtime)
        with self.assertRaisesRegex(RuntimeVerificationError, "symlinked"):
            _protected(symlink)

    def test_private_manifest_requires_private_regular_file(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.manifest))
        path.chmod(0o600)
        self.assertEqual(read_private_manifest(path), self.manifest)
        path.chmod(0o644)
        with self.assertRaises(Exception):
            read_private_manifest(path)

    def config(self, workspace):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest))
        manifest_path.chmod(0o600)
        return {
            "provenance": PILOT_PROVENANCE,
            "scope": "synthetic-local-only",
            "executable": "/usr/lib/chromium/chromium",
            "version": self.policy.version,
            "sha256": self.policy.sha256,
            "manifest_path": str(manifest_path),
            "approved_manifest_sha256": manifest_digest(self.manifest),
            "approval_reference": self.gate.reference,
            "approved_at": self.gate.approved_at.isoformat(),
            "expires_at": self.gate.expires_at.isoformat(),
            "workspace": str(workspace),
        }

    def test_loader_binds_exact_workspace_and_has_no_automatic_approval(self):
        store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(store.close)
        config = self.config(store.root)
        path = self.root / "pilot-policy.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        adapter = load_installed_adapter(path, store.profiles)
        self.addCleanup(adapter.shutdown)
        self.assertIsInstance(adapter.gate, LinuxPilotRuntimeGate)
        self.assertIsNone(adapter.vault)
        with self.assertRaisesRegex(WorkspaceError, "blank synthetic"):
            adapter.start(SimpleNamespace(initial_url="https://mail.google.com/mail/u/0/#inbox"))
        for missing in ("approval_reference", "approved_at", "approved_manifest_sha256"):
            incomplete = dict(config)
            del incomplete[missing]
            path.write_text(json.dumps(incomplete))
            with self.assertRaises(WorkspaceError):
                load_installed_adapter(path, store.profiles)
        path.write_text(json.dumps({**config, "workspace": str(self.root / "another-workspace")}))
        with self.assertRaisesRegex(WorkspaceError, "different fresh workspace"):
            load_installed_adapter(path, store.profiles)

    def make_adapter(self):
        store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(store.close)
        path = self.root / "pilot-policy.json"
        path.write_text(json.dumps(self.config(store.root)))
        path.chmod(0o600)
        adapter = load_installed_adapter(path, store.profiles)
        self.addCleanup(adapter.shutdown)
        return store, adapter, path

    def test_ordinary_loader_refuses_an_existing_profile_workspace(self):
        store, adapter, path = self.make_adapter()
        store.create("Existing synthetic fixture")
        with self.assertRaisesRegex(WorkspaceError, "fresh profile workspace"):
            load_installed_adapter(path, store.profiles)

    def test_expiry_requests_owned_shutdown_without_claiming_success(self):
        _, adapter, _ = self.make_adapter()
        handle = SimpleNamespace(stop=Mock(return_value=False))
        adapter.supervisor._handles = [handle]
        with patch.object(adapter.supervisor, "shutdown") as shutdown:
            adapter._expire()
            handle.stop.assert_called_once()
            shutdown.assert_called_once()
        adapter.supervisor._handles = []

    def test_new_browser_data_and_continuing_actions_respect_pilot_scope(self):
        store, adapter, _ = self.make_adapter()
        profile = store.create("Fresh synthetic fixture")
        paths = store.profiles.prepare(profile["id"])
        context = SimpleNamespace(
            initial_url="about:blank", profile_id=profile["id"], browser_data=paths.browser_data
        )
        (paths.browser_data / "existing-cookie-fixture").write_bytes(b"inert")
        with self.assertRaisesRegex(WorkspaceError, "without existing browser data"):
            adapter.start(context)
        (paths.browser_data / "existing-cookie-fixture").unlink()
        delegate = SimpleNamespace(
            focus=Mock(return_value=True),
            set_selected=Mock(),
            tab_snapshot=Mock(),
            focus_tabs=Mock(),
        )
        with patch(
            "team_browser.client.installed_browser.InstalledBrowserAdapter.start",
            return_value=delegate,
        ):
            handle = adapter.start(context)
        self.assertTrue(handle.focus())
        with patch.object(
            adapter.gate, "_check_approval", side_effect=RuntimeVerificationError("expired")
        ):
            for operation in (
                handle.focus,
                lambda: handle.set_selected(True),
                lambda: handle.tab_snapshot(lambda: True),
                lambda: handle.focus_tabs(lambda: True),
            ):
                with self.assertRaisesRegex(RuntimeVerificationError, "expired"):
                    operation()
        with self.assertRaisesRegex(WorkspaceError, "account sign-in"):
            handle.open_gmail()


if __name__ == "__main__":
    unittest.main()
