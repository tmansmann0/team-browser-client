import hashlib
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from team_browser.client import WorkspaceStore, WorkspaceError
from team_browser.client.installed_browser import InstalledBrowserAdapter
from team_browser.client.lifecycle import LaunchContext
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence


class FixtureSignature:
    def verify(self, executable, expected_sha256):
        return SignatureEvidence(
            expected_sha256, "synthetic-signer", True, True, datetime.now(timezone.utc)
        )


class FixtureSupervisor:
    def check(self, runtime):
        pass

    def launch(self, *args, **kwargs):
        raise AssertionError("Engine-binding regression must never launch a process")


class EngineBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.temp.name) / "workspace")
        self.binary = Path(self.temp.name) / "synthetic-browser"
        self.binary.write_bytes(b"non-executable synthetic fixture")
        self.binary.chmod(0o600)
        self.policy = RuntimePolicy(
            "chromium",
            "synthetic-1",
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "synthetic-signer",
        )
        self.adapter = InstalledBrowserAdapter(
            profile_store=self.store.profiles,
            executable=self.binary,
            observed_version=self.policy.version,
            policy=self.policy,
            runtime_gate=RuntimeGate(FixtureSignature()),
            supervisor=FixtureSupervisor(),
        )
        self.profile = self.store.create("Synthetic profile", network_policy="local_direct")
        self.paths = self.store.profiles.prepare(self.profile["id"])

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_camoufox_marker_blocks_chromium_reuse(self):
        (self.paths.directory / ".camoufox-identity.json").write_text("{}")
        blockers = self.adapter.blockers(self.profile)
        self.assertTrue(any("Camoufox" in message for message in blockers))
        self.assertTrue((self.paths.directory / ".camoufox-identity.json").exists())

    def test_marker_created_after_preflight_is_rechecked(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.store.profiles.acquire(self.profile["id"]) as lease:
            (self.paths.directory / ".camoufox-identity.json").write_text("{}")
            context = LaunchContext(
                self.profile["id"], "chromium", self.paths.browser_data, 1, lease=lease
            )
            with self.assertRaises(WorkspaceError) as result:
                self.adapter.start(context)
            self.assertEqual(result.exception.code, "profile_engine_mismatch")
