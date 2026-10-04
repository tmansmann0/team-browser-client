"""Coordinator integration uses only the explicit fake browser driver fixtures."""

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import time
import unittest

from team_browser.client import LifecycleCoordinator, WorkspaceStore
from team_browser.client.camoufox_runtime import (
    CAMOUFOX_VERSION,
    PLAYWRIGHT_VERSION,
    CamoufoxAcceptance,
    CamoufoxAdapter,
    CamoufoxProfilePolicy,
    CamoufoxRuntimeMetadata,
    CamoufoxSupervisor,
    profile_policy_binding,
)
from team_browser.local.runtime import RuntimeGate, RuntimePolicy
from test_client_camoufox_runtime import FakeDriver, FixtureVerifier


class CamoufoxCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = WorkspaceStore(root / "workspace")
        self.profile = self.store.create(
            "Synthetic Camoufox", preset_id="isolated", network_policy="local_direct"
        )
        binary = root / "never-execute"
        binary.write_bytes(b"fake-native-contract")
        binary.chmod(0o700)
        policy = RuntimePolicy(
            "camoufox",
            "synthetic-build",
            hashlib.sha256(binary.read_bytes()).hexdigest(),
            "synthetic",
        )
        self.driver = FakeDriver()
        self.supervisor = CamoufoxSupervisor(
            acceptance=CamoufoxAcceptance(
                policy.sha256,
                policy.version,
                sys.platform,
                "synthetic-only",
                datetime.now(timezone.utc) + timedelta(hours=1),
            ),
            factory=lambda: self.driver,
            launcher=self.driver.launch,
            dependencies=lambda: (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION),
        )
        store = self.store

        class ReviewedPolicies:
            def for_profile(self, profile_id):
                profile = store.get(profile_id)
                return CamoufoxProfilePolicy(
                    profile_id,
                    profile_policy_binding(profile),
                    profile["preset_id"],
                    "en-US",
                    "UTC",
                )

        inventory = root / "synthetic-runtime-metadata.txt"
        inventory.write_text(policy.version)
        inventory.chmod(0o600)

        def synthetic_metadata_observer(executable):
            # Test-only observation, never a vendor distribution version mapping.
            raw = inventory.read_bytes()
            info = inventory.stat()
            return CamoufoxRuntimeMetadata(
                raw.decode(),
                inventory,
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
                hashlib.sha256(raw).hexdigest(),
            )

        self.adapter = CamoufoxAdapter(
            profile_store=self.store.profiles,
            executable=binary,
            observed_version=policy.version,
            policy=policy,
            runtime_gate=RuntimeGate(FixtureVerifier()),
            supervisor=self.supervisor,
            profile_policies=ReviewedPolicies(),
            metadata_observer=synthetic_metadata_observer,
        )
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)

    def tearDown(self):
        self.coordinator.shutdown()
        self.store.close()
        self.temp.cleanup()

    def wait_state(self, state):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            self.coordinator.refresh()
            if self.store.get(self.profile["id"])["state"] == state:
                return
            time.sleep(0.005)
        self.fail(self.store.get(self.profile["id"]))

    def test_explicit_adapter_is_recognized_and_repeated_select_reuses_context(self):
        self.assertTrue(self.coordinator.installed)
        result = self.coordinator.action(self.profile["id"], "start", expected_revision=1)
        self.assertIn(result["profile"]["state"], ("starting", "running"))
        self.wait_state("running")
        self.coordinator.action(self.profile["id"], "select")
        self.coordinator.action(self.profile["id"], "start")
        self.assertEqual(len(self.driver.calls), 1)
        self.assertEqual(
            self.driver.calls[0]["from_options"]["user_data_dir"],
            str(self.store.profiles.root / self.profile["id"] / "browser-data"),
        )

    def test_metadata_edits_and_relaunch_preserve_stable_identity(self):
        self.coordinator.action(self.profile["id"], "start")
        self.wait_state("running")
        current = self.store.get(self.profile["id"])
        self.store.update(
            current["id"], current["revision"], name="Renamed synthetic", favorite=True
        )
        self.coordinator.action(self.profile["id"], "stop")
        self.wait_state("stopped")
        self.coordinator.action(self.profile["id"], "start")
        self.wait_state("running")
        self.assertEqual(len(self.driver.calls), 2)
        self.assertEqual(
            self.driver.calls[0]["from_options"]["env"], self.driver.calls[1]["from_options"]["env"]
        )
