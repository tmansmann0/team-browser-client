"""Ordinary app/CLI setup contracts. Every runtime and browser is synthetic."""

import hashlib
import json
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

import test_client_camoufox_runtime as native
from test_client_engine_identity import binding
from test_client_engine_identity_runtime import RuntimeGenerator, SyntheticIdentityProbe
from team_browser.client.app import create_local_app
from team_browser.client.camoufox_deployment import AcceptedProfileTemplate
from team_browser.client.camoufox_runtime import (
    CamoufoxIdentityProgramAcceptance,
    CamoufoxIdentityProperties,
    CamoufoxRuntimeMetadata,
    CamoufoxAcceptance,
    CamoufoxSupervisor,
    CAMOUFOX_VERSION,
    PLAYWRIGHT_VERSION,
)
from team_browser.client.camoufox_setup import CamoufoxSetup
from team_browser.local.runtime import RuntimeGate, RuntimePolicy
from team_browser.client.store import WorkspaceError


class SyntheticDeployment:
    def __init__(self, root, generator, probe, *, qualified=True):
        self.revoked = False
        self.qualified = qualified
        self.executable = root / "synthetic-never-execute"
        self.executable.write_bytes(b"synthetic-not-native")
        self.executable.chmod(0o700)
        self.policy = RuntimePolicy(
            "camoufox",
            "synthetic-build",
            hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            "synthetic",
        )
        self.gate = RuntimeGate(native.FixtureVerifier())
        self.display = binding().display
        self.configuration = SimpleNamespace(profiles=[], use_accepted_profile_defaults=True)
        template = AcceptedProfileTemplate(
            preset_id="isolated",
            locale="en-US",
            timezone_id="America/New_York",
            network_policy="local_direct",
        )
        b = replace(
            binding(),
            platform=sys.platform,
            target_os={"linux": "linux", "darwin": "macos"}[sys.platform],
        )
        config, _, _ = generator.generate(b)
        types = {str: "str", int: "uint", bool: "bool", list: "array", dict: "dict"}
        self.properties_path = root / "properties.json"
        self.properties_path.write_text(
            json.dumps(
                [{"property": key, "type": types[type(value)]} for key, value in config.items()]
            )
        )
        self.record = SimpleNamespace(
            firefox_version="150.0",
            platform=sys.platform,
            files={
                "properties.json": hashlib.sha256(self.properties_path.read_bytes()).hexdigest()
            },
            properties="properties.json",
            profile_defaults=template,
        )
        self.generator, self.probe = generator, probe
        self.inventory = root / "synthetic-inventory.json"
        self.inventory.write_text(json.dumps({"version": self.policy.version}))
        self.expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    def current(self):
        if self.revoked:
            raise WorkspaceError(
                "synthetic_revoked", "Deployment authorization changed; request a fresh review."
            )

    def verify(self, *args, **kwargs):
        self.current()
        return self.gate.verify(*args, **kwargs)

    def metadata(self, executable):
        self.current()
        raw = self.inventory.read_bytes()
        info = self.inventory.stat()
        return CamoufoxRuntimeMetadata(
            self.policy.version,
            self.inventory,
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            hashlib.sha256(raw).hexdigest(),
        )

    def properties(self, executable):
        self.current()
        raw = self.properties_path.read_bytes()
        info = self.properties_path.stat()
        return CamoufoxIdentityProperties(
            self.properties_path,
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            hashlib.sha256(raw).hexdigest(),
            raw,
        )

    def acceptance(self):
        if not self.qualified:
            return None
        return CamoufoxAcceptance(
            self.policy.sha256,
            self.policy.version,
            sys.platform,
            "synthetic-not-native-acceptance",
            self.expiry,
        )

    def program(self):
        self.current()
        if not self.qualified:
            raise WorkspaceError(
                "native_qualification_required",
                "Independent native release qualification is required before validation.",
            )
        return CamoufoxIdentityProgramAcceptance(
            self.policy.sha256,
            self.policy.version,
            150,
            sys.platform,
            self.display,
            self.generator.provenance(binding()),
            self.record.files["properties.json"],
            self.probe.probe_id,
            "synthetic-not-native-proof",
            self.expiry,
        )


class SetupAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.generator = RuntimeGenerator()
        self.probe = SyntheticIdentityProbe(binding().display)
        self.deployment = SyntheticDeployment(self.root, self.generator, self.probe)
        self.driver = native.FakeDriver()
        self.supervisor = CamoufoxSupervisor(
            acceptance=self.deployment.acceptance(),
            factory=lambda: self.driver,
            launcher=self.driver.launch,
            dependencies=lambda: (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION),
        )

        def loader(path, store, **kwargs):
            return CamoufoxSetup(
                store,
                self.deployment,
                generator=self.generator,
                probe=self.probe,
                supervisor=self.supervisor,
            )

        with patch("team_browser.client.camoufox_setup.load_camoufox_setup", side_effect=loader):
            self.app = create_local_app(
                self.root / "workspace", camoufox_config=self.root / "unused.json"
            )
        self.client = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 54321)
        )
        self.client.__enter__()
        config = self.client.get("/local/config").json()
        self.headers = {"x-local-csrf": config["csrf_token"]}
        self.profile = self.client.post(
            "/local/v1/profiles",
            json={
                "name": "Synthetic Camoufox",
                "preset_id": "isolated",
                "network_policy": "local_direct",
            },
            headers=self.headers,
        ).json()
        self.pid = self.profile["id"]
        self.path = f"/local/v1/profiles/{self.pid}/camoufox-setup"
        self.setup = self.app.state.camoufox_setup

    def tearDown(self):
        # Only fake driver contexts exist in these tests; release sticky unknown
        # fixture handles explicitly after asserting the production retention.
        for handle in self.supervisor._handles:
            handle.ownership_uncertain = False
            if handle.context is not None and handle.context.is_closed():
                handle._set_phase("stopped")
            else:
                handle.stop()
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def status(self):
        result = self.client.get(self.path)
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def action(self, action, **extra):
        state = self.status()
        return self.client.post(
            self.path + "/actions",
            json={
                "action": action,
                "expected_revision": state["profile_revision"],
                "expected_setup_revision": state["revision"],
                **extra,
            },
            headers=self.headers,
        )

    def settle(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = self.status()
            if state["state"] not in {"preparing", "validating"}:
                return state
            time.sleep(0.01)
        self.fail("Synthetic setup did not settle")

    def prepare(self):
        prior_calls = len(self.driver.calls)
        self.assertEqual(self.action("prepare").status_code, 202)
        result = self.settle()
        self.assertEqual(result["state"], "prepared", result)
        self.assertEqual(len(self.driver.calls), prior_calls)
        return result

    def test_full_ordinary_app_prepare_validate_launch(self):
        self.prepare()
        self.assertEqual(self.action("validate").status_code, 202)
        state = self.settle()
        self.assertEqual(state["state"], "ready", state)
        self.assertTrue(state["admission_acknowledged"])
        self.assertTrue(state["launch_available"])
        self.assertEqual(len(self.driver.calls), 1)
        options = self.driver.calls[0]["from_options"]
        self.assertFalse(options["headless"])
        self.assertEqual(options["firefox_user_prefs"]["network.proxy.type"], 0)
        self.assertFalse(options["firefox_user_prefs"]["browser.sessionstore.resume_from_crash"])
        self.assertTrue(all(context.closed for context in self.driver.contexts))
        result = self.client.post(
            f"/local/v1/profiles/{self.pid}/actions",
            json={"action": "start", "expected_revision": state["profile_revision"]},
            headers=self.headers,
        )
        self.assertEqual(result.status_code, 200, result.text)
        until = time.monotonic() + 3
        while time.monotonic() < until and len(self.driver.calls) < 2:
            time.sleep(0.01)
        self.assertEqual(len(self.driver.calls), 2)
        self.assertEqual(
            self.setup._entries[self.pid].policy.admission.artifact_sha256,
            self.setup._entries[self.pid].artifact.artifact_sha256,
        )

    def test_web_cannot_supply_proof_or_paths(self):
        for extra in (
            {"admission_acknowledged": True},
            {"test_id": "approved"},
            {"signature_hex": "a" * 128},
            {"executable": "/tmp/foreign"},
            {"url": "https://example.com"},
            {"generation": 1},
        ):
            result = self.action("prepare", **extra)
            self.assertEqual(result.status_code, 422, result.text)
        self.assertFalse(self.driver.calls)

    def test_csrf_and_revisions_are_required(self):
        state = self.status()
        body = {
            "action": "prepare",
            "expected_revision": state["profile_revision"],
            "expected_setup_revision": state["revision"],
        }
        self.assertEqual(self.client.post(self.path + "/actions", json=body).status_code, 403)
        body["expected_setup_revision"] += 1
        self.assertEqual(
            self.client.post(self.path + "/actions", json=body, headers=self.headers).status_code,
            409,
        )
        self.assertFalse(self.driver.calls)

    def test_offline_prepare_does_not_need_native_qualification(self):
        self.deployment.qualified = False
        self.supervisor.acceptance = None
        self.assertFalse(self.client.get("/local/v1/camoufox-setup").json()["usable"])
        self.assertIn("prepare", self.status()["available_actions"])
        self.assertEqual(self.action("prepare").status_code, 202)
        state = self.settle()
        self.assertEqual(state["state"], "needs_approval")
        self.assertFalse(state["admission_acknowledged"])
        self.assertEqual(self.action("validate").status_code, 409)
        self.assertFalse(self.driver.calls)

    def test_failed_worker_start_releases_unspawned_lease(self):
        with patch(
            "team_browser.client.camoufox_setup.threading.Thread.start",
            side_effect=RuntimeError("synthetic worker exhaustion"),
        ):
            response = self.action("prepare")
        self.assertEqual(response.status_code, 409)
        entry = self.setup._entries[self.pid]
        self.assertIsNone(entry.operation_id)
        self.assertIsNone(entry.lease)
        self.assertFalse(self.driver.calls)
        self.prepare()

    def test_managed_direct_and_proxy_have_no_fallback(self):
        self.app.state.workspace.db.execute(
            "UPDATE profiles SET origin='managed', network_policy='verified_proxy' WHERE id=?",
            (self.pid,),
        )
        state = self.status()
        self.assertEqual(state["state"], "needs_approval")
        self.assertNotIn("prepare", state["available_actions"])
        self.assertFalse(self.driver.calls)

    def test_cancellation_before_spawn_retains_artifact_and_blocks_mutations(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.generator.generate

        def delayed(b):
            entered.set()
            release.wait(3)
            return original(b)

        self.generator.generate = delayed
        self.assertEqual(self.action("prepare").status_code, 202)
        self.assertTrue(entered.wait(1))
        state = self.status()
        changed = self.client.patch(
            f"/local/v1/profiles/{self.pid}",
            json={"expected_revision": state["profile_revision"], "name": "Changed"},
            headers=self.headers,
        )
        self.assertEqual(changed.status_code, 409)
        self.assertEqual(self.action("cancel").status_code, 202)
        release.set()
        self.settle()
        self.assertFalse(self.driver.calls)
        self.assertEqual(self.action("prepare").status_code, 202)
        self.assertEqual(self.settle()["state"], "prepared")

    def test_unknown_native_ownership_keeps_lease_and_requires_recovery(self):
        self.prepare()
        self.driver.fail = True
        self.assertEqual(self.action("validate").status_code, 202)
        state = self.settle()
        self.assertEqual(state["state"], "recovery_required", state)
        self.assertFalse(state["admission_acknowledged"])
        self.assertTrue(self.setup._entries[self.pid].lease.active)
        self.assertEqual(self.action("validate").status_code, 409)

    def test_native_validation_reserves_capacity_against_ordinary_launch(self):
        self.prepare()
        self.action("validate")
        self.assertEqual(self.settle()["state"], "ready")
        second = self.client.post(
            "/local/v1/profiles",
            json={
                "name": "Second synthetic",
                "preset_id": "isolated",
                "network_policy": "local_direct",
            },
            headers=self.headers,
        ).json()
        first_id, first_path = self.pid, self.path
        self.pid, self.path = second["id"], f"/local/v1/profiles/{second['id']}/camoufox-setup"
        self.prepare()
        self.pid, self.path = first_id, first_path
        settings = self.app.state.workspace.metadata("settings")
        self.app.state.coordinator.update_settings(settings["revision"], max_warm_profiles=1)
        self.driver.delay = 0.3
        second_state = self.client.get(f"/local/v1/profiles/{second['id']}/camoufox-setup").json()
        response = self.client.post(
            f"/local/v1/profiles/{second['id']}/camoufox-setup/actions",
            json={
                "action": "validate",
                "expected_revision": second_state["profile_revision"],
                "expected_setup_revision": second_state["revision"],
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 202, response.text)
        resources = self.app.state.coordinator.resources()
        self.assertEqual(resources["resident_profiles"], 1)
        self.assertEqual(resources["setup_reserved_profiles"], 1)
        first = self.app.state.workspace.get(first_id)
        response = self.client.post(
            f"/local/v1/profiles/{first_id}/actions",
            json={"action": "start", "expected_revision": first["revision"]},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["detail"]["code"], "budget_exceeded")
        self.pid, self.path = second["id"], f"/local/v1/profiles/{second['id']}/camoufox-setup"
        self.settle()
        self.assertEqual(self.app.state.coordinator.resources()["setup_reserved_profiles"], 0)

    def test_malformed_resource_reservation_fails_closed(self):
        self.app.state.coordinator._reserved_slots = lambda: True
        with self.assertRaisesRegex(WorkspaceError, "resource ownership"):
            self.app.state.coordinator.resources()

    def test_runtime_revocation_invalidates_ready(self):
        self.prepare()
        self.action("validate")
        self.assertEqual(self.settle()["state"], "ready")
        self.deployment.revoked = True
        state = self.status()
        self.assertEqual(state["state"], "needs_approval")
        self.assertFalse(state["admission_acknowledged"])

    def test_expired_admission_cannot_launch(self):
        self.prepare()
        self.action("validate")
        self.settle()
        entry = self.setup._entries[self.pid]
        entry.policy = replace(
            entry.policy,
            admission=replace(
                entry.policy.admission,
                valid_until=datetime.now(timezone.utc) - timedelta(seconds=1),
            ),
        )
        self.assertFalse(self.status()["admission_acknowledged"])


class UnconfiguredSetupTests(unittest.TestCase):
    def test_ordinary_app_exposes_truthful_unavailable_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            app = create_local_app(Path(temp) / "workspace")
            with TestClient(
                app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 23456)
            ) as client:
                overview = client.get("/local/v1/camoufox-setup").json()
                self.assertFalse(overview["configured"])
                self.assertFalse(overview["usable"])
                self.assertEqual(overview["state"], "unavailable")
                self.assertTrue(client.get("/local/config").json()["camoufox_setup"]["supported"])

    def test_bad_config_is_a_safe_blocker_and_does_not_crash_app(self):
        with tempfile.TemporaryDirectory() as temp:
            app = create_local_app(
                Path(temp) / "workspace", camoufox_config=Path(temp) / "missing.json"
            )
            with TestClient(
                app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 23456)
            ) as client:
                overview = client.get("/local/v1/camoufox-setup").json()
                self.assertTrue(overview["configured"])
                self.assertEqual(overview["state"], "needs_approval")
                self.assertNotIn(temp, json.dumps(overview))
