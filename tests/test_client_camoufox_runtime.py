"""Fake launcher/context contracts only. No Camoufox import or native execution."""

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from team_browser.client.camoufox_runtime import (
    CAMOUFOX_VERSION,
    PLAYWRIGHT_VERSION,
    ROUTE_PREFS,
    ROUTE_PREFS_SHA256,
    CamoufoxAcceptance,
    CamoufoxAdapter,
    CamoufoxProfilePolicy,
    CamoufoxProxyRoute,
    CamoufoxRuntimeMetadata,
    CamoufoxSupervisor,
    profile_policy_binding,
)
from team_browser.client.lifecycle import GMAIL_INBOX_URL, LaunchContext
from team_browser.client.store import WorkspaceError
from team_browser.local.proxy import ProxyConfiguration, ProxyExpectations, ProxyProbeEvidence
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence
from team_browser.local.secrets import SecretRef
from team_browser.local.storage import ProfileStore


class FixtureVerifier:
    def verify(self, executable, digest):
        return SignatureEvidence(digest, "synthetic", True, True, datetime.now(timezone.utc))


class FakePage:
    def __init__(self):
        self.closed, self.targets, self.focuses = False, [], 0

    def is_closed(self):
        return self.closed

    async def goto(self, target, **kwargs):
        self.targets.append(target)

    async def bring_to_front(self):
        self.focuses += 1


class FakeContext:
    def __init__(self):
        self.pages, self.callbacks, self.closed = [FakePage()], {}, False

    def on(self, event, callback):
        self.callbacks[event] = callback

    def is_closed(self):
        return self.closed

    async def new_page(self):
        page = FakePage()
        self.pages.append(page)
        return page

    async def close(self):
        self.closed = True
        self.callbacks["close"]()


class FakeDriver:
    def __init__(self):
        self.calls, self.contexts = [], []
        self.delay, self.fail = 0, False
        self.entered = threading.Event()

    async def start(self):
        return self

    async def stop(self):
        pass

    async def launch(self, playwright, **kwargs):
        self.calls.append(kwargs)
        self.entered.set()
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("synthetic process outcome uncertain")
        context = FakeContext()
        self.contexts.append(context)
        return context


class Policies:
    def __init__(self, value):
        self.value = value

    def for_profile(self, profile_id):
        return self.value


class FakeProbe:
    def __init__(self):
        self.contexts, self.fail_after = [], None

    async def collect(self, context, configuration, expectations):
        self.contexts.append(context)
        passed = self.fail_after is None or len(self.contexts) < self.fail_after
        return ProxyProbeEvidence(
            expectations.profile_id,
            expectations.runtime_sha256,
            configuration.fingerprint,
            datetime.now(timezone.utc),
            ("203.0.113.7",),
            route_verified=passed,
            dns_via_proxy=True,
            webrtc_udp_blocked=True,
            ipv6_routed_or_blocked=True,
            direct_fallback_blocked=True,
            tls_verified=True,
        )


class NoTrafficTransport:
    async def connect(self, host, port):
        raise AssertionError("Runtime contracts never send provider traffic")


class CamoufoxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name).resolve()
        self.binary = root / "synthetic-never-execute"
        self.binary.write_bytes(b"synthetic-runtime-only")
        self.binary.chmod(0o700)
        self.store = ProfileStore(root / "profiles")
        self.policy = RuntimePolicy(
            "camoufox",
            "fixture-build",
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "synthetic",
        )
        self.gate = RuntimeGate(FixtureVerifier())
        self.runtime = self.gate.verify(
            self.binary, observed_version="fixture-build", policy=self.policy
        )
        self.acceptance = CamoufoxAcceptance(
            self.policy.sha256,
            self.policy.version,
            sys.platform,
            "synthetic-contract-not-native-acceptance",
            datetime.now(timezone.utc) + timedelta(hours=1),
            proxy_preferences_sha256=ROUTE_PREFS_SHA256,
            trusted_single_user_host=True,
        )
        self.profile = {
            "id": "synthetic-profile",
            "revision": 1,
            "preset_id": "isolated",
            "engine_id": "camoufox",
            "origin": "local",
            "network_policy": "local_direct",
        }
        self.settings = CamoufoxProfilePolicy(
            "synthetic-profile",
            profile_policy_binding(self.profile),
            "isolated",
            "en-US",
            "America/New_York",
        )
        self.policies = Policies(self.settings)
        self.driver = FakeDriver()
        self.supervisor = CamoufoxSupervisor(
            acceptance=self.acceptance,
            factory=lambda: self.driver,
            launcher=self.driver.launch,
            dependencies=lambda: (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION),
            transport_factory=lambda configuration: NoTrafficTransport(),
        )
        self.inventory = root / "synthetic-inventory.json"
        self.inventory.write_text(json.dumps({"version": self.policy.version}))
        self.adapter = CamoufoxAdapter(
            profile_store=self.store,
            executable=self.binary,
            observed_version=self.policy.version,
            policy=self.policy,
            runtime_gate=self.gate,
            supervisor=self.supervisor,
            profile_policies=self.policies,
            metadata_observer=self.synthetic_metadata_observer,
        )
        self.lease = self.store.acquire(self.profile["id"])
        self.context = LaunchContext(
            self.profile["id"], "camoufox", self.lease.paths.browser_data, 1, lease=self.lease
        )

    def synthetic_metadata_observer(self, executable):
        # Synthetic local fixture only, not an implementation of vendor mapping.
        raw = self.inventory.read_bytes()
        info = self.inventory.stat()
        return CamoufoxRuntimeMetadata(
            json.loads(raw)["version"],
            self.inventory,
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            hashlib.sha256(raw).hexdigest(),
        )

    def tearDown(self):
        for handle in self.supervisor._handles:
            # Unknown ownership in these fixtures belongs only to FakeDriver.
            if handle.ownership_uncertain:
                handle.ownership_uncertain = False
                handle.spawn_attempted = False
            handle.stop()
            self.wait(lambda: handle.phase == "stopped")
        self.supervisor.shutdown()
        self.lease.release()
        self.temp.cleanup()

    def wait(self, predicate, timeout=2):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.005)
        self.fail("Synthetic ownership operation timed out")

    def start(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        return self.adapter.start(self.context)

    def proxy(self, *, credentials=False, age=60):
        config = ProxyConfiguration(
            "synthetic-proxy",
            "https",
            "proxy.example.test",
            443,
            SecretRef("synthetic-credential") if credentials else None,
        )
        self.profile.update(network_policy="verified_proxy", origin="managed")
        self.policies.value = replace(
            self.settings,
            proxy_fingerprint=config.fingerprint,
            profile_binding_sha256=profile_policy_binding(self.profile),
        )
        self.probe = FakeProbe()
        self.route = CamoufoxProxyRoute(
            config,
            ProxyExpectations(
                self.profile["id"],
                self.policy.sha256,
                ("203.0.113.0/24",),
                ("198.51.100.8",),
                max_evidence_age=timedelta(seconds=age),
            ),
            self.probe,
            (("diagnostic.example.test", 443),),
        )
        self.adapter.proxy_routes = Policies(self.route)

    def test_default_acceptance_absent_denies_before_import_or_spawn(self):
        self.supervisor.acceptance = None
        self.assertTrue(self.adapter.global_blockers())
        self.assertTrue(self.adapter.blockers(self.profile))
        with self.assertRaises(WorkspaceError):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_exact_dependencies_version_and_runtime_acceptance(self):
        for changes in (
            {"runtime_sha256": "0" * 64},
            {"engine_version": "changed"},
            {"platform": "different"},
            {"valid_until": datetime.now(timezone.utc)},
            {"camoufox_version": "other"},
            {"playwright_version": "other"},
        ):
            self.supervisor.acceptance = replace(self.acceptance, **changes)
            self.assertTrue(self.adapter.blockers(self.profile), changes)
        self.supervisor.acceptance = self.acceptance
        self.supervisor.dependencies = lambda: ("other", PLAYWRIGHT_VERSION)
        self.assertTrue(self.adapter.blockers(self.profile))
        self.assertFalse(self.driver.calls)

    def test_callable_from_options_fixed_context_and_no_secret_environment(self):
        with patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "secret",
                "CAMOU_CONFIG_9": "bad",
                "MOZ_DISABLE_CONTENT_SANDBOX": "1",
                "DEBUG": "pw:*",
            },
        ):
            handle = self.start()
            self.wait(lambda: handle.phase == "ready")
        call = self.driver.calls[0]
        self.assertTrue(call["persistent_context"])
        options = call["from_options"]
        self.assertEqual(options["executable_path"], str(self.binary))
        self.assertEqual(options["user_data_dir"], str(self.context.browser_data))
        self.assertEqual(options["firefox_user_prefs"], {"network.proxy.type": 0})
        self.assertNotIn("proxy", options)
        self.assertNotIn("args", options)
        self.assertNotIn("ignore_default_args", options)
        self.assertNotIn("HTTP_PROXY", options["env"])
        self.assertNotIn("CAMOU_CONFIG_9", options["env"])
        self.assertNotIn("MOZ_DISABLE_CONTENT_SANDBOX", options["env"])
        self.assertFalse(options["ignore_https_errors"])
        self.assertEqual(
            json.loads(options["env"]["CAMOU_CONFIG_1"])["timezone"], "America/New_York"
        )
        self.assertEqual(options["locale"], "en-US")
        self.assertEqual(handle.context.pages[0].targets, [])
        self.assertTrue(handle.focus())

    def test_profile_policy_binding_preset_and_assignment_are_bound(self):
        for changes in (
            {"profile_binding_sha256": "0" * 64},
            {"preset_id": "standard"},
            {"profile_id": "other-profile"},
        ):
            self.policies.value = replace(self.settings, **changes)
            self.assertTrue(self.adapter.blockers(self.profile))
        self.policies.value = self.settings
        self.assertEqual(self.adapter.blockers(self.profile), ())
        self.policies.value = replace(self.settings, locale="fr-FR")
        with self.assertRaisesRegex(WorkspaceError, "settings changed"):
            self.adapter.start(self.context)

    def test_profile_policy_config_is_deterministic(self):
        self.assertEqual(self.settings.config_json, replace(self.settings).config_json)
        with self.assertRaises(ValueError):
            replace(self.settings, locale="arbitrary \n")
        with self.assertRaises(ValueError):
            replace(self.settings, profile_binding_sha256=True)

    def test_target_and_owned_lease_are_required(self):
        for changes in (
            {"initial_url": "https://unapproved.example.test"},
            {"lease": None},
            {"browser_data": Path(self.temp.name)},
            {"engine_id": "chromium"},
        ):
            self.assertEqual(self.adapter.blockers(self.profile), ())
            with self.assertRaises(WorkspaceError):
                self.adapter.start(replace(self.context, **changes))
        self.assertFalse(self.driver.calls)

    def test_one_use_check_and_changed_binary_invalidation(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        self.binary.write_bytes(b"changed-runtime")
        with self.assertRaisesRegex(WorkspaceError, "changed before execution"):
            self.adapter.start(self.context)
        with self.assertRaisesRegex(WorkspaceError, "fresh profile-bound"):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_gmail_uses_only_exact_owned_context(self):
        self.context = replace(self.context, initial_url=GMAIL_INBOX_URL)
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.assertEqual(handle.page.targets, [GMAIL_INBOX_URL])
        self.assertTrue(handle.open_gmail())
        self.assertEqual(handle.page.targets, [GMAIL_INBOX_URL])
        self.assertEqual(len(handle.context.pages), 1)

    def test_cancel_during_launch_has_no_late_ready_state(self):
        self.driver.delay = 0.05
        handle = self.start()
        self.assertTrue(self.driver.entered.wait(1))
        self.assertFalse(handle.stop())
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(self.driver.contexts[0].closed)
        self.assertFalse(handle.status().alive)

    def test_transport_loss_retains_unknown_ownership(self):
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.supervisor.call(self._unexpected_close(handle))
        with self.assertRaises(WorkspaceError):
            handle.status()
        self.assertFalse(handle.stop())
        self.assertTrue(self.lease.active)

    async def _unexpected_close(self, handle):
        handle.context.callbacks["close"]()

    def test_launch_exception_retains_unknown_ownership(self):
        self.driver.fail = True
        handle = self.start()
        self.wait(lambda: handle.phase == "unknown")
        self.assertTrue(handle.ownership_uncertain)
        self.assertTrue(self.lease.active)

    def test_managed_direct_and_unconfigured_are_denied(self):
        self.profile["origin"] = "managed"
        self.assertTrue(self.adapter.blockers(self.profile))
        self.profile.update(origin="local", network_policy="unconfigured")
        self.assertTrue(self.adapter.blockers(self.profile))
        self.assertFalse(self.driver.calls)

    def test_managed_route_needs_acceptance_and_native_vault_for_credentials(self):
        self.proxy()
        for changes in ({"trusted_single_user_host": False}, {"proxy_preferences_sha256": None}):
            self.supervisor.acceptance = replace(self.acceptance, **changes)
            self.assertTrue(self.adapter.blockers(self.profile))
        self.supervisor.acceptance = self.acceptance
        self.proxy(credentials=True)
        self.assertTrue(self.adapter.blockers(self.profile))
        self.assertFalse(self.driver.calls)

    def test_managed_route_exact_context_relay_prefs_and_probe(self):
        self.proxy()
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.assertEqual(self.probe.contexts, [handle.context])
        prefs = self.driver.calls[0]["from_options"]["firefox_user_prefs"]
        self.assertEqual(prefs, {**ROUTE_PREFS, "network.proxy.socks_port": handle.relay.port})
        self.assertEqual(handle.relay._server.sockets[0].getsockname()[0], "127.0.0.1")
        self.assertFalse(prefs["network.proxy.failover_direct"])
        self.assertFalse(prefs["network.proxy.allow_bypass"])
        self.assertEqual(prefs["network.proxy.no_proxies_on"], "")
        self.assertFalse(prefs["media.peerconnection.enabled"])
        self.assertEqual(
            self.driver.calls[0]["from_options"]["env"]["CAMOU_CONFIG_1"], self.settings.config_json
        )

    def test_initial_probe_failure_closes_before_ready_or_gmail(self):
        self.proxy()
        self.probe.fail_after = 1
        self.context = replace(self.context, initial_url=GMAIL_INBOX_URL)
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertFalse(handle.context.pages[0].targets)
        self.assertFalse(handle.relay.healthy)

    def test_continuous_probe_failure_stops_browser_and_relay(self):
        self.proxy(age=0.2)
        self.probe.fail_after = 2
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertTrue(handle.route_failed)
        self.assertTrue(handle.relay.failed)
        self.assertFalse(handle.relay.healthy)

    def test_relay_failure_stops_owned_browser(self):
        self.proxy()
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")

        async def fail():
            handle.relay.fail_closed()

        self.supervisor.call(fail())
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertTrue(handle.route_failed)

    def test_proxy_assignment_changed_after_preflight_denies(self):
        self.proxy()
        self.assertEqual(self.adapter.blockers(self.profile), ())
        self.adapter.proxy_routes.value = replace(
            self.route, configuration=replace(self.route.configuration, port=444)
        )
        with self.assertRaises(WorkspaceError):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_foreign_browser_data_is_never_adopted(self):
        (self.context.browser_data / "synthetic-foreign-state").write_text("fixture")
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.assertRaisesRegex(WorkspaceError, "fresh app-owned"):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_identity_marker_persists_and_rejects_silent_identity_change(self):
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        marker = self.context.browser_data.parent / ".camoufox-identity.json"
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        before = marker.read_bytes()
        handle.stop()
        self.wait(lambda: handle.phase == "stopped")
        (self.context.browser_data / "synthetic-state").write_text("fixture")
        second = self.start()
        self.wait(lambda: second.phase == "ready")
        self.assertEqual(marker.read_bytes(), before)
        self.assertEqual(
            self.driver.calls[0]["from_options"]["env"]["CAMOU_CONFIG_1"],
            self.driver.calls[1]["from_options"]["env"]["CAMOU_CONFIG_1"],
        )
        second.stop()
        self.wait(lambda: second.phase == "stopped")
        self.policies.value = replace(self.settings, locale="fr-FR")
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.assertRaisesRegex(WorkspaceError, "Persistent Camoufox identity"):
            self.adapter.start(self.context)

    def test_identity_marker_symlink_is_rejected(self):
        unrelated = Path(self.temp.name) / "unrelated"
        unrelated.write_text("do not touch")
        (self.context.browser_data.parent / ".camoufox-identity.json").symlink_to(unrelated)
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.assertRaises(OSError):
            self.adapter.start(self.context)
        self.assertEqual(unrelated.read_text(), "do not touch")

    def test_unexpected_proxy_context_disconnect_closes_route_and_retains_lease(self):
        self.proxy()
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.supervisor.call(self._unexpected_close(handle))
        self.assertTrue(handle.ownership_uncertain)
        self.assertFalse(handle.relay.healthy)
        self.assertTrue(handle.relay.failed)
        self.assertFalse(handle.stop())
        self.assertTrue(self.lease.active)

    def test_stale_context_probe_evidence_never_reaches_ready(self):
        self.proxy()
        original = self.probe.collect

        async def stale(*args):
            evidence = await original(*args)
            return replace(evidence, observed_at=datetime.now(timezone.utc) - timedelta(minutes=5))

        self.probe.collect = stale
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertFalse(handle.relay.healthy)

    def test_metadata_only_changes_do_not_invalidate_persistent_identity(self):
        self.profile.update(revision=32, name="Renamed", favorite=True, state="warm", generation=9)
        self.assertEqual(self.adapter.blockers(self.profile), ())
        handle = self.adapter.start(self.context)
        self.wait(lambda: handle.phase == "ready")
        handle.stop()
        self.wait(lambda: handle.phase == "stopped")
        self.profile.update(revision=91, state="stopped", favorite=False, name="Another name")
        self.assertEqual(self.adapter.blockers(self.profile), ())
        second = self.adapter.start(replace(self.context, generation=10))
        self.wait(lambda: second.phase == "ready")
        self.assertEqual(
            self.driver.calls[0]["from_options"]["env"]["CAMOU_CONFIG_1"],
            self.driver.calls[1]["from_options"]["env"]["CAMOU_CONFIG_1"],
        )

    def test_stable_configuration_changes_require_matching_binding(self):
        for field, value in (
            ("preset_id", "different"),
            ("engine_id", "chromium"),
            ("network_policy", "verified_proxy"),
            ("origin", "managed"),
        ):
            profile = {**self.profile, field: value}
            self.assertNotEqual(
                profile_policy_binding(profile), self.settings.profile_binding_sha256
            )
            self.assertTrue(self.adapter.blockers(profile))

    def test_live_assignment_change_closes_route_on_next_bounded_observation(self):
        self.proxy(age=0.2)
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.adapter.proxy_routes.value = replace(
            self.route, configuration=replace(self.route.configuration, port=444)
        )
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertTrue(handle.relay.failed)

    def test_acceptance_revocation_closes_live_managed_route(self):
        self.proxy(age=0.2)
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.supervisor.acceptance = None
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertTrue(handle.relay.failed)

    def test_asserted_version_without_observer_cannot_enable_execution(self):
        self.adapter.metadata_observer = None
        self.assertTrue(self.adapter.global_blockers())
        self.assertIn("observer", self.adapter.blockers(self.profile)[0])
        self.assertFalse(self.driver.calls)

    def test_fresh_observed_version_must_match_policy(self):
        self.inventory.write_text(json.dumps({"version": "different-build"}))
        self.assertIn("Observed Camoufox version", self.adapter.blockers(self.profile)[0])
        self.assertFalse(self.driver.calls)

    def test_metadata_change_during_signature_verification_denies(self):
        owner = self

        class MutatingVerifier(FixtureVerifier):
            def verify(self, executable, digest):
                evidence = super().verify(executable, digest)
                owner.inventory.write_text(
                    json.dumps({"version": owner.policy.version, "changed": True})
                )
                return evidence

        self.adapter.gate = RuntimeGate(MutatingVerifier())
        self.assertIn("metadata changed during signature", self.adapter.blockers(self.profile)[0])
        self.assertFalse(self.driver.calls)

    def test_metadata_only_change_after_admission_denies(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        self.inventory.write_text(json.dumps({"version": self.policy.version, "changed": True}))
        with self.assertRaisesRegex(WorkspaceError, "changed before execution"):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_metadata_change_during_driver_start_blocks_spawn(self):
        async def changed_start():
            self.inventory.write_text(json.dumps({"version": self.policy.version, "changed": True}))
            return self.driver

        self.driver.start = changed_start
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertFalse(handle.spawn_attempted)
        self.assertFalse(self.driver.calls)

    def test_metadata_change_during_spawn_closes_context_before_ready(self):
        original = self.driver.launch

        async def changed_launch(*args, **kwargs):
            context = await original(*args, **kwargs)
            self.inventory.write_text(json.dumps({"version": self.policy.version, "changed": True}))
            return context

        self.supervisor.launcher = changed_launch
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertFalse(handle.context.pages[0].targets)

    def test_malformed_metadata_observer_and_evidence_fail_closed(self):
        self.adapter.metadata_observer = lambda executable: "fixture-build"
        self.assertIn("metadata evidence is invalid", self.adapter.blockers(self.profile)[0])
        with self.assertRaises(ValueError):
            CamoufoxRuntimeMetadata("fixture", Path("relative"), (1, 2, 3, 4, 5), "a" * 64)
        with self.assertRaises(ValueError):
            CamoufoxRuntimeMetadata("fixture", Path("/synthetic"), (1, 2, True, 4, 5), "a" * 64)

    def test_quarantine_is_held_through_initial_context_proof(self):
        self.proxy()
        original = self.probe.collect
        seen = []

        async def collect(*args):
            seen.append(self.supervisor._handles[-1].relay.quarantined)
            return await original(*args)

        self.probe.collect = collect
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.assertEqual(seen, [True])
        self.assertFalse(handle.relay.quarantined)
        prefs = self.driver.calls[0]["from_options"]["firefox_user_prefs"]
        self.assertEqual(prefs["browser.startup.page"], 0)
        self.assertFalse(prefs["browser.sessionstore.resume_from_crash"])
        self.assertFalse(prefs["browser.sessionstore.resume_session_once"])

    def test_assignment_revoked_during_driver_start_never_spawns(self):
        self.proxy()

        async def changed_start():
            self.adapter.proxy_routes.value = replace(
                self.route, configuration=replace(self.route.configuration, port=444)
            )
            return self.driver

        self.driver.start = changed_start
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertFalse(handle.spawn_attempted)
        self.assertFalse(self.driver.calls)
        self.assertFalse(handle.relay.healthy)

    def test_assignment_revoked_during_proof_never_opens_quarantine(self):
        self.proxy()
        original = self.probe.collect

        async def collect(*args):
            evidence = await original(*args)
            self.adapter.proxy_routes.value = replace(
                self.route, configuration=replace(self.route.configuration, port=444)
            )
            return evidence

        self.probe.collect = collect
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.context.closed)
        self.assertTrue(handle.relay.quarantined)
        self.assertFalse(handle.relay.healthy)

    def test_restored_target_attempt_during_launch_is_rejected_before_upstream(self):
        self.proxy()
        original = self.driver.launch
        replies = []

        async def launch(*args, **kwargs):
            port = kwargs["from_options"]["firefox_user_prefs"]["network.proxy.socks_port"]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                await reader.readexactly(2)
                host = b"restored.example.test"
                writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb")
                await writer.drain()
                replies.append(await reader.readexactly(10))
            finally:
                writer.close()
                await writer.wait_closed()
            return await original(*args, **kwargs)

        self.supervisor.launcher = launch
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.assertEqual(replies[0][:2], b"\x05\x02")
        self.assertFalse(handle.relay.failed)
        self.assertFalse(handle.relay.quarantined)

    def test_context_closed_before_listener_registration_never_becomes_ready(self):
        original = self.driver.launch

        async def already_closed(*args, **kwargs):
            context = await original(*args, **kwargs)
            context.closed = True
            return context

        self.supervisor.launcher = already_closed
        self.context = replace(self.context, initial_url=GMAIL_INBOX_URL)
        handle = self.start()
        self.wait(lambda: handle.phase == "unknown")
        self.assertTrue(handle.ownership_uncertain)
        self.assertFalse(handle.context.pages[0].targets)
        self.assertFalse(handle.stop())
        self.assertTrue(self.lease.active)
        # Fixture-only reset lets the existing test cleanup close its fake object.
        handle.context.closed = False
