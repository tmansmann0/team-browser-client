"""Generated-identity runtime/validation contracts with fake contexts only."""

import asyncio
import hashlib
import json
import os
import sys
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import test_client_camoufox_runtime as legacy
from test_client_engine_identity import SyntheticGenerator, binding
from team_browser.client import camoufox_runtime as runtime_module
from team_browser.client.camoufox_runtime import (
    IDENTITY_SIGNAL_NAMES,
    ROUTE_PREFS,
    CamoufoxGeneratedIdentityPolicy,
    CamoufoxIdentityObservation,
    CamoufoxIdentityProgramAcceptance,
    CamoufoxIdentityProperties,
    expected_identity_core,
)
from team_browser.client.engine_identity import (
    ARTIFACT_NAME,
    EngineIdentityStore,
    IdentityBinding,
    OfflineCamoufoxGenerator,
)
from team_browser.client.installed_browser import InstalledBrowserAdapter
from team_browser.client.lifecycle import GMAIL_INBOX_URL
from team_browser.client.store import WorkspaceError


class RuntimeGenerator(SyntheticGenerator):
    def generate(self, b):
        config, prefs, selected = super().generate(b)
        for prefix in ("webGl", "webGl2"):
            config[f"{prefix}:parameters"].update(
                {"3386": [16384, 16384], "34921": 16, "34930": 16}
            )
        if b.target_os == "macos":
            config.update(
                {
                    "navigator.userAgent": f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{b.firefox_major}.0) Gecko/20100101 Firefox/{b.firefox_major}.0",
                    "navigator.platform": "MacIntel",
                    "navigator.oscpu": "Intel Mac OS X 10.15",
                    "navigator.appVersion": "5.0 (Macintosh)",
                }
            )
        return config, prefs, selected


class SyntheticIdentityProbe:
    probe_id = "synthetic-fixed-probe-v1"

    def __init__(self, display):
        self.display = display
        self.contexts = []
        self.challenges = []
        self.after_collect = lambda: None
        self.wrong_core = False
        self.wrong_challenge = False
        self.stale = False
        self.signal_variant = "e"
        self.changing = False
        self.relay_state = lambda: True
        self.quarantine_states = []

    async def collect(self, context, challenge, artifact):
        self.contexts.append(context)
        self.challenges.append(challenge)
        self.quarantine_states.append(self.relay_state())
        core = expected_identity_core(artifact, self.display)
        if self.wrong_core:
            core["navigator.platform"] = "foreign"
        await asyncio.sleep(0)
        self.after_collect()
        return CamoufoxIdentityObservation(
            self.probe_id,
            "0" * 32 if self.wrong_challenge else challenge,
            artifact.artifact_sha256,
            datetime.now(timezone.utc) - timedelta(seconds=60 if self.stale else 0),
            json.dumps(core, sort_keys=True, separators=(",", ":")),
            tuple(
                (
                    name,
                    ("a" if self.changing and len(self.contexts) % 2 else self.signal_variant) * 64,
                )
                for name in IDENTITY_SIGNAL_NAMES
            ),
        )


class GeneratedRuntimeTests(unittest.TestCase):
    synthetic_metadata_observer = legacy.CamoufoxRuntimeTests.synthetic_metadata_observer
    wait = legacy.CamoufoxRuntimeTests.wait
    proxy = legacy.CamoufoxRuntimeTests.proxy
    tearDown = legacy.CamoufoxRuntimeTests.tearDown

    def setUp(self):
        legacy.CamoufoxRuntimeTests.setUp(self)
        self.proxy()
        settings = self.policies.value
        self.binding = IdentityBinding(
            self.profile["id"],
            settings.profile_binding_sha256,
            settings.preset_id,
            self.policy.version,
            self.policy.sha256,
            150,
            sys.platform,
            {"linux": "linux", "darwin": "macos"}[sys.platform],
            binding().display,
            settings.locale,
            settings.timezone_id,
            settings.proxy_fingerprint,
        )
        self.generator = RuntimeGenerator()
        self.artifact = EngineIdentityStore(self.store).load_or_create(
            self.lease, self.binding, self.generator
        )
        self.properties_path = self.lease.paths.directory / "synthetic-engine-properties.json"
        types = {str: "str", int: "uint", bool: "bool", list: "array", dict: "dict"}
        self.properties_path.write_text(
            json.dumps(
                [
                    {"property": key, "type": types[type(value)]}
                    for key, value in json.loads(self.artifact.config_json).items()
                ]
            )
        )
        self.identity_probe = SyntheticIdentityProbe(self.binding.display)
        self.program = CamoufoxIdentityProgramAcceptance(
            self.policy.sha256,
            self.policy.version,
            150,
            sys.platform,
            self.binding.display,
            self.generator.provenance(self.binding),
            hashlib.sha256(self.properties_path.read_bytes()).hexdigest(),
            self.identity_probe.probe_id,
            "synthetic-program-not-native-proof",
            datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.generated_policy = CamoufoxGeneratedIdentityPolicy(
            self.binding,
            self.artifact.artifact_sha256,
            self.generator,
            self.program,
            self.read_properties,
            self.identity_probe,
        )
        self.generated_provider = legacy.Policies(self.generated_policy)
        self.adapter.generated_identities = self.generated_provider

    def read_properties(self, executable):
        raw = self.properties_path.read_bytes()
        info = self.properties_path.stat()
        return CamoufoxIdentityProperties(
            self.properties_path,
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            hashlib.sha256(raw).hexdigest(),
            raw,
        )

    def begin_validation(self):
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        handle = self.adapter.validate_identity(self.context)
        self.identity_probe.relay_state = lambda: handle.relay.quarantined
        return handle

    def validate_and_admit(self):
        handle = self.begin_validation()
        self.wait(lambda: handle.phase in ("stopped", "unknown"))
        self.assertEqual(handle.phase, "stopped")
        self.assertIsNotNone(handle.identity_admission)
        self.generated_policy = replace(self.generated_policy, admission=handle.identity_admission)
        self.generated_provider.value = self.generated_policy
        return handle

    def normal_start(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        return self.adapter.start(self.context)

    def test_concrete_collector_joins_validation_and_production_admission(self):
        import copy
        import test_client_identity_probe as collector_fixture
        from team_browser.client.identity_probe import (
            FixedCamoufoxIdentityProbe,
            FIXED_IDENTITY_SCRIPT,
        )

        artifact = self.artifact
        display = self.binding.display
        config = json.loads(artifact.config_json)
        measured_core = {key: config[key] for key in runtime_module._IDENTITY_CORE_KEYS}
        measured_core["devicePixelRatio"] = display.device_pixel_ratio

        class JoinedContext(collector_fixture.Events):
            def __init__(self):
                super().__init__()
                self.pages = [legacy.FakePage()]
                self.created_pages = []
                self.closed = False

            def is_closed(self):
                return self.closed

            async def new_page(self):
                page = collector_fixture.FakePage(self)
                original = page.evaluate

                async def evaluate(script, challenge):
                    payload = {
                        "schema": runtime_module.IDENTITY_PROBE_SCHEMA,
                        "challenge": challenge,
                        "core": copy.deepcopy(measured_core),
                        "canvas": [index % 256 for index in range(2048)],
                        "voices": copy.deepcopy(config["voices"]),
                    }
                    for name, prefix in (("webgl", "webGl"), ("webgl2", "webGl2")):
                        payload[name] = {
                            "vendor": config["webGl:vendor"],
                            "renderer": config["webGl:renderer"],
                            "parameters": {
                                str(enum): config[f"{prefix}:parameters"][str(enum)]
                                for enum in runtime_module.IDENTITY_WEBGL_PARAMETERS
                            },
                        }
                    page.output = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    return await original(script, challenge)

                page.evaluate = evaluate
                self.pages.append(page)
                self.created_pages.append(page)
                return page

            async def close(self):
                self.closed = True
                for page in self.pages:
                    page.closed = True
                self.emit("close")

        async def launcher(playwright, **kwargs):
            self.driver.calls.append(kwargs)
            context = JoinedContext()
            self.driver.contexts.append(context)
            return context

        self.supervisor.launcher = launcher
        self.identity_probe = FixedCamoufoxIdentityProbe()
        self.program = replace(self.program, probe_id=self.identity_probe.probe_id)
        self.generated_policy = replace(
            self.generated_policy, program=self.program, probe=self.identity_probe
        )
        self.generated_provider.value = self.generated_policy
        validation = self.validate_and_admit()
        self.assertEqual(len(validation.context.created_pages), 2)
        self.assertTrue(all(page.closed for page in validation.context.created_pages))
        handle = self.normal_start()
        self.wait(lambda: handle.phase == "ready")
        self.assertEqual(len(handle.context.created_pages), 1)
        self.assertTrue(handle.context.created_pages[0].closed)
        for context in self.driver.contexts:
            for page in context.created_pages:
                self.assertEqual(len(page.evaluate_calls), 1)
                self.assertEqual(page.evaluate_calls[0][0], FIXED_IDENTITY_SCRIPT)
                self.assertEqual(page.close_calls, [{"run_before_unload": False}])

    def test_prepared_artifact_alone_does_not_grant_normal_admission(self):
        self.assertTrue(self.adapter.blockers(self.profile))
        with self.assertRaises(WorkspaceError):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)
        self.assertEqual(self.generator.calls, 1)

    def test_bounded_validation_then_normal_launch_probes_before_release(self):
        validation = self.validate_and_admit()
        self.assertTrue(validation.context.closed)
        self.assertTrue(self.lease.active)
        self.assertFalse(validation.relay.healthy)
        self.assertEqual(len(self.identity_probe.contexts), 2)
        self.assertTrue(all(self.identity_probe.quarantine_states))
        self.assertEqual(len(set(self.identity_probe.challenges)), 2)
        self.assertTrue(all(page.targets == [] for page in validation.context.pages))
        report = validation.identity_admission
        self.assertEqual(report.validation_lease_token, self.lease.token)
        self.assertEqual(report.artifact_sha256, self.artifact.artifact_sha256)
        self.assertEqual(report.config_sha256, self.artifact.config_sha256)
        self.assertEqual(report.binding_sha256, self.binding.sha256)
        handle = self.normal_start()
        self.identity_probe.relay_state = lambda: handle.relay.quarantined
        self.wait(lambda: handle.phase == "ready")
        self.assertFalse(handle.relay.quarantined)
        self.assertEqual(len(self.identity_probe.contexts), 3)
        self.assertIs(self.identity_probe.contexts[-1], handle.context)
        self.assertEqual(self.generator.calls, 1)
        self.assertFalse((self.lease.paths.directory / ".camoufox-identity.json").exists())

    def test_validation_cannot_launch_twice_on_one_active_lease(self):
        self.driver.delay = 0.1
        first = self.begin_validation()
        self.assertTrue(self.driver.entered.wait(1))
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with self.assertRaisesRegex(WorkspaceError, "active native owner"):
            self.adapter.validate_identity(self.context)
        self.wait(lambda: first.phase == "stopped")
        self.assertEqual(len(self.driver.calls), 1)

    def test_cancellation_during_validation_close_publishes_no_admission(self):
        original = self.driver.launch
        close_started = threading.Event()
        release = None

        async def launcher(*args, **kwargs):
            nonlocal release
            context = await original(*args, **kwargs)
            original_close = context.close
            release = asyncio.Event()

            async def close():
                close_started.set()
                await release.wait()
                await original_close()

            context.close = close
            return context

        self.supervisor.launcher = launcher
        handle = self.begin_validation()
        self.assertTrue(close_started.wait(2))
        handle.stop()

        async def finish_close():
            release.set()

        self.supervisor.call(finish_close())
        self.wait(lambda: handle.phase == "stopped")
        self.assertIsNone(handle.identity_admission)
        self.assertTrue(handle.context.closed)
        self.assertTrue(self.lease.active)

    def test_close_return_without_closed_context_is_not_admission(self):
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)

            async def close():
                return None

            context.close = close
            return context

        self.supervisor.launcher = launch
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "unknown")
        self.assertIsNone(handle.identity_admission)
        self.assertTrue(self.lease.active)

        async def close():
            handle.context.closed = True

        handle.context.close = close

    def test_timed_out_validation_retains_close_task_without_late_admission(self):
        original_launch = self.driver.launch
        original_wait_for = asyncio.wait_for
        entered = threading.Event()
        holder = {}

        async def launch(*args, **kwargs):
            context = await original_launch(*args, **kwargs)
            original_close = context.close
            holder["release"] = asyncio.Event()

            async def close():
                entered.set()
                await holder["release"].wait()
                await original_close()

            context.close = close
            return context

        async def shorten_close_timeout(awaitable, timeout):
            if timeout == 5 and self.supervisor._handles[-1].close_requested:
                timeout = 0.01
            return await original_wait_for(awaitable, timeout)

        self.supervisor.launcher = launch
        with patch.object(runtime_module.asyncio, "wait_for", shorten_close_timeout):
            handle = self.begin_validation()
            try:
                self.assertTrue(entered.wait(2))
                self.wait(lambda: handle.phase == "unknown")
                close_task = handle.identity_close_task
                self.assertIsNotNone(close_task)
                self.assertFalse(close_task.done())
                self.assertTrue(self.lease.active)
                self.assertIsNone(handle.identity_admission)
            finally:
                self.supervisor._loop.call_soon_threadsafe(holder["release"].set)
                self.wait(lambda: handle.identity_close_task.done())
                self.wait(lambda: handle.launch_future.done())
            self.assertTrue(handle.context.is_closed())
            self.assertFalse(close_task.cancelled())
            self.assertEqual(handle.phase, "unknown")
            self.assertTrue(handle.ownership_uncertain)
            self.assertTrue(self.lease.active)
            self.assertIsNone(handle.identity_admission)
            self.assertFalse(self.supervisor.call(handle._stop()))
            # Only this synthetic fixture has externally verified final exit.
            handle.ownership_uncertain = False
            handle._set_phase("stopped")

    def test_validation_never_releases_quarantine_or_navigates_gmail(self):
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with self.assertRaises(WorkspaceError):
            self.adapter.validate_identity(replace(self.context, initial_url=GMAIL_INBOX_URL))
        self.assertFalse(self.driver.calls)
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with patch.object(
            runtime_module.ProxyRelay,
            "release_quarantine",
            side_effect=AssertionError("validation must never release"),
        ):
            handle = self.adapter.validate_identity(self.context)
            self.wait(lambda: handle.phase == "stopped")
            self.assertIsNotNone(handle.identity_admission)

    def test_local_direct_is_not_a_validation_network_sandbox(self):
        self.profile.update(network_policy="local_direct", origin="local")
        self.policies.value = replace(
            self.policies.value,
            proxy_fingerprint=None,
            profile_binding_sha256=runtime_module.profile_policy_binding(self.profile),
        )
        self.assertTrue(self.adapter.validation_blockers(self.profile))
        self.assertFalse(self.driver.calls)

    def test_missing_artifact_never_generates_in_runtime(self):
        (self.lease.paths.directory / ARTIFACT_NAME).unlink()
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with self.assertRaises(Exception):
            self.adapter.validate_identity(self.context)
        self.assertEqual(self.generator.calls, 1)
        self.assertFalse((self.lease.paths.directory / ARTIFACT_NAME).exists())
        self.assertFalse(self.driver.calls)

    def test_legacy_marker_cannot_be_automatically_migrated(self):
        (self.lease.paths.directory / ".camoufox-identity.json").write_text("synthetic")
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with self.assertRaisesRegex(WorkspaceError, "Legacy"):
            self.adapter.validate_identity(self.context)
        self.assertFalse(self.driver.calls)

    def test_legacy_mode_refuses_generated_marker(self):
        self.adapter.generated_identities = None
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.assertRaisesRegex(WorkspaceError, "generated identity"):
            self.adapter.start(self.context)
        self.assertFalse(self.driver.calls)

    def test_chromium_refuses_generated_marker_even_when_browser_data_empty(self):
        fake_adapter = object.__new__(InstalledBrowserAdapter)
        fake_adapter.profile_store = self.store
        with self.assertRaisesRegex(WorkspaceError, "belongs to Camoufox"):
            fake_adapter._ensure_engine_binding(self.profile["id"])

    def test_exact_program_evidence_changes_block(self):
        for changes in (
            {"runtime_sha256": "0" * 64},
            {"engine_version": "changed"},
            {"firefox_major": 151},
            {"platform": "other"},
            {"display": replace(self.binding.display, width=2600)},
            {"provenance": replace(self.program.provenance, packages_sha256="0" * 64)},
            {"valid_until": datetime.now(timezone.utc)},
            {"identity_schema": True},
            {"probe_schema": "other"},
            {"probe_id": "other"},
        ):
            self.generated_provider.value = replace(
                self.generated_policy, program=replace(self.program, **changes)
            )
            self.assertTrue(self.adapter.validation_blockers(self.profile), changes)
        self.assertFalse(self.driver.calls)

    def test_current_property_bytes_and_observer_identity_are_bound(self):
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        self.properties_path.write_text(self.properties_path.read_text() + " ")
        with self.assertRaisesRegex(WorkspaceError, "properties changed"):
            self.adapter.validate_identity(self.context)
        self.assertFalse(self.driver.calls)

    def test_wrong_unknown_property_schema_never_launches(self):
        rows = json.loads(self.properties_path.read_text())
        rows.pop()
        self.properties_path.write_text(json.dumps(rows))
        self.generated_provider.value = replace(
            self.generated_policy,
            program=replace(
                self.program,
                properties_sha256=hashlib.sha256(self.properties_path.read_bytes()).hexdigest(),
            ),
        )
        self.assertEqual(self.adapter.validation_blockers(self.profile), ())
        with self.assertRaises(Exception):
            self.adapter.validate_identity(self.context)
        self.assertFalse(self.driver.calls)

    def test_lease_release_during_driver_setup_blocks_spawn(self):
        driver = self.driver

        async def start():
            self.lease.release()
            await asyncio.sleep(0)
            return driver

        self.driver.start = start
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "stopped")
        self.assertFalse(self.driver.calls)
        self.assertIsNone(handle.identity_admission)

    def test_property_replacement_during_driver_setup_blocks_spawn(self):
        driver = self.driver

        async def start():
            current = self.properties_path.read_bytes()
            replacement = self.properties_path.with_name("new-properties")
            replacement.write_bytes(current)
            replacement.replace(self.properties_path)
            return driver

        self.driver.start = start
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "stopped")
        self.assertFalse(self.driver.calls)

    def test_artifact_replacement_after_async_route_authority_blocks_spawn(self):
        original = self.supervisor._require_route_authority

        async def revoke(handle):
            await original(handle)
            path = self.lease.paths.directory / ARTIFACT_NAME
            path.write_text(path.read_text() + " ")

        self.supervisor._require_route_authority = revoke
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "stopped")
        self.assertFalse(self.driver.calls)

    def test_wrong_surface_challenge_or_stale_observation_never_admits(self):
        for field in ("wrong_core", "wrong_challenge", "stale"):
            setattr(self.identity_probe, field, True)
            handle = self.begin_validation()
            self.wait(lambda: handle.phase == "stopped")
            self.assertIsNone(handle.identity_admission)
            self.assertTrue(handle.context.closed)
            setattr(self.identity_probe, field, False)

    def test_unstable_observation_has_no_report(self):
        self.identity_probe.changing = True
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "stopped")
        self.assertIsNone(handle.identity_admission)
        self.assertTrue(self.lease.active)

    def test_mid_probe_policy_change_blocks_report(self):
        self.identity_probe.after_collect = lambda: setattr(
            self.generated_provider,
            "value",
            replace(self.generated_policy, artifact_sha256="0" * 64),
        )
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "stopped")
        self.assertIsNone(handle.identity_admission)

    def test_failed_or_unknown_context_close_never_issues_admission(self):
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)

            async def close():
                raise RuntimeError("synthetic unacknowledged close")

            context.close = close
            return context

        self.driver.launch = launch
        self.supervisor.launcher = launch
        handle = self.begin_validation()
        self.wait(lambda: handle.phase == "unknown")
        self.assertIsNone(handle.identity_admission)
        self.assertTrue(self.lease.active)

        # Restore fake-only cleanup acknowledgement; no real process exists.
        async def close():
            handle.context.closed = True

        handle.context.close = close

    def test_ordinary_launch_rechecks_baseline_before_releasing_proxy(self):
        self.validate_and_admit()
        self.identity_probe.signal_variant = "f"
        handle = self.normal_start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.relay.quarantined)
        self.assertTrue(handle.context.closed)

    def test_admission_is_exact_artifact_and_not_foreign_profile_or_program(self):
        self.validate_and_admit()
        admission = self.generated_policy.admission
        for changes in (
            {"profile_id": "other"},
            {"artifact_sha256": "0" * 64},
            {"binding_sha256": "0" * 64},
            {"program_sha256": "0" * 64},
            {"valid_until": datetime.now(timezone.utc)},
        ):
            self.generated_provider.value = replace(
                self.generated_policy, admission=replace(admission, **changes)
            )
            self.assertTrue(self.adapter.blockers(self.profile), changes)

    def test_generated_config_chunks_and_prefs_are_exact_and_scrubbed(self):
        self.validate_and_admit()
        with patch.dict(os.environ, {"CAMOU_CONFIG_99": "foreign", "HTTP_PROXY": "foreign"}):
            handle = self.normal_start()
            self.wait(lambda: handle.phase == "ready")
        options = self.driver.calls[-1]["from_options"]
        environment = options["env"]
        names = sorted(
            (n for n in environment if n.startswith("CAMOU_CONFIG_")),
            key=lambda n: int(n.rsplit("_", 1)[1]),
        )
        self.assertEqual("".join(environment[n] for n in names), self.artifact.config_json)
        self.assertTrue(all(len(environment[n]) <= 32767 for n in names))
        self.assertNotIn("HTTP_PROXY", environment)
        prefs = options["firefox_user_prefs"]
        self.assertEqual(prefs["webgl.enable-webgl2"], True)
        self.assertEqual(prefs["webgl.force-enabled"], True)
        self.assertEqual(prefs["network.proxy.type"], 1)
        self.assertTrue(all(prefs[key] == value for key, value in ROUTE_PREFS.items()))

    def test_chunk_boundaries_use_numbered_complete_canonical_text(self):
        raw = '{"synthetic":"' + "x" * 90000 + '"}'
        chunks = runtime_module._identity_environment(raw)
        self.assertEqual(list(chunks), ["CAMOU_CONFIG_1", "CAMOU_CONFIG_2", "CAMOU_CONFIG_3"])
        self.assertEqual("".join(chunks.values()), raw)
        with self.assertRaises(WorkspaceError):
            runtime_module._identity_environment("x" * 131073)

    @unittest.skipUnless(
        os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1" and sys.platform == "linux",
        "official-wheel offline generator fixture; no native runtime",
    )
    def test_actual_offline_generated_config_flows_through_fake_native_validation(self):
        # A separate fresh profile gets real official generated data; only the
        # launcher/probe/property inventory remain clearly synthetic fixtures.
        self.lease.release()
        self.profile["id"] = "official-generated-profile"
        self.settings = replace(self.settings, profile_id=self.profile["id"])
        self.lease = self.store.acquire(self.profile["id"])
        self.context = replace(
            self.context,
            profile_id=self.profile["id"],
            browser_data=self.lease.paths.browser_data,
            lease=self.lease,
        )
        self.proxy()
        settings = self.policies.value
        self.binding = replace(
            self.binding,
            profile_id=self.profile["id"],
            profile_binding_sha256=settings.profile_binding_sha256,
            proxy_fingerprint=settings.proxy_fingerprint,
        )
        self.generator = OfflineCamoufoxGenerator()
        self.artifact = EngineIdentityStore(self.store).load_or_create(
            self.lease, self.binding, self.generator
        )
        types = {str: "str", int: "uint", bool: "bool", list: "array", dict: "dict"}
        self.properties_path = self.lease.paths.directory / "synthetic-engine-properties.json"
        self.properties_path.write_text(
            json.dumps(
                [
                    {"property": k, "type": types[type(v)]}
                    for k, v in json.loads(self.artifact.config_json).items()
                ]
            )
        )
        self.program = replace(
            self.program,
            provenance=self.generator.provenance(self.binding),
            properties_sha256=hashlib.sha256(self.properties_path.read_bytes()).hexdigest(),
        )
        self.generated_policy = CamoufoxGeneratedIdentityPolicy(
            self.binding,
            self.artifact.artifact_sha256,
            self.generator,
            self.program,
            self.read_properties,
            self.identity_probe,
        )
        self.generated_provider.value = self.generated_policy
        handle = self.validate_and_admit()
        self.assertIsNotNone(handle.identity_admission)
        self.assertGreater(len(self.artifact.config_json), 10000)


if __name__ == "__main__":
    unittest.main()
