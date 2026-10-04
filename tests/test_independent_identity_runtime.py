"""Independent identity-runtime/collector regression probes; no native browser execution."""

import asyncio
import copy
import json
import os
import shutil
import subprocess
import threading
import unittest
from dataclasses import replace

import test_client_engine_identity_runtime as fixtures
from team_browser.client.engine_identity import ARTIFACT_NAME


class IndependentIdentityRuntimeTests(unittest.TestCase):
    # Reuse only synthetic setup helpers, never inherit the implementation's tests.
    setUp = fixtures.GeneratedRuntimeTests.setUp
    tearDown = fixtures.GeneratedRuntimeTests.tearDown
    synthetic_metadata_observer = fixtures.GeneratedRuntimeTests.synthetic_metadata_observer
    wait = fixtures.GeneratedRuntimeTests.wait
    proxy = fixtures.GeneratedRuntimeTests.proxy
    read_properties = fixtures.GeneratedRuntimeTests.read_properties
    begin_validation = fixtures.GeneratedRuntimeTests.begin_validation
    validate_and_admit = fixtures.GeneratedRuntimeTests.validate_and_admit
    normal_start = fixtures.GeneratedRuntimeTests.normal_start

    def await_terminal(self, handle):
        self.wait(lambda: handle.phase in ("ready", "stopped", "unknown"))

    def revoke_route(self):
        self.adapter.proxy_routes.value = replace(
            self.route, diagnostic_targets=(("changed.example.test", 443),)
        )

    def test_successful_identity_reuses_exact_artifact_across_new_profile_lease(self):
        path = self.lease.paths.directory / ARTIFACT_NAME
        original = path.read_bytes()
        validation = self.validate_and_admit()
        self.assertTrue(validation.context.is_closed())
        self.assertEqual(len(self.identity_probe.challenges), 2)
        self.assertEqual(len(set(self.identity_probe.challenges)), 2)
        self.assertTrue(all(self.identity_probe.quarantine_states))
        first = self.normal_start()
        self.await_terminal(first)
        self.assertEqual(first.phase, "ready")
        first.stop()
        self.wait(lambda: first.phase == "stopped")
        previous_token = self.lease.token
        self.lease.release()
        self.lease = self.store.acquire(self.profile["id"])
        self.assertNotEqual(self.lease.token, previous_token)
        self.context = replace(self.context, lease=self.lease)
        second = self.normal_start()
        self.await_terminal(second)
        self.assertEqual(second.phase, "ready")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.generator.calls, 1)
        self.assertFalse((path.parent / ".camoufox-identity.json").exists())
        self.assertEqual(len(self.identity_probe.contexts), 4)
        self.assertIsNot(self.identity_probe.contexts[-1], self.identity_probe.contexts[-2])

    def test_quarantine_stays_closed_through_initial_focus(self):
        self.validate_and_admit()
        original_launch = self.driver.launch
        entered = threading.Event()
        holder = {}

        async def launch(*args, **kwargs):
            context = await original_launch(*args, **kwargs)
            holder["release"] = asyncio.Event()

            async def focus():
                entered.set()
                await holder["release"].wait()

            context.pages[0].bring_to_front = focus
            return context

        self.supervisor.launcher = launch
        handle = self.normal_start()
        self.assertTrue(entered.wait(2))
        try:
            self.assertEqual(handle.phase, "starting")
            self.assertTrue(handle.relay.quarantined)
            self.assertEqual(len(self.identity_probe.contexts), 3)
        finally:
            self.supervisor._loop.call_soon_threadsafe(holder["release"].set)
        self.await_terminal(handle)
        self.assertEqual(handle.phase, "ready")
        self.assertFalse(handle.relay.quarantined)

    @unittest.skipUnless(
        os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1", "optional existing exact-wheel SDK"
    )
    def test_real_sdk_wrapper_runs_complete_generated_runtime_protocol(self):
        from camoufox.async_api import AsyncNewBrowser
        from types import SimpleNamespace
        from unittest.mock import patch

        async def persistent_context(**options):
            return await self.driver.launch(self.driver, from_options=options)

        self.driver.firefox = SimpleNamespace(launch_persistent_context=persistent_context)
        self.supervisor.launcher = AsyncNewBrowser
        with patch(
            "camoufox.async_api.launch_options", side_effect=AssertionError("unexpected generation")
        ):
            validation = self.validate_and_admit()
            self.assertIsNotNone(validation.identity_admission)
            handle = self.normal_start()
            self.await_terminal(handle)
            self.assertEqual(handle.phase, "ready")
        self.assertEqual(len(self.driver.calls), 2)
        for call in self.driver.calls:
            environment = call["from_options"]["env"]
            chunks = [environment[key] for key in environment if key.startswith("CAMOU_CONFIG_")]
            self.assertEqual("".join(chunks), self.artifact.config_json)
        self.assertEqual(self.generator.calls, 1)

    def test_slow_focus_requires_fresh_surface_evidence_before_route_release(self):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch
        from team_browser.client import camoufox_runtime as runtime_module

        class Clock(datetime):
            offset = timedelta()

            @classmethod
            def now(cls, tz=None):
                current = datetime.now(tz) + cls.offset
                return cls.fromtimestamp(current.timestamp(), tz)

        self.program = replace(
            self.program,
            valid_until=Clock.fromtimestamp(self.program.valid_until.timestamp(), timezone.utc),
        )
        self.generated_policy = replace(self.generated_policy, program=self.program)
        self.generated_provider.value = self.generated_policy
        observations = []
        original_collect = self.identity_probe.collect

        async def collect(*args):
            observation = await original_collect(*args)
            observations.append(observation)
            return observation

        self.identity_probe.collect = collect
        original_launch = self.driver.launch
        original_release = runtime_module.ProxyRelay.release_quarantine
        released_ages = []

        async def launch(*args, **kwargs):
            context = await original_launch(*args, **kwargs)

            async def slow_focus():
                Clock.offset += timedelta(seconds=11)

            context.pages[0].bring_to_front = slow_focus
            return context

        def release(relay):
            released_ages.append(
                (Clock.now(timezone.utc) - observations[-1].observed_at).total_seconds()
            )
            return original_release(relay)

        with (
            patch.object(runtime_module, "datetime", Clock),
            patch.object(fixtures, "datetime", Clock),
            patch.object(runtime_module.ProxyRelay, "release_quarantine", release),
        ):
            self.validate_and_admit()
            self.supervisor.launcher = launch
            handle = self.normal_start()
            self.await_terminal(handle)
            self.assertTrue(all(age <= 10 for age in released_ages), released_ages)
            if handle.phase == "ready":
                self.assertTrue(released_ages)
                self.assertGreaterEqual(len(observations), 4)

    def test_route_revoked_during_validation_close_cannot_issue_admission(self):
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)
            close = context.close

            async def changed_close():
                await asyncio.sleep(0)
                self.revoke_route()
                await close()

            context.close = changed_close
            return context

        self.supervisor.launcher = launch
        handle = self.begin_validation()
        self.await_terminal(handle)
        self.assertIsNone(handle.identity_admission)
        self.assertTrue(self.lease.active)
        self.assertFalse(handle.relay.healthy)

    def test_artifact_changed_during_new_page_cannot_become_ready(self):
        self.validate_and_admit()
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)
            context.pages.clear()
            new_page = context.new_page

            async def changed_new_page():
                await asyncio.sleep(0)
                path = self.lease.paths.directory / ARTIFACT_NAME
                path.write_text(path.read_text() + " ")
                return await new_page()

            context.new_page = changed_new_page
            return context

        self.supervisor.launcher = launch
        handle = self.normal_start()
        self.await_terminal(handle)
        self.assertNotEqual(handle.phase, "ready")
        self.assertTrue(handle.relay.quarantined or not handle.relay.healthy)

    def test_lease_released_during_focus_cannot_become_ready(self):
        self.validate_and_admit()
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)

            async def changed_focus():
                await asyncio.sleep(0)
                self.lease.release()

            context.pages[0].bring_to_front = changed_focus
            return context

        self.supervisor.launcher = launch
        self.context = replace(self.context, selected=True)
        handle = self.normal_start()
        self.await_terminal(handle)
        self.assertNotEqual(handle.phase, "ready")
        self.assertTrue(handle.relay.quarantined or not handle.relay.healthy)

    def test_route_revoked_in_final_identity_guard_cannot_release_quarantine(self):
        self.validate_and_admit()
        original = self.supervisor._runtime_current

        async def changed_current(handle, runtime):
            result = await original(handle, runtime)
            if len(self.identity_probe.contexts) >= 3:
                self.revoke_route()
            return result

        self.supervisor._runtime_current = changed_current
        handle = self.normal_start()
        self.await_terminal(handle)
        self.assertNotEqual(handle.phase, "ready")
        self.assertTrue(handle.relay.quarantined or not handle.relay.healthy)

    def test_runtime_replaced_after_focus_guard_cannot_release_quarantine(self):
        from unittest.mock import patch
        from team_browser.client import camoufox_runtime as runtime_module

        self.validate_and_admit()
        original_current = self.supervisor._runtime_current
        original_launch = self.driver.launch
        focused = False
        mutated = False
        releases = []

        async def launch(*args, **kwargs):
            context = await original_launch(*args, **kwargs)

            async def focus():
                nonlocal focused
                focused = True

            context.pages[0].bring_to_front = focus
            return context

        async def changed_current(handle, runtime):
            nonlocal mutated
            result = await original_current(handle, runtime)
            if focused and not mutated:
                mutated = True
                self.binary.write_bytes(b"synthetic-replaced-runtime")
            return result

        original_release = runtime_module.ProxyRelay.release_quarantine

        def release(relay):
            releases.append(True)
            return original_release(relay)

        self.supervisor.launcher = launch
        self.supervisor._runtime_current = changed_current
        with patch.object(runtime_module.ProxyRelay, "release_quarantine", release):
            handle = self.normal_start()
            self.await_terminal(handle)
        self.assertTrue(mutated)
        self.assertFalse(releases)
        self.assertNotEqual(handle.phase, "ready")

    def test_validation_close_timeout_is_bounded_even_when_driver_ignores_cancel(self):
        from unittest.mock import patch
        from team_browser.client import camoufox_runtime as runtime_module

        original_launch = self.driver.launch
        original_wait_for = asyncio.wait_for
        entered = threading.Event()
        holder = {}

        async def launch(*args, **kwargs):
            context = await original_launch(*args, **kwargs)
            holder["release"] = asyncio.Event()
            original_close = context.close

            async def resistant_close():
                entered.set()
                try:
                    await holder["release"].wait()
                except asyncio.CancelledError:
                    await holder["release"].wait()
                await original_close()

            context.close = resistant_close
            return context

        async def shorten_close_timeout(awaitable, timeout):
            if (
                timeout == 5
                and self.supervisor._handles
                and self.supervisor._handles[-1].close_requested
            ):
                timeout = 0.01
            return await original_wait_for(awaitable, timeout)

        self.supervisor.launcher = launch
        with patch.object(runtime_module.asyncio, "wait_for", shorten_close_timeout):
            handle = self.begin_validation()
            try:
                self.assertTrue(entered.wait(1))
                self.wait(lambda: handle.phase == "unknown", timeout=0.15)
                self.assertIsNone(handle.identity_admission)
                self.assertTrue(self.lease.active)
            finally:
                self.supervisor._loop.call_soon_threadsafe(holder["release"].set)
                self.wait(lambda: handle.launch_future.done())
                self.wait(lambda: handle.context.is_closed())
                # Only release the deliberately synthetic teardown fixture; late
                # native close completion must not clear production uncertainty.
                handle.ownership_uncertain = False
                handle._set_phase("stopped")

    def test_cancelled_identity_probe_retains_explicit_unknown_ownership(self):
        async def cancelled(context, challenge, artifact):
            raise asyncio.CancelledError

        self.identity_probe.collect = cancelled
        handle = self.begin_validation()
        self.wait(lambda: handle.launch_future.done())
        try:
            self.assertIsNone(handle.identity_admission)
            self.assertEqual(handle.phase, "unknown")
            self.assertTrue(self.lease.active)
            self.assertTrue(handle.relay.quarantined or not handle.relay.healthy)
        finally:
            # A cancelled fixture launch future would also cancel its cleanup
            # waiter. Remove that already-finished fake future for teardown.
            handle.launch_future = None

    def test_rejected_normal_probe_without_close_ack_preserves_unknown_ownership(self):
        self.validate_and_admit()
        self.identity_probe.signal_variant = "f"
        original = self.driver.launch

        async def launch(*args, **kwargs):
            context = await original(*args, **kwargs)

            async def no_ack_close():
                await asyncio.sleep(0)

            context.close = no_ack_close
            return context

        self.supervisor.launcher = launch
        handle = self.normal_start()
        self.await_terminal(handle)
        try:
            self.assertEqual(handle.phase, "unknown")
            self.assertTrue(self.lease.active)
            self.assertFalse(handle.context.is_closed())
        finally:
            # This is solely fake-context cleanup; no native process is involved.
            async def acknowledge():
                handle.context.closed = True

            handle.context.close = acknowledge


class IndependentConcreteCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_cannot_change_page_owner_and_still_return_evidence(self):
        import test_client_identity_probe as fixture
        from team_browser.client.identity_probe import FixedCamoufoxIdentityProbe
        from team_browser.client.store import WorkspaceError

        context = fixture.FakeContext()
        page = context.page
        foreign = fixture.FakeContext()
        # The object returned by the driver ceases to belong to the exact context
        # while the close await is in flight. A closed flag alone is insufficient.
        page.on_close = lambda: setattr(page, "context", foreign)
        with self.assertRaises(WorkspaceError):
            await FixedCamoufoxIdentityProbe().collect(
                context, fixture.CHALLENGE, fixture.artifact()
            )
        self.assertEqual(foreign.page.close_calls, [])
        self.assertEqual(page.close_calls, [{"run_before_unload": False}])

    async def test_concurrent_foreign_tab_is_untouched(self):
        import test_client_identity_probe as fixture
        from team_browser.client.identity_probe import FixedCamoufoxIdentityProbe

        context = fixture.FakeContext()
        concurrent = fixture.ForeignPage()
        context.page.after_evaluate = lambda: context.pages.append(concurrent)
        result = await FixedCamoufoxIdentityProbe().collect(
            context, fixture.CHALLENGE, fixture.artifact()
        )
        self.assertEqual(result.challenge, fixture.CHALLENGE)
        self.assertEqual(context.pages, [context.original, concurrent])
        self.assertEqual(context.page.close_calls, [{"run_before_unload": False}])


# Run the actual immutable JS literal using synthetic browser globals. This is a
# syntax/data-flow test, explicitly NOT a browser or native-surface observation.
_JS_FIXTURE_RUNNER = r"""
const fs = require('fs'), vm = require('vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const observed = input.observed;
let timers = 0, voiceReads = 0, creations = 0, clockReads = 0;
const window = {frames: [], devicePixelRatio: observed.core.devicePixelRatio};
window.top = window;
window.speechSynthesis = {getVoices() {
  return voiceReads++ < (input.emptyVoiceReads || 0) ? [] : observed.voices.map(v => ({
    name: v.name, lang: v.lang, voiceURI: v.voiceUri,
    default: v.isDefault, localService: v.isLocalService
  }));
}};
const navigator = {}, screen = {};
for (const [key, value] of Object.entries(observed.core)) {
  if (key.startsWith('navigator.')) navigator[key.slice(10)] = value;
  if (key.startsWith('screen.')) screen[key.slice(7)] = value;
}
const document = {URL: 'about:blank', createElement(kind) {
  if (kind !== 'canvas') throw Error('non-canvas element');
  creations++;
  return {getContext(type) {
    if (type === '2d') return {
      createLinearGradient() {return {addColorStop() {}}},
      fillRect() {}, beginPath() {}, arc() {}, fill() {},
      getImageData(x,y,w,h) {
        if (x !== 0 || y !== 0 || w !== 32 || h !== 16) throw Error('unfixed fixture');
        return {data: observed.canvas};
      }
    };
    const gpu = observed[type];
    if (!gpu) throw Error('unexpected GPU');
    return {isContextLost() {return false}, getExtension(name) {
      if (name !== 'WEBGL_debug_renderer_info') throw Error('unexpected extension');
      return {};
    }, getParameter(n) {
      if (n === 37445) return gpu.vendor;
      if (n === 37446) return gpu.renderer;
      return gpu.parameters[String(n)];
    }};
  }};
}};
const sandbox = {window, document, navigator, screen, location: {href: 'about:blank'},
  performance: {now() {return clockReads++ ? (input.elapsed || 0) : 0}},
  Intl: {DateTimeFormat() {return {resolvedOptions() {return {timeZone: observed.core.timezone}}}}},
  setTimeout(fn, delay) {
    if (delay !== 50) throw Error('unexpected timer');
    timers++; Promise.resolve().then(fn);
  }
};
(async () => {
  try {
    const fn = vm.runInNewContext('(' + input.script + ')', sandbox, {timeout: 1000});
    const raw = await fn(input.challenge);
    process.stdout.write(JSON.stringify({raw, timers, voiceReads, creations}));
  } catch (error) {
    process.stdout.write(JSON.stringify({error: error.message, timers, voiceReads, creations}));
  }
})();
"""


@unittest.skipUnless(shutil.which("node"), "existing Node needed for offline JS fixture")
class IndependentLiteralScriptTests(unittest.TestCase):
    def execute(self, **changes):
        import test_client_identity_probe as fixture
        from team_browser.client.identity_probe import FIXED_IDENTITY_SCRIPT

        request = {
            "script": FIXED_IDENTITY_SCRIPT,
            "challenge": fixture.CHALLENGE,
            "observed": fixture.payload(),
            **changes,
        }
        result = subprocess.run(
            [shutil.which("node"), "--no-warnings", "-e", _JS_FIXTURE_RUNNER],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_literal_script_executes_and_collects_independent_values(self):
        import test_client_identity_probe as fixture
        from team_browser.client.identity_probe import _observed

        result = self.execute()
        self.assertNotIn("error", result)
        self.assertEqual(json.loads(result["raw"]), fixture.payload())
        self.assertEqual(result["creations"], 3)
        self.assertEqual(result["timers"], 0)
        first, signals = _observed(result["raw"], fixture.CHALLENGE)
        data = fixture.payload()
        data["core"]["navigator.userAgent"] = "Independent observed UA"
        data["canvas"][5] = 117
        altered = self.execute(observed=data)
        second, new_signals = _observed(altered["raw"], fixture.CHALLENGE)
        self.assertNotEqual(first, second)
        self.assertNotEqual(dict(signals)["canvas"], dict(new_signals)["canvas"])

    def test_literal_script_voice_wait_is_bounded_and_never_echoes_empty_input(self):
        delayed = self.execute(emptyVoiceReads=10)
        self.assertNotIn("error", delayed)
        self.assertEqual((delayed["voiceReads"], delayed["timers"]), (11, 10))
        absent = self.execute(emptyVoiceReads=11)
        self.assertEqual(absent["error"], "identity-probe-invalid")
        self.assertEqual((absent["voiceReads"], absent["timers"]), (11, 10))
        self.assertNotIn("raw", absent)

    def test_literal_script_rejects_invalid_browser_measurements(self):
        import test_client_identity_probe as fixture

        mutations = (
            lambda value: value["core"].update({"navigator.hardwareConcurrency": True}),
            lambda value: value["core"].update({"devicePixelRatio": 0}),
            lambda value: value["voices"][0].update(isDefault=1),
            lambda value: value["webgl2"]["parameters"].update({"3386": [8192]}),
            lambda value: value.update(canvas=[0] * 100),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = copy.deepcopy(fixture.payload())
                mutate(data)
                result = self.execute(observed=data)
                self.assertEqual(result.get("error"), "identity-probe-invalid")
                self.assertNotIn("raw", result)
        self.assertEqual(self.execute(elapsed=1501).get("error"), "identity-probe-invalid")


@unittest.skipUnless(
    os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1", "optional existing exact-wheel SDK"
)
class IndependentExactSDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_sdk_wrapper_preserves_options_without_generation_or_driver_spawn(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from camoufox import async_api
        from team_browser.client.camoufox_runtime import _identity_environment

        calls = []
        context = object()

        async def launch_persistent_context(**options):
            calls.append(options)
            return context

        fake_driver = SimpleNamespace(
            firefox=SimpleNamespace(launch_persistent_context=launch_persistent_context)
        )
        options = {
            "executable_path": "/synthetic/never-execute",
            "user_data_dir": "/synthetic/never-read-profile",
            "headless": False,
            "no_viewport": True,
            "env": _identity_environment('{"synthetic":"kept exactly"}'),
            "firefox_user_prefs": {"network.proxy.type": 1},
        }
        before = copy.deepcopy(options)
        with (
            patch.object(async_api, "launch_options", side_effect=AssertionError("generation")),
            patch.object(
                async_api, "generate_context_fingerprint", side_effect=AssertionError("generation")
            ),
            patch.object(async_api, "VirtualDisplay", side_effect=AssertionError("display spawn")),
        ):
            returned = await async_api.AsyncNewBrowser(
                fake_driver, from_options=options, persistent_context=True
            )
        self.assertIs(returned, context)
        self.assertEqual(options, before)
        self.assertEqual(calls, [before])


if __name__ == "__main__":
    unittest.main()
