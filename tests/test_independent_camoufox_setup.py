"""Independent bridge regressions; synthetic drivers only, never native execution."""

import asyncio
import json
import subprocess
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_client_camoufox_setup as fixtures
from team_browser.client.camoufox_setup import CamoufoxSetup
from team_browser.client.camoufox_runtime import CamoufoxProfileIdentityAdmission
from team_browser.client.store import WorkspaceError


class IndependentSetupTests(unittest.TestCase):
    setUp = fixtures.SetupAppTests.setUp
    tearDown = fixtures.SetupAppTests.tearDown
    status = fixtures.SetupAppTests.status
    action = fixtures.SetupAppTests.action
    settle = fixtures.SetupAppTests.settle
    prepare = fixtures.SetupAppTests.prepare

    def test_loopback_origin_host_and_csrf_cover_setup_get_and_post(self):
        for headers in (
            {"origin": "https://attacker.invalid"},
            {"origin": "http://localhost:8765"},
            {"host": "attacker.invalid:8765"},
            {"sec-fetch-site": "cross-site"},
        ):
            for path in (self.path, "/local/v1/camoufox-setup"):
                with self.subTest(headers=headers, path=path):
                    self.assertEqual(self.client.get(path, headers=headers).status_code, 403)
            result = self.client.post(
                self.path + "/actions",
                json={"action": "prepare", "expected_revision": 1, "expected_setup_revision": 1},
                headers={**self.headers, **headers},
            )
            self.assertEqual(result.status_code, 403)
        self.assertFalse(self.driver.calls)

    def test_web_action_types_are_strict_and_operation_set_is_closed(self):
        for extra in (
            {"action": "install"},
            {"action": "reset"},
            {"action": "approve"},
            {"expected_revision": True},
            {"expected_setup_revision": "1"},
            {"expected_revision": 1.0},
            {"expected_setup_revision": 0},
            {"receipt": {"success": True}},
        ):
            with self.subTest(extra=extra):
                state = self.status()
                response = self.client.post(
                    self.path + "/actions",
                    json={
                        "action": "prepare",
                        "expected_revision": state["profile_revision"],
                        "expected_setup_revision": state["revision"],
                        **extra,
                    },
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 422, response.text)
        self.assertFalse(self.driver.calls)

    def test_stale_profile_revision_cannot_prepare(self):
        state = self.status()
        changed = self.client.patch(
            f"/local/v1/profiles/{self.pid}",
            json={"expected_revision": state["profile_revision"], "name": "New name"},
            headers=self.headers,
        )
        self.assertEqual(changed.status_code, 200)
        response = self.client.post(
            self.path + "/actions",
            json={
                "action": "prepare",
                "expected_revision": state["profile_revision"],
                "expected_setup_revision": state["revision"],
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.driver.calls)

    def test_passive_status_does_not_hash_complete_distribution(self):
        self.prepare()
        self.assertEqual(self.action("validate").status_code, 202)
        self.assertEqual(self.settle()["state"], "ready")
        with patch.object(
            self.deployment, "verify", side_effect=AssertionError("Full tree hash on GET")
        ):
            self.assertTrue(self.status()["admission_acknowledged"])
            self.assertTrue(self.client.get("/local/v1/camoufox-setup").json()["usable"])

    def test_start_rechecks_complete_distribution_after_ready(self):
        self.prepare()
        self.action("validate")
        state = self.settle()
        calls = len(self.driver.calls)
        with patch.object(self.deployment, "verify", side_effect=ValueError("Resource changed")):
            result = self.client.post(
                f"/local/v1/profiles/{self.pid}/actions",
                json={"action": "start", "expected_revision": state["profile_revision"]},
                headers=self.headers,
            )
            self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(len(self.driver.calls), calls)

    def test_cancel_during_delayed_native_launch_never_admits(self):
        self.prepare()
        self.driver.delay = 0.25
        self.assertEqual(self.action("validate").status_code, 202)
        self.assertTrue(self.driver.entered.wait(1))
        self.assertEqual(self.action("cancel").status_code, 202)
        state = self.settle()
        self.assertFalse(state["admission_acknowledged"])
        self.assertNotEqual(state["state"], "ready")
        self.assertTrue(all(context.is_closed() for context in self.driver.contexts))
        self.assertIsNone(self.setup._entries[self.pid].lease)

    def test_close_acknowledgement_is_required_before_ready(self):
        self.prepare()
        entered, release = threading.Event(), threading.Event()
        original = fixtures.native.FakeContext.close

        async def delayed(context):
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.005)
            await original(context)

        with patch.object(fixtures.native.FakeContext, "close", delayed):
            try:
                self.assertEqual(self.action("validate").status_code, 202)
                self.assertTrue(entered.wait(2))
                state = self.status()
                self.assertEqual(state["state"], "validating")
                self.assertFalse(state["admission_acknowledged"])
                self.assertTrue(self.setup._entries[self.pid].lease.active)
            finally:
                release.set()
            self.assertEqual(self.settle()["state"], "ready")

    def test_profile_revision_change_during_validation_never_admits(self):
        self.prepare()
        self.driver.delay = 0.15
        self.assertEqual(self.action("validate").status_code, 202)
        self.assertTrue(self.driver.entered.wait(1))
        self.app.state.workspace._change(self.pid, name="Synthetic out-of-band change")
        state = self.settle()
        self.assertFalse(state["admission_acknowledged"])
        self.assertTrue(all(context.is_closed() for context in self.driver.contexts))

    def test_generation_change_during_validation_never_admits(self):
        self.prepare()
        self.driver.delay = 0.15
        self.assertEqual(self.action("validate").status_code, 202)
        self.assertTrue(self.driver.entered.wait(1))
        store = self.app.state.workspace
        store._change(self.pid, generation=store.get(self.pid)["generation"] + 1)
        self.assertFalse(self.settle()["admission_acknowledged"])

    def test_ready_admission_cannot_be_reused_for_foreign_profile(self):
        self.prepare()
        self.action("validate")
        self.settle()
        entry = self.setup._entries[self.pid]
        entry.policy = replace(
            entry.policy, admission=replace(entry.policy.admission, profile_id="foreign-profile")
        )
        self.assertFalse(self.status()["admission_acknowledged"])
        self.assertFalse(self.status()["launch_available"])

    def test_native_restart_requires_new_diagnostic_but_reuses_identity(self):
        self.prepare()
        self.action("validate")
        self.assertEqual(self.settle()["state"], "ready")
        original = self.setup._entries[self.pid].artifact
        restarted = CamoufoxSetup(
            self.app.state.workspace,
            self.deployment,
            generator=self.generator,
            probe=self.probe,
            supervisor=self.supervisor,
        )
        state = restarted.snapshot(self.pid)
        self.assertEqual(state["state"], "not_prepared")
        self.assertFalse(state["admission_acknowledged"])
        restarted.action(
            self.pid,
            action="prepare",
            expected_revision=state["profile_revision"],
            expected_setup_revision=state["revision"],
        )
        restarted._entries[self.pid].thread.join(3)
        self.assertEqual(restarted.snapshot(self.pid)["state"], "prepared")
        self.assertEqual(
            restarted._entries[self.pid].artifact.artifact_sha256, original.artifact_sha256
        )
        self.assertTrue(restarted.shutdown())

    def test_changed_template_cannot_regenerate_immutable_profile(self):
        self.prepare()
        self.deployment.record.profile_defaults = replace_template = (
            self.deployment.record.profile_defaults.model_copy(update={"locale": "fr-FR"})
        )
        self.assertEqual(replace_template.locale, "fr-FR")
        self.assertEqual(self.status()["state"], "recovery_required")
        self.assertEqual(self.action("prepare").status_code, 409)
        self.assertFalse(self.driver.calls)

    def test_local_proxy_and_managed_direct_do_not_fall_back(self):
        for origin, network in (
            ("local", "verified_proxy"),
            ("managed", "local_direct"),
            ("local", "unconfigured"),
        ):
            with self.subTest(origin=origin, network=network):
                self.app.state.workspace.db.execute(
                    "UPDATE profiles SET origin=?, network_policy=? WHERE id=?",
                    (origin, network, self.pid),
                )
                state = self.status()
                self.assertEqual(state["state"], "needs_approval")
                self.assertEqual(state["available_actions"], [])
        self.assertFalse(self.driver.calls)

    def test_shutdown_during_prepare_retains_and_releases_safely(self):
        entered, release = threading.Event(), threading.Event()
        original = self.generator.generate

        def delayed(b):
            entered.set()
            release.wait(3)
            return original(b)

        self.generator.generate = delayed
        self.action("prepare")
        self.assertTrue(entered.wait(1))
        stopped = []
        worker = threading.Thread(target=lambda: stopped.append(self.setup.shutdown()))
        worker.start()
        release.set()
        worker.join(4)
        self.assertEqual(stopped, [True])
        self.assertIsNone(self.setup._entries[self.pid].lease)
        self.assertFalse(self.driver.calls)

    def test_expiry_invalidates_ready_and_preserves_stable_artifact(self):
        self.prepare()
        self.action("validate")
        self.settle()
        entry = self.setup._entries[self.pid]
        digest = entry.artifact.artifact_sha256
        entry.policy = replace(
            entry.policy,
            admission=replace(
                entry.policy.admission,
                valid_until=datetime.now(timezone.utc) - timedelta(seconds=1),
            ),
        )
        state = self.status()
        self.assertFalse(state["admission_acknowledged"])
        self.assertEqual(entry.artifact.artifact_sha256, digest)
        self.assertNotIn(str(self.root), json.dumps(state))

    def _two_profiles(self):
        self.prepare()
        self.action("validate")
        self.assertEqual(self.settle()["state"], "ready")
        first = (self.pid, self.path)
        other = self.client.post(
            "/local/v1/profiles",
            json={
                "name": "Second synthetic profile",
                "preset_id": "isolated",
                "network_policy": "local_direct",
            },
            headers=self.headers,
        ).json()
        self.pid, self.path = other["id"], f"/local/v1/profiles/{other['id']}/camoufox-setup"
        self.assertEqual(self.action("prepare").status_code, 202)
        self.assertEqual(self.settle()["state"], "prepared")
        settings = self.app.state.workspace.metadata("settings")
        self.app.state.coordinator.update_settings(settings["revision"], max_warm_profiles=1)
        return first

    def _start(self, profile_id):
        profile = self.app.state.workspace.get(profile_id)
        return self.client.post(
            f"/local/v1/profiles/{profile_id}/actions",
            json={"action": "start", "expected_revision": profile["revision"]},
            headers=self.headers,
        )

    def test_normal_browser_reserves_capacity_against_validation(self):
        first, _ = self._two_profiles()
        self.assertEqual(self._start(first).status_code, 200)
        # Start schedules the already-authorized native launch asynchronously.
        # Settle it before comparing global driver counts; otherwise that first
        # launch can append while the second profile is correctly rejected.
        deadline = time.monotonic() + 3
        while True:
            started = self.client.get(f"/local/v1/profiles/{first}").json()
            if started["state"] != "starting" or time.monotonic() >= deadline:
                break
            time.sleep(0.005)
        self.assertEqual(started["state"], "running", started)
        before = len(self.driver.calls)
        result = self.action("validate")
        self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(result.json()["detail"]["code"], "budget_exceeded")
        self.assertEqual(len(self.driver.calls), before)
        self.assertIsNone(self.setup._entries[self.pid].lease)
        self.assertEqual(self.app.state.coordinator.resources()["resident_profiles"], 1)

    def test_unknown_native_ownership_retains_capacity_against_other_profile(self):
        first, _ = self._two_profiles()
        self.driver.fail = True
        self.action("validate")
        self.assertEqual(self.settle()["state"], "recovery_required")
        resources = self.app.state.coordinator.resources()
        self.assertEqual(resources["resident_profiles"], 1)
        self.assertEqual(resources["setup_reserved_profiles"], 1)
        self.assertEqual(self._start(first).status_code, 409)
        self.assertEqual(self.action("cancel").status_code, 409)
        self.assertEqual(self.app.state.coordinator.resources()["setup_reserved_profiles"], 1)

    def test_concurrent_normal_launch_and_validation_share_one_capacity_slot(self):
        first, _ = self._two_profiles()
        self.driver.delay = 0.3
        barrier = threading.Barrier(2)

        def start():
            barrier.wait()
            return self._start(first)

        def validate():
            barrier.wait()
            return self.action("validate")

        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = (pool.submit(start), pool.submit(validate))
            results = [future.result(timeout=4) for future in pending]
        self.assertEqual(
            sum(result.status_code in {200, 202} for result in results),
            1,
            [result.text for result in results],
        )
        self.assertEqual(sum(result.status_code == 409 for result in results), 1)
        self.assertLessEqual(self.app.state.coordinator.resources()["resident_profiles"], 1)
        if results[1].status_code == 202:
            self.settle()

    def test_malformed_or_failed_reservation_observation_blocks_validation(self):
        self.prepare()
        coordinator = self.app.state.coordinator
        old = coordinator._reserved_slots
        try:
            for value in (True, -1, 17, "0", None, 0.0, object()):
                with self.subTest(value=repr(value)):
                    coordinator._reserved_slots = lambda: value
                    with self.assertRaises(WorkspaceError):
                        coordinator.resources()
                    self.assertEqual(self.action("validate").status_code, 409)
            coordinator._reserved_slots = lambda: (_ for _ in ()).throw(RuntimeError("unknown"))
            self.assertEqual(self.action("validate").status_code, 409)
        finally:
            coordinator._reserved_slots = old
        self.assertFalse(self.driver.calls)

    def test_previous_admission_cannot_be_reused_with_another_validation_lease(self):
        self.prepare()
        self.action("validate")
        self.assertEqual(self.settle()["state"], "ready")
        entry = self.setup._entries[self.pid]
        previous = entry.policy.admission
        entry.policy = replace(entry.policy, admission=None)
        handle = SimpleNamespace(
            identity_admission=previous,
            status=lambda: SimpleNamespace(alive=False),
            stop=lambda: None,
        )
        with patch.object(self.setup.adapter, "validate_identity", return_value=handle):
            self.assertEqual(self.action("validate").status_code, 202)
            state = self.settle()
        self.assertFalse(state["admission_acknowledged"])
        self.assertIsNone(entry.policy.admission)
        self.assertIsNone(entry.lease)

    def test_cancellation_after_candidate_check_still_prevents_publication(self):
        self.prepare()
        original = CamoufoxProfileIdentityAdmission.check

        def cancel_after_check(admission, policy, artifact=None):
            original(admission, policy, artifact)
            if threading.current_thread().name == "camoufox-setup":
                self.setup._entries[self.pid].cancel.set()

        with patch.object(CamoufoxProfileIdentityAdmission, "check", cancel_after_check):
            self.assertEqual(self.action("validate").status_code, 202)
            self.assertFalse(self.settle()["admission_acknowledged"])
        self.assertIsNone(self.setup._entries[self.pid].policy.admission)

    def test_missing_origin_does_not_inherit_local_direct_validation(self):
        self.prepare()
        profile = self.app.state.workspace.get(self.pid)
        profile.pop("origin")
        self.assertTrue(self.setup.adapter.validation_blockers(profile))
        self.assertFalse(self.driver.calls)


class IndependentSetupUITests(unittest.TestCase):
    def test_independent_combined_transport_stale_and_escaping_scenarios(self):
        root = Path(__file__).resolve().parents[1]
        # Reuse only the minimal synthetic DOM/request fixture, not the owner's
        # assertions. All cases below are independent; Node launches no browser.
        script = r"""
const fixture = require('node:fs').readFileSync('tests/frontend_camoufox_setup.cjs', 'utf8').split('let count = 0;')[0];
const independent = `
(async () => {
  // Exercise the real transport module together with the setup component.
  const t = setup();
  vm.runInNewContext(workspace, t.context);
  let profile = {...baseProfile}, status = admitted(profile), writes = 0;
  const client = t.context.window.TeamWorkspace.createClient({getConfig: () => ({mode:'local', api_base:'/local/v1', csrf_token:'fixture-csrf'}), fetcher: async (url, options) => {
    if (options.method === 'POST') { writes++; throw new Error('uncertain private /tmp/runtime detail'); }
    const data = url === '/local/v1/camoufox-setup' ? runtime() : url.endsWith('/camoufox-setup') ? status : profile;
    return {ok:true,status:200,json:async () => structuredClone(data)};
  }});
  t.setNext(client); t.activate(); await settle(); assert(t.component.canLaunch(t.profile));
  status = {...status, profile_id:'another-profile'}; await t.component.poll(); assert(!t.component.canLaunch(t.profile)); assert.equal(t.component.state.snapshot,null);
  status = admitted(profile); await t.component.poll(); assert(t.component.canLaunch(t.profile));
  status = {...status, profile_revision:profile.revision-1}; await t.component.poll(); assert(!t.component.canLaunch(t.profile));
  status = snapshot(profile); await t.component.poll(); await t.component.action('prepare'); assert.equal(writes,1); assert(!t.text().includes('/tmp/runtime')); assert(!t.component.canLaunch(t.profile));
  await t.component.action('prepare'); assert.equal(writes,1); t.component.deactivate();
  // Dismiss/reopen while both old reads and mutations are unresolved.
  const u = setup(), pending = held(); u.setNext(() => pending.promise); u.activate(); u.component.deactivate();
  u.setNext(null); u.setState(snapshot(baseProfile)); u.activate(); await settle(); pending.resolve(runtime()); await settle(); assert.equal(u.component.state.snapshot.state,'not_prepared'); assert(!u.component.canLaunch(u.profile));
  const write = held(); u.setNext(() => write.promise); const action = u.component.action('prepare'); u.component.deactivate(); u.setNext(null); u.setState(snapshot(baseProfile)); u.activate(); await settle(); write.resolve(admitted()); await action; assert.equal(u.component.state.snapshot.state,'not_prepared'); assert(!u.component.canLaunch(u.profile)); u.component.deactivate();
  // Refresh arriving after expiry cannot preserve old readiness on failure.
  const v = setup(); v.setState(admitted()); v.activate(); await settle(); v.tick(6001); assert(!v.component.canLaunch(v.profile)); v.setNext(async () => {throw new Error('private');}); await v.component.poll(); assert.equal(v.component.state.snapshot,null); v.component.deactivate();
  // Names, blockers and next steps remain text even under hostile-looking text.
  const p = {...baseProfile,name:'<svg/onload=throw(1)>'}, e = setup({profile:p}); e.setState(snapshot(p,{blockers:['<img src=x onerror=throw(2)>'],next_step:'<iframe src=javascript:throw(3)>'})); e.activate(); await settle(); assert(e.text().includes('<svg')); assert(e.text().includes('<img')); assert(e.text().includes('<iframe')); assert(!e.all().some(el => ['SVG','IMG','IFRAME'].includes(el.tagName))); e.component.deactivate();
  console.log('PASS independent combined setup/transport: foreign/stale revisions, uncertain write, dismissal/read/write races, expiry failure, and literal escaping');
})().catch(error => {console.error(error); process.exitCode=1;});
`;
eval(fixture + independent);
"""
        result = subprocess.run(
            ["node", "-e", script],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
