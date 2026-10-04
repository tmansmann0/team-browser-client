"""Independent public host/bridge/race checks, with synthetic native seams only."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import test_client_managed_host as fixture
from team_browser.client import managed_host as host
from team_browser.client.app import create_local_app


class IndependentManagedHostTests(unittest.TestCase):
    setUp = fixture.ManagedHostTests.setUp
    cleanup_host = fixture.ManagedHostTests.cleanup_host
    wait = fixture.ManagedHostTests.wait
    status = fixture.ManagedHostTests.status
    prepared = fixture.ManagedHostTests.prepared
    started = fixture.ManagedHostTests.started
    available = fixture.ManagedHostTests.available

    def test_signout_during_profiles_skips_presets_and_drops_results(self):
        self.available()
        entered, release = self.f.block("profiles")
        self.host.refresh_records()
        self.assertTrue(entered.wait(2))
        result = self.host.sign_out().public()
        self.assertIsNone(result["membership"])
        self.assertEqual(result["profiles"], [])
        release.set()
        self.status(host.HostStatus.SIGNED_OUT)
        self.assertNotIn("presets", self.f.calls)
        self.assertEqual(self.f.delete_count, 1)

    def test_signout_during_presets_drops_all_staged_records(self):
        self.available()
        entered, release = self.f.block("presets")
        self.host.refresh_records()
        self.assertTrue(entered.wait(2))
        self.host.sign_out()
        release.set()
        result = self.status(host.HostStatus.SIGNED_OUT)
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["presets"], [])
        self.assertFalse(result["records_loaded"])
        self.assertEqual(self.f.delete_count, 1)

    def test_monotonic_expiry_during_profiles_prevents_later_read(self):
        self.available()
        entered, release = self.f.block("profiles")
        self.host.refresh_records()
        self.assertTrue(entered.wait(2))
        self.f.mono += 301
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)
        release.set()
        result = self.status(host.HostStatus.EXPIRED)
        self.assertNotIn("presets", self.f.calls)
        self.assertFalse(result["managed_access_available"])
        self.assertEqual(result["profiles"], [])

    def test_shutdown_during_final_observation_retains_vault_until_read_settles(self):
        self.available()
        entered, release = self.f.block("session_snapshot")
        self.host.refresh_records()
        self.assertTrue(entered.wait(2))
        result = self.host.shutdown().public()
        self.assertEqual(result["profiles"], [])
        self.assertFalse(result["managed_access_available"])
        self.assertFalse(self.host.wait_closed(0.02))
        self.assertEqual(self.f.close_count, 0)
        release.set()
        self.assertTrue(self.host.wait_closed(2))
        self.assertEqual(self.f.delete_count, 1)
        self.assertEqual(self.f.close_count, 1)

    def test_duplicate_refresh_cancel_and_prepare_cannot_queue_extra_reads(self):
        self.available()
        entered, release = self.f.block("profiles")
        self.host.refresh_records()
        self.assertTrue(entered.wait(2))
        for _ in range(10):
            self.host.refresh_records()
            self.host.prepare()
            self.host.sign_in()
            self.host.cancel_sign_in()
        release.set()
        result = self.status(host.HostStatus.AVAILABLE)
        self.assertTrue(result["records_loaded"])
        self.assertEqual(self.f.calls.count("profiles"), 1)
        self.assertEqual(self.f.calls.count("presets"), 1)
        self.assertEqual(len(self.f.coordinators), 1)

    def test_loopback_bridge_does_not_observe_or_act_for_remote_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_local_app(Path(directory), managed_host=self.host)
            with (
                patch.object(self.host, "snapshot") as snapshot,
                patch.object(self.host, "prepare") as prepare,
                TestClient(
                    app, base_url="http://127.0.0.1:8765", client=("198.51.100.1", 1234)
                ) as client,
            ):
                self.assertEqual(client.get("/local/v1/managed-native").status_code, 403)
                self.assertEqual(
                    client.post(
                        "/local/v1/managed-native/actions", json={"action": "prepare"}
                    ).status_code,
                    403,
                )
                snapshot.assert_not_called()
                prepare.assert_not_called()


POLL_RACE_SCRIPT = r"""
const assert = require('assert/strict'), fs = require('fs'), vm = require('vm');
const pending = [];
const container = {innerHTML: '', querySelectorAll: () => []};
const context = {
  window: {}, document: {getElementById: () => null}, AbortController, Date,
  setTimeout: () => 1, clearTimeout: () => {}
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const app = context.window.TeamManagedWorkspace.mount({
  request: () => new Promise((resolve, reject) => pending.push({resolve, reject})),
  container, esc: x => String(x), icon: () => '', notify: () => {}
});
const current = {
  status: 'available', configured: true, managed_access_available: true,
  expires_at: Math.floor(Date.now()/1000) + 300,
  membership: {member_id: 'member-a', tenant_id: 'org-a', display_name: 'Synthetic member', role: 'member'},
  profiles: [{id: 'p', name: 'PRIVATE SYNTHETIC PROFILE'}], presets: [],
  records_loaded: true, capabilities: {can_sign_out: true}
};
(async () => {
  app.activate('profiles'); pending.shift().resolve(current);
  await new Promise(resolve => setImmediate(resolve));
  const old = app.poll(), newer = app.poll();
  if (process.argv[2] === 'deny') {
    pending[1].resolve({...current, status: 'membership_denied', managed_access_available: false,
      membership: null, profiles: [], records_loaded: false});
  } else {
    pending[1].reject(new Error('synthetic status transport failure'));
  }
  await newer;
  assert(!container.innerHTML.includes('PRIVATE SYNTHETIC PROFILE'));
  pending[0].resolve(current); await old;
  assert(!container.innerHTML.includes('PRIVATE SYNTHETIC PROFILE'),
    'Older successful poll restored records after newer denial/error');
  app.deactivate();
})().catch(error => {console.error(error); process.exitCode = 1;});
"""


class IndependentManagedPresentationTests(unittest.TestCase):
    def run_poll_race(self, outcome):
        source = (
            Path(__file__).resolve().parents[1] / "src/team_browser/static/managed_workspace.js"
        )
        result = subprocess.run(
            ["node", "-e", POLL_RACE_SCRIPT, str(source), outcome],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_older_status_success_cannot_overwrite_newer_membership_denial(self):
        self.run_poll_race("deny")

    def test_older_status_success_cannot_overwrite_newer_transport_error(self):
        self.run_poll_race("error")


EXPIRY_SCRIPT = r"""
const assert = require('assert/strict'), fs = require('fs'), vm = require('vm');
let now = 1800000000000, serial = 0;
const pending = [], timers = new Map();
const container = {innerHTML: '', querySelectorAll: () => []};
const context = {
  window: {}, document: {getElementById: () => null}, AbortController,
  Date: {now: () => now},
  setTimeout: (fn, ms) => {timers.set(++serial, {fn, ms}); return serial;},
  clearTimeout: id => timers.delete(id)
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const app = context.window.TeamManagedWorkspace.mount({
  request: () => new Promise(resolve => pending.push(resolve)),
  container, esc: String, icon: () => '', notify: () => {}
});
(async () => {
  app.activate('profiles');
  pending.shift()({status: 'available', configured: true, managed_access_available: true,
    expires_at: 1800000003, membership: {member_id: 'm', tenant_id: 'o',
      display_name: 'PRIVATE SYNTHETIC IDENTITY', role: 'member'},
    profiles: [{id: 'p', name: 'PRIVATE SYNTHETIC RECORD'}], presets: [],
    records_loaded: true, capabilities: {}});
  await new Promise(setImmediate);
  assert(container.innerHTML.includes('PRIVATE SYNTHETIC RECORD'));
  now += 4000;
  const scheduled = [...timers.values()].filter(timer => timer.ms <= 4000);
  assert(scheduled.length > 0, 'An active managed UI needs scheduled status/expiry observation');
  for (const timer of scheduled) timer.fn();
  // Keep any new network observation pending. Local expiry must hide already
  // displayed records without waiting for that transport to finish or time out.
  assert(!container.innerHTML.includes('PRIVATE SYNTHETIC RECORD'),
    'Expired records remained visible while status transport stalled');
  assert(!container.innerHTML.includes('PRIVATE SYNTHETIC IDENTITY'));
  app.deactivate();
})().catch(error => {console.error(error); process.exitCode = 1;});
"""


class IndependentManagedExpiryPresentationTests(unittest.TestCase):
    def test_local_expiry_hides_displayed_identity_without_waiting_for_status_transport(self):
        source = (
            Path(__file__).resolve().parents[1] / "src/team_browser/static/managed_workspace.js"
        )
        result = subprocess.run(
            ["node", "-e", EXPIRY_SCRIPT, str(source)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
