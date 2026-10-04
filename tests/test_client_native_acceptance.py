"""Opt-in native macOS acceptance harness. NEVER runs in the default suite.

Requires all three: actual macOS, TBM_NATIVE_ACCEPTANCE=1, and a reviewed private
TBM_RUNTIME_POLICY path. It uses a fresh app-owned workspace and an in-process
loopback fixture only. No Gmail, credentials, browser downloads or paid CI jobs.
Run only after the operator approves the target Mac/runtime test scope.
"""

import asyncio
import http.server
import os
import sys
import tempfile
import shutil
import threading
import time
import unittest
from pathlib import Path

from team_browser.client import LifecycleCoordinator, WorkspaceStore
from team_browser.client.installed_browser import load_installed_adapter


_ENABLED = (
    sys.platform == "darwin"
    and os.environ.get("TBM_NATIVE_ACCEPTANCE") == "1"
    and bool(os.environ.get("TBM_RUNTIME_POLICY"))
)


class FixturePage(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<!doctype html><title>Team Browser synthetic native acceptance</title><p>Local synthetic fixture</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipUnless(
    _ENABLED, "Native acceptance is opt-in on an approved Mac with reviewed runtime policy"
)
class NativeInstalledAcceptance(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="tbm-native-acceptance-")).resolve()
        self.addCleanup(self.cleanup_owned_fixture)
        self.store = WorkspaceStore(self.root / "owned-workspace")
        self.addCleanup(self.store.close)
        self.adapter = load_installed_adapter(
            Path(os.environ["TBM_RUNTIME_POLICY"]), self.store.profiles
        )
        blockers = self.adapter.global_blockers()
        self.assertFalse(blockers, blockers)
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.addCleanup(self.coordinator.shutdown)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixturePage)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/fixture"

    def cleanup_owned_fixture(self):
        coordinator = getattr(self, "coordinator", None)
        if coordinator is not None and coordinator._running:
            print(
                f"Native lifetime is uncertain; retain the synthetic workspace for approved inspection: {self.root}"
            )
            return
        shutil.rmtree(self.root)

    def await_state(self, profile_id, target):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            self.coordinator.refresh()
            profile = self.store.get(profile_id)
            if profile["state"] == target:
                return
            if profile["state"] in {"error", "recovery_required", "blocked"}:
                self.fail(f"Native state {profile['state']}: {profile['blockers']}")
            time.sleep(0.05)
        self.fail(f"Native profile did not reach {target}")

    def native_handle(self, profile_id):
        return self.coordinator._running[profile_id].handle

    def test_profile_isolation_persistence_focus_and_acknowledged_close(self):
        first = self.store.create("Synthetic A", network_policy="local_direct")["id"]
        second = self.store.create("Synthetic B", network_policy="local_direct")["id"]
        self.coordinator.action(first, "start")
        self.await_state(first, "running")
        first_handle = self.native_handle(first)
        self.coordinator.action(second, "start")
        self.await_state(second, "running")
        second_handle = self.native_handle(second)

        async def write_fixture(handle):
            await handle.page.goto(self.url)
            await handle.page.evaluate("localStorage.setItem('tbm_native_fixture', 'synthetic-A')")
            await handle.page.evaluate("document.cookie='tbm_fixture=synthetic-A; path=/'")

        async def read_fixture(handle):
            await handle.page.goto(self.url)
            return await handle.page.evaluate(
                "({local:localStorage.getItem('tbm_native_fixture'),cookie:document.cookie})"
            )

        self.adapter.supervisor.call(write_fixture(first_handle))
        second_data = self.adapter.supervisor.call(read_fixture(second_handle))
        self.assertIsNone(second_data["local"])
        self.assertNotIn("synthetic-A", second_data["cookie"])
        selected = self.coordinator.action(first, "select")
        self.assertEqual(selected["profile"]["state"], "running")
        self.assertIs(self.native_handle(first), first_handle)
        self.coordinator.action(first, "stop")
        self.await_state(first, "stopped")
        self.coordinator.action(first, "start")
        self.await_state(first, "running")
        saved = self.adapter.supervisor.call(read_fixture(self.native_handle(first)))
        self.assertEqual(saved["local"], "synthetic-A")
        self.assertIn("tbm_fixture=synthetic-A", saved["cookie"])
        for profile_id in (first, second):
            self.coordinator.action(profile_id, "stop")
            self.await_state(profile_id, "stopped")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 0)

    def test_early_cancel_does_not_resurrect_native_profile(self):
        profile_id = self.store.create("Synthetic cancel", network_policy="local_direct")["id"]
        self.coordinator.action(profile_id, "start")
        self.coordinator.action(profile_id, "cancel")
        self.await_state(profile_id, "stopped")
        # Give the native loop an opportunity to deliver any late ready event.
        self.adapter.supervisor.call(asyncio.sleep(0.25))
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile_id)["state"], "stopped")
