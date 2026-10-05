"""Actual rendered browser tests for CI/a permitted local runtime.

These do not run during ordinary unit discovery. They are intentionally gated
and require an installed official Chrome with sandbox enabled plus Playwright's
FFmpeg for video capture. CI uses the Ubuntu runner's existing Chrome install.
Only generated local workspace data is used; external navigation is blocked.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit
from urllib.request import urlopen


@unittest.skipUnless(
    os.getenv("TBM_RUN_BROWSER_TESTS") == "1",
    "Rendered browser tests require an explicitly enabled supported runtime",
)
class LocalBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        cls.root = Path(__file__).resolve().parents[1]
        cls.workspace = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.port = 8876
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.server = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from team_browser.client_cli import main; main()",
                "--workspace",
                str(Path(cls.workspace.name) / "workspace"),
                "--port",
                str(cls.port),
            ],
            cwd=cls.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        cls.addClassCleanup(cls.stop_server)
        for _ in range(100):
            try:
                with urlopen(cls.url + "/healthz", timeout=0.5) as response:
                    if response.status == 200:
                        break
            except OSError:
                if cls.server.poll() is not None:
                    raise RuntimeError("Local workspace server exited before browser tests")
                time.sleep(0.1)
        else:
            cls.server.terminate()
            raise RuntimeError("Local workspace server was not reachable")
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        # Never relax the sandbox to make this test pass. An unavailable sandbox
        # is a runtime blocker, not permission to change OS/browser security.
        cls.browser = cls.playwright.chromium.launch(
            headless=True, channel="chrome", chromium_sandbox=True
        )
        cls.addClassCleanup(cls.browser.close)
        cls.artifacts = cls.root / "artifacts/browser"
        cls.artifacts.mkdir(parents=True, exist_ok=True)

    @classmethod
    def stop_server(cls):
        if hasattr(cls, "server"):
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)

    def setUp(self):
        self.context = self.browser.new_context(
            viewport={"width": 1440, "height": 960},
            record_video_dir=str(self.artifacts / "raw-video"),
            record_video_size={"width": 1440, "height": 960},
        )
        self.context.route(
            "**/*",
            lambda route: (
                route.continue_()
                if urlsplit(route.request.url).scheme + "://" + urlsplit(route.request.url).netloc
                == self.url
                else route.abort()
            ),
        )
        self.page = self.context.new_page()
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.goto(self.url + "/preview/")
        self.page.locator("#choose-local").click()
        self.page.locator("#new-profile").wait_for(state="visible")

    def tearDown(self):
        try:
            if getattr(self, "shortcut_diagnostics", False):
                self.write_shortcut_diagnostics()
            self.page.screenshot(
                path=str(self.artifacts / (self._testMethodName + ".png")), full_page=True
            )
        finally:
            self.context.close()
        self.assertEqual(self.errors, [])

    def write_shortcut_diagnostics(self):
        try:
            evidence = self.page.evaluate("""() => {
                window.__tbmShortcutDiagnostics.record('teardown');
                return window.__tbmShortcutDiagnostics.read();
            }""")
            encoded = json.dumps(evidence, separators=(",", ":"))
            # Retain the latest key/focus evidence if the byte bound is reached.
            events = evidence.get("events") if isinstance(evidence, dict) else None
            while isinstance(events, list) and events and len(encoded.encode("utf-8")) >= 65536:
                events.pop(0)
                evidence["sizeTruncated"] = True
                encoded = json.dumps(evidence, separators=(",", ":"))
            if len(encoded.encode("utf-8")) >= 65536:
                encoded = '{"diagnostic_error":"size_limit"}'
        except Exception as error:
            # Diagnostic capture must not mask the original test failure or
            # expose arbitrary browser exceptions, page text, or token values.
            encoded = json.dumps({"diagnostic_error": type(error).__name__})
        try:
            (self.artifacts / "tablet-shortcut-diagnostics.json").write_text(encoded + "\n")
        except OSError as error:
            print("Shortcut diagnostic write failed:", type(error).__name__)

    def create_profile(self, name):
        self.page.locator("#new-profile").click()
        self.page.get_by_label("Profile name", exact=True).fill(name)
        # close() hides a dialog before its queued close event restores focus.
        # Register after the app's handlers and wait for that event to finish.
        self.page.locator("#detail-dialog").evaluate("""dialog => {
            dialog.__tbmCreateCloseComplete = false;
            dialog.addEventListener('close', () => {
                dialog.__tbmCreateCloseComplete = true;
            }, {once: true});
        }""")
        self.page.locator("#save-local-profile").click()
        self.page.locator(".profile-rail-item").filter(
            has=self.page.get_by_text(name, exact=True)
        ).wait_for()
        self.page.wait_for_function(
            "() => document.getElementById('detail-dialog').__tbmCreateCloseComplete === true",
            timeout=5000,
        )

    def test_create_cancel_refresh_and_keyboard_switch(self):
        self.create_profile("Synthetic Alpha")
        self.create_profile("Synthetic Beta")
        self.page.keyboard.press("Control+k")
        self.page.locator("#switcher-search").fill("Synthetic Alpha")
        self.page.keyboard.press("Enter")
        self.page.locator(".profile-heading").get_by_text("Synthetic Alpha", exact=True).wait_for()
        self.page.reload()
        self.page.locator(".profile-heading").get_by_text("Synthetic Alpha", exact=True).wait_for()
        self.page.locator("#new-profile").click()
        self.page.get_by_label("Profile name", exact=True).fill("Canceled Synthetic")
        self.page.locator("#cancel-profile-edit").click()
        self.assertEqual(
            self.page.get_by_role("button", name="Canceled Synthetic", exact=True).count(), 0
        )
        self.page.keyboard.press("Control+k")
        self.page.keyboard.press("Escape")
        self.assertFalse(self.page.locator("#switcher-dialog").is_visible())

    def test_tablet_resource_navigation_and_switcher(self):
        self.page.set_viewport_size({"width": 768, "height": 1024})
        self.page.evaluate(Path(__file__).with_name("shortcut_diagnostics.js").read_text())
        self.shortcut_diagnostics = True
        self.create_profile("Synthetic Tablet")
        self.page.locator("#detail-dialog").wait_for(state="hidden")
        # Saving restores focus to profile search after the opener is rendered
        # again. Navigation shortcuts deliberately do not run in editing fields.
        profile_url = self.page.url
        self.page.locator("#local-search").press("Alt+3")
        self.assertEqual(self.page.url, profile_url)
        self.assertFalse(self.page.locator("#resource-form").is_visible())
        # Target a non-editable control without clicking or opening its dialog.
        self.page.locator("#quick-switch-button").press("Alt+3")
        self.page.locator("#resource-form").wait_for(state="visible")
        self.assertEqual(urlsplit(self.page.url).fragment, "resources")
        self.page.keyboard.press("Control+k")
        self.page.locator("#switcher-search").fill("Synthetic Tablet")
        self.page.keyboard.press("Escape")
        self.assertFalse(self.page.locator("#switcher-dialog").is_visible())
        width = self.page.evaluate(
            "({content:document.documentElement.scrollWidth,viewport:innerWidth})"
        )
        self.assertLessEqual(width["content"], width["viewport"] + 1)
        self.page.screenshot(path=str(self.artifacts / "tablet-resources.png"), full_page=True)

    def test_mobile_layout_and_honest_engine_blocker(self):
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.create_profile("Synthetic Mobile")
        self.page.locator(".profile-rail-item").filter(
            has=self.page.get_by_text("Synthetic Mobile", exact=True)
        ).locator("[data-select]").click()
        self.assertFalse(self.page.locator("#detail-open-browser").is_enabled())
        self.page.locator(".launch-reason").wait_for(state="visible")
        width = self.page.evaluate(
            "({content:document.documentElement.scrollWidth,viewport:innerWidth})"
        )
        self.assertLessEqual(width["content"], width["viewport"] + 1)
        self.page.screenshot(
            path=str(self.artifacts / "mobile-profile-workspace.png"), full_page=True
        )


if __name__ == "__main__":
    unittest.main()
