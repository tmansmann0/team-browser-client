"""Synthetic page/context fixtures only; no browser import, install or execution."""

import asyncio
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from team_browser.client import LifecycleCoordinator, WorkspaceError, WorkspaceStore
from team_browser.client.camoufox_runtime import CamoufoxHandle
from team_browser.client.playwright_supervisor import PlaywrightHandle, PlaywrightSupervisor
from team_browser.client.tabs import MAX_TABS, MAX_TITLE, safe_title, web_origin


class Page:
    def __init__(self, url="https://example.test/", title="Synthetic tab", visible=False):
        self.url, self.label, self.visible = url, title, visible
        self.closed = False
        self.context = None
        self.focuses = 0
        self.focus_entered, self.focus_release = threading.Event(), threading.Event()
        self.title_entered, self.title_release = threading.Event(), threading.Event()
        self.delay_focus = self.delay_title = self.fail_title = False
        self.scripts = []

    def is_closed(self):
        return self.closed

    async def title(self):
        self.title_entered.set()
        if self.fail_title:
            raise RuntimeError("DO NOT RETURN: synthetic secret failure")
        while self.delay_title and not self.title_release.is_set():
            await asyncio.sleep(0.002)
        return self.label

    async def evaluate(self, script):
        self.scripts.append(script)
        assert script == "document.visibilityState === 'visible'"
        return self.visible

    async def bring_to_front(self):
        self.focus_entered.set()
        while self.delay_focus and not self.focus_release.is_set():
            await asyncio.sleep(0.002)
        self.focuses += 1
        if self.context is not None:
            for page in self.context.pages:
                page.visible = page is self
            self.context.log.append(self)

    async def goto(self, *_args, **_kwargs):
        raise AssertionError("Tab controls cannot navigate")


class Context:
    def __init__(self, pages, log):
        self.pages, self.log, self.closed, self.callbacks = pages, log, False, {}
        for page in pages:
            page.context = self

    def is_closed(self):
        return self.closed

    def on(self, name, callback):
        self.callbacks[name] = callback

    async def new_page(self):
        raise AssertionError("Tab controls cannot create pages")

    async def close(self):
        self.closed = True
        for page in self.pages:
            page.closed = True
            page.focus_release.set()
            page.title_release.set()
        if "close" in self.callbacks:
            self.callbacks["close"]()


class SyntheticOwnedAdapter:
    execution_kind = "synthetic"

    def __init__(self, handle_type):
        self.handle_type = handle_type
        self.owner = PlaywrightSupervisor(factory=lambda: None, operation_timeout=1)
        self.next_pages = []
        self.handles = {}
        self.log = []

    def blockers(self, profile):
        return ()

    def start(self, launch):
        self.owner._ensure_loop()
        handle = self.handle_type(self.owner, launch)
        self.owner._handles.append(handle)
        handle.context = Context(self.next_pages, self.log)
        handle.context.on("close", handle._on_close)
        handle.page = self.next_pages[0] if self.next_pages else None
        handle._set_phase("ready")
        self.handles[launch.profile_id] = handle
        return handle

    def shutdown(self):
        self.owner.shutdown()


class TabContracts:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.temp.name) / "workspace")
        self.adapter = SyntheticOwnedAdapter(self.handle_type)
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)

    def tearDown(self):
        # Release every synthetic delayed IPC before disposing the test workspace.
        for handle in self.adapter.handles.values():
            for page in handle.context.pages:
                page.focus_release.set()
                page.title_release.set()
            # Unknown-process tests restore fixture evidence only for cleanup.
            handle.ownership_uncertain = False
            if handle.context.closed:
                handle._set_phase("stopped")
            elif handle.phase == "unknown":
                handle._set_phase("ready")
        self.coordinator.shutdown()
        for handle in self.adapter.handles.values():
            if handle.stop_future:
                handle.stop_future.result(timeout=3)
        self.coordinator.refresh()
        self.store.close()
        self.temp.cleanup()

    def start(self, *pages):
        profile_id = self.store.create("Synthetic native profile")["id"]
        self.adapter.next_pages = list(pages)
        self.coordinator.action(profile_id, "start")
        return profile_id, self.adapter.handles[profile_id]

    def wait_focus(self, expected="focused"):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = self.coordinator._focus_pump.snapshot()
            if result["status"] not in {"pending", "queued"}:
                self.assertEqual(result["status"], expected)
                return result
            time.sleep(0.002)
        self.fail("Synthetic focus did not finish")

    def enable_mirror(self, enabled=True):
        settings = self.store.metadata("settings")
        self.coordinator.update_settings(settings["revision"], mirror_same_origin=enabled)

    def test_ids_stable_bounded_metadata_and_no_url_components(self):
        page = Page("https://EXAMPLE.test:443/private-user?token=SENSITIVE#secret", "Title\n\u202e")
        _, handle = self.start(page, Page("about:blank"))
        first = self.coordinator.selected_tabs()
        second = self.coordinator.selected_tabs()
        self.assertEqual(first["status"], "ready")
        self.assertEqual(first["tabs"], second["tabs"])
        self.assertEqual(first["tabs"][0]["origin"], "https://example.test")
        self.assertEqual(first["tabs"][0]["title"], "Title")
        self.assertIsNone(first["tabs"][1]["origin"])
        serialized = json.dumps(first)
        for secret in ("private-user", "SENSITIVE", "secret", "token", "cookies", "favicon"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(len(handle.tabs.pages), 2)

    def test_focus_only_current_existing_tab_and_stable_id_after_selection(self):
        one, two = Page(visible=True), Page("https://other.test/path")
        profile, handle = self.start(one, two)
        tab_id = self.coordinator.selected_tabs()["tabs"][1]["id"]
        result = self.coordinator.focus_tab(profile, tab_id, generation=1)
        self.assertEqual(result["outcome"], "queued")
        self.wait_focus()
        self.assertIs(handle.page, two)
        self.assertEqual(one.focuses, 0)
        self.assertEqual(two.focuses, 1)
        self.assertEqual(self.coordinator.selected_tabs()["active_tab_id"], tab_id)

    def test_closed_and_detached_tabs_are_rejected(self):
        for detached in (False, True):
            with self.subTest(detached=detached):
                first, second = Page(), Page()
                profile, handle = self.start(first, second)
                tab_id = self.coordinator.selected_tabs()["tabs"][1]["id"]
                if detached:
                    handle.context.pages.remove(second)
                else:
                    second.closed = True
                self.coordinator.focus_tab(profile, tab_id, generation=1)
                self.wait_focus("stale_tab")
                self.assertEqual(second.focuses, 0)
                self.assertNotIn(tab_id, handle.tabs.pages)

    def test_empty_context_never_creates_tab(self):
        profile, _ = self.start()
        self.coordinator.action(profile, "start")
        self.wait_focus("empty")
        self.assertEqual(self.coordinator.selected_tabs()["tabs"], [])

    def test_repeated_profile_selection_never_focuses_or_mirrors_native_windows(self):
        source_page = Page("https://service.test", visible=True)
        source, source_handle = self.start(source_page)
        fallback, match = Page("https://fallback.test", visible=True), Page("https://service.test")
        target, target_handle = self.start(fallback, match)
        self.enable_mirror()
        for _ in range(10):
            for profile_id in (source, source, target, target):
                self.coordinator.action(profile_id, "select")
        self.wait_focus("idle")
        self.assertEqual(len(self.adapter.owner._handles), 2)
        self.assertEqual(self.adapter.log, [])
        self.assertTrue(all(page.focuses == 0 for page in (source_page, fallback, match)))
        self.assertTrue(all(page.scripts == [] for page in (source_page, fallback, match)))
        self.assertIs(source_handle.page, source_page)
        self.assertIs(target_handle.page, fallback)
        self.assertEqual(self.store.selected(), target)

    def test_selection_cancels_focus_before_native_admission(self):
        source_page, target_page = Page(), Page("https://other.test")
        source, _ = self.start(source_page)
        target, handle = self.start(target_page)
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()
        original_focus = handle.tabs._focus
        original_focus_tabs = handle.focus_tabs

        async def pending_admission(*args, **kwargs):
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.002)
            return await original_focus(*args, **kwargs)

        def observe_completion(*args, **kwargs):
            try:
                return original_focus_tabs(*args, **kwargs)
            finally:
                completed.set()

        handle.tabs._focus = pending_admission
        handle.focus_tabs = observe_completion
        self.coordinator.action(target, "start")
        try:
            self.assertTrue(entered.wait(1))
            # A newer re-selection alone invalidates the old focus intent.
            self.coordinator.action(target, "select")
            for _ in range(5):
                self.coordinator.action(source, "select")
                self.coordinator.action(target, "select")
        finally:
            release.set()
        self.assertTrue(completed.wait(2))
        self.wait_focus("idle")
        self.assertEqual(self.adapter.log, [])
        self.assertEqual(source_page.focuses, 0)
        self.assertEqual(target_page.focuses, 0)
        self.assertEqual(len(self.adapter.owner._handles), 2)
        self.assertEqual(self.store.selected(), target)

    def test_unknown_ownership_retains_lease_and_invalidates_tabs(self):
        profile, handle = self.start(Page())
        self.coordinator.selected_tabs()
        handle._on_close()
        result = self.coordinator.selected_tabs()
        self.assertEqual(result["status"], "not_ready")
        self.assertEqual(handle.tabs.pages, {})
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertTrue(self.coordinator._running[profile].lease.active)
        self.assertFalse(handle.stop())

    def test_missing_lease_wrong_pid_and_replaced_context_invalidate(self):
        _, handle = self.start(Page())
        first = self.coordinator.selected_tabs()["tabs"][0]["id"]
        handle.tabs.pid = -1
        self.assertEqual(self.coordinator.selected_tabs()["status"], "not_ready")
        self.assertEqual(handle.tabs.pages, {})
        import os

        handle.tabs.pid = os.getpid()
        second = self.coordinator.selected_tabs()["tabs"][0]["id"]
        self.assertNotEqual(first, second)
        handle.context = Context([Page()], self.adapter.log)
        self.assertEqual(self.coordinator.selected_tabs()["status"], "not_ready")
        self.assertTrue(handle.ownership_uncertain)
        self.assertEqual(handle.tabs.pages, {})
        handle.launch_context.lease.release()
        self.assertEqual(self.coordinator.selected_tabs()["status"], "not_ready")

    def test_mirror_disabled_by_default_and_exact_unique_match_when_enabled(self):
        source, _ = self.start(Page("https://service.test/account-a", visible=True))
        fallback, match = (
            Page("https://different.test/", visible=True),
            Page("https://service.test:443/b"),
        )
        target, target_handle = self.start(fallback, match)
        self.coordinator.action(source, "start")
        self.wait_focus()
        self.coordinator.action(target, "start")
        self.wait_focus()
        self.assertIs(target_handle.page, fallback)
        self.enable_mirror()
        self.coordinator.action(source, "start")
        self.wait_focus()
        self.coordinator.action(target, "start")
        self.wait_focus()
        self.assertIs(target_handle.page, match)

    def test_duplicate_no_match_http_subdomain_and_port_never_mirror(self):
        source, _ = self.start(Page("https://service.test/", visible=True))
        cases = (
            [Page("https://service.test/a"), Page("https://service.test/b")],
            [Page("http://service.test/")],
            [Page("https://sub.service.test/")],
            [Page("https://service.test:444/")],
        )
        self.enable_mirror()
        for alternatives in cases:
            with self.subTest(urls=[p.url for p in alternatives]):
                # Keep two contexts resident in this fixture; never native-evict.
                if len(self.coordinator._running) > 1:
                    previous = next(p for p in self.coordinator._running if p != source)
                    self.coordinator.action(previous, "stop")
                    future = self.adapter.handles[previous].stop_future
                    future.result(timeout=2)
                    self.coordinator.refresh()
                fallback = Page("https://fallback.test", visible=True)
                target, handle = self.start(fallback, *alternatives)
                self.coordinator.action(source, "start")
                self.wait_focus()
                self.coordinator.action(target, "start")
                self.wait_focus()
                self.assertIs(handle.page, fallback)
                self.assertTrue(all(p.focuses == 0 for p in alternatives))

    def test_manual_tab_change_uses_fresh_visibility_not_last_manager_tab(self):
        stale = Page("https://old.test", visible=True)
        current = Page("https://current.test")
        source, source_handle = self.start(stale, current)
        fallback, old_match, new_match = (
            Page("https://fallback.test"),
            Page("https://old.test"),
            Page("https://current.test"),
        )
        target, target_handle = self.start(fallback, old_match, new_match)
        self.enable_mirror()
        self.coordinator.action(source, "start")
        self.wait_focus()
        stale.visible, current.visible = False, True
        self.assertIs(source_handle.page, stale)
        self.coordinator.action(target, "start")
        self.wait_focus()
        self.assertIs(target_handle.page, new_match)
        self.assertEqual(old_match.focuses, 0)

    def test_ambiguous_visibility_and_nonweb_source_do_not_mirror(self):
        first, other = (
            Page("https://service.test", visible=True),
            Page("https://other.test", visible=True),
        )
        source, _ = self.start(first, other)
        fallback, match = Page("https://fallback.test"), Page("https://service.test")
        target, handle = self.start(fallback, match)
        self.enable_mirror()
        for nonweb in (False, True):
            self.coordinator.action(source, "start")
            self.wait_focus()
            if nonweb:
                first.url, other.visible = "about:blank", False
            else:
                first.visible = other.visible = True
            self.coordinator.action(target, "start")
            self.wait_focus()
            self.assertIs(handle.page, fallback)
            self.assertEqual(match.focuses, 0)

    def test_latest_explicit_open_intent_follows_delayed_native_focus(self):
        delayed = Page()
        source, _ = self.start(delayed)
        final_page = Page("https://final.test")
        target, _ = self.start(final_page)
        delayed.delay_focus = True
        self.coordinator.action(source, "start")
        self.assertTrue(delayed.focus_entered.wait(1))
        before = time.monotonic()
        for _ in range(10):
            self.coordinator.action(source, "start")
            self.coordinator.action(target, "start")
        self.assertLess(time.monotonic() - before, 0.3)
        delayed.focus_release.set()
        self.wait_focus()
        self.assertIs(self.adapter.log[-1], final_page)
        self.assertEqual(self.store.selected(), target)
        self.assertEqual(delayed.focuses, 1)

    def test_latest_tab_intent_and_generation_fence(self):
        one, two = Page(), Page("https://second.test")
        profile, handle = self.start(one, two)
        tabs = self.coordinator.selected_tabs()["tabs"]
        one.delay_focus = True
        self.coordinator.focus_tab(profile, tabs[0]["id"], generation=1)
        self.assertTrue(one.focus_entered.wait(1))
        self.coordinator.focus_tab(profile, tabs[1]["id"], generation=1)
        one.focus_release.set()
        self.wait_focus()
        self.assertIs(self.adapter.log[-1], two)
        self.assertIs(handle.page, two)
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.focus_tab(profile, tabs[0]["id"], generation=2)
        self.assertEqual(caught.exception.code, "stale_context")

    def test_settings_off_while_source_metadata_pending_prevents_mirror(self):
        source_page = Page("https://service.test", visible=True)
        source, _ = self.start(source_page)
        fallback, match = Page("https://fallback.test"), Page("https://service.test")
        target, handle = self.start(fallback, match)
        self.enable_mirror()
        self.coordinator.action(source, "start")
        self.wait_focus()
        source_page.delay_title = True
        self.coordinator.action(target, "start")
        self.assertTrue(source_page.title_entered.wait(1))
        self.enable_mirror(False)
        source_page.title_release.set()
        self.wait_focus()
        self.assertIs(handle.page, fallback)
        self.assertEqual(match.focuses, 0)

    def test_metadata_failure_returns_typed_empty_result(self):
        page = Page()
        page.fail_title = True
        self.start(page)
        result = self.coordinator.selected_tabs()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["tabs"], [])
        self.assertNotIn("secret failure", json.dumps(result))

    def test_size_bounds_disable_unique_match_in_incomplete_snapshot(self):
        pages = [
            Page(f"https://site{i}.test", "x" * 1000, visible=i == 0) for i in range(MAX_TABS + 1)
        ]
        _, handle = self.start(*pages)
        result = self.coordinator.selected_tabs()
        self.assertEqual(result["status"], "limited")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["tabs"]), MAX_TABS)
        self.assertIsNone(result["active_tab_id"])
        self.assertTrue(all(len(tab["title"]) <= MAX_TITLE for tab in result["tabs"]))
        self.assertEqual(len(handle.tabs.pages), MAX_TABS)

    def test_profile_change_during_snapshot_returns_no_stale_tabs(self):
        delayed = Page()
        source, _ = self.start(delayed)
        target, _ = self.start(Page())
        self.coordinator.action(source, "select")
        self.wait_focus("idle")
        delayed.delay_title = True
        results = []
        thread = threading.Thread(target=lambda: results.append(self.coordinator.selected_tabs()))
        thread.start()
        self.assertTrue(delayed.title_entered.wait(1))
        self.coordinator.action(target, "select")
        delayed.title_release.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["status"], "superseded")
        self.assertEqual(results[0]["tabs"], [])
        self.wait_focus("idle")

    def test_concurrent_snapshot_is_bounded_and_timeout_is_honest(self):
        from unittest.mock import patch

        page = Page()
        page.delay_title = True
        _, handle = self.start(page)
        results = []
        with patch("team_browser.client.tabs.SNAPSHOT_TIMEOUT", 0.08):
            thread = threading.Thread(
                target=lambda: results.append(self.coordinator.selected_tabs())
            )
            thread.start()
            self.assertTrue(page.title_entered.wait(1))
            busy = self.coordinator.selected_tabs()
            self.assertEqual(busy["status"], "busy")
            self.assertEqual(busy["tabs"], [])
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["status"], "unavailable")
        self.assertEqual(results[0]["tabs"], [])
        self.assertEqual(len(handle.tabs.pages), 1)
        page.title_release.set()
        self.assertEqual(self.coordinator.selected_tabs()["status"], "ready")

    def test_closed_context_without_callback_is_unknown_not_stopped(self):
        profile, handle = self.start(Page())
        self.coordinator.selected_tabs()
        handle.context.closed = True
        result = self.coordinator.selected_tabs()
        self.assertEqual(result["status"], "not_ready")
        self.assertEqual(handle.tabs.pages, {})
        self.assertTrue(handle.ownership_uncertain)
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertTrue(self.coordinator._running[profile].lease.active)

    def test_generation_change_during_native_read_discards_result(self):
        page = Page()
        page.delay_title = True
        profile, _ = self.start(page)
        results = []
        thread = threading.Thread(target=lambda: results.append(self.coordinator.selected_tabs()))
        thread.start()
        self.assertTrue(page.title_entered.wait(1))
        with self.store.lock:
            self.store._change(profile, generation=2)
        page.title_release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["status"], "superseded")
        self.assertEqual(results[0]["tabs"], [])
        self.assertTrue(self.coordinator._running[profile].lease.active)

    def test_unknown_id_is_typed_and_malformed_input_rejected(self):
        profile, _ = self.start(Page())
        self.coordinator.focus_tab(profile, "tab_" + "0" * 32, generation=1)
        self.wait_focus("stale_tab")
        for tab_id, generation in (("https://other.test", 1), ("tab_" + "0" * 32, True)):
            with self.assertRaises(WorkspaceError):
                self.coordinator.focus_tab(profile, tab_id, generation=generation)

    def test_layout_only_settings_do_not_trim_or_stop(self):
        _, handle = self.start(Page())
        self.coordinator._trim = lambda *a, **kw: self.fail("Layout edit cannot trim profiles")
        settings = self.store.metadata("settings")
        updated = self.coordinator.update_settings(
            settings["revision"],
            profile_navigation="grid",
            tab_navigation="side",
            mirror_same_origin=True,
        )
        self.assertEqual(updated["profile_navigation"], "grid")
        self.assertIsNone(handle.stop_future)
        for value in (1, "true", None):
            with self.assertRaises(ValueError):
                self.coordinator.update_settings(updated["revision"], mirror_same_origin=value)


class ChromiumTabTests(TabContracts, unittest.TestCase):
    handle_type = PlaywrightHandle


class CamoufoxTabTests(TabContracts, unittest.TestCase):
    handle_type = CamoufoxHandle


class TabMetadataTests(unittest.TestCase):
    def test_exact_origin_canonicalization(self):
        for url, origin in (
            ("https://EXAMPLE.test:443/path?secret#fragment", "https://example.test"),
            ("https://example.test:8443/a", "https://example.test:8443"),
            ("https://[2001:db8::1]:443/a", "https://[2001:db8::1]"),
            ("https://xn--bcher-kva.test/", "https://xn--bcher-kva.test"),
        ):
            self.assertEqual(web_origin(url), origin)
        for url in (
            "http://example.test",
            "about:blank",
            "file:///private/path",
            "data:text/plain,secret",
            "https://user:password@example.test",
            "https://@example.test",
            "https://faß.test",
            "https://example.test:0",
            "https://example.test:99999",
            "https://example.test\\evil",
            "https://example.test\n.evil",
            "https://[::1%25scope]",
            "https://",
        ):
            self.assertIsNone(web_origin(url))

    def test_titles_strip_controls_and_url_components(self):
        title = safe_title("\u202esee https://example.test/private?token=PRIVATE#secret\x00\nnow")
        self.assertEqual(title, "see https://example.test now")
        self.assertEqual(safe_title(None), "Untitled tab")
        self.assertLessEqual(len(safe_title("x" * 10000)), MAX_TITLE)
