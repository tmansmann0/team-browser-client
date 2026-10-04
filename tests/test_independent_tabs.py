"""Independent synthetic-only tab admission, race, and privacy review."""

import asyncio
import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from team_browser.client import LifecycleCoordinator, WorkspaceError, WorkspaceStore
from team_browser.client.camoufox_runtime import CamoufoxHandle
from team_browser.client.lifecycle import LaunchContext
from team_browser.client.playwright_supervisor import PlaywrightHandle, PlaywrightSupervisor
from team_browser.client.tabs import MAX_TABS, LatestFocusPump, OwnedTabs


class ReviewPage:
    def __init__(self, origin="https://review.test", *, visible=False):
        self.url = origin + "/private-path?token=SYNTHETIC_QUERY#fragment"
        self.label = "Review tab"
        self.visible = visible
        self.closed = False
        self.calls = []
        self.on_title = None
        self.on_focus = None
        self.context = None

    def is_closed(self):
        return self.closed

    async def title(self):
        if self.on_title:
            await self.on_title()
        return self.label

    async def evaluate(self, script):
        if script != "document.visibilityState === 'visible'":
            raise AssertionError("Unexpected metadata script")
        self.calls.append("visibility")
        return self.visible

    async def bring_to_front(self):
        self.calls.append("focus")
        if self.on_focus:
            await self.on_focus()

    async def goto(self, *args, **kwargs):
        raise AssertionError("Tab selection must not navigate")


class ReviewContext:
    def __init__(self, pages):
        self.pages, self.closed, self.callbacks = list(pages), False, {}
        for page in self.pages:
            page.context = self

    def is_closed(self):
        return self.closed

    def on(self, event, callback):
        self.callbacks[event] = callback

    async def new_page(self):
        raise AssertionError("Tab selection must not create pages")

    async def close(self):
        self.closed = True
        if "close" in self.callbacks:
            self.callbacks["close"]()


class ReviewOwner:
    def __init__(self):
        self.lock = asyncio.Lock()

    def native_focus_lock(self):
        return self.lock


def isolated_handle(pages, kind=PlaywrightHandle):
    paths = SimpleNamespace(profile_id="review-profile", browser_data=Path("/synthetic/data"))
    lease = SimpleNamespace(active=True, token="synthetic-token", paths=paths)
    launch = LaunchContext("review-profile", "synthetic", paths.browser_data, 1, lease=lease)
    handle = kind(ReviewOwner(), launch)
    handle.context = ReviewContext(pages)
    handle.page = pages[0] if pages else None
    handle._set_phase("ready")
    return handle


class IndependentTabRegistryTests(unittest.IsolatedAsyncioTestCase):
    async def test_growth_past_bound_during_metadata_is_not_complete(self):
        pages = [ReviewPage(visible=i == 0) for i in range(MAX_TABS)]
        handle = isolated_handle(pages)
        added = False

        async def append_visible_window():
            nonlocal added
            if not added:
                added = True
                handle.context.pages.append(ReviewPage("https://second-window.test", visible=True))

        pages[0].on_title = append_visible_window
        result = await handle.tabs.snapshot(lambda: True)
        self.assertIn(result.status, {"changed", "limited", "unavailable"})
        self.assertIsNone(result.active_tab_id)
        self.assertFalse(any(tab.active for tab in result.tabs))

    async def test_detach_and_replace_during_metadata_discards_all_entries(self):
        page = ReviewPage(visible=True)
        handle = isolated_handle([page])

        async def replace_page():
            handle.context.pages[:] = [ReviewPage("https://replacement.test")]

        page.on_title = replace_page
        result = await handle.tabs.snapshot(lambda: True)
        self.assertEqual(result.status, "changed")
        self.assertEqual(result.tabs, ())

    async def test_new_registry_same_page_never_accepts_prior_opaque_id(self):
        for kind in (PlaywrightHandle, CamoufoxHandle):
            with self.subTest(kind=kind.__name__):
                page = ReviewPage()
                handle = isolated_handle([page], kind)
                old = (await handle.tabs.snapshot(lambda: True)).tabs[0].id
                handle.tabs = OwnedTabs(handle)
                new = (await handle.tabs.snapshot(lambda: True)).tabs[0].id
                self.assertNotEqual(old, new)
                self.assertEqual(await handle.tabs.focus(lambda: True, tab_id=old), "stale_tab")
                self.assertNotIn("focus", page.calls)

    async def test_exact_launch_and_lease_token_are_rechecked_after_metadata(self):
        for mutation in ("lease", "launch"):
            with self.subTest(mutation=mutation):
                page = ReviewPage()
                handle = isolated_handle([page])

                async def change_binding():
                    if mutation == "lease":
                        handle.launch_context.lease.token = "replacement"
                    else:
                        handle.launch_context = replace(handle.launch_context, generation=2)

                page.on_title = change_binding
                result = await handle.tabs.snapshot(lambda: True)
                self.assertEqual(result.status, "not_ready")
                self.assertEqual(result.tabs, ())
                self.assertEqual(handle.tabs.pages, {})
                self.assertTrue(handle.launch_context.lease.active)

    async def test_lease_loss_at_native_admission_prevents_side_effect(self):
        page = ReviewPage()
        handle = isolated_handle([page])
        tab = (await handle.tabs.snapshot(lambda: True)).tabs[0].id

        def admit():
            handle.launch_context.lease.active = False
            return True, True

        result = await handle.tabs.focus(lambda: True, tab_id=tab, admit=admit)
        self.assertEqual(result, "not_ready")
        self.assertNotIn("focus", page.calls)

    async def test_unknown_ownership_after_admission_never_claims_success_or_exit(self):
        page = ReviewPage()
        handle = isolated_handle([page])
        tab = (await handle.tabs.snapshot(lambda: True)).tabs[0].id

        async def disconnect():
            handle._on_close()

        page.on_focus = disconnect
        result = await handle.tabs.focus(lambda: True, tab_id=tab)
        self.assertEqual(result, "superseded")
        self.assertTrue(handle.ownership_uncertain)
        self.assertEqual(handle.phase, "unknown")
        self.assertTrue(handle.launch_context.lease.active)

    async def test_mirror_zero_multiple_and_truncated_preserve_existing_fallback(self):
        for alternatives in ([], [ReviewPage(), ReviewPage()], [ReviewPage()] * MAX_TABS):
            with self.subTest(count=len(alternatives)):
                fallback = ReviewPage("https://fallback.test")
                handle = isolated_handle([fallback, *alternatives])
                self.assertEqual(
                    await handle.tabs.focus(lambda: True, mirror_origin="https://review.test"),
                    "focused",
                )
                self.assertIs(handle.page, fallback)
                self.assertEqual(fallback.calls.count("focus"), 1)
                self.assertTrue(all("focus" not in page.calls for page in alternatives))

    async def test_page_metadata_is_not_authority_and_url_components_stay_private(self):
        page = ReviewPage()
        page.label = (
            "<script>alert(1)</script> https://review.test/PRIVATE?token=SECRET#HIDDEN\u202e"
        )
        page.visible = "true"  # A truthy script result is not the exact boolean hint.
        handle = isolated_handle([page])
        result = await handle.tabs.snapshot(lambda: True)
        self.assertIsNone(result.active_tab_id)
        public = json.dumps(result.as_dict())
        for fragment in ("PRIVATE", "SECRET", "HIDDEN", "SYNTHETIC_QUERY", "private-path"):
            self.assertNotIn(fragment, public)
        self.assertEqual(result.tabs[0].origin, "https://review.test")
        self.assertIn("<script>", result.tabs[0].title)  # Caller must render text, never HTML.
        self.assertEqual(page.calls, ["visibility"])

    async def test_newest_intent_fences_focus_waiting_for_native_lock(self):
        page = ReviewPage()
        handle = isolated_handle([page])
        current = True
        await handle.owner.lock.acquire()
        task = asyncio.create_task(handle.tabs.focus(lambda: current))
        await asyncio.sleep(0)
        current = False
        handle.owner.lock.release()
        self.assertEqual(await task, "not_ready")
        self.assertNotIn("focus", page.calls)


class IndependentFocusPumpTests(unittest.TestCase):
    def test_replacements_are_bounded_and_wait_for_real_acknowledgement(self):
        pump = LatestFocusPump()
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        executed = []

        def old():
            entered.set()
            release.wait(3)
            executed.append(1)
            return "focused"

        def latest():
            executed.append(500)
            finished.set()
            return "focused"

        try:
            pump.submit(1, old)
            self.assertTrue(entered.wait(1))
            for epoch in range(2, 500):
                pump.submit(epoch, lambda e=epoch: executed.append(e) or "focused")
            pump.submit(500, latest)
            self.assertEqual(pump.snapshot(), {"intent": 500, "status": "queued"})
            self.assertFalse(finished.is_set())
            release.set()
            self.assertTrue(finished.wait(2))
            self.assertEqual(executed, [1, 500])
        finally:
            release.set()
            pump.close()
            pump._thread.join(2)


class ReviewAdapter:
    execution_kind = "synthetic"

    def __init__(self):
        self.owner = PlaywrightSupervisor(factory=lambda: None, operation_timeout=1)
        self.handles = []
        self.pages = []

    def blockers(self, profile):
        return ()

    def start(self, launch):
        self.owner._ensure_loop()
        handle = PlaywrightHandle(self.owner, launch)
        handle.context = ReviewContext(self.pages)
        handle.context.on("close", handle._on_close)
        handle.page = self.pages[0] if self.pages else None
        handle._set_phase("ready")
        self.owner._handles.append(handle)
        self.handles.append(handle)
        return handle

    def shutdown(self):
        self.owner.shutdown()


class IndependentTabCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.directory.name) / "workspace")
        self.adapter = ReviewAdapter()
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.releases = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for release in self.releases:
            release.set()
        self.coordinator.shutdown()
        self.coordinator.refresh()
        self.store.close()
        self.directory.cleanup()

    def start(self, *pages):
        profile = self.store.create("Independent synthetic tab review")
        self.adapter.pages = list(pages)
        self.coordinator.action(profile["id"], "start")
        return profile["id"], self.adapter.handles[-1]

    def settled(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = self.coordinator._focus_pump.snapshot()["status"]
            if status not in {"queued", "pending"}:
                return status
            time.sleep(0.002)
        self.fail("Synthetic focus did not settle")

    def test_settings_revision_change_fences_mirror_even_if_enabled_again(self):
        source_page = ReviewPage(visible=True)
        source, _ = self.start(source_page)
        fallback, match = ReviewPage("https://fallback.test"), ReviewPage()
        target, handle = self.start(fallback, match)
        self.coordinator.action(source, "start")
        self.assertEqual(self.settled(), "focused")
        settings = self.store.metadata("settings")
        self.coordinator.update_settings(settings["revision"], mirror_same_origin=True)
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)

        async def pending_metadata():
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.002)

        source_page.on_title = pending_metadata
        self.coordinator.action(target, "start")
        self.assertTrue(entered.wait(1))
        settings = self.store.metadata("settings")
        self.coordinator.update_settings(settings["revision"], mirror_same_origin=False)
        settings = self.store.metadata("settings")
        self.coordinator.update_settings(settings["revision"], mirror_same_origin=True)
        release.set()
        self.assertEqual(self.settled(), "focused")
        self.assertIs(handle.page, fallback)
        self.assertNotIn("focus", match.calls)

    def test_incomplete_source_growth_never_selects_unique_target_origin(self):
        source_pages = [ReviewPage(visible=i == 0) for i in range(MAX_TABS)]
        source, source_handle = self.start(*source_pages)
        fallback, match = ReviewPage("https://fallback.test"), ReviewPage()
        target, target_handle = self.start(fallback, match)
        self.coordinator.action(source, "start")
        self.assertEqual(self.settled(), "focused")
        settings = self.store.metadata("settings")
        self.coordinator.update_settings(settings["revision"], mirror_same_origin=True)
        added = False

        async def append_visible_window():
            nonlocal added
            if not added:
                added = True
                source_handle.context.pages.append(
                    ReviewPage("https://second-window.test", visible=True)
                )

        source_pages[0].on_title = append_visible_window
        self.coordinator.action(target, "start")
        self.assertEqual(self.settled(), "focused")
        self.assertTrue(added)
        self.assertIs(target_handle.page, fallback)
        self.assertNotIn("focus", match.calls)

    def test_tab_id_from_other_profile_and_revision_conflict_have_no_side_effect(self):
        first, first_handle = self.start(ReviewPage())
        token = self.coordinator.selected_tabs()["tabs"][0]["id"]
        second, second_handle = self.start(ReviewPage())
        self.coordinator.focus_tab(second, token, generation=1)
        self.assertEqual(self.settled(), "stale_tab")
        current = self.coordinator.selected_tabs()["tabs"][0]["id"]
        with self.assertRaises(WorkspaceError):
            self.coordinator.focus_tab(second, current, generation=1, expected_revision=0)
        self.assertNotIn("focus", first_handle.page.calls)
        self.assertNotIn("focus", second_handle.page.calls)
        self.assertNotEqual(first, second)
