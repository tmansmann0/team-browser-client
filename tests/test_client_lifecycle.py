"""Typed synthetic process lifecycle tests; never launch an actual process."""

import tempfile
import threading
import unittest
from pathlib import Path

from team_browser.client import LifecycleCoordinator, ProcessStatus, WorkspaceError, WorkspaceStore


class FakeHandle:
    def __init__(self, *, ready=True):
        self.alive, self.ready = True, ready
        self.focuses = 0
        self.gmail_opens = 0
        self.safe_to_stop = True
        self.stops = 0
        self.stop_succeeds = True

    def status(self):
        return ProcessStatus(self.alive, self.ready, self.safe_to_stop)

    def focus(self):
        self.focuses += 1
        return self.alive

    def open_gmail(self):
        self.gmail_opens += 1
        return self.alive

    def stop(self):
        self.stops += 1
        if self.stop_succeeds:
            self.alive = False
        return self.stop_succeeds


class SyntheticAdapter:
    execution_kind = "synthetic"

    def __init__(self):
        self.contexts = []
        self.handles = {}
        self.ready = True
        self.failure = False

    def blockers(self, profile):
        return ()

    def start(self, context):
        if self.failure:
            raise RuntimeError("Synthetic fixture startup failed")
        self.contexts.append(context)
        handle = FakeHandle(ready=self.ready)
        self.handles[context.profile_id] = handle
        return handle


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "workspace"
        self.store = WorkspaceStore(self.root)
        self.adapter = SyntheticAdapter()
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.addCleanup(self.store.close)
        self.addCleanup(self.coordinator.shutdown)

    def profile(self, name="Synthetic test profile"):
        return self.store.create(name)["id"]

    def test_repeated_start_focuses_existing_single_process(self):
        p = self.profile()
        first = self.coordinator.action(p, "start", idempotency_key="start-key-one")
        self.assertEqual(first["profile"]["state"], "running")
        second = self.coordinator.action(p, "start")
        self.assertEqual(second["outcome"], "focused_existing")
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.adapter.handles[p].focuses, 1)
        replay = self.coordinator.action(
            p, "start", expected_revision=1, idempotency_key="start-key-one"
        )
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.adapter.handles[p].focuses, 1)
        self.assertTrue(self.coordinator.capabilities()["available"])
        self.assertFalse(self.coordinator.capabilities()["actual_process_available"])
        self.assertEqual(self.coordinator.capabilities()["execution_kind"], "synthetic")

    def test_selection_changes_warm_state_without_focus(self):
        one, two = self.profile("One"), self.profile("Two")
        self.coordinator.action(one, "start")
        self.coordinator.action(two, "start")
        self.assertEqual(self.store.get(one)["state"], "warm")
        self.assertEqual(self.store.get(two)["state"], "running")
        self.coordinator.action(one, "select")
        self.assertEqual(self.store.get(one)["state"], "running")
        self.assertEqual(self.store.get(two)["state"], "warm")
        self.assertEqual(self.adapter.handles[one].focuses, 0)
        self.assertEqual(len(self.adapter.contexts), 2)

    def test_repeated_selection_never_creates_or_focuses_processes(self):
        one, two = self.profile("One"), self.profile("Two")
        for _ in range(5):
            for profile_id in (one, one, two, two):
                self.coordinator.action(profile_id, "select")
        self.assertEqual(self.adapter.contexts, [])
        self.assertEqual(self.adapter.handles, {})
        for profile_id in (one, two):
            self.coordinator.action(profile_id, "start")
        for _ in range(5):
            for profile_id in (one, one, two, two):
                self.coordinator.action(profile_id, "select")
        self.assertEqual(len(self.adapter.contexts), 2)
        self.assertTrue(all(handle.focuses == 0 for handle in self.adapter.handles.values()))
        self.assertEqual(self.store.selected(), two)
        # The explicit command still activates an existing process, without a duplicate.
        result = self.coordinator.action(one, "start")
        self.assertEqual(result["outcome"], "focused_existing")
        self.assertEqual(self.adapter.handles[one].focuses, 1)
        self.assertEqual(len(self.adapter.contexts), 2)

    def test_reselection_fences_older_startup_focus_and_selection_intent(self):
        pending, selected = self.profile("Pending"), self.profile("Selected")
        self.coordinator.action(selected, "select")
        entered, release = threading.Event(), threading.Event()
        outcomes = []

        def blockers(_profile):
            entered.set()
            if not release.wait(2):
                return ("Synthetic preflight timed out",)
            return ()

        self.adapter.blockers = blockers

        def start_pending():
            try:
                outcomes.append(self.coordinator.action(pending, "start"))
            except Exception as error:
                outcomes.append(error)

        worker = threading.Thread(target=start_pending)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            for _ in range(5):
                self.coordinator.action(selected, "select")
            self.assertEqual(self.adapter.contexts, [])
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], dict, outcomes)
        self.assertEqual(self.store.selected(), selected)
        self.assertEqual(self.store.get(pending)["state"], "warm")
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertFalse(self.adapter.contexts[0].selected)
        self.assertEqual(self.adapter.handles[pending].focuses, 0)

    def test_reselecting_pending_profile_fences_its_startup_focus(self):
        pending = self.profile("Already selected")
        self.coordinator.action(pending, "select")
        entered, release = threading.Event(), threading.Event()
        outcomes = []

        def blockers(_profile):
            entered.set()
            if not release.wait(2):
                return ("Synthetic preflight timed out",)
            return ()

        self.adapter.blockers = blockers

        def start_pending():
            try:
                outcomes.append(self.coordinator.action(pending, "start"))
            except Exception as error:
                outcomes.append(error)

        worker = threading.Thread(target=start_pending)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            self.coordinator.action(pending, "select")
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], dict, outcomes)
        self.assertEqual(self.store.selected(), pending)
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertFalse(
            self.adapter.contexts[0].selected,
            "A newer same-profile selection must fence the older native startup focus",
        )

    def test_bounded_warm_slots_evict_least_recent_profile(self):
        self.coordinator.update_settings(1, max_warm_profiles=2)
        one, two, three = self.profile("One"), self.profile("Two"), self.profile("Three")
        self.coordinator.action(one, "start")
        self.coordinator.action(two, "start")
        self.coordinator.action(three, "start")
        self.assertEqual(self.store.get(one)["state"], "stopped")
        self.assertEqual(self.adapter.handles[one].stops, 1)
        self.assertEqual(self.store.get(two)["state"], "warm")
        self.assertEqual(self.store.get(three)["state"], "running")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 2)

    def test_budget_reduction_preserves_selected_and_trims_warm(self):
        profiles = [self.profile(str(index)) for index in range(3)]
        for profile in profiles:
            self.coordinator.action(profile, "start")
        settings = self.coordinator.update_settings(1, memory_budget_mb=512)
        self.assertEqual(settings["effective_capacity"], 1)
        self.assertEqual(settings["resident_profiles"], 1)
        self.assertEqual(self.store.get(profiles[-1])["state"], "running")
        self.assertTrue(all(self.store.get(p)["state"] == "stopped" for p in profiles[:-1]))

    def test_starting_progress_cancel_and_stop_are_idempotent(self):
        self.adapter.ready = False
        p = self.profile()
        self.assertEqual(self.coordinator.action(p, "start")["outcome"], "starting")
        self.assertEqual(self.coordinator.action(p, "start")["outcome"], "already_starting")
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.coordinator.action(p, "cancel")["outcome"], "cancelled")
        self.assertEqual(self.coordinator.action(p, "stop")["outcome"], "already_stopped")
        self.assertEqual(self.store.get(p)["state"], "stopped")

    def test_poll_promotes_starting_and_detects_exit(self):
        self.adapter.ready = False
        p = self.profile()
        self.coordinator.action(p, "start")
        self.adapter.handles[p].ready = True
        self.coordinator.refresh()
        self.assertEqual(self.store.get(p)["state"], "running")
        self.adapter.handles[p].alive = False
        self.coordinator.refresh()
        self.assertEqual(self.store.get(p)["state"], "error")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 0)
        self.coordinator.action(p, "start")
        self.assertEqual(len(self.adapter.contexts), 2)

    def test_no_extra_process_if_eviction_stop_unconfirmed(self):
        self.coordinator.update_settings(1, max_warm_profiles=1)
        one, two = self.profile("One"), self.profile("Two")
        self.coordinator.action(one, "start")
        self.adapter.handles[one].stop_succeeds = False
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.action(two, "start")
        self.assertEqual(caught.exception.code, "stop_unconfirmed")
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.store.get(one)["state"], "recovery_required")
        self.assertEqual(self.store.get(two)["state"], "stopped")
        self.adapter.handles[one].stop_succeeds = True
        self.coordinator.action(one, "stop")
        self.assertEqual(self.store.get(one)["state"], "stopped")

    def test_engine_change_and_removal_refused_while_running(self):
        p = self.profile()
        self.coordinator.action(p, "start")
        current = self.store.get(p)
        with self.assertRaises(WorkspaceError):
            self.store.update(p, current["revision"], preset_id="isolated")
        with self.assertRaises(WorkspaceError):
            self.store.delete(p, current["revision"])
        renamed = self.store.update(p, current["revision"], name="Renamed running profile")
        self.assertEqual(renamed["state"], "running")

    def test_conflicting_idempotency_key_refused(self):
        p, other = self.profile(), self.profile()
        self.coordinator.action(p, "select", idempotency_key="shared-operation")
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.action(other, "select", idempotency_key="shared-operation")
        self.assertEqual(caught.exception.code, "idempotency_conflict")

    def test_native_adapter_cannot_unlock_by_claiming_no_blockers(self):
        class UntrustedAdapter(SyntheticAdapter):
            execution_kind = "native"

        native = UntrustedAdapter()
        coordinator = LifecycleCoordinator(self.store, native)
        p = self.profile()
        with self.assertRaises(WorkspaceError) as caught:
            coordinator.action(p, "start")
        self.assertEqual(caught.exception.code, "engine_unavailable")
        self.assertEqual(native.contexts, [])
        self.assertFalse(coordinator.capabilities()["actual_process_available"])

    def test_failure_releases_lease_and_can_retry(self):
        p = self.profile()
        self.adapter.failure = True
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.action(p, "start")
        self.assertEqual(caught.exception.code, "start_failed")
        self.adapter.failure = False
        result = self.coordinator.action(p, "start")
        self.assertEqual(result["profile"]["state"], "running")

    def test_gmail_intent_uses_fixed_profile_target_and_focuses_existing(self):
        p = self.profile()
        first = self.coordinator.action(
            p, "start", intent="gmail", expected_revision=1, idempotency_key="open-gmail-request"
        )
        self.assertEqual(self.adapter.contexts[0].profile_id, p)
        self.assertEqual(
            self.adapter.contexts[0].initial_url, "https://mail.google.com/mail/u/0/#inbox"
        )
        self.coordinator.action(
            p, "start", intent="gmail", expected_revision=first["profile"]["revision"]
        )
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.adapter.handles[p].gmail_opens, 1)
        self.coordinator.action(
            p, "start", intent="gmail", expected_revision=1, idempotency_key="open-gmail-request"
        )
        self.assertEqual(self.adapter.handles[p].gmail_opens, 1)
        with self.assertRaises(WorkspaceError):
            self.coordinator.action(
                p, "start", expected_revision=1, idempotency_key="open-gmail-request"
            )

    def test_unknown_unsaved_state_blocks_budget_eviction(self):
        self.coordinator.update_settings(1, max_warm_profiles=1)
        one, two = self.profile("One"), self.profile("Two")
        self.coordinator.action(one, "start")
        self.adapter.handles[one].safe_to_stop = False
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.action(two, "start")
        self.assertEqual(caught.exception.code, "budget_exceeded")
        self.assertEqual(self.adapter.handles[one].stops, 0)
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.store.get(one)["state"], "running")
        with self.store.profiles.acquire(two):
            pass  # A rejected start must release its target lease.

    def test_target_lease_failure_is_typed_and_does_not_evict(self):
        self.coordinator.update_settings(1, max_warm_profiles=1)
        one, two = self.profile("One"), self.profile("Two")
        self.coordinator.action(one, "start")
        with self.store.profiles.acquire(two):
            with self.assertRaises(WorkspaceError) as caught:
                self.coordinator.action(two, "start", idempotency_key="lease-failure-key")
            self.assertEqual(caught.exception.code, "profile_in_use")
        self.assertEqual(self.adapter.handles[one].stops, 0)
        operation = self.store.db.execute(
            "SELECT outcome FROM operations WHERE key=?", ("lease-failure-key",)
        ).fetchone()
        self.assertEqual(operation["outcome"], "profile_in_use")
        self.assertEqual(len(self.adapter.contexts), 1)

    def test_unknown_crash_state_blocks_restart_stop_and_delete(self):
        p = self.profile()
        self.store._change(p, state="starting")
        self.store.close()
        self.store = WorkspaceStore(self.root)
        self.addCleanup(self.store.close)
        coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.assertEqual(self.store.get(p)["state"], "recovery_required")
        for action in ("start", "stop", "cancel"):
            with self.subTest(action=action), self.assertRaises(WorkspaceError) as caught:
                coordinator.action(p, action)
            self.assertEqual(caught.exception.code, "recovery_required")
        self.assertTrue(coordinator.action(p, "select")["profile"]["selected"])
        with self.assertRaises(WorkspaceError):
            self.store.delete(p, self.store.get(p)["revision"])
        self.assertEqual(self.adapter.contexts, [])

    def test_clean_shutdown_persists_stopped(self):
        p = self.profile()
        self.coordinator.action(p, "start")
        self.coordinator.shutdown()
        self.coordinator.shutdown()
        self.assertEqual(self.store.get(p)["state"], "stopped")
        self.assertEqual(self.adapter.handles[p].stops, 1)
        with self.assertRaises(WorkspaceError) as caught:
            self.coordinator.action(p, "start")
        self.assertEqual(caught.exception.code, "workspace_closed")
