"""Official supervisor contracts using a wholly fake async Playwright driver.

No Playwright import, executable launch, browser download or network request.
"""

import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path

from team_browser.client import LifecycleCoordinator, WorkspaceStore
from team_browser.client.installed_browser import InstalledBrowserAdapter
from team_browser.client.playwright_supervisor import PlaywrightSupervisor
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence
from datetime import datetime, timezone
import hashlib


class FixtureVerifier:
    def verify(self, executable, digest):
        return SignatureEvidence(digest, "fixture", True, True, datetime.now(timezone.utc))


class FakePage:
    def __init__(self):
        self.closed = False
        self.targets = []
        self.focuses = 0

    def is_closed(self):
        return self.closed

    async def goto(self, target, **kwargs):
        self.targets.append(target)

    async def bring_to_front(self):
        self.focuses += 1


class FakeContext:
    def __init__(self):
        self.pages = [FakePage()]
        self.callbacks = {}
        self.closed = False

    def is_closed(self):
        return self.closed

    def on(self, event, callback):
        self.callbacks[event] = callback

    async def new_page(self):
        page = FakePage()
        self.pages.append(page)
        return page

    async def close(self):
        self.closed = True
        for page in self.pages:
            page.closed = True
        if "close" in self.callbacks:
            self.callbacks["close"]()


class FakeDriver:
    def __init__(self, delay=0):
        self.chromium = self
        self.delay = delay
        self.calls = []
        self.contexts = []
        self.stopped = False
        self.entered = threading.Event()

    async def start(self):
        return self

    async def launch_persistent_context(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.entered.set()
        await asyncio.sleep(self.delay)
        context = FakeContext()
        self.contexts.append(context)
        return context

    async def stop(self):
        self.stopped = True


class PlaywrightSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.store = WorkspaceStore(root / "workspace")
        self.addCleanup(self.store.close)
        binary = root / "never-execute"
        binary.write_bytes(b"contract-only")
        binary.chmod(0o700)
        policy = RuntimePolicy(
            "chromium", "fixture", hashlib.sha256(binary.read_bytes()).hexdigest(), "fixture"
        )
        self.driver = FakeDriver()
        self.supervisor = PlaywrightSupervisor(factory=lambda: self.driver, operation_timeout=1)
        adapter = InstalledBrowserAdapter(
            profile_store=self.store.profiles,
            executable=binary,
            observed_version="fixture",
            policy=policy,
            runtime_gate=RuntimeGate(FixtureVerifier()),
            supervisor=self.supervisor,
        )
        self.coordinator = LifecycleCoordinator(self.store, adapter)
        self.addCleanup(self.coordinator.shutdown)

    def profile(self, name="Fixture"):
        return self.store.create(name, network_policy="local_direct")["id"]

    def await_state(self, profile, state):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.coordinator.refresh()
            if self.store.get(profile)["state"] == state:
                return
            time.sleep(0.005)
        self.fail(f"Profile state never became {state}: {self.store.get(profile)}")

    def test_launch_preserves_security_defaults_and_pipe_private_profile(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.await_state(profile, "running")
        args, kw = self.driver.calls[0]
        self.assertEqual(args, (str(self.store.profiles.root / profile / "browser-data"),))
        self.assertTrue(kw["ignore_default_args"])
        self.assertTrue(kw["chromium_sandbox"])
        self.assertFalse(kw["headless"])
        self.assertIn("--remote-debugging-pipe", kw["args"])
        self.assertFalse(any("remote-debugging-port" in arg for arg in kw["args"]))
        for forbidden in (
            "--no-sandbox",
            "--password-store=basic",
            "--use-mock-keychain",
            "--disable-component-update",
            "--safebrowsing-disable-auto-update",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-web-security",
            "--disable-ipc-flooding-protection",
        ):
            self.assertNotIn(forbidden, kw["args"])

    def test_delayed_launch_cancel_is_nonblocking_and_no_late_running_state(self):
        self.driver.delay = 0.25
        first, second = self.profile("First"), self.profile("Second")
        started_at = time.monotonic()
        result = self.coordinator.action(first, "start")
        self.assertEqual(result["profile"]["state"], "starting")
        self.assertLess(time.monotonic() - started_at, 0.2)
        self.assertTrue(self.driver.entered.wait(1))
        started_at = time.monotonic()
        result = self.coordinator.action(first, "cancel")
        self.assertEqual(result["outcome"], "stopping")
        self.coordinator.action(second, "select")
        self.assertLess(time.monotonic() - started_at, 0.2)
        self.assertEqual(self.store.selected(), second)
        self.await_state(first, "stopped")
        self.assertTrue(self.driver.contexts[0].closed)
        self.assertEqual(self.driver.contexts[0].pages[0].focuses, 0)
        self.assertEqual(self.store.selected(), second)

    def test_late_ready_does_not_steal_newer_selection(self):
        self.driver.delay = 0.1
        first, second = self.profile("First"), self.profile("Second")
        self.coordinator.action(first, "start")
        self.coordinator.action(second, "select")
        self.await_state(first, "warm")
        self.assertEqual(self.store.selected(), second)
        self.assertEqual(self.driver.contexts[0].pages[0].focuses, 0)

    def test_cancel_during_signature_preflight_fences_late_start(self):
        profile = self.profile()
        entered, release = threading.Event(), threading.Event()
        original = self.coordinator.adapter.blockers

        def delayed(p):
            entered.set()
            release.wait(2)
            return original(p)

        self.coordinator.adapter.blockers = delayed
        outcomes = []

        def start():
            try:
                outcomes.append(self.coordinator.action(profile, "start"))
            except Exception as exc:
                outcomes.append(exc)

        worker = threading.Thread(target=start)
        worker.start()
        self.assertTrue(entered.wait(1))
        self.coordinator.action(profile, "cancel")
        release.set()
        worker.join(2)
        self.assertEqual(outcomes[0].code, "operation_superseded")
        self.assertEqual(self.driver.calls, [])
        self.assertEqual(self.store.get(profile)["state"], "stopped")

    def test_same_profile_reselection_fences_older_preflight_focus(self):
        first, second = self.profile("First"), self.profile("Second")
        self.coordinator.action(second, "select")
        entered, release = threading.Event(), threading.Event()
        original = self.coordinator.adapter.blockers

        def delayed(profile):
            entered.set()
            release.wait(2)
            return original(profile)

        self.coordinator.adapter.blockers = delayed
        outcomes = []
        worker = threading.Thread(
            target=lambda: outcomes.append(self.coordinator.action(first, "start"))
        )
        worker.start()
        self.assertTrue(entered.wait(1))
        self.coordinator.action(
            second, "select"
        )  # A new intent even though B was already selected.
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.await_state(first, "warm")
        self.assertEqual(self.store.selected(), second)
        self.assertEqual(self.driver.contexts[0].pages[0].focuses, 0)

    def test_fixed_gmail_and_repeated_open_share_owned_context(self):
        profile = self.profile()
        self.coordinator.action(profile, "start", intent="gmail", expected_revision=1)
        self.await_state(profile, "running")
        page = self.driver.contexts[0].pages[0]
        self.assertEqual(page.targets, ["https://mail.google.com/mail/u/0/#inbox"])
        self.coordinator.action(
            profile, "start", intent="gmail", expected_revision=self.store.get(profile)["revision"]
        )
        self.assertEqual(len(self.driver.calls), 1)
        self.assertEqual(page.targets, ["https://mail.google.com/mail/u/0/#inbox"])
        self.assertEqual(len(self.driver.contexts[0].pages), 1)

    def test_failed_gmail_navigation_never_becomes_cached_success(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.await_state(profile, "running")
        context = self.driver.contexts[0]
        candidate = FakePage()
        attempts = []

        async def failed_goto(target, **kwargs):
            attempts.append(target)
            raise RuntimeError("Synthetic navigation failed")

        candidate.goto = failed_goto

        async def new_page():
            context.pages.append(candidate)
            return candidate

        context.new_page = new_page
        from team_browser.client import WorkspaceError

        for _ in range(2):
            with self.assertRaises(WorkspaceError) as caught:
                self.coordinator.action(
                    profile,
                    "start",
                    intent="gmail",
                    expected_revision=self.store.get(profile)["revision"],
                )
            self.assertEqual(caught.exception.code, "gmail_open_failed")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(context.pages.count(candidate), 1)
        self.assertEqual(candidate.focuses, 0)

    def test_unsolicited_disconnect_is_recovery_required(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.await_state(profile, "running")
        self.driver.contexts[0].callbacks["close"]()
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 1)
        handle = self.coordinator._running[profile].handle
        handle.ownership_uncertain = False
        handle._set_phase("stopped")

    def test_unsolicited_close_cannot_be_cleared_by_noop_close(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.await_state(profile, "running")
        context = self.driver.contexts[0]
        context.closed = True
        context.callbacks["close"]()
        self.coordinator.refresh()

        async def noop_close():
            return None

        context.close = noop_close
        from team_browser.client import WorkspaceError
        from team_browser.local import ProfileInUseError

        with self.assertRaises(WorkspaceError):
            self.coordinator.action(profile, "stop")
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 1)
        with self.assertRaises(ProfileInUseError):
            self.store.profiles.acquire(profile)
        # Test-only cleanup: the fake has no real process. Explicitly confirm its
        # fixture ownership so the daemon driver can close without leaking tests.
        handle = self.coordinator._running[profile].handle
        handle.ownership_uncertain = False
        handle._set_phase("stopped")

    def test_signature_preflight_does_not_lock_metadata_selection(self):
        profile, other = self.profile(), self.profile("Other")
        entered, release = threading.Event(), threading.Event()
        original = self.coordinator.adapter.blockers

        def delayed(p):
            entered.set()
            release.wait(2)
            return original(p)

        self.coordinator.adapter.blockers = delayed
        outcomes = []

        def start():
            try:
                outcomes.append(self.coordinator.action(profile, "start"))
            except Exception as exc:
                outcomes.append(exc)

        worker = threading.Thread(target=start)
        worker.start()
        self.assertTrue(entered.wait(1))
        started_at = time.monotonic()
        self.coordinator.action(other, "select")
        self.assertLess(time.monotonic() - started_at, 0.1)
        # Touching the same profile cancels stale preflight authority via revision.
        self.store.update(profile, self.store.get(profile)["revision"], favorite=True)
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes[0].code, "revision_conflict")
        self.assertEqual(self.driver.calls, [])
