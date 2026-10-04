"""Public-client-only QA. Disposable local data and synthetic process handles only."""

from concurrent.futures import ThreadPoolExecutor
import asyncio
from datetime import datetime, timezone
import hashlib
import os
import plistlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch as mock_patch

from fastapi.testclient import TestClient

from team_browser.client.app import create_local_app
from team_browser.client.lifecycle import GMAIL_INBOX_URL, ProcessStatus
from team_browser.client.installed_browser import (
    InstalledBrowserAdapter,
    read_macos_bundle_metadata,
)
from team_browser.client.playwright_supervisor import PlaywrightSupervisor
from team_browser.client import LifecycleCoordinator, WorkspaceError, WorkspaceStore
from team_browser.local.errors import ProfileInUseError, RuntimeVerificationError
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence
from team_browser.local.storage import ProfileStore
from team_browser.local.wipe import WipeRejected, wipe_profile_data


class SyntheticHandle:
    def __init__(self):
        self.alive = True
        self.ready = False
        self.safe_to_stop = False
        self.status_error = False
        self.focuses = 0
        self.gmail_opens = 0
        self.stop_count = 0

    def status(self):
        if self.status_error:
            raise RuntimeError("Synthetic status unavailable")
        return ProcessStatus(self.alive, self.ready, self.safe_to_stop)

    def focus(self):
        self.focuses += 1
        return self.alive

    def open_gmail(self):
        self.gmail_opens += 1
        return self.alive

    def stop(self):
        self.stop_count += 1
        self.alive = False
        return True


class SyntheticAdapter:
    execution_kind = "synthetic"

    def __init__(self):
        self.contexts = []
        self.handles = {}

    def blockers(self, profile):
        return ()

    def start(self, context):
        self.contexts.append(context)
        handle = SyntheticHandle()
        self.handles[context.profile_id] = handle
        return handle


class IndependentClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "workspace"
        self.client = None
        self.adapter = SyntheticAdapter()
        self.open_client()
        self.addCleanup(self.close_client)

    def open_client(self, adapter=None):
        self.app = create_local_app(self.root, process_adapter=adapter or self.adapter)
        self.client = TestClient(
            self.app,
            base_url="http://127.0.0.1:8765",
            client=("127.0.0.1", 50000),
            raise_server_exceptions=False,
        )
        self.client.__enter__()
        response = self.client.get("/local/config")
        self.assertEqual(response.status_code, 200, response.text)
        self.config = response.json()
        self.csrf = self.config["csrf_token"]

    def close_client(self):
        if self.client is not None:
            client, self.client = self.client, None
            for handle in self.adapter.handles.values():
                handle.status_error = False
            client.__exit__(None, None, None)

    def req(self, method, path, **kwargs):
        headers = {"X-Local-CSRF": self.csrf, **kwargs.pop("headers", {})}
        return self.client.request(method, path, headers=headers, **kwargs)

    def create(self, name="Synthetic profile"):
        response = self.req("POST", "/local/v1/profiles", json={"name": name})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def action(self, profile, action, **extra):
        return self.req(
            "POST", f"/local/v1/profiles/{profile}/actions", json={"action": action, **extra}
        )

    def test_account_free_config_and_synthetic_capability_are_honest(self):
        self.assertFalse(self.config["account_required"])
        self.assertTrue(self.config["persistent"])
        self.assertEqual(self.config["launch"]["execution_kind"], "synthetic")
        self.assertFalse(self.config["launch"]["actual_process_available"])
        self.assertFalse(self.config["managed"]["authenticated"])
        self.assertEqual(self.config["managed"]["status"], "not_enrolled")
        self.assertFalse(self.config["inbox"]["native_open_available"])

    def test_csrf_origin_host_and_json_are_required_for_mutations(self):
        path = "/local/v1/profiles"
        self.assertEqual(self.client.post(path, json={"name": "No token"}).status_code, 403)
        self.assertEqual(
            self.req(
                "POST", path, headers={"X-Local-CSRF": "wrong"}, json={"name": "Wrong"}
            ).status_code,
            403,
        )
        bad = self.client.post(
            path, headers=[(b"x-local-csrf", b"\xff")], json={"name": "Malformed"}
        )
        self.assertEqual(bad.status_code, 403, bad.text)
        for headers in (
            {"Origin": "https://outside.test"},
            {"Origin": "http://localhost:8765"},
            {"Sec-Fetch-Site": "cross-site"},
            {"Host": "outside.test"},
        ):
            self.assertEqual(
                self.req("POST", path, headers=headers, json={"name": "Denied"}).status_code, 403
            )
        self.assertEqual(
            self.req(
                "POST",
                path,
                content='{"name":"Wrong type"}',
                headers={"Content-Type": "text/plain"},
            ).status_code,
            415,
        )
        self.assertEqual(self.client.get(path).json(), [])

    def test_forwarded_headers_cannot_make_remote_client_loopback(self):
        remote = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("192.0.2.15", 50000)
        )
        try:
            response = remote.get("/local/config", headers={"X-Forwarded-For": "127.0.0.1"})
            self.assertEqual(response.status_code, 403)
        finally:
            remote.close()

    def test_durable_metadata_and_restart_rotated_csrf(self):
        profile = self.create()
        selected = self.action(profile["id"], "select")
        self.assertEqual(selected.status_code, 200)
        old_csrf = self.csrf
        self.close_client()
        self.open_client()
        self.assertNotEqual(self.csrf, old_csrf)
        self.assertEqual(self.config["selected_profile_id"], profile["id"])
        self.assertEqual(self.client.get("/local/v1/profiles").json()[0]["id"], profile["id"])
        self.assertEqual(
            self.client.post(
                "/local/v1/profiles",
                headers={"X-Local-CSRF": old_csrf},
                json={"name": "Stale token"},
            ).status_code,
            403,
        )

    def test_strict_inputs_and_revision_conflicts(self):
        for patch in (
            {"favorite": "true"},
            {"engine_id": "arbitrary"},
            {"cookies": "forbidden"},
            {"name": "bad\nname"},
        ):
            response = self.req("POST", "/local/v1/profiles", json={"name": "Synthetic", **patch})
            self.assertEqual(response.status_code, 422, response.text)
        profile = self.create()
        path = f"/local/v1/profiles/{profile['id']}"
        self.assertEqual(
            self.req("PATCH", path, json={"expected_revision": 1, "favorite": True}).status_code,
            200,
        )
        self.assertEqual(
            self.req("PATCH", path, json={"expected_revision": 1, "name": "Stale"}).status_code, 409
        )
        self.assertEqual(
            self.req("PATCH", path, json={"expected_revision": 2, "name": None}).status_code, 422
        )

    def test_managed_configuration_never_becomes_enrollment_or_stores_credentials(self):
        path = "/local/v1/managed-connection"
        for url in (
            "http://example.test",
            "https://user:secret@example.test",
            "https://example.test/?token=synthetic",
            "https://example.test/path",
            "https://example.test/#fragment",
        ):
            self.assertEqual(
                self.req("PUT", path, json={"expected_revision": 1, "server_url": url}).status_code,
                422,
            )
        valid = self.req(
            "PUT",
            path,
            json={"expected_revision": 1, "server_url": "https://control.example.test/"},
        )
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertEqual(valid.json()["status"], "not_enrolled")
        self.assertFalse(valid.json()["authenticated"])
        self.assertEqual(
            self.req("PUT", path, json={"expected_revision": 2, "authenticated": True}).status_code,
            422,
        )

    def test_concurrent_repeat_starts_once_and_cancel_does_not_resurrect(self):
        profile = self.create()
        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(
                pool.map(
                    lambda _: self.action(profile["id"], "start", idempotency_key="same-qa-start"),
                    range(6),
                )
            )
        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(len(self.adapter.contexts), 1)
        self.assertEqual(self.action(profile["id"], "cancel").status_code, 200)
        replay = self.action(profile["id"], "start", idempotency_key="same-qa-start")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["outcome"], "replayed")
        self.assertEqual(replay.json()["profile"]["state"], "stopped")
        self.assertEqual(len(self.adapter.contexts), 1)

    def test_profile_switch_preserves_isolated_paths_and_gmail_binding(self):
        first, second = self.create("Synthetic A"), self.create("Synthetic B")
        opened = self.action(
            first["id"],
            "start",
            intent="gmail",
            expected_revision=1,
            idempotency_key="gmail-first-open",
        )
        self.assertEqual(opened.status_code, 200, opened.text)
        self.assertEqual(self.adapter.contexts[0].initial_url, GMAIL_INBOX_URL)
        self.assertEqual(self.action(second["id"], "start").status_code, 200)
        self.assertNotEqual(
            self.adapter.contexts[0].browser_data, self.adapter.contexts[1].browser_data
        )
        self.assertEqual(self.adapter.contexts[1].initial_url, "about:blank")
        self.assertEqual(
            self.action(first["id"], "start", intent="gmail", expected_revision=1).status_code, 409
        )
        self.assertEqual(
            self.action(
                second["id"],
                "start",
                intent="gmail",
                expected_revision=1,
                idempotency_key="gmail-first-open",
            ).status_code,
            409,
        )
        arbitrary = self.req(
            "POST",
            f"/local/v1/profiles/{first['id']}/actions",
            json={
                "action": "start",
                "url": "https://outside.test",
                "intent": "gmail",
                "expected_revision": 1,
            },
        )
        self.assertEqual(arbitrary.status_code, 422)

    def test_busy_target_does_not_evict_existing_profile(self):
        first, second = self.create("One"), self.create("Two")
        self.req(
            "PATCH", "/local/v1/settings", json={"expected_revision": 1, "max_warm_profiles": 1}
        )
        self.action(first["id"], "start")
        self.adapter.handles[first["id"]].safe_to_stop = True
        with self.app.state.workspace.profiles.acquire(second["id"]):
            blocked = self.action(second["id"], "start", idempotency_key="target-locked-qa")
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(blocked.json()["detail"]["code"], "profile_in_use")
        self.assertEqual(self.adapter.handles[first["id"]].stop_count, 0)
        self.assertEqual(len(self.adapter.contexts), 1)

    def test_uncertain_process_status_retains_lease_and_blocks_destructive_actions(self):
        profile = self.create()
        self.action(profile["id"], "start")
        self.adapter.handles[profile["id"]].status_error = True
        current = self.client.get(f"/local/v1/profiles/{profile['id']}").json()
        self.assertEqual(current["state"], "recovery_required")
        with self.assertRaises(ProfileInUseError):
            self.app.state.workspace.profiles.acquire(profile["id"])
        deletion = self.req(
            "DELETE",
            f"/local/v1/profiles/{profile['id']}",
            params={"expected_revision": current["revision"]},
        )
        self.assertEqual(deletion.status_code, 409)
        self.assertEqual(self.action(profile["id"], "start").status_code, 409)

    def test_removing_metadata_does_not_claim_or_perform_data_wipe(self):
        profile = self.create()
        path = (
            self.app.state.workspace.profiles.prepare(profile["id"]).browser_data / "synthetic.txt"
        )
        path.write_text("invented local fixture")
        response = self.req(
            "DELETE", f"/local/v1/profiles/{profile['id']}", params={"expected_revision": 1}
        )
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(path.read_text(), "invented local fixture")
        self.assertEqual(self.client.get(f"/local/v1/profiles/{profile['id']}").status_code, 404)


class IndependentNativeSupervisorTests(unittest.TestCase):
    """Only fake async driver objects; the synthetic runtime bytes are never executed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.store = WorkspaceStore(root / "workspace")
        self.addCleanup(self.store.close)
        executable = root / "never-execute-synthetic-fixture"
        executable.write_bytes(b"synthetic contract bytes, not an executable")
        executable.chmod(0o600)
        policy = RuntimePolicy(
            "chromium",
            "qa-fixture",
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            "qa-signer",
        )

        class SignatureFixture:
            def verify(self, path, digest):
                return SignatureEvidence(
                    digest, "qa-signer", True, True, datetime.now(timezone.utc)
                )

        class Page:
            def __init__(self):
                self.focuses = 0
                self.targets = []

            def is_closed(self):
                return False

            async def bring_to_front(self):
                self.focuses += 1

            async def goto(self, target, **kwargs):
                self.targets.append(target)

        class Context:
            def __init__(self):
                self.pages = [Page()]
                self.callbacks = {}
                self.close_calls = 0
                self.closed = False

            def is_closed(self):
                return self.closed

            def on(self, name, callback):
                self.callbacks[name] = callback

            async def close(self):
                # Like an already-closed Playwright context, return may be a no-op.
                self.close_calls += 1
                self.closed = True
                if "close" in self.callbacks:
                    self.callbacks["close"]()

            async def new_page(self):
                page = Page()
                self.pages.append(page)
                return page

        class Driver:
            def __init__(self):
                self.chromium = self
                self.calls = []
                self.contexts = []
                self.delay = 0
                self.entered = threading.Event()

            async def start(self):
                return self

            async def launch_persistent_context(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                self.entered.set()
                await asyncio.sleep(self.delay)
                context = Context()
                self.contexts.append(context)
                return context

            async def stop(self):
                pass

        self.driver = Driver()
        self.supervisor = PlaywrightSupervisor(factory=lambda: self.driver, operation_timeout=1)
        adapter = InstalledBrowserAdapter(
            profile_store=self.store.profiles,
            executable=executable,
            observed_version="qa-fixture",
            policy=policy,
            runtime_gate=RuntimeGate(SignatureFixture()),
            supervisor=self.supervisor,
        )
        self.coordinator = LifecycleCoordinator(self.store, adapter)
        self.addCleanup(self.cleanup_fake_resources)

    def cleanup_fake_resources(self):
        # No native process exists in these tests. Dispose only fake handles and
        # their event loop after assertions; this is not production recovery.
        for handle in self.supervisor._handles:
            if handle.launch_future is not None:
                try:
                    handle.launch_future.result(timeout=2)
                except Exception:
                    pass
            if handle.stop_future is not None:
                try:
                    handle.stop_future.result(timeout=2)
                except Exception:
                    pass
            handle.ownership_uncertain = False
            handle._set_phase("stopped")
        self.coordinator.shutdown()

    def profile(self, name="Synthetic native contract"):
        return self.store.create(name, network_policy="local_direct")["id"]

    def settle(self, profile, expected):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.coordinator.refresh()
            if self.store.get(profile)["state"] == expected:
                return
            time.sleep(0.005)
        self.fail(f"Expected {expected}, observed {self.store.get(profile)['state']}")

    def test_startup_close_event_cannot_be_overwritten_by_ready(self):
        original = self.driver.launch_persistent_context

        async def close_after_registration(*args, **kwargs):
            context = await original(*args, **kwargs)
            register = context.on

            def on(name, callback):
                register(name, callback)
                context.closed = True
                callback()

            context.on = on
            return context

        self.driver.launch_persistent_context = close_after_registration
        profile = self.profile()
        try:
            self.coordinator.action(profile, "start")
        except WorkspaceError as exc:
            # The owner loop may report the close before start's first refresh.
            # That immediate rejection is as safe as observing it below.
            self.assertEqual(exc.code, "start_failed")
            self.assertEqual(exc.details["profile"]["state"], "recovery_required")
        handle = self.supervisor._handles[0]
        handle.launch_future.result(timeout=2)
        self.assertTrue(handle.ownership_uncertain)
        self.assertEqual(handle.phase, "unknown")
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 1)
        with self.assertRaises(ProfileInUseError):
            self.store.profiles.acquire(profile)

    def test_disconnect_noop_close_cannot_release_uncertain_profile_lease(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.settle(profile, "running")
        context = self.driver.contexts[0]
        context.callbacks["close"]()
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        try:
            self.coordinator.action(profile, "stop")
        except Exception:
            pass
        handle = self.supervisor._handles[0]
        if handle.stop_future is not None:
            handle.stop_future.result(timeout=2)
        self.coordinator.refresh()
        self.assertEqual(self.store.get(profile)["state"], "recovery_required")
        self.assertEqual(self.coordinator.resources()["resident_profiles"], 1)
        with self.assertRaises(ProfileInUseError):
            self.store.profiles.acquire(profile)

    def test_cancel_during_launch_does_not_focus_after_selection_changes(self):
        self.driver.delay = 0.15
        first, second = self.profile("First"), self.profile("Second")
        self.coordinator.action(first, "start")
        self.assertTrue(self.driver.entered.wait(1))
        self.coordinator.action(first, "cancel")
        self.coordinator.action(second, "select")
        self.settle(first, "stopped")
        self.assertEqual(self.store.selected(), second)
        self.assertEqual(self.driver.contexts[0].pages[0].focuses, 0)

    def test_newer_same_profile_selection_fences_older_preflight(self):
        pending, selected = self.profile("Pending"), self.profile("Selected")
        self.coordinator.action(selected, "select")
        entered, release = threading.Event(), threading.Event()
        original = self.coordinator.adapter.blockers

        def delayed(profile):
            entered.set()
            release.wait(2)
            return original(profile)

        self.coordinator.adapter.blockers = delayed
        outcomes = []

        def start_pending():
            try:
                outcomes.append(self.coordinator.action(pending, "start"))
            except Exception as error:
                outcomes.append(error)

        thread = threading.Thread(target=start_pending)
        thread.start()
        self.assertTrue(entered.wait(1))
        self.coordinator.action(selected, "select")
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(isinstance(outcomes[0], Exception), outcomes)
        self.assertEqual(self.store.selected(), selected)
        self.settle(pending, "warm")
        self.assertEqual(self.driver.contexts[0].pages[0].focuses, 0)

    def test_failed_gmail_navigation_is_not_cached_as_success_on_retry(self):
        profile = self.profile()
        self.coordinator.action(profile, "start")
        self.settle(profile, "running")

        class FailedPage:
            def is_closed(self):
                return False

            async def goto(self, target, **kwargs):
                raise RuntimeError("Synthetic Gmail navigation failure")

            async def bring_to_front(self):
                pass

        async def failed_page():
            return FailedPage()

        self.driver.contexts[0].new_page = failed_page
        for _ in range(2):
            with self.assertRaises(WorkspaceError) as caught:
                self.coordinator.action(
                    profile,
                    "start",
                    intent="gmail",
                    expected_revision=self.store.get(profile)["revision"],
                )
            self.assertEqual(caught.exception.code, "gmail_open_failed")

    def test_control_pipe_uses_isolated_profile_without_security_or_secret_flags(self):
        profile = self.profile()
        with mock_patch.dict(
            os.environ, {"LD_PRELOAD": "synthetic-invalid", "PASSWORD": "fake-value"}
        ):
            self.coordinator.action(profile, "start")
            self.settle(profile, "running")
        args, options = self.driver.calls[0]
        self.assertEqual(args[0], str(self.store.profiles.root / profile / "browser-data"))
        self.assertIs(options["chromium_sandbox"], True)
        self.assertIs(options["ignore_default_args"], True)
        self.assertIn("--remote-debugging-pipe", options["args"])
        self.assertFalse(any("remote-debugging-port" in arg for arg in options["args"]))
        self.assertFalse(
            any(
                flag in options["args"]
                for flag in (
                    "--no-sandbox",
                    "--password-store=basic",
                    "--use-mock-keychain",
                    "--disable-web-security",
                )
            )
        )
        self.assertNotIn("LD_PRELOAD", options["env"])
        self.assertNotIn("PASSWORD", options["env"])


class IndependentBundleMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "Synthetic Browser.app"
        self.executable = self.bundle / "Contents" / "MacOS" / "Synthetic Browser"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b"synthetic bytes, never executed")
        self.executable.chmod(0o600)
        self.info = self.bundle / "Contents" / "Info.plist"
        self.write_info()

    def write_info(self, values=None, fmt=plistlib.FMT_XML):
        self.info.write_bytes(
            plistlib.dumps(
                values
                or {
                    "CFBundleShortVersionString": "1.2.3",
                    "CFBundleExecutable": self.executable.name,
                },
                fmt=fmt,
            )
        )
        self.info.chmod(0o600)

    def test_xml_and_binary_version_observation_does_not_execute(self):
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            self.write_info(fmt=fmt)
            with mock_patch("subprocess.run", side_effect=AssertionError("Must not execute")):
                result = read_macos_bundle_metadata(self.executable)
            self.assertEqual(result.version, "1.2.3")
            self.assertEqual(result.executable_name, self.executable.name)
            self.assertEqual(result.info_sha256, hashlib.sha256(self.info.read_bytes()).hexdigest())

    def test_missing_invalid_mismatched_and_oversized_metadata_rejected(self):
        for values in (
            {"CFBundleExecutable": self.executable.name},
            {"CFBundleShortVersionString": 123, "CFBundleExecutable": self.executable.name},
            {"CFBundleShortVersionString": "1.2.3\n", "CFBundleExecutable": self.executable.name},
            {"CFBundleShortVersionString": "1.2.3", "CFBundleExecutable": "Other"},
        ):
            self.write_info(values)
            with self.assertRaises(RuntimeVerificationError):
                read_macos_bundle_metadata(self.executable)
        self.info.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)
        self.info.unlink()
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)

    def test_metadata_links_and_unsafe_permissions_are_rejected(self):
        self.info.chmod(0o666)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)
        self.info.chmod(0o600)
        outside = self.root / "same-file.plist"
        os.link(self.info, outside)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)
        outside.unlink()
        self.info.rename(outside)
        self.info.symlink_to(outside)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)
        self.info.unlink()
        outside.rename(self.info)
        contents = self.bundle / "Contents"
        renamed = self.bundle / "RealContents"
        contents.rename(renamed)
        contents.symlink_to(renamed, target_is_directory=True)
        with self.assertRaises(RuntimeVerificationError):
            read_macos_bundle_metadata(self.executable)

    def test_observed_version_and_metadata_cache_are_independent_of_policy(self):
        store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(store.close)
        calls = []

        class Verifier:
            def verify(self, executable, digest):
                calls.append(digest)
                return SignatureEvidence(digest, "qa", True, True, datetime.now(timezone.utc))

        class Supervisor:
            def check(self, runtime):
                pass

            def launch(self, *args, **kwargs):
                raise AssertionError("No execution permitted in metadata QA")

        policy = RuntimePolicy(
            "chromium", "1.2.3", hashlib.sha256(self.executable.read_bytes()).hexdigest(), "qa"
        )
        adapter = InstalledBrowserAdapter(
            profile_store=store.profiles,
            executable=self.executable,
            observed_version=None,
            policy=policy,
            runtime_gate=RuntimeGate(Verifier()),
            supervisor=Supervisor(),
            metadata_observer=read_macos_bundle_metadata,
        )
        self.assertEqual(adapter.global_blockers(), ())
        self.assertEqual(adapter.global_blockers(), ())
        self.assertEqual(len(calls), 1)
        self.write_info(
            {
                "CFBundleShortVersionString": "1.2.3",
                "CFBundleExecutable": self.executable.name,
                "SyntheticExtra": "changed",
            }
        )
        self.assertEqual(adapter.global_blockers(), ())
        self.assertEqual(len(calls), 2)
        profile = store.create("Synthetic metadata QA", network_policy="local_direct")
        self.assertEqual(adapter.blockers(profile), ())
        self.assertEqual(adapter.blockers(profile), ())
        self.assertEqual(
            len(calls),
            4,
            "Each new launch preflight must repeat whole-bundle signature verification",
        )
        self.write_info(
            {"CFBundleShortVersionString": "9.9.9", "CFBundleExecutable": self.executable.name}
        )
        self.assertTrue(adapter.global_blockers())
        self.assertEqual(
            len(calls), 4, "A version mismatch must block even if executable bytes are unchanged"
        )


class IndependentWipeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ProfileStore(Path(self.temp.name).resolve() / "profiles")
        self.lease = self.store.acquire("synthetic-wipe-qa")
        self.addCleanup(lambda: self.lease.release())
        self.fixture = self.lease.paths.browser_data / "synthetic.txt"
        self.fixture.write_text("Invented disposable wipe fixture")

    def test_callback_cannot_release_lease_then_authorize_deletion(self):
        def stops_but_releases(lease):
            lease.release()
            return True

        with self.assertRaises(WipeRejected):
            wipe_profile_data(self.lease, confirm_stopped=stops_but_releases)
        self.assertTrue(self.fixture.exists())

    def test_replaced_lock_inode_cannot_authorize_old_lease(self):
        lock_path = self.lease.paths.directory / ".lease.lock"
        lock_path.unlink()
        lock_path.write_text("synthetic replacement")
        lock_path.chmod(0o600)
        with self.assertRaises(WipeRejected):
            wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue(self.fixture.exists())

    def test_interruption_between_quarantine_and_mkdir_recovers_on_new_lease(self):
        real_mkdir = os.mkdir

        def interrupted_mkdir(path, *args, **kwargs):
            if path == "browser-data":
                raise OSError("Synthetic interruption")
            return real_mkdir(path, *args, **kwargs)

        with mock_patch("team_browser.local.wipe.os.mkdir", side_effect=interrupted_mkdir):
            with self.assertRaises(WipeRejected):
                wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertFalse(self.lease.paths.browser_data.exists())
        self.assertTrue(any(self.lease.paths.directory.glob(".wipe-*")))
        self.lease.release()
        self.lease = self.store.acquire("synthetic-wipe-qa")
        result = wipe_profile_data(self.lease, confirm_stopped=lambda lease: True)
        self.assertTrue(result.local_data_removed)
        self.assertFalse(any(self.lease.paths.directory.glob(".wipe-*")))
        self.assertFalse(self.fixture.exists())


if __name__ == "__main__":
    unittest.main()
