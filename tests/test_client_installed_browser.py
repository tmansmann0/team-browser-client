"""Installed runtime contract tests with synthetic bits and fake subprocess only.

These are not proof of vendor authenticity, native vault support, window focus,
actual browser compatibility, proxy behavior or real process-tree supervision.
"""

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.client import LifecycleCoordinator, WorkspaceError, WorkspaceStore
from team_browser.client.installed_browser import (
    InstalledBrowserAdapter,
    LinuxSubprocessSupervisor,
    MacOSCodeSignatureVerifier,
    OwnedProcessHandle,
    SupervisionAcceptance,
    load_installed_adapter,
)
from team_browser.client.lifecycle import GMAIL_INBOX_URL, LaunchContext, ProcessStatus
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence


class FixtureSignatureVerifier:
    def verify(self, executable, digest):
        return SignatureEvidence(digest, "FIXTURE:chromium", True, True, datetime.now(timezone.utc))


class FixtureVault:
    def assert_available(self):
        pass


class FixtureWindows:
    def ready(self, profile_id, pid):
        return True

    def focus(self, profile_id, pid):
        return True

    def open_gmail(self, profile_id, pid):
        return True


class FixtureHandle:
    def __init__(self):
        self.alive = True

    def status(self):
        return ProcessStatus(self.alive, self.alive)

    def stop(self):
        self.alive = False
        return True

    def focus(self):
        return self.alive

    def open_gmail(self):
        return self.alive


class FixtureSupervisor(LinuxSubprocessSupervisor):
    def __init__(self):
        self.launches = []

    def check(self, runtime):
        pass

    def launch(self, runtime, context, argv, *, home):
        self.launches.append((runtime, context, argv, home))
        return FixtureHandle()


class InstalledBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(self.store.close)
        self.binary = self.root / "synthetic-chromium"
        self.binary.write_bytes(b"synthetic binary fixture; must never execute")
        self.binary.chmod(0o700)
        self.policy = RuntimePolicy(
            "chromium",
            "1.0-fixture",
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "FIXTURE:chromium",
        )
        self.gate = RuntimeGate(FixtureSignatureVerifier())
        self.supervisor = FixtureSupervisor()
        self.adapter = self.make_adapter()
        self.coordinator = LifecycleCoordinator(self.store, self.adapter)
        self.addCleanup(self.coordinator.shutdown)

    def make_adapter(self, *, supervisor=None, vault=True):
        return InstalledBrowserAdapter(
            profile_store=self.store.profiles,
            executable=self.binary,
            observed_version=self.policy.version,
            policy=self.policy,
            runtime_gate=self.gate,
            supervisor=supervisor or self.supervisor,
            vault=FixtureVault() if vault else None,
        )

    def test_explicit_local_direct_uses_only_owned_profile_and_fixed_flags(self):
        profile = self.store.create("Direct fixture", network_policy="local_direct")
        result = self.coordinator.action(
            profile["id"], "start", intent="gmail", expected_revision=1
        )
        self.assertEqual(result["profile"]["state"], "running")
        runtime, context, argv, home = self.supervisor.launches[0]
        self.assertEqual(context.initial_url, GMAIL_INBOX_URL)
        self.assertIn("--no-proxy-server", argv)
        self.assertIn(
            f"--user-data-dir={self.store.profiles.root / profile['id'] / 'browser-data'}", argv
        )
        self.assertNotIn("--no-sandbox", argv)
        self.assertNotIn("--disable-web-security", argv)
        self.assertFalse(any("password" in arg for arg in argv))
        self.assertEqual(home, self.store.root)
        self.assertTrue(context.lease.active)
        self.coordinator.action(profile["id"], "start")
        self.assertEqual(len(self.supervisor.launches), 1)

    def test_default_choice_managed_direct_and_unverified_proxy_are_blocked(self):
        for network, origin in (
            ("unconfigured", "local"),
            ("local_direct", "managed"),
            ("verified_proxy", "local"),
            ("verified_proxy", "managed"),
        ):
            with self.subTest(network=network, origin=origin):
                profile = self.store.create("Blocked fixture", network_policy=network)
                self.store.db.execute(
                    "UPDATE profiles SET origin=? WHERE id=?", (origin, profile["id"])
                )
                with self.assertRaises(WorkspaceError):
                    self.coordinator.action(profile["id"], "start")
        self.assertEqual(self.supervisor.launches, [])

    def test_missing_vault_and_lifetime_acceptance_block(self):
        profile = self.store.create("Missing prerequisites", network_policy="local_direct")
        self.assertEqual(self.make_adapter(vault=False).blockers(profile), ())
        self.assertTrue(self.make_adapter(supervisor=LinuxSubprocessSupervisor()).blockers(profile))
        self.assertEqual(self.supervisor.launches, [])

    def test_runtime_update_invalidates_policy(self):
        profile = self.store.create("Updated runtime", network_policy="local_direct")
        self.binary.write_bytes(b"different runtime release")
        self.assertTrue(self.adapter.blockers(profile))
        self.assertEqual(self.supervisor.launches, [])

    def test_no_lease_no_fresh_approval_or_arbitrary_target(self):
        profile = self.store.create("Fixture", network_policy="local_direct")
        paths = self.store.profiles.prepare(profile["id"])
        context = LaunchContext(profile["id"], "chromium", paths.browser_data, 1)
        with self.assertRaises(WorkspaceError):
            self.adapter.start(context)
        self.assertEqual(self.adapter.blockers(profile), ())
        with self.assertRaises(WorkspaceError) as caught:
            self.adapter.start(context)
        self.assertEqual(caught.exception.code, "profile_lease_required")
        with self.store.profiles.acquire(profile["id"]) as lease:
            self.assertEqual(self.adapter.blockers(profile), ())
            context = LaunchContext(
                profile["id"], "chromium", paths.browser_data, 1, "https://arbitrary.example", lease
            )
            with self.assertRaises(WorkspaceError) as caught:
                self.adapter.start(context)
            self.assertEqual(caught.exception.code, "launch_context_mismatch")
        self.assertEqual(self.supervisor.launches, [])

    def test_subprocess_contract_uses_fd_no_shell_and_scrubbed_environment(self):
        runtime = self.gate.verify(
            self.binary, observed_version=self.policy.version, policy=self.policy
        )
        profile = self.store.create("Subprocess fixture", network_policy="local_direct")
        acceptance = SupervisionAcceptance(runtime.sha256, "linux", "synthetic-contract-only")
        supervisor = LinuxSubprocessSupervisor(FixtureWindows(), acceptance)
        with self.store.profiles.acquire(profile["id"]) as lease:
            context = LaunchContext(
                profile["id"], "chromium", lease.paths.browser_data, 1, "about:blank", lease
            )
            fake_process = SimpleNamespace(pid=12345, poll=lambda: None)
            with patch(
                "team_browser.client.installed_browser.subprocess.Popen", return_value=fake_process
            ) as popen:
                with patch.dict(
                    os.environ, {"LD_PRELOAD": "unsafe", "PASSWORD": "synthetic-not-secret"}
                ):
                    supervisor.launch(
                        runtime, context, (str(self.binary), "about:blank"), home=self.store.root
                    )
            kwargs = popen.call_args.kwargs
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["close_fds"])
            self.assertTrue(kwargs["start_new_session"])
            self.assertTrue(kwargs["executable"].startswith("/proc/self/fd/"))
            self.assertEqual(len(kwargs["pass_fds"]), 1)
            self.assertNotIn("LD_PRELOAD", kwargs["env"])
            self.assertNotIn("PASSWORD", kwargs["env"])

    def test_lost_leader_or_group_is_uncertain_never_claimed_stopped(self):
        context = LaunchContext("local_fixture", "chromium", self.root, 1)
        process = SimpleNamespace(pid=12345, poll=lambda: 0)
        handle = OwnedProcessHandle(process, context, FixtureWindows())
        with patch("team_browser.client.installed_browser.os.killpg", return_value=None):
            with self.assertRaises(WorkspaceError):
                handle.status()
            self.assertFalse(handle.stop())
        process = SimpleNamespace(pid=12345, poll=lambda: None)
        handle = OwnedProcessHandle(process, context, FixtureWindows())
        with patch(
            "team_browser.client.installed_browser.os.killpg", side_effect=ProcessLookupError
        ):
            with self.assertRaises(WorkspaceError):
                handle.status()
            with self.assertRaises(WorkspaceError):
                handle.status()  # Must not label a living escaped leader ended on next check.

    def test_local_policy_file_cannot_assert_trust_or_secrets(self):
        config = {
            "executable": str(self.binary),
            "engine_id": "chromium",
            "version": self.policy.version,
            "sha256": self.policy.sha256,
            "signer_identity": self.policy.signer_identity,
            "require_notarization": True,
        }
        path = self.root / "runtime-policy.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        adapter = load_installed_adapter(path, self.store.profiles)
        self.assertTrue(adapter.global_blockers())
        for field in ("trusted", "argv", "vault_password", "supervision_accepted"):
            path.write_text(json.dumps({**config, field: True}))
            with self.assertRaises(WorkspaceError):
                load_installed_adapter(path, self.store.profiles)
        path.write_text(json.dumps(config))
        path.chmod(0o644)
        with self.assertRaises(WorkspaceError):
            load_installed_adapter(path, self.store.profiles)

    def test_mac_signature_command_contract_and_notarization(self):
        bundle = self.root / "Synthetic Chrome.app"
        executable = bundle / "Contents" / "MacOS" / "Chrome"
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            text = (
                "source=Notarized Developer ID"
                if command[0].endswith("spctl")
                else "TeamIdentifier=TESTTEAM\nIdentifier=com.example.synthetic"
            )
            return SimpleNamespace(returncode=0, stdout="", stderr=text)

        with patch("team_browser.client.installed_browser.sys.platform", "darwin"):
            evidence = MacOSCodeSignatureVerifier(runner).verify(executable, self.policy.sha256)
        self.assertEqual(evidence.signer_identity, "TESTTEAM:com.example.synthetic")
        self.assertTrue(evidence.notarized)
        self.assertEqual(len(calls), 3)
        self.assertTrue(
            all(call[1]["shell"] is False and call[1]["timeout"] == 15 for call in calls)
        )
        self.assertEqual(calls[0][0][:4], ("/usr/bin/codesign", "--verify", "--deep", "--strict"))
