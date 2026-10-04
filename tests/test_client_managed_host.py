"""Synthetic lifecycle tests; no credentials, native Keychain or provider traffic."""

import json
import socket
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest.mock import patch

from team_browser.client import managed_host as host
from team_browser.client import managed_session as managed
from team_browser.client import session_vault as vault_module
from team_browser.client import signin_callback as callback_module
from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthResult,
    AuthStatus,
    HTTPResponse,
    entra_native_configuration,
)
from team_browser.client.managed_session import (
    ManagedMembership,
    ManagedPreset,
    ManagedProfile,
    ManagedSessionError,
    ManagedSnapshot,
    ManagedStatus,
    MemberRole,
    TrustedBackendConfiguration,
)
from team_browser.client.signin_callback import SignInSnapshot
from team_browser.local.macos_keychain import KeychainConfiguration, SecretNotFound


OIDC = entra_native_configuration(
    tenant_id="11111111-1111-4111-8111-111111111111",
    desktop_client_id="22222222-2222-4222-8222-222222222222",
    api_client_id="33333333-3333-4333-8333-333333333333",
)
BACKEND = TrustedBackendConfiguration("https://managed.example.test", OIDC)
KEYCHAIN = KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", "managed-signin")
MEMBER = ManagedMembership("member-a", "company-a", "Synthetic Member", MemberRole.MEMBER)
PROFILE = ManagedProfile("profile-a", "Synthetic", "preset-a", "member-a", 1, "unprovisioned")
PRESET = ManagedPreset("preset-a", "Synthetic", "normal-browser", "en-US", "UTC", True, 1)
SECRET = "NEVER_EXPOSE_SYNTHETIC_NATIVE_DETAIL"


class Fixture:
    def __init__(self):
        self.wall, self.mono = float(int(time.time())), 1000.0
        self.calls = []
        self.threads = []
        self.hooks = {}
        self.vaults, self.coordinators, self.sessions = [], [], []
        self.current = None
        self.delete_count = 0
        self.recover_count = 0
        self.close_count = 0
        self.gates = []
        self.cleanup_error = False
        self.recover_error = False
        self.cancel_cleanup = False

    def call(self, name):
        self.calls.append(name)
        self.threads.append(threading.get_ident())
        hook = self.hooks.get(name)
        if hook:
            hook()

    def block(self, name):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)

        def wait():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Test failed to release a synthetic native gate")

        self.hooks[name] = wait
        return entered, release

    def vault(self, configuration, *, oidc_configuration):
        self.call("vault_construct")
        assert configuration == KEYCHAIN and oidc_configuration == OIDC
        fixture = self

        class Vault:
            def recover_discard_all(self):
                fixture.call("recover")
                fixture.recover_count += 1
                if fixture.recover_error:
                    raise RuntimeError(SECRET)
                fixture.current = None

            def close(self):
                fixture.call("close")
                fixture.close_count += 1

        result = Vault()
        self.vaults.append(result)
        return result

    def transport(self, configuration):
        self.call("transport_construct")
        assert configuration == OIDC
        return object()

    def coordinator(self, configuration, *, transport, vault):
        self.call("coordinator_construct")
        assert configuration == OIDC and vault in self.vaults
        fixture = self

        class Attempt:
            def __init__(self):
                self.finished = threading.Event()
                self.started = False
                self.cancel_requested = False
                self.terminal = False
                self.result = AuthResult(AuthStatus.READY, "native_start_required")
                self._vault = SimpleNamespace(discard_unpublished_commit=self.discard)

            def discard(self):
                fixture.call("discard_exact_callback")
                fixture.delete_count += 1
                if fixture.cleanup_error:
                    raise RuntimeError(SECRET)
                if fixture.current != "exact-owned-session":
                    raise RuntimeError("Cannot delete another session")
                fixture.current = None

            def snapshot(self):
                return SignInSnapshot(
                    self.result,
                    self.started and not self.finished.is_set(),
                    self.finished.is_set(),
                    self.cancel_requested,
                    self.started and not self.finished.is_set(),
                    not self.terminal and not self.finished.is_set(),
                )

            def start(self):
                fixture.call("start")
                self.started = True
                self.result = AuthResult(AuthStatus.WAITING, "awaiting_callback")
                return self.snapshot()

            def cancel(self):
                if not self.terminal and not self.finished.is_set():
                    self.cancel_requested = True
                    if not self.started:
                        self.finish(AuthStatus.CANCELLED)
                return self.snapshot()

            def wait_finished(self, timeout=None):
                return self.finished.wait(timeout)

            def finish(self, status=AuthStatus.IDENTITY_VERIFIED, *, settled=True):
                if status == AuthStatus.IDENTITY_VERIFIED:
                    fixture.current = "exact-owned-session"
                    self.result = AuthResult(
                        status,
                        "identity_verified",
                        AccountIdentity(OIDC.issuer, SECRET),
                        int(fixture.wall) + 300,
                    )
                else:
                    self.result = AuthResult(status, SECRET)
                    if status == AuthStatus.CANCELLED and fixture.cancel_cleanup:
                        self.discard()
                self.terminal = True
                if settled:
                    self.finished.set()

        result = Attempt()
        self.coordinators.append(result)
        return result

    def session(self, configuration, *, vault):
        self.call("session_construct")
        assert configuration == BACKEND and vault in self.vaults
        fixture = self

        class Session:
            def __init__(self):
                self.bound = fixture.current

            def me(self):
                fixture.call("me")
                return MEMBER

            def profiles(self):
                fixture.call("profiles")
                return (PROFILE,)

            def presets(self):
                fixture.call("presets")
                return (PRESET,)

            def snapshot(self):
                fixture.call("session_snapshot")
                return ManagedSnapshot(ManagedStatus.AVAILABLE, MEMBER, int(fixture.wall) + 300)

            def logout(self):
                fixture.call("logout")
                fixture.delete_count += 1
                if fixture.cleanup_error:
                    raise ManagedSessionError("local_logout_unconfirmed")
                if fixture.current != self.bound:
                    raise ManagedSessionError("local_logout_unconfirmed")
                fixture.current = None
                return ManagedSnapshot(ManagedStatus.LOGGED_OUT, None)

        result = Session()
        self.sessions.append(result)
        return result


class ManagedHostTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.f = Fixture()
        for name, replacement in (
            ("MacOSSessionVault", self.f.vault),
            ("NativeOIDCHTTPSTransport", self.f.transport),
            ("NativeSignInCoordinator", self.f.coordinator),
            ("NativeManagedSession", self.f.session),
            ("time", SimpleNamespace(time=lambda: self.f.wall, monotonic=lambda: self.f.mono)),
        ):
            self.stack.enter_context(patch.object(host, name, replacement))
        self.host = host.NativeManagedHost(OIDC, BACKEND, KEYCHAIN)
        self.addCleanup(self.cleanup_host)

    def cleanup_host(self):
        for gate in self.f.gates:
            gate.set()
        for coordinator in self.f.coordinators:
            if not coordinator.finished.is_set():
                coordinator.finish(AuthStatus.CANCELLED)
        self.host.shutdown()
        self.assertTrue(self.host.wait_closed(3), "Synthetic workers did not settle")

    def wait(self, predicate):
        until = time.monotonic() + 3
        while not predicate():
            if time.monotonic() >= until:
                self.fail(f"Synthetic state did not settle: {self.host.snapshot().public()}")
            time.sleep(0.002)

    def status(self, status):
        self.wait(
            lambda: (
                self.host.snapshot().status == status
                and not self.host.snapshot().native_operations_pending
            )
        )
        return self.host.snapshot().public()

    def prepared(self):
        self.host.prepare()
        self.status(host.HostStatus.READY)

    def started(self):
        self.prepared()
        self.host.sign_in()
        self.wait(lambda: bool(self.f.coordinators) and self.f.coordinators[-1].started)
        return self.f.coordinators[-1]

    def available(self):
        coordinator = self.started()
        coordinator.finish()
        return self.status(host.HostStatus.AVAILABLE)

    def test_construction_and_snapshots_are_inert(self):
        self.assertEqual(self.f.calls, [])
        for action in (
            self.host.snapshot,
            self.host.sign_in,
            self.host.refresh_records,
            self.host.sign_out,
        ):
            self.assertEqual(action().status, host.HostStatus.PREPARATION_REQUIRED)
        self.assertEqual(self.f.calls, [])

    def test_worker_start_failure_is_sanitized_without_automatic_retry(self):
        with patch.object(threading.Thread, "start", side_effect=RuntimeError(SECRET)):
            projection = self.host.prepare().public()
        self.assertEqual(projection["status"], "recovery_required")
        self.assertNotIn(SECRET, json.dumps(projection))
        self.assertFalse(projection["native_operations_pending"])
        self.assertEqual(self.f.calls, [])
        self.host.recover()
        self.status(host.HostStatus.READY)
        self.assertEqual(self.f.recover_count, 1)

    def test_configuration_exact_types_and_matching_policy(self):
        class Derived(type(OIDC)):
            pass

        for oidc, backend, keychain in (
            ({}, BACKEND, KEYCHAIN),
            (OIDC, {}, KEYCHAIN),
            (OIDC, BACKEND, {}),
            (Derived(**OIDC.__dict__), BACKEND, KEYCHAIN),
            (OIDC, BACKEND, replace(KEYCHAIN, namespace="proxy")),
            (replace(OIDC, local_session_ttl_seconds=60), BACKEND, KEYCHAIN),
        ):
            with self.subTest(oidc=type(oidc), keychain=type(keychain)):
                with self.assertRaises((TypeError, ValueError)):
                    host.NativeManagedHost(oidc, backend, keychain)
        self.assertEqual(self.f.calls, [])

    def test_no_production_adapter_or_url_arguments(self):
        with self.assertRaises(TypeError):
            host.NativeManagedHost(OIDC, BACKEND, KEYCHAIN, vault=object())
        with self.assertRaises(TypeError):
            self.host.sign_in(url=SECRET)
        with self.assertRaises(TypeError):
            self.host.refresh_records(url=SECRET)

    def test_unconfigured_projection_is_complete_and_safe(self):
        projection = host.unconfigured_snapshot().public()
        self.assertFalse(projection["configured"])
        self.assertIsNone(projection["expires_at"])
        self.assertEqual(projection["profiles"], [])
        self.assertEqual(projection["presets"], [])
        self.assertTrue(all(value is False for value in projection["capabilities"].values()))

    def test_prepare_is_explicit_async_and_duplicate_bounded(self):
        entered, release = self.f.block("recover")
        self.host.prepare()
        self.assertTrue(entered.wait(1))
        for _ in range(50):
            self.host.prepare()
            self.host.recover()
            self.host.sign_in()
        self.assertEqual(self.f.recover_count, 0)
        self.assertEqual(self.f.calls, ["vault_construct", "recover"])
        self.assertTrue(self.host.snapshot().native_operations_pending)
        release.set()
        self.status(host.HostStatus.READY)
        self.assertEqual(self.f.recover_count, 1)
        self.assertNotIn(threading.get_ident(), self.f.threads)

    def test_identity_success_must_settle_before_consumer_construction(self):
        coordinator = self.started()
        coordinator.finish(settled=False)
        self.assertFalse(self.host.snapshot().can_cancel)
        self.host.cancel_sign_in()
        self.assertFalse(coordinator.cancel_requested)
        self.assertNotIn("session_construct", self.f.calls)
        self.assertFalse(self.host.snapshot().identity_verified)
        coordinator.finished.set()
        projection = self.status(host.HostStatus.AVAILABLE)
        self.assertTrue(projection["identity_verified"])
        self.assertTrue(projection["company_membership_verified"])
        self.assertFalse(projection["device_enrolled"])

    def test_membership_requires_me_and_initial_lists_are_not_requested(self):
        entered, release = self.f.block("me")
        coordinator = self.started()
        coordinator.finish()
        self.assertTrue(entered.wait(1))
        projection = self.host.snapshot().public()
        self.assertEqual(projection["status"], "membership_unverified")
        self.assertTrue(projection["identity_verified"])
        self.assertFalse(projection["company_membership_verified"])
        self.assertIsNone(projection["membership"])
        release.set()
        self.status(host.HostStatus.AVAILABLE)
        self.assertFalse(self.host.snapshot().public()["records_loaded"])
        self.assertNotIn("profiles", self.f.calls)
        self.assertNotIn("presets", self.f.calls)
        self.assertNotIn(threading.get_ident(), self.f.threads)

    def test_duplicate_sign_in_never_relaunches(self):
        coordinator = self.started()
        for _ in range(100):
            self.host.sign_in()
        self.assertEqual(self.f.calls.count("start"), 1)
        coordinator.finish(AuthStatus.CANCELLED)
        self.status(host.HostStatus.CANCELLED)

    def test_cancel_is_callback_only_and_new_attempt_is_explicit(self):
        coordinator = self.started()
        projection = self.host.cancel_sign_in().public()
        self.assertTrue(projection["cancellation_requested"])
        self.assertEqual(projection["status"], "cancelling")
        coordinator.finish(AuthStatus.CANCELLED)
        self.status(host.HostStatus.CANCELLED)
        self.assertEqual(self.f.delete_count, 0)
        self.assertEqual(len(self.f.coordinators), 1)
        self.host.sign_in()
        self.wait(lambda: len(self.f.coordinators) == 2)

    def test_cancel_after_success_is_honest_noop(self):
        self.available()
        projection = self.host.cancel_sign_in().public()
        self.assertEqual(projection["status"], "available")
        self.assertFalse(projection["can_cancel"])
        self.assertFalse(projection["cancellation_requested"])
        self.assertEqual(self.f.delete_count, 0)

    def test_refresh_is_one_bounded_operation_and_projects_records(self):
        self.available()
        entered, release = self.f.block("profiles")
        self.host.refresh_records()
        self.assertTrue(entered.wait(1))
        for _ in range(50):
            self.host.refresh_records()
        release.set()
        projection = self.status(host.HostStatus.AVAILABLE)
        self.assertTrue(projection["records_loaded"])
        self.assertEqual(projection["profiles"], [PROFILE.public()])
        self.assertEqual(projection["presets"], [PRESET.public()])
        self.assertEqual(self.f.calls.count("me"), 2)
        self.assertEqual(self.f.calls.count("profiles"), 1)
        self.assertEqual(self.f.calls.count("presets"), 1)

    def test_sign_out_immediately_hides_and_fences_blocked_refresh(self):
        self.available()
        entered, release = self.f.block("me")
        self.host.refresh_records()
        self.assertTrue(entered.wait(1))
        projection = self.host.sign_out().public()
        self.assertEqual(projection["status"], "signing_out")
        for key in ("identity_verified", "company_membership_verified", "managed_access_available"):
            self.assertFalse(projection[key])
        self.assertIsNone(projection["membership"])
        self.assertEqual(projection["profiles"], [])
        for _ in range(30):
            self.host.sign_out()
            self.host.recover()
            self.host.sign_in()
        self.assertEqual(self.f.delete_count, 0)
        self.assertFalse(self.host.snapshot().can_prepare)
        release.set()
        self.status(host.HostStatus.SIGNED_OUT)
        self.assertEqual(self.f.delete_count, 1)
        self.assertNotIn("profiles", self.f.calls)
        self.assertIsNone(self.f.current)

    def test_sign_out_during_consumer_bind_skips_me_and_deletes_once(self):
        entered, release = self.f.block("session_construct")
        coordinator = self.started()
        coordinator.finish()
        self.assertTrue(entered.wait(1))
        self.host.sign_out()
        release.set()
        self.status(host.HostStatus.SIGNED_OUT)
        self.assertNotIn("me", self.f.calls)
        self.assertEqual(self.f.delete_count, 1)

    def test_sign_out_after_callback_publication_before_settlement_deletes_exact_commit(self):
        coordinator = self.started()
        coordinator.finish(settled=False)
        self.host.sign_out()
        self.assertFalse(coordinator.cancel_requested)
        self.assertEqual(self.f.delete_count, 0)
        coordinator.finished.set()
        self.status(host.HostStatus.SIGNED_OUT)
        self.assertEqual(self.f.calls.count("discard_exact_callback"), 1)
        self.assertNotIn("session_construct", self.f.calls)
        self.assertEqual(self.f.recover_count, 1)

    def test_sign_out_accepted_cancel_does_not_repeat_callback_cleanup(self):
        coordinator = self.started()
        self.f.current = "exact-owned-session"
        self.f.cancel_cleanup = True
        self.host.sign_out()
        coordinator.finish(AuthStatus.CANCELLED)
        self.status(host.HostStatus.SIGNED_OUT)
        self.assertEqual(self.f.delete_count, 1)
        self.assertEqual(self.f.calls.count("discard_exact_callback"), 1)

    def test_uncertain_callback_retains_ownership_until_settlement_and_explicit_recovery(self):
        coordinator = self.started()
        coordinator.finish(AuthStatus.RECOVERY_REQUIRED, settled=False)
        self.host.recover()
        self.host.sign_in()
        self.assertEqual(self.f.recover_count, 1)
        self.assertFalse(self.host.snapshot().can_prepare)
        coordinator.finished.set()
        self.status(host.HostStatus.RECOVERY_REQUIRED)
        self.assertEqual(self.f.recover_count, 1)
        self.host.recover()
        self.status(host.HostStatus.READY)
        self.assertEqual(self.f.recover_count, 2)

    def test_network_error_does_not_retry_and_clears_cached_records(self):
        self.available()
        self.host.refresh_records()
        self.status(host.HostStatus.AVAILABLE)

        def fail():
            raise ManagedSessionError(SECRET)

        self.f.hooks["profiles"] = fail
        self.host.refresh_records()
        projection = self.status(host.HostStatus.UNAVAILABLE)
        self.assertEqual(projection["profiles"], [])
        self.assertIsNone(projection["membership"])
        count = len(self.f.calls)
        self.host.refresh_records()
        self.host.sign_in()
        self.assertEqual(len(self.f.calls), count)
        self.assertNotIn(SECRET, json.dumps(projection))

    def test_denial_and_membership_change_have_fixed_diagnostics(self):
        for reason, status, expected in (
            ("membership_denied", host.HostStatus.MEMBERSHIP_DENIED, "membership_denied"),
            ("membership_changed", host.HostStatus.UNAVAILABLE, "membership_changed"),
        ):
            with self.subTest(reason=reason):
                if self.host.snapshot().status != host.HostStatus.PREPARATION_REQUIRED:
                    self.f.hooks.clear()
                    self.host.recover()
                    self.status(host.HostStatus.READY)
                    count = len(self.f.coordinators)
                    self.host.sign_in()
                    self.wait(
                        lambda: (
                            len(self.f.coordinators) == count + 1
                            and self.f.coordinators[-1].started
                        )
                    )
                    self.f.coordinators[-1].finish()
                    self.status(host.HostStatus.AVAILABLE)
                else:
                    self.available()

                def fail(reason=reason):
                    raise ManagedSessionError(reason)

                self.f.hooks["me"] = fail
                self.host.refresh_records()
                projection = self.status(status)
                self.assertEqual(projection["reason"], expected)
                self.assertFalse(projection["identity_verified"])

    def test_sign_out_cleanup_uncertainty_is_not_automatically_retried_at_shutdown(self):
        self.available()
        self.f.cleanup_error = True
        self.host.sign_out()
        self.status(host.HostStatus.RECOVERY_REQUIRED)
        self.assertEqual(self.f.delete_count, 1)
        self.host.shutdown()
        self.assertTrue(self.host.wait_closed(1))
        self.assertEqual(self.f.delete_count, 1)
        self.assertEqual(self.host.snapshot().status, host.HostStatus.RECOVERY_REQUIRED)

    def test_exact_cleanup_will_not_delete_a_replacement_record(self):
        self.available()
        self.f.current = "newer-unrelated-session"
        self.host.sign_out()
        self.status(host.HostStatus.RECOVERY_REQUIRED)
        self.assertEqual(self.f.current, "newer-unrelated-session")
        self.assertEqual(self.f.recover_count, 1)

    def test_explicit_recovery_after_error_resets_only_after_success(self):
        self.f.recover_error = True
        self.host.prepare()
        self.status(host.HostStatus.RECOVERY_REQUIRED)
        self.host.sign_in()
        self.assertNotIn("start", self.f.calls)
        self.f.recover_error = False
        self.host.recover()
        self.status(host.HostStatus.READY)
        self.assertEqual(self.f.recover_count, 2)
        self.assertEqual(len(self.f.vaults), 1)

    def test_cached_snapshot_clamps_wall_expiry_without_io(self):
        self.available()
        cached = self.host.snapshot()
        count = len(self.f.calls)
        self.f.wall += 301
        self.assertEqual(cached.public()["status"], "expired")
        projection = self.host.snapshot().public()
        self.assertEqual(projection["status"], "expired")
        self.assertFalse(projection["managed_access_available"])
        self.assertEqual(len(self.f.calls), count)
        self.f.wall -= 301
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)

    def test_cached_snapshot_clamps_monotonic_and_backward_clock(self):
        self.available()
        cached = self.host.snapshot()
        self.f.mono += 301
        self.assertEqual(cached.public()["status"], "expired")
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)

    def test_wall_rollback_invalidates_available_cache(self):
        self.available()
        self.f.wall -= 1
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)

    def test_invalid_clock_invalidates_available_cache(self):
        self.available()
        self.f.mono = float("nan")
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)

    def test_expiry_during_blocked_me_never_publishes_membership(self):
        entered, release = self.f.block("me")
        coordinator = self.started()
        coordinator.finish()
        self.assertTrue(entered.wait(1))
        self.f.mono += 301
        self.assertEqual(self.host.snapshot().status, host.HostStatus.EXPIRED)
        release.set()
        self.status(host.HostStatus.EXPIRED)
        self.assertIsNone(self.host.snapshot().membership)

    def test_shutdown_keeps_vault_while_callback_workers_block(self):
        coordinator = self.started()
        projection = self.host.shutdown().public()
        self.assertTrue(projection["shutting_down"])
        self.assertFalse(projection["closed"])
        self.assertTrue(projection["native_operations_pending"])
        self.assertFalse(self.host.wait_closed(0.02))
        self.assertEqual(self.f.close_count, 0)
        coordinator.finish(AuthStatus.CANCELLED)
        self.assertTrue(self.host.wait_closed(1))
        self.assertEqual(self.f.close_count, 1)
        self.assertEqual(self.host.snapshot().status, host.HostStatus.CLOSED)

    def test_shutdown_keeps_vault_until_read_and_logout_settle(self):
        self.available()
        entered, release = self.f.block("me")
        self.host.refresh_records()
        self.assertTrue(entered.wait(1))
        self.host.shutdown()
        self.assertFalse(self.host.wait_closed(0.02))
        self.assertEqual(self.f.close_count, 0)
        release.set()
        self.assertTrue(self.host.wait_closed(1))
        self.assertEqual(self.f.calls[-2:], ["logout", "close"])

    def test_blocked_native_close_is_reported_pending(self):
        self.prepared()
        entered, release = self.f.block("close")
        self.host.shutdown()
        self.assertTrue(entered.wait(1))
        self.assertTrue(self.host.snapshot().native_operations_pending)
        self.assertFalse(self.host.wait_closed(0.02))
        release.set()
        self.assertTrue(self.host.wait_closed(1))

    def test_shutdown_without_preparation_is_inert(self):
        self.host.shutdown()
        self.assertTrue(self.host.wait_closed(0))
        self.assertEqual(self.f.calls, [])
        self.assertFalse(self.host.snapshot().can_prepare)

    def test_no_identity_urls_session_references_or_exception_text_cross_projection(self):
        self.available()
        self.host.refresh_records()
        projection = self.status(host.HostStatus.AVAILABLE)
        encoded = json.dumps(projection)
        for forbidden in (
            SECRET,
            OIDC.issuer,
            OIDC.authorization_endpoint,
            BACKEND.origin,
            "exact-owned-session",
            "access_token",
            "id_token",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("identity", projection)


class ConcreteCompositionTests(unittest.TestCase):
    """Real host/coordinator/core/vault/consumer, synthetic storage/provider seams.

    The sole network is an exact disposable 127.0.0.1 callback socket. No
    production adapter constructor is replaced in these composition checks.
    """

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.oidc = entra_native_configuration(
            tenant_id="11111111-1111-4111-8111-111111111111",
            desktop_client_id="22222222-2222-4222-8222-222222222222",
            api_client_id="33333333-3333-4333-8333-333333333333",
            loopback_port=port,
        )
        self.backend = TrustedBackendConfiguration("https://managed.example.test", self.oidc)
        self.items = {}
        self.os_threads = []
        self.delete_count = 0
        self.opened = threading.Event()
        self.exchange_entered, self.exchange_release = threading.Event(), threading.Event()
        self.exchange_release.set()
        self.urls = []
        self.backend_calls = []
        self.provider_calls = []
        self.backend_hook = None
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        self.jwk.update(kid="synthetic-signing-key", alg="RS256", use="sig")
        fixture = self

        class Store:
            def get(self, reference):
                fixture.os_threads.append(threading.get_ident())
                if reference.account_id not in fixture.items:
                    raise SecretNotFound()
                return fixture.items[reference.account_id]

            def put(self, reference, value):
                fixture.os_threads.append(threading.get_ident())
                fixture.items[reference.account_id] = value

            def delete(self, reference):
                fixture.os_threads.append(threading.get_ident())
                fixture.delete_count += 1
                fixture.items.pop(reference.account_id, None)

        self.stack.enter_context(
            patch.object(vault_module, "_open_native_store", return_value=Store())
        )
        self.stack.enter_context(
            patch.object(vault_module, "_lease_directory", return_value=Path(self.temp) / "lease")
        )
        self.stack.enter_context(
            patch.object(callback_module, "_launch_macos_authorization", side_effect=self.open)
        )
        self.stack.enter_context(
            patch.object(
                host.NativeOIDCHTTPSTransport, "_request", autospec=True, side_effect=self.provider
            )
        )
        self.stack.enter_context(
            patch.object(
                managed._BackendHTTPS, "_get", autospec=True, side_effect=self.backend_read
            )
        )
        self.host = host.NativeManagedHost(self.oidc, self.backend, KEYCHAIN)
        self.addCleanup(self.close)

    def close(self):
        self.exchange_release.set()
        self.host.shutdown()
        self.assertTrue(self.host.wait_closed(3))

    def open(self, url, endpoint):
        self.assertEqual(endpoint, self.oidc.authorization_endpoint)
        self.urls.append(url)
        self.opened.set()

    def response(self, url, data):
        return HTTPResponse(200, url, json.dumps(data).encode())

    def provider(self, transport, method, url, fields, timeout, redirects):
        self.provider_calls.append((method, url))
        if method == "GET":
            self.assertEqual(url, self.oidc.jwks_endpoint)
            return self.response(url, {"keys": [self.jwk]})
        self.assertEqual(url, self.oidc.token_endpoint)
        self.exchange_entered.set()
        if not self.exchange_release.wait(5):
            raise RuntimeError("Synthetic exchange gate was not released")
        nonce = parse_qs(urlsplit(self.urls[-1]).query)["nonce"][0]
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": self.oidc.issuer,
                "tid": self.oidc.provider_policy.tenant_id,
                "ver": "2.0",
                "aud": self.oidc.client_id,
                "sub": "synthetic-native-subject",
                "nonce": nonce,
                "iat": now,
                "exp": now + 600,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": "synthetic-signing-key"},
        )
        return self.response(
            url,
            {
                "access_token": "SYNTHETIC_ACCESS_NOT_A_CREDENTIAL",
                "id_token": token,
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": self.oidc.provider_policy.api_scope,
            },
        )

    def backend_read(self, transport, operation, access_token):
        self.assertEqual(access_token, "SYNTHETIC_ACCESS_NOT_A_CREDENTIAL")
        self.backend_calls.append(operation.value)
        if self.backend_hook:
            self.backend_hook()
        values = {
            "/v1/me": {
                "id": "member-a",
                "org_id": "company-a",
                "display_name": "Synthetic Member",
                "role": "member",
            },
            "/v1/profiles": [PROFILE.public()],
            "/v1/presets": [PRESET.public()],
        }
        return self.response(self.backend.origin + operation.value, values[operation.value])

    def wait(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail(f"Concrete synthetic flow stalled: {self.host.snapshot().public()}")
            time.sleep(0.005)

    def begin(self):
        self.assertEqual(self.items, {})
        self.host.prepare()
        self.wait(lambda: self.host.snapshot().can_sign_in)
        self.host.sign_in()
        self.assertTrue(self.opened.wait(3))

    def callback(self):
        params = parse_qs(urlsplit(self.urls[-1]).query)
        parsed = urlsplit(self.oidc.redirect_uri)
        target = (
            parsed.path + "?" + urlencode({"state": params["state"][0], "code": "SYNTHETIC_CODE"})
        )
        with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as connection:
            connection.sendall(f"GET {target} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n".encode())
            data = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        self.assertIn(b"Return to Team Browser", data)
        self.assertNotIn(b"SYNTHETIC_CODE", data)

    def test_concrete_composition_identity_membership_records_and_exact_logout(self):
        self.begin()
        self.callback()
        self.wait(lambda: self.host.snapshot().can_refresh_records)
        initial = self.host.snapshot().public()
        self.assertTrue(initial["company_membership_verified"])
        self.assertFalse(initial["records_loaded"])
        self.assertEqual(self.backend_calls, ["/v1/me"])
        self.host.refresh_records()
        self.wait(
            lambda: (
                self.host.snapshot().records_loaded
                and not self.host.snapshot().native_operations_pending
            )
        )
        public = self.host.snapshot().public()
        self.assertEqual(public["profiles"], [PROFILE.public()])
        self.assertEqual(public["presets"], [PRESET.public()])
        self.assertFalse(public["device_enrolled"])
        self.assertNotIn("SYNTHETIC_ACCESS", json.dumps(public))
        self.assertNotIn("synthetic-native-subject", json.dumps(public))
        deletes = self.delete_count
        self.host.sign_out()
        self.wait(lambda: self.host.snapshot().status == host.HostStatus.SIGNED_OUT)
        self.assertEqual(self.delete_count, deletes + 1)
        self.assertNotIn("managed-signin-payload-v1", self.items)
        self.assertNotIn(threading.get_ident(), self.os_threads)

    def test_concrete_exchange_cancel_waits_and_never_verifies_membership(self):
        self.exchange_release.clear()
        self.begin()
        self.callback()
        self.assertTrue(self.exchange_entered.wait(1))
        self.host.cancel_sign_in()
        self.assertTrue(self.host.snapshot().cancellation_requested)
        self.assertFalse(self.host.snapshot().can_prepare)
        self.assertEqual(self.backend_calls, [])
        self.exchange_release.set()
        self.wait(
            lambda: (
                self.host.snapshot().status == host.HostStatus.CANCELLED
                and not self.host.snapshot().native_operations_pending
            )
        )
        self.assertEqual(self.backend_calls, [])
        self.assertNotIn("managed-signin-payload-v1", self.items)
        self.assertEqual(sum(method == "POST" for method, _ in self.provider_calls), 1)


if __name__ == "__main__":
    unittest.main()
