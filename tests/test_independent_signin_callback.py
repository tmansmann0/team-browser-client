"""Independent actual-loopback callback tests; synthetic provider and OS vault only."""

import asyncio
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client import session_vault, signin_callback
from team_browser.client.auth_flow import AuthResult, AuthStatus, entra_native_configuration
from team_browser.client.signin_callback import NativeSignInCoordinator
from team_browser.local.macos_keychain import KeychainConfiguration

from test_client_provider_signin import API, DESKTOP, TENANT, SyntheticTransport
from test_client_session_vault import FakeStore


class IndependentCallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        with socket.socket() as temporary_socket:
            temporary_socket.bind(("127.0.0.1", 0))
            port = temporary_socket.getsockname()[1]
        self.config = entra_native_configuration(
            tenant_id=TENANT, desktop_client_id=DESKTOP, api_client_id=API, loopback_port=port
        )
        self.temp = tempfile.TemporaryDirectory()
        self.store = FakeStore()
        self.store_patches = [
            patch.object(session_vault, "_open_native_store", return_value=self.store),
            patch.object(
                session_vault, "_lease_directory", return_value=Path(self.temp.name) / "lease"
            ),
        ]
        for item in self.store_patches:
            item.start()
        self.vault = session_vault.MacOSSessionVault(
            KeychainConfiguration(
                "SYNTHETIC1", "invalid.example.CallbackQA", session_vault.NAMESPACE
            ),
            oidc_configuration=self.config,
        )
        self.vault.recover_discard_all()
        self.transport = SyntheticTransport(self.key, self.config, int(time.time()))
        self.opened = threading.Event()
        self.release_open = threading.Event()
        self.release_open.set()
        self.release_exchange = threading.Event()
        self.release_exchange.set()
        self.urls = []
        self.opener_error = False
        self.opener = patch.object(
            signin_callback, "_launch_macos_authorization", side_effect=self.open_url
        )
        self.opener.start()
        self.coordinator = NativeSignInCoordinator(
            self.config, transport=self.transport, vault=self.vault
        )
        self.addCleanup(self.cleanup)

    def open_url(self, url, endpoint):
        self.assertEqual(endpoint, self.config.authorization_endpoint)
        self.urls.append(url)
        self.transport.nonce = parse_qs(urlsplit(url).query)["nonce"][0]
        self.opened.set()
        self.release_open.wait(5)
        if self.opener_error:
            raise RuntimeError("SYNTHETIC-SENSITIVE-OPENER-DIAGNOSTIC")

    def cleanup(self):
        self.release_open.set()
        self.release_exchange.set()
        self.coordinator.shutdown()
        settled = self.coordinator.wait_finished(5)
        self.opener.stop()
        self.vault.close()
        for item in reversed(self.store_patches):
            item.stop()
        self.temp.cleanup()
        self.assertTrue(settled, "Synthetic callback threads must terminate")

    def wait(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.005)
        self.fail("Synthetic callback operation did not settle")

    def start(self):
        self.coordinator.start()
        self.assertTrue(self.opened.wait(3))

    def request(self, *, changes=None, extra_headers=(), raw=None):
        redirect = urlsplit(self.config.redirect_uri)
        params = parse_qs(urlsplit(self.urls[0]).query)
        query = {"state": params["state"][0], "code": "INDEPENDENT-SYNTHETIC-CODE"}
        query.update(changes or {})
        if "error" in query:
            query.pop("code", None)
        target = redirect.path + "?" + urlencode(query)
        if raw is None:
            raw = (
                f"GET {target} HTTP/1.1\r\nHost: {redirect.netloc}\r\n"
                + "".join(header + "\r\n" for header in extra_headers)
                + "\r\n"
            ).encode()
        with socket.create_connection((redirect.hostname, redirect.port), timeout=2) as connection:
            connection.sendall(raw)
            response = b""
            while True:
                try:
                    chunk = connection.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    return response
                response += chunk
            return response

    def test_real_loopback_core_and_concrete_vault_publish_only_identity(self):
        self.start()
        response = self.request()
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertFalse(snapshot.listener_open)
        self.assertFalse(snapshot.native_operations_pending)
        payload = json.loads(self.store.items[session_vault._PAYLOAD.account_id])
        public = json.dumps(snapshot.public()).encode() + response
        for value in (
            payload["access_token"],
            payload["id_token"],
            payload["session_id"],
            "INDEPENDENT-SYNTHETIC-CODE",
        ):
            self.assertNotIn(value.encode(), public)
        self.assertFalse(snapshot.public()["managed_access_available"])
        self.assertFalse(snapshot.public()["device_enrolled"])
        self.assertIsNone(self.vault.assert_session_current(payload["session_id"]))

    def test_callback_waits_for_opener_and_pending_cancel_prevents_redemption(self):
        self.release_open.clear()
        self.start()
        self.request()
        self.assertFalse(self.coordinator.snapshot().finished)
        self.assertTrue(self.coordinator.snapshot().native_operations_pending)
        self.assertEqual(self.transport.posts, [])
        self.assertNotIn(session_vault._PAYLOAD.account_id, self.store.items)
        self.coordinator.cancel()
        self.release_open.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.CANCELLED)
        self.assertIsNone(snapshot.result.identity)
        self.assertEqual(self.transport.posts, [])
        self.assertNotIn(session_vault._PAYLOAD.account_id, self.store.items)

    def test_rejected_origin_and_bad_state_do_not_consume_legitimate_attempt(self):
        self.start()
        response = self.request(extra_headers=("Origin: https://foreign.example.test",))
        self.assertTrue(response.startswith(b"HTTP/1.1 400"))
        self.request(changes={"state": "invalid-synthetic-state"})
        self.wait(lambda: not self.coordinator.snapshot().native_operations_pending)
        self.assertEqual(self.transport.posts, [])
        self.assertTrue(self.coordinator.snapshot().listener_open)
        self.request(changes={"error": "access_denied", "error_description": "PRIVATE-SYNTHETIC"})
        self.assertTrue(self.coordinator.wait_finished(3))
        self.assertEqual(self.coordinator.snapshot().result.status, AuthStatus.CANCELLED)
        self.assertEqual(self.transport.posts, [])

    def test_concurrent_callback_replay_issues_one_exchange_and_one_payload(self):
        entered = threading.Event()
        self.release_exchange.clear()

        def hold_exchange():
            entered.set()
            self.release_exchange.wait(5)

        self.transport.on_post = hold_exchange
        self.start()
        self.request()
        self.assertTrue(entered.wait(3))
        for _ in range(4):
            self.assertTrue(self.request().startswith(b"HTTP/1.1 409"))
        self.release_exchange.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        self.assertEqual(len(self.transport.posts), 1)
        self.assertEqual(self.store.events.count(("put", session_vault._PAYLOAD.account_id)), 1)
        self.assertEqual(self.coordinator.snapshot().result.status, AuthStatus.IDENTITY_VERIFIED)

    def test_cancel_during_key_fetch_never_commits_a_late_verified_session(self):
        entered = threading.Event()
        self.release_exchange.clear()

        def hold_keys():
            entered.set()
            self.release_exchange.wait(5)

        self.transport.on_get = hold_keys
        self.start()
        self.request()
        self.assertTrue(entered.wait(3))
        before = time.monotonic()
        snapshot = self.coordinator.cancel()
        self.assertLess(time.monotonic() - before, 0.2)
        self.assertTrue(snapshot.cancellation_requested)
        self.assertFalse(snapshot.finished)
        self.wait(lambda: not self.coordinator.snapshot().listener_open)
        self.release_exchange.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.CANCELLED)
        self.assertIsNone(snapshot.result.identity)
        self.assertNotIn(session_vault._PAYLOAD.account_id, self.store.items)

    def hold_completed_core_before_coordinator_publication(self):
        entered = threading.Event()
        self.release_exchange.clear()
        original_complete = self.coordinator._core.complete_callback
        original_status = self.coordinator._core.status

        def pending_status():
            result = original_status()
            if result.status == AuthStatus.IDENTITY_VERIFIED and not self.release_exchange.is_set():
                return AuthResult(AuthStatus.EXCHANGING, "synthetic_result_pending")
            return result

        def hold_complete(url):
            result = original_complete(url)
            self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
            entered.set()
            self.release_exchange.wait(5)
            return result

        self.coordinator._core.status = pending_status
        self.coordinator._core.complete_callback = hold_complete
        self.start()
        self.request()
        self.assertTrue(entered.wait(3))
        self.assertIn(session_vault._PAYLOAD.account_id, self.store.items)
        self.assertFalse(self.coordinator.snapshot().finished)

    def test_cancel_accepted_before_publication_discards_only_just_committed_session(self):
        self.hold_completed_core_before_coordinator_publication()
        self.store.items["unrelated-feature"] = b"SYNTHETIC-UNRELATED"
        snapshot = self.coordinator.cancel()
        self.assertTrue(snapshot.cancellation_requested)
        self.release_exchange.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.CANCELLED)
        self.assertIsNone(snapshot.result.identity)
        self.assertNotIn(session_vault._PAYLOAD.account_id, self.store.items)
        self.assertEqual(self.store.items["unrelated-feature"], b"SYNTHETIC-UNRELATED")

    def test_cancel_accepted_before_publication_preserves_uncertain_cleanup_as_recovery(self):
        self.hold_completed_core_before_coordinator_publication()
        with patch.object(self.store, "delete", return_value=False) as erase:
            self.coordinator.cancel()
            self.release_exchange.set()
            self.assertTrue(self.coordinator.wait_finished(3))
            self.assertEqual(erase.call_count, 1)
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(snapshot.result.identity)
        with self.assertRaises(session_vault.SessionVaultError):
            self.vault.assert_available()

    def test_callback_worker_failure_after_core_commit_cannot_leave_success_published(self):
        entered = threading.Event()
        self.release_exchange.clear()
        original = self.coordinator._core.complete_callback

        def fail_after_commit(url):
            result = original(url)
            self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
            entered.set()
            self.release_exchange.wait(5)
            raise RuntimeError("SYNTHETIC-PRIVATE-CALLBACK-FAILURE")

        self.coordinator._core.complete_callback = fail_after_commit
        self.start()
        self.request()
        self.assertTrue(entered.wait(3))
        # Allow multiple status observations while the accepted callback worker
        # remains deliberately pending. A fixed coordinator may withhold success.
        time.sleep(0.12)
        self.assertFalse(self.coordinator.snapshot().finished)
        self.release_exchange.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(snapshot.result.identity)
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(snapshot.public()))

    def test_published_terminal_success_explicitly_declines_late_cancel_during_cleanup(self):
        published = threading.Event()
        self.release_exchange.clear()
        original = self.coordinator._publish

        async def hold_published(result):
            await original(result)
            if result.status == AuthStatus.IDENTITY_VERIFIED:
                published.set()
                while not self.release_exchange.is_set():
                    await asyncio.sleep(0.005)

        self.coordinator._publish = hold_published
        self.start()
        self.request()
        self.assertTrue(published.wait(3))
        self.assertFalse(self.coordinator.snapshot().finished)
        snapshot = self.coordinator.cancel()
        self.assertFalse(snapshot.can_cancel)
        self.assertFalse(snapshot.cancellation_requested)
        self.release_exchange.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        self.assertEqual(self.coordinator.snapshot().result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertIn(session_vault._PAYLOAD.account_id, self.store.items)

    def test_failed_opener_with_waiting_callback_never_redeems_code(self):
        self.release_open.clear()
        self.opener_error = True
        self.start()
        self.request()
        self.assertEqual(self.transport.posts, [])
        self.release_open.set()
        self.assertTrue(self.coordinator.wait_finished(3))
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.result.status, AuthStatus.CANCELLED)
        self.assertEqual(snapshot.diagnostic, "external_browser_launch_uncertain")
        self.assertEqual(self.transport.posts, [])
        self.assertNotIn(session_vault._PAYLOAD.account_id, self.store.items)
        self.assertNotIn("SYNTHETIC-SENSITIVE", json.dumps(snapshot.public()))

    def test_cancel_before_start_is_final_and_performs_no_native_operation(self):
        before = len(self.store.events)
        self.assertTrue(self.coordinator.cancel().finished)
        self.coordinator.start()
        self.assertEqual(self.urls, [])
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(len(self.store.events), before)
        self.assertEqual(self.coordinator.snapshot().result.status, AuthStatus.CANCELLED)

    def test_second_start_reuses_one_attempt_and_opener(self):
        self.start()
        for _ in range(5):
            self.coordinator.start()
        self.assertEqual(len(self.urls), 1)
        self.request(changes={"error": "access_denied"})
        self.assertTrue(self.coordinator.wait_finished(3))
        self.coordinator.start()
        self.assertEqual(len(self.urls), 1)

    def test_occupied_exact_port_never_uses_alternate_or_launches_browser(self):
        redirect = urlsplit(self.config.redirect_uri)
        before = len(self.store.events)
        with socket.socket() as blocker:
            blocker.bind((redirect.hostname, redirect.port))
            blocker.listen()
            self.coordinator.start()
            self.assertTrue(self.coordinator.wait_finished(3))
        self.assertEqual(self.coordinator.snapshot().result.reason, "callback_bind_failed")
        self.assertEqual(self.urls, [])
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(len(self.store.events), before)


if __name__ == "__main__":
    unittest.main()
