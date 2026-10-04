"""Independent managed-consumer regressions; public imports and synthetic seams only.

Reuse storage/socket fixture setup, never the builder's TestCase inheritance or
assertions. No native Keychain, real DNS/socket, provider, browser or account I/O.
"""

import json
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

import test_client_managed_session as fixture
from team_browser.client import managed_session as managed
from team_browser.client import session_vault as vault
from team_browser.client.auth_flow import HTTPResponse


class IndependentManagedSessionTests(unittest.TestCase):
    setUp = fixture.ManagedSessionTests.setUp
    material = fixture.ManagedSessionTests.material
    fresh = fixture.ManagedSessionTests.fresh

    def test_lost_lease_in_final_timeout_step_never_emits_bearer(self):
        original = self.wire.settimeout
        count = 0

        def lose_ownership(timeout):
            nonlocal count
            count += 1
            if count == 2:
                self.vault._lease.close()
            return original(timeout)

        with (
            patch.object(self.wire, "settimeout", side_effect=lose_ownership),
            self.assertRaises(managed.ManagedSessionError),
        ):
            self.client.me()
        self.assertEqual(self.wire.sent, [], "Bearer emitted after native lease was lost")
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_explicit_default_port_is_retained_in_exact_origin_and_host(self):
        backend = replace(fixture.BACKEND, origin="https://api.example.test:443")
        self.client = managed.NativeManagedSession(backend, vault=self.vault)
        self.assertEqual(self.client.me().tenant_id, fixture.ME["org_id"])
        self.assertIn(b"Host: api.example.test:443\r\n", self.wire.sent[-1])
        self.assertEqual(self.raw.destination, (fixture.PUBLIC, 443))
        self.assertEqual(
            self.tls.wrap_socket.call_args.kwargs["server_hostname"], "api.example.test"
        )

    def test_forged_response_origin_is_terminal_and_not_public(self):
        response = HTTPResponse(
            200, "https://other.example.test/v1/me", json.dumps(fixture.ME).encode()
        )
        with (
            patch.object(managed._BackendReader, "response", return_value=response),
            self.assertRaises(managed.ManagedSessionError),
        ):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        count = len(self.wire.sent)
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(len(self.wire.sent), count)

    def test_two_public_dns_addresses_do_not_enable_failover_or_retry(self):
        self.resolve.return_value = [fixture.PUBLIC, "1.1.1.1"]
        with (
            patch.object(
                self.raw, "connect", side_effect=OSError("synthetic network failure")
            ) as connect,
            self.assertRaises(managed.ManagedSessionError),
        ):
            self.client.me()
        connect.assert_called_once_with((fixture.PUBLIC, 443))
        self.socket.assert_called_once()
        self.assertEqual(self.wire.sent, [])
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.socket.assert_called_once()

    def test_changed_payload_during_connection_cleanup_cannot_publish(self):
        self.wire.on_close = lambda: self.store.items.update(
            {vault._PAYLOAD.account_id: b"synthetic-invalid-replacement"}
        )
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_replaced_lock_inode_during_response_invalidates_consumer(self):
        def replace_inode():
            path = self.vault._lease._path / "owner.lock"
            path.unlink()
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)

        self.wire.on_send = replace_inode
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_second_bound_consumer_cannot_restore_logged_out_record(self):
        peer = managed.NativeManagedSession(fixture.BACKEND, vault=self.vault)
        self.client.me()
        peer.logout()
        calls = self.resolve.call_count
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(self.resolve.call_count, calls)
        self.assertIsNone(self.client.snapshot().membership)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertEqual(self.client.logout().status, managed.ManagedStatus.LOGGED_OUT)

    def test_old_generation_logout_preserves_reused_reference_in_new_epoch(self):
        self.vault.recover_discard_all()
        self.vault.store_session(fixture.SESSION, self.material())
        payload = self.store.items[vault._PAYLOAD.account_id]
        with self.assertRaises(managed.ManagedSessionError):
            self.client.logout()
        self.assertEqual(self.store.items[vault._PAYLOAD.account_id], payload)
        self.assertIsNone(self.vault.assert_session_current(fixture.SESSION))

    def test_maximum_list_is_complete_and_overflow_is_not_truncated(self):
        self.client.me()
        rows = [dict(fixture.PROFILES[0], id=f"profile-{i}") for i in range(256)]
        self.wire.data = fixture.response(rows)
        self.assertEqual(len(self.client.profiles()), 256)
        self.wire.data = fixture.response(rows + [dict(rows[0], id="profile-overflow")])
        with self.assertRaises(managed.ManagedSessionError):
            self.client.profiles()
        self.assertIsNone(self.client.snapshot().membership)

    def test_reflected_id_token_in_profile_label_is_rejected_after_json_decoding(self):
        self.client.me()
        rows = [dict(fixture.PROFILES[0], name="prefix " + fixture.ID_TOKEN + " suffix")]
        self.wire.data = fixture.response(
            body=json.dumps(rows).replace("SYNTHETIC", "\\u0053YNTHETIC").encode()
        )
        with self.assertRaises(managed.ManagedSessionError):
            self.client.profiles()
        self.assertNotIn(fixture.ID_TOKEN, json.dumps(self.client.snapshot().public()))

    def test_non_bearer_material_fails_without_network_or_secret_diagnostic(self):
        self.vault.delete_session(fixture.SESSION)
        invalid = "SYNTHETIC TOKEN WITH SPACES"
        with self.assertRaises(vault.SessionVaultError) as error:
            self.vault.store_session(fixture.OTHER, self.material(access_token=invalid))
        self.resolve.assert_not_called()
        self.assertNotIn(invalid, str(error.exception))
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)

    def test_signout_after_auth_denial_still_confirms_exact_local_deletion(self):
        self.client.me()
        self.wire.data = fixture.response(status=403)
        with self.assertRaises(managed.ManagedSessionError):
            self.client.profiles()
        requests = len(self.wire.sent)
        self.assertEqual(self.client.logout().status, managed.ManagedStatus.LOGGED_OUT)
        self.assertEqual(len(self.wire.sent), requests)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
