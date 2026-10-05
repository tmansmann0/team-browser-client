"""Independent native-vault QA with synthetic bytes and disposable empty locks."""

import json
import multiprocessing
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client import auth_flow, session_vault as vault
from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthStatus,
    ManagedSignIn,
    NativeSessionMaterial,
)
from team_browser.local.macos_keychain import KeychainConfiguration

from test_client_session_vault import FakeStore


CONFIG = KeychainConfiguration("SYNTHETIC1", "invalid.example.IndependentVault", vault.NAMESPACE)
SESSION = "INDEPENDENT_SYNTHETIC_SESSION_0123456789"
OTHER = "INDEPENDENT_OTHER_SESSION_9876543210"


def _child_probe_lease(path, connection):
    try:
        lease = vault._ProcessLease(Path(path))
    except vault.SessionVaultError:
        connection.send("blocked")
    else:
        lease.assert_owned()
        lease.close()
        connection.send("owned")
    finally:
        connection.close()


class IndependentSessionVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "lease"
        self.store = FakeStore()
        self.wall, self.monotonic = time.time(), 1000.0
        self.instances = []
        self.patches = [
            patch.object(vault, "_open_native_store", return_value=self.store),
            patch.object(vault, "_lease_directory", return_value=self.root),
            patch.object(
                vault,
                "time",
                SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.monotonic),
            ),
            # The core and vault must share the fixture clock. Otherwise RSA
            # generation crossing a real second makes the core's 600-second
            # expiry exceed the frozen vault's strict 600-second TTL limit.
            patch.object(
                auth_flow,
                "time",
                SimpleNamespace(time=lambda: self.wall),
            ),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for instance in self.instances:
            instance.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def open(self, recover=True, **kwargs):
        instance = vault.MacOSSessionVault(CONFIG, **kwargs)
        self.instances.append(instance)
        if recover:
            self.assertIsNone(instance.recover_discard_all())
        return instance

    def material(self, **changes):
        material = NativeSessionMaterial(
            AccountIdentity("https://identity.example.test", "independent-subject"),
            "INVENTED_ACCESS_FIXTURE",
            "INVENTED_ID_FIXTURE",
            int(self.wall) + 300,
        )
        return replace(material, **changes)

    def assert_quarantined_without_io(self, instance):
        before = len(self.store.events)
        for action in (
            instance.assert_available,
            lambda: instance.assert_session_current(SESSION),
            lambda: instance.delete_session(SESSION),
        ):
            with self.assertRaises(vault.SessionVaultError):
                action()
        self.assertEqual(len(self.store.events), before)

    def test_constructor_and_clean_restart_never_restore_or_read_prior_material(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        snapshot = dict(self.store.items)
        instance.close()
        before = len(self.store.events)
        restarted = self.open(recover=False)
        self.assert_quarantined_without_io(restarted)
        self.assertEqual(self.store.items, snapshot)
        self.assertEqual(len(self.store.events), before)
        restarted.recover_discard_all()
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertIsNone(restarted.assert_available())

    def test_false_quarantine_write_ack_prevents_payload_mutation(self):
        instance = self.open()
        original = self.store.put

        def false_marker(reference, value):
            acknowledgement = original(reference, value)
            return False if reference == vault._JOURNAL else acknowledgement

        before = len(self.store.events)
        with patch.object(self.store, "put", side_effect=false_marker):
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(SESSION, self.material())
        self.assertNotIn(("put", vault._PAYLOAD.account_id), self.store.events[before:])
        self.assert_quarantined_without_io(instance)

    def test_changed_commit_readback_cannot_publish_persisted_payload(self):
        instance = self.open()
        original = self.store.put

        def corrupt_ready(reference, value):
            acknowledgement = original(reference, value)
            if reference == vault._JOURNAL and json.loads(value)["state"] == "ready":
                self.store.items[reference.account_id] = b"synthetic-readback-mismatch"
            return acknowledgement

        with patch.object(self.store, "put", side_effect=corrupt_ready):
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(SESSION, self.material())
        self.assertIn(vault._PAYLOAD.account_id, self.store.items)
        self.assert_quarantined_without_io(instance)
        instance.close()
        self.assert_quarantined_without_io(self.open(recover=False))

    def test_delete_noop_ack_does_not_claim_absence_or_repeat(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        with patch.object(self.store, "delete", return_value=None) as erase:
            with self.assertRaises(vault.SessionVaultError):
                instance.delete_session(SESSION)
            self.assertEqual(erase.call_count, 1)
        self.assertIn(vault._PAYLOAD.account_id, self.store.items)
        self.assert_quarantined_without_io(instance)

    def test_prior_epoch_payload_replay_cannot_become_current(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        old = self.store.items[vault._PAYLOAD.account_id]
        instance.recover_discard_all()
        instance.store_session(SESSION, self.material())
        self.store.items[vault._PAYLOAD.account_id] = old
        with self.assertRaises(vault.SessionVaultError):
            instance.assert_session_current(SESSION)
        self.assert_quarantined_without_io(instance)

    def test_expiry_during_journal_read_is_cleaned_before_payload_read(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        before = len(self.store.events)
        fired = False

        def expire(operation, reference):
            nonlocal fired
            if not fired and operation == "get" and reference == vault._JOURNAL:
                fired = True
                self.wall += 301
                self.monotonic += 301

        self.store.hook = expire
        with self.assertRaises(vault.SessionExpired):
            instance.assert_session_current(SESSION)
        self.store.hook = None
        events = self.store.events[before:]
        self.assertLess(
            events.index(("delete", vault._PAYLOAD.account_id)),
            events.index(("get", vault._PAYLOAD.account_id)),
        )
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertIsNone(instance.assert_available())

    def test_monotonic_expiry_cannot_be_extended_by_static_wall_clock(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        self.monotonic += 301
        with self.assertRaises(vault.SessionExpired):
            instance.assert_session_current(SESSION)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)

    def test_old_identifier_cannot_delete_new_current_session(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        instance.delete_session(SESSION)
        instance.store_session(OTHER, self.material())
        before = len(self.store.events)
        self.assertIsNone(instance.delete_session(SESSION))
        self.assertNotIn(("delete", vault._PAYLOAD.account_id), self.store.events[before:])
        self.assertIsNone(instance.assert_session_current(OTHER))

    def test_replaced_lease_inode_quarantines_before_any_store_operation(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        before = len(self.store.events)
        lock = self.root / "owner.lock"
        lock.rename(self.root / "retired-empty-lock")
        lock.write_bytes(b"")
        lock.chmod(0o600)
        with self.assertRaises(vault.SessionVaultError):
            instance.assert_session_current(SESSION)
        self.assertEqual(len(self.store.events), before)
        self.assert_quarantined_without_io(instance)

    def test_closed_instance_cannot_touch_new_owners_session(self):
        old = self.open()
        old.store_session(SESSION, self.material())
        old.close()
        current = self.open()
        current.store_session(OTHER, self.material())
        before = len(self.store.events)
        with self.assertRaises(vault.SessionVaultError):
            old.delete_session(SESSION)
        self.assertEqual(len(self.store.events), before)
        self.assertIsNone(current.assert_session_current(OTHER))

    def test_independent_process_cannot_acquire_until_owner_closes(self):
        instance = self.open()
        process_context = multiprocessing.get_context("spawn")
        for expected in ("blocked", "owned"):
            ours, theirs = process_context.Pipe(duplex=False)
            process = process_context.Process(
                target=_child_probe_lease, args=(str(self.root), theirs)
            )
            process.start()
            theirs.close()
            try:
                self.assertTrue(ours.poll(5))
                self.assertEqual(ours.recv(), expected)
                process.join(5)
                self.assertEqual(process.exitcode, 0)
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
                ours.close()
            instance.close()

    def assert_entra_identity_only(self, exchange_seconds=0):
        from test_client_provider_signin import CONFIG as OIDC, SyntheticTransport

        instance = self.open(oidc_configuration=OIDC)
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            transport = SyntheticTransport(key, OIDC, int(self.wall))

            def advance_exchange_clock():
                self.wall += exchange_seconds
                self.monotonic += exchange_seconds

            transport.on_post = advance_exchange_clock
            core = ManagedSignIn(
                OIDC, transport=transport, vault=instance, monotonic=lambda: self.monotonic
            )
            request = core.begin()
            self.assertEqual(request.result.status, AuthStatus.WAITING)
            params = parse_qs(urlsplit(request.authorization_url).query)
            transport.nonce = params["nonce"][0]
            result = core.complete_callback(
                OIDC.redirect_uri
                + "?"
                + urlencode({"state": params["state"][0], "code": "independent-synthetic-code"})
            )
            self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
            payload = json.loads(self.store.items[vault._PAYLOAD.account_id])
            self.assertEqual(tuple(payload["scopes"]), OIDC.scopes)
            self.assertEqual(payload["issuer"], OIDC.issuer)
            self.assertGreater(payload["expires_at"] - self.wall, 0)
            self.assertLessEqual(payload["expires_at"] - self.wall, OIDC.local_session_ttl_seconds)
            self.assertIsNone(instance.assert_session_current(payload["session_id"]))
            public = json.dumps(result.public())
            self.assertNotIn(payload["access_token"], public)
            self.assertNotIn(payload["id_token"], public)
            self.assertFalse(result.public()["managed_access_available"])
            self.assertFalse(result.public()["company_membership_verified"])
        finally:
            instance.close()

    def test_entra_real_core_and_native_vault_contract_commit_identity_only(self):
        self.assert_entra_identity_only()

    def test_entra_commit_keeps_strict_ttl_across_fixture_clock_boundaries(self):
        for fractional_second, exchange_seconds in ((0.0, 0.0), (0.99, 0.02), (0.25, 2.0)):
            with self.subTest(fraction=fractional_second, exchange_seconds=exchange_seconds):
                # Real time is already two seconds beyond the frozen fixture,
                # deterministically reproducing the original clock mismatch.
                self.wall = int(time.time()) - 2 + fractional_second
                self.assert_entra_identity_only(exchange_seconds)

    def test_native_entra_rejects_contradictory_or_missing_tenant_version_claims(self):
        import jwt
        from test_client_provider_signin import CONFIG as OIDC, OTHER, SyntheticTransport

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for claim, value in (("tid", OTHER), ("ver", "1.0"), ("tid", None), ("ver", None)):
            with self.subTest(claim=claim, value=value):
                instance = self.open(oidc_configuration=OIDC)
                try:
                    transport = SyntheticTransport(key, OIDC, int(self.wall))
                    original = transport.post_form

                    def changed_claims(*args, **kwargs):
                        response = original(*args, **kwargs)
                        payload = json.loads(response.body)
                        claims = jwt.decode(
                            payload["id_token"], options={"verify_signature": False}
                        )
                        if value is None:
                            claims.pop(claim)
                        else:
                            claims[claim] = value
                        payload["id_token"] = jwt.encode(
                            claims, key, algorithm="RS256", headers={"kid": "test-key"}
                        )
                        return replace(response, body=json.dumps(payload).encode())

                    transport.post_form = changed_claims
                    core = ManagedSignIn(OIDC, transport=transport, vault=instance)
                    request = core.begin()
                    params = parse_qs(urlsplit(request.authorization_url).query)
                    transport.nonce = params["nonce"][0]
                    result = core.complete_callback(
                        OIDC.redirect_uri
                        + "?"
                        + urlencode(
                            {"state": params["state"][0], "code": "independent-synthetic-code"}
                        )
                    )
                    self.assertEqual(result.status, AuthStatus.ERROR)
                    self.assertEqual(result.reason, "token_validation_failed")
                    self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
                finally:
                    instance.close()

    def test_trusted_entra_scope_or_issuer_mismatch_performs_no_store_calls(self):
        from test_client_provider_signin import CONFIG as OIDC

        instance = self.open(oidc_configuration=OIDC)
        expected = self.material(
            identity=AccountIdentity(OIDC.issuer, "synthetic-subject"), scopes=OIDC.scopes
        )
        for material in (
            replace(expected, scopes=("openid",)),
            replace(expected, scopes=OIDC.scopes + ("offline_access",)),
            replace(expected, scopes=("openid", "profile", "api://other/access_as_user")),
            replace(expected, identity=AccountIdentity("https://other.example.test", "subject")),
        ):
            before = len(self.store.events)
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(SESSION, material)
            self.assertEqual(len(self.store.events), before)
        self.assertIsNone(instance.assert_available())

    def test_legacy_vault_does_not_accept_entra_scopes_without_trusted_configuration(self):
        from test_client_provider_signin import CONFIG as OIDC

        instance = self.open()
        before = len(self.store.events)
        material = self.material(
            identity=AccountIdentity(OIDC.issuer, "synthetic-subject"), scopes=OIDC.scopes
        )
        with self.assertRaises(vault.SessionVaultError):
            instance.store_session(SESSION, material)
        self.assertEqual(len(self.store.events), before)

    def test_recovery_and_liveness_touch_only_reserved_keys_and_empty_lock(self):
        self.store.items["foreign-feature"] = b"UNRELATED_SYNTHETIC_RECORD"
        instance = self.open()
        instance.store_session(SESSION, self.material())
        self.assertIsNone(instance.assert_session_current(SESSION))
        instance.delete_session(SESSION)
        self.assertEqual(self.store.items["foreign-feature"], b"UNRELATED_SYNTHETIC_RECORD")
        self.assertEqual(
            {key for _, key in self.store.events},
            {vault._JOURNAL.account_id, vault._PAYLOAD.account_id},
        )
        files = [p for p in Path(self.temp.name).rglob("*") if p.is_file()]
        self.assertEqual([p.name for p in files], ["owner.lock"])
        self.assertEqual(files[0].read_bytes(), b"")
        for method in ("get", "get_token", "get_session", "get_access_token", "with_token"):
            self.assertFalse(hasattr(instance, method))


if __name__ == "__main__":
    unittest.main()
