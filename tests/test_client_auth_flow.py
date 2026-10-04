"""Synthetic-only native OIDC tests. No network, real providers or persistent vault."""

import base64
import hashlib
import json
import threading
import time
import unittest
from dataclasses import asdict, replace
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthStatus,
    HTTPResponse,
    ManagedSignIn,
    TrustedOIDCConfiguration,
)


CONFIG = TrustedOIDCConfiguration(
    issuer="https://identity.example.test/tenant",
    client_id="synthetic-desktop-client",
    authorization_endpoint="https://identity.example.test/authorize",
    token_endpoint="https://identity.example.test/token",
    jwks_endpoint="https://keys.example.test/jwks",
    redirect_uri="http://127.0.0.1:43187/oidc/callback",
)


class FakeVault:
    def __init__(self):
        self.items = {}
        self.stores = 0
        self.deletes = 0
        self.unavailable = False
        self.store_error = False
        self.delete_error = False
        self.on_store = None
        self.health_checks = 0
        self.health_ack = None
        self.store_ack = None
        self.delete_ack = None
        self.preserve_on_delete = False

    def assert_available(self):
        self.health_checks += 1
        if self.unavailable:
            raise RuntimeError("PRIVATE_VAULT_DIAGNOSTIC")
        return self.health_ack

    def store_session(self, session_id, material):
        self.stores += 1
        self.items[session_id] = material
        if self.on_store:
            self.on_store()
        if self.store_error:
            raise RuntimeError("PRIVATE_VAULT_DIAGNOSTIC")
        return self.store_ack

    def delete_session(self, session_id):
        self.deletes += 1
        if self.delete_error:
            raise RuntimeError("PRIVATE_VAULT_DIAGNOSTIC")
        if not self.preserve_on_delete:
            self.items.pop(session_id, None)
        return self.delete_ack


class FakeTransport:
    def __init__(self, signing_key):
        self.key = signing_key
        self.algorithm = "RS256"
        self.headers = {"kid": "synthetic-key"}
        self.nonce = ""
        self.posts = []
        self.gets = []
        self.payload_changes = {}
        self.claim_changes = {}
        self.remove_claims = []
        self.on_post = None
        self.on_get = None
        self.post_response = None
        self.get_response = None
        self.post_error = False
        self.get_error = False
        self.jwk_changes = {}
        self.duplicate_key = False

    def post_form(self, url, fields, *, timeout_seconds, follow_redirects):
        self.posts.append((url, fields, timeout_seconds, follow_redirects))
        if self.on_post:
            self.on_post()
        if self.post_error:
            raise TimeoutError("PRIVATE_TRANSPORT_DIAGNOSTIC")
        if self.post_response:
            return self.post_response
        now = int(time.time())
        claims = {
            "iss": CONFIG.issuer,
            "sub": "synthetic-member",
            "aud": CONFIG.client_id,
            "nonce": self.nonce,
            "iat": now,
            "exp": now + 300,
        }
        claims.update(self.claim_changes)
        for name in self.remove_claims:
            claims.pop(name, None)
        token = jwt.encode(claims, self.key, algorithm=self.algorithm, headers=self.headers)
        payload = {
            "token_type": "Bearer",
            "access_token": "SYNTHETIC_ACCESS_VALUE",
            "id_token": token,
            "expires_in": 300,
            "scope": "openid",
        }
        payload.update(self.payload_changes)
        return HTTPResponse(200, url, json.dumps(payload).encode())

    def get(self, url, *, timeout_seconds, follow_redirects):
        self.gets.append((url, timeout_seconds, follow_redirects))
        if self.on_get:
            self.on_get()
        if self.get_error:
            raise RuntimeError("PRIVATE_TRANSPORT_DIAGNOSTIC")
        if self.get_response:
            return self.get_response
        algorithm = jwt.algorithms.get_default_algorithms()[self.algorithm]
        key = json.loads(algorithm.to_jwk(self.key.public_key()))
        key.update({"kid": "synthetic-key", "use": "sig", "alg": self.algorithm})
        key.update(self.jwk_changes)
        keys = [key, key] if self.duplicate_key else [key]
        return HTTPResponse(200, url, json.dumps({"keys": keys}).encode())


class ManagedSignInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generated in test memory only. Never registered, transmitted or saved.
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = 1000.0
        self.transport = FakeTransport(self.key)
        self.vault = FakeVault()
        self.flow = ManagedSignIn(
            CONFIG, transport=self.transport, vault=self.vault, monotonic=lambda: self.now
        )

    def start(self, **kwargs):
        request = self.flow.begin(**kwargs)
        self.assertEqual(request.result.status, AuthStatus.WAITING)
        self.params = {
            key: value[0]
            for key, value in parse_qs(urlsplit(request.authorization_url).query).items()
        }
        self.transport.nonce = self.params["nonce"]
        return request

    def callback(self, **overrides):
        fields = {
            "state": self.params["state"],
            "code": "synthetic-one-use-code",
            "iss": CONFIG.issuer,
        }
        fields.update(overrides)
        return CONFIG.redirect_uri + "?" + urlencode(fields)

    def finish(self, **overrides):
        return self.flow.complete_callback(self.callback(**overrides))

    def assert_blocked(self, result, reason="token_validation_failed"):
        self.assertEqual(result.status, AuthStatus.ERROR)
        self.assertEqual(result.reason, reason)
        self.assertEqual(self.vault.items, {})
        self.assertIsNone(result.identity)

    def test_unconfigured_is_explicit_and_cannot_begin(self):
        flow = ManagedSignIn()
        self.assertEqual(flow.status().status, AuthStatus.UNCONFIGURED)
        caps = flow.capabilities()
        self.assertFalse(caps.configured)
        self.assertFalse(caps.can_begin)
        self.assertEqual(len(caps.blockers), 3)
        self.assertIsNone(flow.begin().authorization_url)

    def test_configuration_requires_typed_operator_input(self):
        with self.assertRaises(TypeError):
            ManagedSignIn(asdict(CONFIG))

    def test_config_rejects_untrusted_endpoint_forms(self):
        for endpoint in (
            "http://identity.example.test/issuer",
            "https://me:secret@identity.example.test",
            "https://identity.example.test/issuer?next=bad",
            "https://identity.example.test/#bad",
            "https://127.0.0.1/token",
            "https://localhost/token",
            "https://host.local/token",
            "https://identity.example.test:4433/token",
            "https://identity.example.test/%2e%2e/token",
            "https://identity.example.test/../token",
            "https://identity.example.test/\\token",
            "https://identity.example.test/token\n",
            "https://bad..example.test/token",
            "https://identity.example.test/token?",
            "https://identity.example.test/token#",
            "https://IDENTITY.example.test/token",
            "https://identity.example.test:/token",
        ):
            for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_endpoint"):
                with self.subTest(endpoint=endpoint, field=field), self.assertRaises(ValueError):
                    replace(CONFIG, **{field: endpoint})

    def test_callback_requires_fixed_literal_loopback(self):
        for callback in (
            "https://127.0.0.1:43187/oidc/callback",
            "http://localhost:43187/oidc/callback",
            "http://0.0.0.0:43187/oidc/callback",
            "http://127.0.0.2:43187/oidc/callback",
            "http://127.0.0.1:0/oidc/callback",
            "http://127.0.0.1/oidc/callback",
            "http://127.0.0.1:43187/oidc/callback?next=evil",
            "http://127.0.0.1:43187/#fragment",
            "http://127.0.0.1:43187/../callback",
            "http://user@127.0.0.1:43187/oidc/callback",
            "http://127.0.0.1:043187/oidc/callback",
        ):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                replace(CONFIG, redirect_uri=callback)
        self.assertEqual(
            replace(CONFIG, redirect_uri="http://[::1]:43187/oidc/callback").scopes, ("openid",)
        )

    def test_config_cannot_expand_scopes_or_allow_symmetric_signatures(self):
        for scopes in (
            ("openid", "offline_access"),
            ("openid", "email"),
            ("https://www.googleapis.com/auth/gmail.readonly",),
            ["openid"],
        ):
            with self.subTest(scopes=scopes), self.assertRaises(ValueError):
                replace(CONFIG, scopes=scopes)
        for algorithms in (("none",), ("HS256",), ("RS256", "RS256"), (), ["RS256"]):
            with self.subTest(algorithms=algorithms), self.assertRaises(ValueError):
                replace(CONFIG, algorithms=algorithms)

    def test_time_limits_are_bounded_and_strict(self):
        for field, value in (
            ("authorization_ttl_seconds", 601),
            ("max_id_token_lifetime_seconds", 86400),
            ("max_access_token_lifetime_seconds", True),
            ("clock_skew_seconds", 61),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(CONFIG, **{field: value})

    def test_pkce_s256_minimal_scopes_and_external_browser_request(self):
        request = self.start()
        self.assertEqual(self.params["code_challenge_method"], "S256")
        self.assertEqual(self.params["scope"], "openid")
        self.assertEqual(self.params["response_type"], "code")
        self.assertEqual(self.params["redirect_uri"], CONFIG.redirect_uri)
        self.assertEqual(self.params["prompt"], "select_account")
        self.assertNotIn("code_verifier", self.params)
        self.assertNotIn("client_secret", self.params)
        self.assertNotEqual(self.params["state"], self.params["nonce"])
        self.assertGreaterEqual(len(self.params["state"]), 43)
        self.assertNotIn(self.params["state"], repr(request))
        self.finish()
        fields = self.transport.posts[0][1]
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(challenge, self.params["code_challenge"])
        self.assertEqual(fields["grant_type"], "authorization_code")
        self.assertNotIn("client_secret", fields)

    def test_success_is_identity_only_without_tokens_in_ui_or_reprs(self):
        self.start()
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(result.identity, AccountIdentity(CONFIG.issuer, "synthetic-member"))
        self.assertEqual(len(self.vault.items), 1)
        material = next(iter(self.vault.items.values()))
        public = json.dumps(result.public()) + repr(result) + repr(material)
        self.assertNotIn(material.access_token, public)
        self.assertNotIn(material.id_token, public)
        self.assertNotIn("PRIVATE_", public)
        self.assertFalse(result.public()["company_membership_verified"])
        self.assertFalse(result.public()["device_enrolled"])
        self.assertFalse(result.public()["managed_access_available"])
        self.assertFalse(self.flow.capabilities().native_integration_verified)
        self.assertEqual(self.transport.gets, [(CONFIG.jwks_endpoint, 10, False)])
        self.assertFalse(self.transport.posts[0][3])
        self.assertFalse(self.flow.capabilities().can_begin)
        self.assertLessEqual(result.expires_at, int(time.time()) + 300)

    def test_second_begin_does_not_replace_pending_state(self):
        self.start()
        self.assertIsNone(self.flow.begin().authorization_url)
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_unknown_state_does_not_consume_legitimate_attempt(self):
        self.start()
        result = self.finish(state="attacker-state")
        self.assertEqual(result.reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_callback_issuer_is_exact_and_required(self):
        self.start()
        for issuer in ("https://identity.example.test/tenant/", "https://other.example.test", ""):
            self.assertEqual(self.finish(iss=issuer).reason, "callback_rejected")
        missing = (
            CONFIG.redirect_uri
            + "?"
            + urlencode({"state": self.params["state"], "code": "synthetic-one-use-code"})
        )
        self.assertEqual(self.flow.complete_callback(missing).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])

    def test_redirect_target_and_query_are_strictly_validated(self):
        self.start()
        valid = self.callback()
        for callback in (
            valid.replace("127.0.0.1", "localhost"),
            valid.replace(":43187", ":43188"),
            valid.replace("/oidc/callback", "/oidc/callback/"),
            valid + "#fragment",
            valid + "&state=" + self.params["state"],
            valid + "&next=https%3A%2F%2Fevil.test",
            valid + "&code=extra",
            valid + "&error=access_denied",
            valid + "&broken",
            valid + "&error_description=%xx",
            valid.replace("http:", "https:"),
            valid + "&access_token=not-allowed",
        ):
            with self.subTest(callback=callback):
                self.assertEqual(self.flow.complete_callback(callback).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_consent_denial_is_sanitized_consumed_and_not_exchanged(self):
        self.start()
        denied = (
            CONFIG.redirect_uri
            + "?"
            + urlencode(
                {
                    "state": self.params["state"],
                    "iss": CONFIG.issuer,
                    "error": "access_denied",
                    "error_description": "PRIVATE_PROVIDER_DIAGNOSTIC",
                }
            )
        )
        result = self.flow.complete_callback(denied)
        self.assertEqual(result.reason, "consent_denied")
        self.assertEqual(result.status, AuthStatus.CANCELLED)
        self.assertNotIn("PRIVATE_PROVIDER", repr(result))
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])

    def test_other_provider_error_is_not_reflected(self):
        self.start()
        callback = (
            CONFIG.redirect_uri
            + "?"
            + urlencode(
                {
                    "state": self.params["state"],
                    "iss": CONFIG.issuer,
                    "error": "private_provider_error",
                }
            )
        )
        result = self.flow.complete_callback(callback)
        self.assertEqual(result.reason, "provider_error")
        self.assertNotIn("private_provider_error", repr(result))

    def test_callback_replay_never_redeems_code_twice(self):
        self.start()
        self.finish()
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(len(self.transport.posts), 1)
        self.assertEqual(self.flow.status().status, AuthStatus.IDENTITY_VERIFIED)

    def test_cancel_then_late_callback_does_not_exchange(self):
        self.start()
        self.assertEqual(self.flow.cancel().status, AuthStatus.CANCELLED)
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])

    def test_expiry_uses_monotonic_clock_and_clears_pending_attempt(self):
        self.start()
        self.now += 180
        self.assertEqual(self.flow.status().status, AuthStatus.EXPIRED)
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])

    def test_new_attempt_is_not_affected_by_old_callback(self):
        self.start()
        old = self.callback()
        old_state, old_nonce = self.params["state"], self.params["nonce"]
        self.flow.cancel()
        self.start()
        self.assertNotEqual(old_state, self.params["state"])
        self.assertNotEqual(old_nonce, self.params["nonce"])
        self.assertEqual(self.flow.complete_callback(old).reason, "callback_rejected")
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_cancel_during_token_request_never_stores_tokens(self):
        self.start()
        self.transport.on_post = lambda: self.assertEqual(
            self.flow.cancel().status, AuthStatus.CANCELLING
        )
        self.assertEqual(self.finish().status, AuthStatus.CANCELLED)
        self.assertEqual(self.vault.stores, 0)
        self.assertEqual(self.transport.gets, [])

    def test_cancel_during_jwks_request_never_stores_tokens(self):
        self.start()
        self.transport.on_get = self.flow.cancel
        self.assertEqual(self.finish().status, AuthStatus.CANCELLED)
        self.assertEqual(self.vault.stores, 0)

    def test_cancel_during_vault_commit_deletes_new_record(self):
        self.start()
        self.vault.on_store = self.flow.cancel
        self.assertEqual(self.finish().status, AuthStatus.CANCELLED)
        self.assertEqual(self.vault.stores, 1)
        self.assertEqual(self.vault.deletes, 1)
        self.assertEqual(self.vault.items, {})

    def test_cancel_during_commit_with_uncertain_cleanup_blocks_new_flows(self):
        self.start()
        self.vault.on_store = self.flow.cancel
        self.vault.delete_error = True
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "vault_cleanup_uncertain")
        self.assertIsNone(result.identity)
        self.assertFalse(self.flow.capabilities().can_begin)
        self.assertIsNone(self.flow.begin().authorization_url)

    def test_expiry_during_exchange_never_stores_tokens(self):
        self.start()
        self.transport.on_post = lambda: setattr(self, "now", self.now + 181)
        self.assertEqual(self.finish().status, AuthStatus.EXPIRED)
        self.assertEqual(self.vault.stores, 0)

    def test_expiry_during_commit_removes_vault_record(self):
        self.start()
        self.vault.on_store = lambda: setattr(self, "now", self.now + 181)
        self.assertEqual(self.finish().status, AuthStatus.EXPIRED)
        self.assertEqual(self.vault.items, {})

    def test_transport_uncertainty_is_sanitized_and_not_retried(self):
        self.start()
        self.transport.post_error = True
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "token_exchange_uncertain")
        self.assertNotIn("PRIVATE_TRANSPORT", repr(result))
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(len(self.transport.posts), 1)
        self.assertFalse(self.flow.capabilities().can_begin)

    def test_vault_unavailable_prevents_authorization(self):
        self.vault.unavailable = True
        request = self.flow.begin()
        self.assertEqual(request.result.reason, "vault_unavailable")
        self.assertIsNone(request.authorization_url)
        self.assertEqual(self.transport.posts, [])
        self.assertNotIn("PRIVATE_VAULT", repr(request))

    def test_vault_partial_write_is_removed_without_plaintext_fallback(self):
        self.start()
        self.vault.store_error = True
        self.assert_blocked(self.finish(), "vault_store_failed")
        self.assertEqual(self.vault.deletes, 1)

    def test_vault_uncertain_write_and_cleanup_require_reconciliation(self):
        self.start()
        self.vault.store_error = True
        self.vault.delete_error = True
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "vault_cleanup_uncertain")
        self.assertIsNone(result.identity)
        self.assertIsNone(self.flow.begin().authorization_url)

    def test_malformed_vault_health_acknowledgement_requires_recovery(self):
        for acknowledgement in (False, True, 0, 1, "", "ok", [], {}):
            with self.subTest(acknowledgement=acknowledgement):
                self.setUp()
                self.vault.health_ack = acknowledgement
                request = self.flow.begin()
                self.assertEqual(request.result.status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(request.result.reason, "vault_health_uncertain")
                self.assertIsNone(request.authorization_url)
                self.assertEqual(self.transport.posts, [])
                self.assertIsNone(self.flow.begin().authorization_url)
                self.assertEqual(self.vault.health_checks, 1)

    def test_malformed_vault_store_acknowledgement_never_publishes_identity(self):
        for acknowledgement in (False, True, 0, 1, "", "ok", [], {}):
            with self.subTest(acknowledgement=acknowledgement):
                self.setUp()
                self.start()
                self.vault.store_ack = acknowledgement
                result = self.finish()
                self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(result.reason, "vault_store_uncertain")
                self.assertIsNone(result.identity)
                self.assertEqual(self.vault.items, {})
                self.assertEqual(self.vault.stores, 1)
                self.assertEqual(self.vault.deletes, 1)
                self.assertIsNone(self.flow.begin().authorization_url)
                self.assertEqual(self.vault.health_checks, 1)

    def test_cancel_with_false_delete_ack_does_not_claim_cleanup(self):
        for acknowledgement in (False, True, 0, 1, "", "ok", [], {}):
            with self.subTest(acknowledgement=acknowledgement):
                self.setUp()
                self.start()
                self.vault.on_store = self.flow.cancel
                self.vault.delete_ack = acknowledgement
                self.vault.preserve_on_delete = True
                result = self.finish()
                self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(result.reason, "vault_cleanup_uncertain")
                self.assertIsNone(result.identity)
                self.assertEqual(len(self.vault.items), 1)
                self.assertFalse(self.flow.capabilities().can_begin)
                self.assertIsNone(self.flow.begin().authorization_url)
                self.assertEqual(self.flow.cancel().status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(self.vault.deletes, 1)
                self.assertEqual(self.vault.stores, 1)

    def test_malformed_store_and_delete_acknowledgements_do_not_retry(self):
        self.start()
        self.vault.store_ack = False
        self.vault.delete_ack = False
        self.vault.preserve_on_delete = True
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "vault_cleanup_uncertain")
        self.assertEqual(len(self.vault.items), 1)
        self.assertEqual(self.vault.stores, 1)
        self.assertEqual(self.vault.deletes, 1)
        self.assertIsNone(self.flow.begin().authorization_url)
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.vault.deletes, 1)

    def test_expiry_with_false_delete_ack_does_not_claim_cleanup(self):
        self.start()
        result = self.finish()
        self.vault.delete_ack = False
        self.vault.preserve_on_delete = True
        with patch("team_browser.client.auth_flow.time.time", return_value=result.expires_at):
            expired = self.flow.status()
        self.assertEqual(expired.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(expired.reason, "vault_cleanup_uncertain")
        self.assertIsNone(expired.identity)
        self.assertEqual(len(self.vault.items), 1)
        self.assertIsNone(self.flow.begin().authorization_url)
        self.assertEqual(self.flow.status().status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(self.vault.deletes, 1)

    def test_wrong_account_never_reaches_vault(self):
        self.start(expected_account=AccountIdentity(CONFIG.issuer, "expected-member"))
        self.assert_blocked(self.finish(), "wrong_account")
        self.assertEqual(self.vault.stores, 0)

    def test_expected_account_issuer_must_match_configuration(self):
        request = self.flow.begin(
            expected_account=AccountIdentity("https://other.example.test", "expected-member")
        )
        self.assertEqual(request.result.reason, "invalid_account_binding")
        self.assertIsNone(request.authorization_url)

    def test_correct_account_binding_is_accepted(self):
        self.start(expected_account=AccountIdentity(CONFIG.issuer, "synthetic-member"))
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_required_id_claims_are_all_enforced(self):
        for name in ("iss", "sub", "aud", "exp", "iat", "nonce"):
            with self.subTest(claim=name):
                self.setUp()
                self.start()
                self.transport.remove_claims = [name]
                self.assert_blocked(self.finish())

    def test_invalid_claims_never_reach_vault(self):
        now = int(time.time())
        for claims in (
            {"iss": CONFIG.issuer + "/"},
            {"iss": "https://identity.example.test"},
            {"aud": "other-client"},
            {"aud": [CONFIG.client_id, "other-client"]},
            {"aud": [CONFIG.client_id]},
            {"azp": "other-client"},
            {"nonce": "different-nonce"},
            {"nonce": None},
            {"exp": now - 1},
            {"iat": now + 120},
            {"iat": now - 120},
            {"exp": now + 86400},
            {"exp": str(now + 300)},
            {"exp": True},
            {"iat": float(now)},
            {"sub": ""},
            {"sub": "x" * 256},
            {"nbf": now + 120},
            {"nbf": float(now)},
            {"at_hash": "wrong-hash"},
        ):
            with self.subTest(claims=claims):
                self.setUp()
                self.start()
                self.transport.claim_changes = claims
                self.assert_blocked(self.finish())

    def test_at_hash_when_present_is_verified(self):
        self.start()
        self.transport.claim_changes["at_hash"] = (
            base64.urlsafe_b64encode(hashlib.sha256(b"SYNTHETIC_ACCESS_VALUE").digest()[:16])
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_invalid_token_responses_and_scope_expansion_are_rejected(self):
        for payload in (
            {"token_type": "MAC"},
            {"access_token": ""},
            {"id_token": "bad.jwt"},
            {"error": "invalid_grant"},
            {"expires_in": "300"},
            {"expires_in": True},
            {"expires_in": 86400},
            {"expires_in": 0},
            {"refresh_token": "UNSOLICITED_SYNTHETIC_REFRESH"},
            {"refresh_token": None},
            {"scope": "openid offline_access"},
            {"scope": "openid https://www.googleapis.com/auth/gmail.readonly"},
        ):
            with self.subTest(payload=payload):
                self.setUp()
                self.start()
                self.transport.payload_changes = payload
                self.assert_blocked(self.finish())

    def test_no_scope_response_assumes_only_requested_scope(self):
        self.start()
        original = self.transport.post_form

        def response_without_scope(*args, **kwargs):
            response = original(*args, **kwargs)
            payload = json.loads(response.body)
            payload.pop("scope")
            return replace(response, body=json.dumps(payload).encode())

        self.transport.post_form = response_without_scope
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_token_endpoint_redirects_errors_and_malformed_bodies_fail_closed(self):
        for response in (
            HTTPResponse(302, CONFIG.token_endpoint, b"{}"),
            HTTPResponse(200, "https://attacker.example.test/token", b"{}"),
            HTTPResponse(200, CONFIG.token_endpoint, b"{}", redirected=True),
            HTTPResponse(200, CONFIG.token_endpoint, b"{}", content_type="text/html"),
            HTTPResponse(200, CONFIG.token_endpoint, b"{"),
            HTTPResponse(200, CONFIG.token_endpoint, b'{"access_token":"a","access_token":"b"}'),
            HTTPResponse(200, CONFIG.token_endpoint, b"[1,2]"),
            HTTPResponse(200, CONFIG.token_endpoint, b"x" * 65537),
            HTTPResponse(400, CONFIG.token_endpoint, b'{"error":"invalid_grant"}'),
        ):
            with self.subTest(response=response):
                self.setUp()
                self.start()
                self.transport.post_response = response
                result = self.finish()
                self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(result.reason, "token_exchange_uncertain")
                self.assertFalse(self.flow.capabilities().can_begin)
                self.assertEqual(self.vault.items, {})
                self.assertEqual(len(self.transport.posts), 1)
                self.assertEqual(self.transport.gets, [])

    def test_jwks_redirects_errors_and_duplicates_fail_closed(self):
        for response in (
            HTTPResponse(302, CONFIG.jwks_endpoint, b"{}"),
            HTTPResponse(200, "https://attacker.example.test/jwks", b"{}"),
            HTTPResponse(200, CONFIG.jwks_endpoint, b"{}", redirected=True),
            HTTPResponse(200, CONFIG.jwks_endpoint, b'{"keys":[]}'),
            HTTPResponse(200, CONFIG.jwks_endpoint, b'{"keys":[],"keys":[]}'),
        ):
            with self.subTest(response=response):
                self.setUp()
                self.start()
                self.transport.get_response = response
                self.assert_blocked(self.finish())
        self.setUp()
        self.start()
        self.transport.duplicate_key = True
        self.assert_blocked(self.finish())

    def test_jwks_unavailable_does_not_leak_diagnostics(self):
        self.start()
        self.transport.get_error = True
        result = self.finish()
        self.assert_blocked(result)
        self.assertNotIn("PRIVATE_TRANSPORT", repr(result))

    def test_token_headers_cannot_choose_key_urls_or_embedded_keys(self):
        for header in (
            {"jku": "https://attacker.example.test/keys"},
            {"x5u": "https://attacker.example.test/cert"},
            {"jwk": {"kty": "oct"}},
            {"crit": ["b64"]},
            {"typ": "at+jwt"},
            {"kid": "unknown-key"},
        ):
            with self.subTest(header=header):
                self.setUp()
                self.start()
                self.transport.headers.update(header)
                self.assert_blocked(self.finish())
                self.assertTrue(
                    all(item[0] == CONFIG.jwks_endpoint for item in self.transport.gets)
                )

    def test_jwk_constraints_prevent_confusion_private_keys_and_weak_keys(self):
        for changes in (
            {"alg": "HS256"},
            {"use": "enc"},
            {"key_ops": ["sign"]},
            {"d": "synthetic-private-part"},
            {"k": "synthetic-symmetric-part"},
            {"kid": "not-matching"},
        ):
            with self.subTest(changes=changes):
                self.setUp()
                self.start()
                self.transport.jwk_changes = changes
                self.assert_blocked(self.finish())
        self.setUp()
        self.start()
        self.transport.key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.assert_blocked(self.finish())

    def test_invalid_signature_is_rejected_with_correct_key_id(self):
        self.start()
        original = self.transport.get
        correct_key = self.transport.key

        def get_expected_key(*args, **kwargs):
            self.transport.key = correct_key
            return original(*args, **kwargs)

        self.transport.get = get_expected_key
        self.transport.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assert_blocked(self.finish())

    def test_symmetric_and_unsigned_tokens_are_rejected(self):
        for algorithm, key in (("HS256", b"synthetic-symmetric-test-key-only" * 2), ("none", "")):
            with self.subTest(algorithm=algorithm):
                self.setUp()
                self.start()
                self.transport.algorithm = algorithm
                self.transport.key = key
                self.assert_blocked(self.finish())
                self.assertEqual(self.transport.gets, [])

    def test_es256_with_p256_key_is_accepted(self):
        self.start()
        self.transport.key = ec.generate_private_key(ec.SECP256R1())
        self.transport.algorithm = "ES256"
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_verified_identity_expires_and_removes_native_record(self):
        self.start()
        result = self.finish()
        with patch("team_browser.client.auth_flow.time.time", return_value=result.expires_at):
            expired = self.flow.status()
        self.assertEqual(expired.status, AuthStatus.EXPIRED)
        self.assertIsNone(expired.identity)
        self.assertEqual(self.vault.items, {})
        self.assertEqual(self.vault.deletes, 1)

    def test_expired_identity_cleanup_failure_remains_closed(self):
        self.start()
        result = self.finish()
        self.vault.delete_error = True
        with patch("team_browser.client.auth_flow.time.time", return_value=result.expires_at):
            expired = self.flow.status()
        self.assertEqual(expired.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(expired.identity)
        self.assertFalse(self.flow.capabilities().can_begin)

    def test_slow_vault_commit_cannot_publish_expired_identity(self):
        self.start()
        clock_patch = patch(
            "team_browser.client.auth_flow.time.time", return_value=time.time() + 3600
        )
        self.vault.on_store = clock_patch.start
        try:
            result = self.finish()
        finally:
            clock_patch.stop()
        self.assertEqual(result.status, AuthStatus.EXPIRED)
        self.assertEqual(self.vault.items, {})

    def test_id_token_cannot_be_replayed_with_new_nonce(self):
        self.start()
        previous_nonce = self.params["nonce"]
        self.flow.cancel()
        self.start()
        self.transport.nonce = previous_nonce
        self.assert_blocked(self.finish())

    def test_concurrent_replay_loses_before_network_exchange(self):
        self.start()
        entered, release = threading.Event(), threading.Event()
        self.transport.on_post = lambda: (entered.set(), release.wait(3))
        results = []
        thread = threading.Thread(target=lambda: results.append(self.finish()))
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.finish().reason, "callback_rejected")
            self.assertEqual(len(self.transport.posts), 1)
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].status, AuthStatus.IDENTITY_VERIFIED)

    def test_concurrent_cancel_remains_responsive_during_transport(self):
        self.start()
        entered, release = threading.Event(), threading.Event()
        self.transport.on_post = lambda: (entered.set(), release.wait(3))
        results = []
        thread = threading.Thread(target=lambda: results.append(self.finish()))
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.flow.cancel().status, AuthStatus.CANCELLING)
            self.assertIsNone(self.flow.begin().authorization_url)
        finally:
            release.set()
            thread.join(3)
        self.assertEqual(results[0].status, AuthStatus.CANCELLED)
        self.assertEqual(self.vault.items, {})


if __name__ == "__main__":
    unittest.main()
