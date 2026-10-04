"""Independent native sign-in contracts. Fake transport/vault and ephemeral keys only."""

import base64
import hashlib
import json
import threading
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthStatus,
    HTTPResponse,
    ManagedSignIn,
    TrustedOIDCConfiguration,
)


CONFIG = TrustedOIDCConfiguration(
    issuer="https://qa-identity.example.test",
    client_id="synthetic-public-client",
    authorization_endpoint="https://qa-identity.example.test/authorize",
    token_endpoint="https://qa-identity.example.test/token",
    jwks_endpoint="https://qa-identity.example.test/keys",
    redirect_uri="http://127.0.0.1:8877/oidc/callback",
)


class SyntheticVault:
    def __init__(self):
        self.sessions = {}
        self.on_store = None
        self.fail_delete = False

    def assert_available(self):
        pass

    def store_session(self, identifier, material):
        self.sessions[identifier] = material
        if self.on_store:
            self.on_store()

    def delete_session(self, identifier):
        if self.fail_delete:
            raise RuntimeError("PRIVATE SYNTHETIC VAULT DIAGNOSTIC")
        self.sessions.pop(identifier, None)


class SyntheticTransport:
    def __init__(self, key):
        self.key = key
        self.nonce = None
        self.posts = []
        self.gets = []
        self.claim_changes = {}
        self.token_changes = {}
        self.header_changes = {}
        self.on_post = None
        self.response_override = None

    def post_form(self, url, fields, **options):
        self.posts.append((url, fields.copy(), options))
        if self.on_post:
            self.on_post()
        if self.response_override:
            return self.response_override
        now = int(time.time())
        claims = {
            "iss": CONFIG.issuer,
            "sub": "qa-subject",
            "aud": CONFIG.client_id,
            "iat": now,
            "exp": now + 120,
            "nonce": self.nonce,
            **self.claim_changes,
        }
        token = jwt.encode(
            claims, self.key, algorithm="RS256", headers={"kid": "qa-key", **self.header_changes}
        )
        body = {
            "access_token": "SYNTHETIC-NOT-A-LIVE-TOKEN",
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": 90,
            "scope": "openid",
            **self.token_changes,
        }
        return HTTPResponse(200, url, json.dumps(body).encode())

    def get(self, url, **options):
        self.gets.append((url, options))
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        key.update(kid="qa-key", alg="RS256", use="sig", key_ops=["verify"])
        return HTTPResponse(200, url, json.dumps({"keys": [key]}).encode())


class IndependentSignInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.clock = 1000
        self.transport = SyntheticTransport(self.signing_key)
        self.vault = SyntheticVault()
        self.flow = ManagedSignIn(
            CONFIG, transport=self.transport, vault=self.vault, monotonic=lambda: self.clock
        )

    def begin(self, **kwargs):
        request = self.flow.begin(**kwargs)
        self.assertEqual(request.result.status, AuthStatus.WAITING)
        self.params = {
            key: values[0]
            for key, values in parse_qs(urlsplit(request.authorization_url).query).items()
        }
        self.transport.nonce = self.params["nonce"]
        return request

    def callback(self, **changes):
        query = {
            "code": "synthetic-code",
            "state": self.params["state"],
            "iss": CONFIG.issuer,
            **changes,
        }
        return CONFIG.redirect_uri + "?" + urlencode(query)

    def test_verified_identity_does_not_grant_membership_or_device_access(self):
        request = self.begin(expected_account=AccountIdentity(CONFIG.issuer, "qa-subject"))
        result = self.flow.complete_callback(self.callback())
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        public = result.public()
        for field in ("company_membership_verified", "device_enrolled", "managed_access_available"):
            self.assertIs(public[field], False)
        self.assertNotIn("access_token", public)
        self.assertNotIn(self.params["state"], repr(request))
        self.assertNotIn(
            "SYNTHETIC-NOT-A-LIVE-TOKEN", repr(next(iter(self.vault.sessions.values())))
        )

    def test_pkce_exchange_matches_challenge_and_never_follows_redirects(self):
        self.begin()
        self.flow.complete_callback(self.callback())
        url, fields, options = self.transport.posts[0]
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(challenge, self.params["code_challenge"])
        self.assertEqual(self.params["code_challenge_method"], "S256")
        self.assertEqual(url, CONFIG.token_endpoint)
        self.assertIs(options["follow_redirects"], False)
        self.assertEqual(self.transport.gets[0][0], CONFIG.jwks_endpoint)
        self.assertIs(self.transport.gets[0][1]["follow_redirects"], False)
        self.assertNotIn("client_secret", fields)
        self.assertEqual(self.params["scope"], "openid")

    def test_invalid_state_issuer_and_duplicate_fields_do_not_exchange(self):
        self.begin()
        callbacks = [
            self.callback(state="wrong"),
            self.callback(iss="https://outside.example.test"),
            self.callback() + "&state=duplicate",
            self.callback() + "#fragment",
            self.callback().replace(":8877/", ":8878/"),
        ]
        for callback in callbacks:
            self.assertEqual(self.flow.complete_callback(callback).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.flow.status().status, AuthStatus.WAITING)
        self.assertEqual(
            self.flow.complete_callback(self.callback()).status, AuthStatus.IDENTITY_VERIFIED
        )

    def test_callback_replay_and_concurrent_duplicate_cannot_exchange_twice(self):
        self.begin()
        entered, release = threading.Event(), threading.Event()

        def hold_exchange():
            entered.set()
            release.wait(2)

        self.transport.on_post = hold_exchange
        results = []
        thread = threading.Thread(
            target=lambda: results.append(self.flow.complete_callback(self.callback()))
        )
        thread.start()
        self.assertTrue(entered.wait(1))
        duplicate = self.flow.complete_callback(self.callback())
        self.assertEqual(duplicate.reason, "callback_rejected")
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].status, AuthStatus.IDENTITY_VERIFIED)
        self.flow.complete_callback(self.callback())
        self.assertEqual(len(self.transport.posts), 1)

    def test_cancel_during_exchange_prevents_vault_commit(self):
        self.begin()
        entered, release = threading.Event(), threading.Event()
        self.transport.on_post = lambda: (entered.set(), release.wait(2))
        results = []
        thread = threading.Thread(
            target=lambda: results.append(self.flow.complete_callback(self.callback()))
        )
        thread.start()
        self.assertTrue(entered.wait(1))
        self.assertEqual(self.flow.cancel().status, AuthStatus.CANCELLING)
        self.assertFalse(self.flow.capabilities().can_begin)
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].status, AuthStatus.CANCELLED)
        self.assertEqual(self.vault.sessions, {})

    def test_cancel_during_committed_vault_write_requires_confirmed_cleanup(self):
        self.begin()
        self.vault.fail_delete = True
        self.vault.on_store = self.flow.cancel
        result = self.flow.complete_callback(self.callback())
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "vault_cleanup_uncertain")
        self.assertIsNone(result.identity)
        self.assertFalse(self.flow.capabilities().can_begin)
        self.assertIsNone(self.flow.begin().authorization_url)
        self.assertNotIn("PRIVATE SYNTHETIC", str(result.public()))

    def test_malformed_vault_delete_result_is_not_confirmed_cleanup(self):
        self.begin()
        self.vault.on_store = self.flow.cancel
        self.vault.delete_session = lambda identifier: False
        result = self.flow.complete_callback(self.callback())
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertFalse(self.flow.capabilities().can_begin)
        self.assertEqual(len(self.vault.sessions), 1)

    def test_malformed_vault_store_result_does_not_claim_committed_session(self):
        self.begin()
        self.vault.store_session = lambda identifier, material: False
        result = self.flow.complete_callback(self.callback())
        self.assertNotEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(self.vault.sessions, {})

    def test_token_exchange_unknown_outcome_never_reposts_code(self):
        self.begin()

        def timeout():
            raise TimeoutError("PRIVATE SYNTHETIC TOKEN DIAGNOSTIC")

        self.transport.on_post = timeout
        result = self.flow.complete_callback(self.callback())
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "token_exchange_uncertain")
        self.flow.complete_callback(self.callback())
        self.assertIsNone(self.flow.begin().authorization_url)
        self.assertEqual(len(self.transport.posts), 1)
        self.assertNotIn("PRIVATE SYNTHETIC", str(result.public()))

    def test_wrong_account_valid_signature_does_not_establish_session(self):
        self.begin(expected_account=AccountIdentity(CONFIG.issuer, "different-subject"))
        result = self.flow.complete_callback(self.callback())
        self.assertEqual(result.status, AuthStatus.ERROR)
        self.assertEqual(result.reason, "wrong_account")
        self.assertEqual(self.vault.sessions, {})

    def test_nonce_issuer_audience_azp_and_numeric_claim_types_fail_closed(self):
        for claims in (
            {"nonce": "wrong"},
            {"iss": "https://other.example.test"},
            {"aud": [CONFIG.client_id]},
            {"azp": "other-client"},
            {"iat": True},
            {"exp": int(time.time()) + 120.5},
            {"nbf": "0"},
        ):
            with self.subTest(claims=claims):
                self.setUp()
                self.begin()
                self.transport.claim_changes = claims
                result = self.flow.complete_callback(self.callback())
                self.assertEqual(result.status, AuthStatus.ERROR)
                self.assertEqual(self.vault.sessions, {})

    def test_refresh_tokens_expanded_scopes_and_invalid_token_types_are_rejected(self):
        for changes in (
            {"refresh_token": "synthetic-refresh"},
            {"scope": "openid profile"},
            {"token_type": "MAC"},
            {"expires_in": True},
            {"expires_in": "90"},
        ):
            with self.subTest(changes=changes):
                self.setUp()
                self.begin()
                self.transport.token_changes = changes
                result = self.flow.complete_callback(self.callback())
                self.assertEqual(result.status, AuthStatus.ERROR)
                self.assertEqual(self.vault.sessions, {})

    def test_redirected_or_duplicate_json_token_response_is_uncertain_and_redacted(self):
        for response in (
            HTTPResponse(200, "https://other.example.test/token", b"{}", redirected=True),
            HTTPResponse(
                200, CONFIG.token_endpoint, b'{"access_token":"one","access_token":"two"}'
            ),
        ):
            with self.subTest(response=response):
                self.setUp()
                self.begin()
                self.transport.response_override = response
                result = self.flow.complete_callback(self.callback())
                self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
                self.assertEqual(self.transport.gets, [])
                self.assertEqual(self.vault.sessions, {})

    def test_expired_authorization_cannot_exchange_or_reuse_state(self):
        self.begin()
        old_callback = self.callback()
        self.clock += CONFIG.authorization_ttl_seconds
        self.assertEqual(self.flow.status().status, AuthStatus.EXPIRED)
        self.flow.complete_callback(old_callback)
        self.assertEqual(self.transport.posts, [])
        self.begin()
        self.assertEqual(self.flow.complete_callback(old_callback).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])


if __name__ == "__main__":
    unittest.main()
