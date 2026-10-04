"""Provider contract tests with synthetic keys, tokens, transport and vault only.

No sockets, provider requests, registrations, credentials or OS-vault access.
"""

import hashlib
import json
import threading
import time
import unittest
from dataclasses import asdict, replace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthorizationResponseIssuer,
    AuthStatus,
    EntraNativePolicy,
    HTTPResponse,
    ManagedSignIn,
    entra_native_configuration,
    issuer_bound_loopback_redirect,
)


TENANT = "11111111-1111-4111-8111-111111111111"
DESKTOP = "22222222-2222-4222-8222-222222222222"
API = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
CONFIG = entra_native_configuration(tenant_id=TENANT, desktop_client_id=DESKTOP, api_client_id=API)


class SyntheticVault:
    def __init__(self):
        self.items = {}
        self.stores = 0
        self.deletes = 0
        self.on_store = None

    def assert_available(self):
        return None

    def store_session(self, identifier, material):
        self.stores += 1
        self.items[identifier] = material
        if self.on_store:
            self.on_store()

    def delete_session(self, identifier):
        self.deletes += 1
        self.items.pop(identifier, None)


class SyntheticTransport:
    def __init__(self, key, config, now):
        self.key, self.config, self.now = key, config, now
        self.nonce = ""
        self.posts = []
        self.gets = []
        self.claim_changes = {}
        self.remove_claims = []
        self.token_changes = {}
        self.remove_scope = False
        self.tamper_signature = False
        self.on_post = None
        self.on_get = None

    def post_form(self, url, fields, *, timeout_seconds, follow_redirects):
        assert url == self.config.token_endpoint
        assert timeout_seconds == 10 and follow_redirects is False
        self.posts.append(dict(fields))
        if self.on_post:
            self.on_post()
        claims = {
            "iss": self.config.issuer,
            "sub": "synthetic-pairwise-desktop-subject",
            "aud": self.config.client_id,
            "nonce": self.nonce,
            "iat": self.now - 120,
            "nbf": self.now - 120,
            "exp": self.now + 3480,
            "tid": TENANT,
            "ver": "2.0",
        }
        claims.update(self.claim_changes)
        for name in self.remove_claims:
            claims.pop(name, None)
        encoded = jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})
        if self.tamper_signature:
            parts = encoded.split(".")
            parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
            encoded = ".".join(parts)
        payload = {
            "token_type": "Bearer",
            "access_token": "SYNTHETIC_OPAQUE_API_ACCESS_TOKEN",
            "id_token": encoded,
            "expires_in": 5400,
            "scope": self.config.provider_policy.api_scope,
        }
        payload.update(self.token_changes)
        if self.remove_scope:
            payload.pop("scope", None)
        return HTTPResponse(200, url, json.dumps(payload).encode())

    def get(self, url, *, timeout_seconds, follow_redirects):
        assert url == self.config.jwks_endpoint
        assert timeout_seconds == 10 and follow_redirects is False
        self.gets.append(url)
        if self.on_get:
            self.on_get()
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="test-key", use="sig", alg="RS256")
        return HTTPResponse(200, url, json.dumps({"keys": [jwk]}).encode())


class ProviderSignInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = int(time.time())
        self.monotonic = 1000.0
        self.configure(CONFIG)

    def configure(self, config):
        self.config = config
        self.transport = SyntheticTransport(self.key, config, self.now)
        self.vault = SyntheticVault()
        self.flow = ManagedSignIn(
            config, transport=self.transport, vault=self.vault, monotonic=lambda: self.monotonic
        )

    def start(self, **kwargs):
        request = self.flow.begin(**kwargs)
        self.assertEqual(request.result.status, AuthStatus.WAITING)
        self.params = {
            name: values[0]
            for name, values in parse_qs(urlsplit(request.authorization_url).query).items()
        }
        self.transport.nonce = self.params["nonce"]
        return request

    def callback(self, **changes):
        values = {"state": self.params["state"], "code": "synthetic-code"}
        values.update(changes)
        return self.config.redirect_uri + "?" + urlencode(values)

    def finish(self, **changes):
        return self.flow.complete_callback(self.callback(**changes))

    def assert_rejected_token(self):
        result = self.finish()
        self.assertEqual(result.status, AuthStatus.ERROR)
        self.assertEqual(result.reason, "token_validation_failed")
        self.assertIsNone(result.identity)
        self.assertEqual(self.vault.items, {})
        self.assertEqual(self.vault.stores, 0)

    def test_builder_pins_tenant_native_client_api_and_exact_distinct_callback(self):
        expected = hashlib.sha256(CONFIG.issuer.encode("ascii")).hexdigest()
        self.assertEqual(
            CONFIG.redirect_uri, f"http://127.0.0.1:43821/auth/callback/issuer/{expected}"
        )
        self.assertEqual(
            CONFIG.provider_policy.scopes, ("openid", "profile", f"api://{API}/access_as_user")
        )
        self.assertEqual(CONFIG.algorithms, ("RS256",))
        self.assertIn(f"/{TENANT}/oauth2/v2.0/", CONFIG.token_endpoint)
        self.assertEqual(CONFIG.max_id_token_lifetime_seconds, 3600)
        self.assertEqual(CONFIG.max_access_token_lifetime_seconds, 5400)
        self.assertEqual(CONFIG.local_session_ttl_seconds, 600)
        self.assertFalse(self.flow.capabilities().native_integration_verified)
        self.assertEqual(self.flow.capabilities().scopes, CONFIG.scopes)
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.transport.gets, [])

    def test_distinct_callback_is_bound_to_issuer_not_an_operator_boolean(self):
        for changes in (
            {"redirect_uri": "http://127.0.0.1:43821/auth/callback/entra-jt"},
            {
                "redirect_uri": issuer_bound_loopback_redirect(
                    f"https://login.microsoftonline.com/{OTHER}/v2.0"
                )
            },
            {"authorization_response_issuer": "issuer_bound_redirect"},
            {"authorization_response_issuer": True},
            {"provider_policy": asdict(CONFIG.provider_policy)},
            {"issuer": f"https://login.microsoftonline.com/{OTHER}/v2.0"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(CONFIG, **changes)
        other = entra_native_configuration(
            tenant_id=OTHER, desktop_client_id=DESKTOP, api_client_id=API
        )
        self.assertNotEqual(CONFIG.redirect_uri, other.redirect_uri)

    def test_policy_rejects_other_clouds_endpoints_invalid_identifiers_or_shared_client(self):
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_endpoint"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(CONFIG, **{field: "https://other.example.test/endpoint"})
        for field in ("tenant_id", "desktop_client_id", "api_client_id"):
            for value in (
                "common",
                "organizations",
                "bad",
                "FFFFFFFF-1111-4111-8111-111111111111",
                True,
            ):
                arguments = {
                    "tenant_id": TENANT,
                    "desktop_client_id": DESKTOP,
                    "api_client_id": API,
                }
                arguments[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    entra_native_configuration(**arguments)
        with self.assertRaises(ValueError):
            entra_native_configuration(tenant_id=TENANT, desktop_client_id=API, api_client_id=API)
        with self.assertRaises(ValueError):
            EntraNativePolicy(TENANT, "00000003-0000-0000-c000-000000000000")
        for port in (True, 0, 1023, 65536, "43821"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                issuer_bound_loopback_redirect(CONFIG.issuer, port=port)

    def test_only_explicit_reviewed_request_scope_set_is_accepted(self):
        for scope in (
            "email",
            "offline_access",
            "User.Read",
            "Mail.Read",
            "https://graph.microsoft.com/User.Read",
            "https://www.googleapis.com/auth/gmail.readonly",
            f"api://{OTHER}/access_as_user",
            f"api://{API}/.default",
            f"api://{API}/admin",
            "access_as_user",
        ):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                replace(CONFIG, scopes=CONFIG.scopes + (scope,))
        for scopes in (("openid",), CONFIG.scopes + ("openid",), list(CONFIG.scopes)):
            with self.subTest(scopes=scopes), self.assertRaises(ValueError):
                replace(CONFIG, scopes=scopes)
        reordered = replace(CONFIG, scopes=tuple(reversed(CONFIG.scopes)))
        self.configure(reordered)
        self.start()
        self.assertEqual(self.params["scope"], " ".join(reordered.scopes))
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(next(iter(self.vault.items.values())).scopes, reordered.scopes)

    def test_normal_provider_lifetimes_do_not_extend_local_session(self):
        self.start()
        with patch("team_browser.client.auth_flow.time.time", return_value=self.now):
            result = self.finish()
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(result.expires_at, self.now + 600)
        material = next(iter(self.vault.items.values()))
        self.assertEqual(material.scopes, CONFIG.scopes)
        self.assertEqual(material.expires_at, result.expires_at)
        self.assertFalse(result.public()["company_membership_verified"])
        self.assertFalse(result.public()["managed_access_available"])
        self.assertNotIn(material.access_token, str(result.public()) + repr(material))
        self.assertNotIn(material.id_token, str(result.public()) + repr(material))

    def test_smaller_local_provider_id_or_access_expiry_wins(self):
        for ttl, claims, token, expected in (
            (120, {}, {}, 120),
            (600, {"exp": self.now + 90}, {}, 90),
            (600, {}, {"expires_in": 60}, 60),
        ):
            with self.subTest(ttl=ttl, claims=claims, token=token):
                self.configure(replace(CONFIG, local_session_ttl_seconds=ttl))
                self.start()
                self.transport.claim_changes.update(claims)
                self.transport.token_changes.update(token)
                with patch("team_browser.client.auth_flow.time.time", return_value=self.now):
                    result = self.finish()
                self.assertEqual(result.expires_at, self.now + expected)

    def test_local_ttl_uses_response_receipt_not_later_key_fetch(self):
        self.start()
        wall = [self.now]
        self.transport.on_get = lambda: wall.__setitem__(0, self.now + 45)
        with patch("team_browser.client.auth_flow.time.time", side_effect=lambda: wall[0]):
            result = self.finish()
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(result.expires_at, self.now + 600)

    def test_local_expiry_cleanup_does_not_wait_for_provider_expiration(self):
        self.start()
        result = self.finish()
        with patch("team_browser.client.auth_flow.time.time", return_value=result.expires_at):
            expired = self.flow.status()
        self.assertEqual(expired.status, AuthStatus.EXPIRED)
        self.assertEqual(self.vault.items, {})
        self.assertEqual(self.vault.deletes, 1)

    def test_provider_and_local_lifetime_configuration_remains_bounded(self):
        for field, value in (
            ("local_session_ttl_seconds", True),
            ("local_session_ttl_seconds", 601),
            ("local_session_ttl_seconds", 29),
            ("max_id_token_lifetime_seconds", 3601),
            ("max_access_token_lifetime_seconds", 5401),
            ("clock_skew_seconds", 61),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                replace(CONFIG, **{field: value})

    def test_provider_response_scope_normalization_is_an_allowlisted_set(self):
        resource = CONFIG.provider_policy.api_scope
        for scopes in (
            resource,
            f"profile {resource} openid",
            f"{resource} openid",
            f"{resource} profile",
            f"{resource} {resource}",
        ):
            with self.subTest(scopes=scopes):
                self.configure(CONFIG)
                self.start()
                self.transport.token_changes["scope"] = scopes
                self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)
                self.assertEqual(next(iter(self.vault.items.values())).scopes, CONFIG.scopes)

    def test_wrong_missing_or_expanded_grants_are_rejected_before_jwks(self):
        resource = CONFIG.provider_policy.api_scope
        for scopes in (
            "openid profile",
            "access_as_user",
            f"api://{OTHER}/access_as_user",
            f"{resource} offline_access",
            f"{resource} email",
            f"{resource} User.Read",
            f"{resource} https://graph.microsoft.com/Mail.Read",
            f"{resource} api://{API}/admin",
            f"{resource} https://www.googleapis.com/auth/gmail.readonly",
            "",
            f" {resource}",
            f"{resource}\n",
            f"{resource}\topenid",
            None,
            [resource],
        ):
            with self.subTest(scopes=scopes):
                self.configure(CONFIG)
                self.start()
                self.transport.token_changes["scope"] = scopes
                self.assert_rejected_token()
                self.assertEqual(self.transport.gets, [])
        self.configure(CONFIG)
        self.start()
        self.transport.remove_scope = True
        self.assert_rejected_token()

    def test_refresh_token_is_unsolicited_even_if_empty_or_null(self):
        for value in ("SYNTHETIC_REFRESH", "", None):
            with self.subTest(value=value):
                self.configure(CONFIG)
                self.start()
                self.transport.token_changes["refresh_token"] = value
                self.assert_rejected_token()

    def test_missing_callback_issuer_is_accepted_only_in_selected_mode(self):
        self.configure(
            replace(
                CONFIG, authorization_response_issuer=AuthorizationResponseIssuer.RFC9207_REQUIRED
            )
        )
        self.start()
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.finish(iss=CONFIG.issuer).status, AuthStatus.IDENTITY_VERIFIED)

    def test_wrong_issuer_or_different_issuer_callback_never_downgrades_or_consumes(self):
        self.start()
        for issuer in ("", CONFIG.issuer + "/", f"https://login.microsoftonline.com/{OTHER}/v2.0"):
            with self.subTest(issuer=issuer):
                self.assertEqual(self.finish(iss=issuer).reason, "callback_rejected")
        wrong_uri = issuer_bound_loopback_redirect(
            f"https://login.microsoftonline.com/{OTHER}/v2.0"
        )
        self.assertEqual(
            self.flow.complete_callback(
                self.callback().replace(CONFIG.redirect_uri, wrong_uri)
            ).reason,
            "callback_rejected",
        )
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_bounded_extensions_are_ignored_and_never_reflected(self):
        self.start()
        callback = (
            self.callback(
                session_state="synthetic-session",
                scope="UNTRUSTED_CALLBACK_SCOPE Mail.Read",
                client_info="PRIVATE_PROVIDER_TEXT",
                next="https://evil.example.test/",
            )
            + "&future_extension=one&future_extension=two"
        )
        result = self.flow.complete_callback(callback)
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertNotIn("PRIVATE_PROVIDER_TEXT", str(result.public()))
        self.assertNotIn("UNTRUSTED", str(result.public()))
        self.assertEqual(next(iter(self.vault.items.values())).scopes, CONFIG.scopes)

    def test_invalid_extensions_critical_duplicates_and_code_error_mixtures_rejected(self):
        self.start()
        suffixes = (
            "&state=extra",
            "&code=extra",
            "&iss=" + CONFIG.issuer + "&iss=" + CONFIG.issuer,
            "&error=access_denied",
            "&error_description=unexpected",
            "&error_uri=https://evil.test/",
            "&access_token=implicit",
            "&id_token=hybrid",
            "&refresh_token=bad",
            "&response=jwt",
            "&code_verifier=bad",
            "&client_secret=bad",
            "&broken",
            "&x=%xx",
            "&x=%00",
            "&x=%0d%0a",
            "&x=%C2%85",
            "&x=" + "a" * 2049,
            "&" + "x" * 65 + "=value",
            "".join(f"&x{i}=a" for i in range(31)),
        )
        for suffix in suffixes:
            with self.subTest(suffix=suffix[:80]):
                self.assertEqual(
                    self.flow.complete_callback(self.callback() + suffix).reason,
                    "callback_rejected",
                )
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_denial_without_issuer_consumes_state_with_sanitized_extensions(self):
        self.start()
        fields = {
            "state": self.params["state"],
            "error": "access_denied",
            "error_description": "PRIVATE_PROVIDER_TEXT",
            "session_state": "synthetic",
            "error_uri": "https://evil.example.test/do-not-follow",
        }
        denied = CONFIG.redirect_uri + "?" + urlencode(fields)
        for name in ("state", "error", "error_description", "error_uri"):
            self.assertEqual(
                self.flow.complete_callback(denied + "&" + urlencode({name: "duplicate"})).reason,
                "callback_rejected",
            )
        result = self.flow.complete_callback(denied)
        self.assertEqual(result.status, AuthStatus.CANCELLED)
        self.assertEqual(result.reason, "consent_denied")
        self.assertNotIn("PRIVATE", str(result.public()))
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.assertEqual(self.transport.gets, [])

    def test_normal_older_iat_does_not_relax_signature_nonce_or_time_checks(self):
        for changes in (
            {"nonce": "old-attempt"},
            {"iss": CONFIG.issuer + "/"},
            {"aud": API},
            {"exp": self.now},
            {"iat": self.now + 120},
            {"nbf": self.now + 120},
            {"iat": self.now - 121, "exp": self.now + 3480},
            {"iat": True},
            {"exp": float(self.now + 300)},
            {"nbf": "0"},
            {"nbf": self.now + 20, "exp": self.now + 10},
        ):
            with self.subTest(changes=changes):
                self.configure(CONFIG)
                self.start()
                self.transport.claim_changes.update(changes)
                self.assert_rejected_token()
        self.configure(CONFIG)
        self.start()
        self.transport.tamper_signature = True
        self.assert_rejected_token()

    def test_access_token_response_lifetime_ceiling_is_not_app_ttl(self):
        for value in (0, 5401, True, "5400", 5400.0):
            with self.subTest(value=value):
                self.configure(CONFIG)
                self.start()
                self.transport.token_changes["expires_in"] = value
                self.assert_rejected_token()

    def test_entra_id_token_requires_exact_tenant_and_v2_claims_before_storage(self):
        for claim, values in (
            ("tid", (OTHER, "", None, [TENANT], True)),
            ("ver", ("1.0", "", None, 2.0, ["2.0"], True)),
        ):
            for value in values:
                with self.subTest(claim=claim, value=value):
                    self.configure(CONFIG)
                    self.start()
                    self.transport.claim_changes[claim] = value
                    self.assert_rejected_token()
            with self.subTest(missing=claim):
                self.configure(CONFIG)
                self.start()
                self.transport.remove_claims.append(claim)
                self.assert_rejected_token()

    def test_entra_id_token_tenant_is_bound_to_selected_configuration(self):
        config = entra_native_configuration(
            tenant_id=OTHER, desktop_client_id=DESKTOP, api_client_id=API
        )
        self.configure(config)
        self.start()
        self.transport.claim_changes["tid"] = OTHER
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_legacy_oidc_does_not_require_or_interpret_entra_claims(self):
        from test_client_auth_flow import CONFIG as LEGACY_CONFIG, FakeTransport

        for claims in ({}, {"tid": OTHER, "ver": "1.0"}):
            with self.subTest(claims=claims):
                transport = FakeTransport(self.key)
                transport.claim_changes.update(claims)
                vault = SyntheticVault()
                flow = ManagedSignIn(LEGACY_CONFIG, transport=transport, vault=vault)
                request = flow.begin()
                params = parse_qs(urlsplit(request.authorization_url).query)
                transport.nonce = params["nonce"][0]
                callback = (
                    LEGACY_CONFIG.redirect_uri
                    + "?"
                    + urlencode(
                        {
                            "state": params["state"][0],
                            "code": "synthetic-code",
                            "iss": LEGACY_CONFIG.issuer,
                        }
                    )
                )
                self.assertEqual(
                    flow.complete_callback(callback).status, AuthStatus.IDENTITY_VERIFIED
                )
                self.assertEqual(vault.stores, 1)

    def test_expected_account_binding_stays_exact_issuer_and_pairwise_subject(self):
        self.start(expected_account=AccountIdentity(CONFIG.issuer, "different-subject"))
        result = self.finish()
        self.assertEqual(result.reason, "wrong_account")
        self.assertEqual(self.vault.items, {})

    def test_cancel_then_restart_rejects_old_state_and_old_nonce(self):
        self.start()
        old_callback, old_nonce = self.callback(), self.params["nonce"]
        self.assertEqual(self.flow.cancel().status, AuthStatus.CANCELLED)
        self.assertEqual(self.flow.complete_callback(old_callback).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.start()
        self.assertEqual(self.flow.complete_callback(old_callback).reason, "callback_rejected")
        self.transport.claim_changes["nonce"] = old_nonce
        self.assert_rejected_token()

    def test_cancel_during_post_jwks_or_commit_keeps_no_session(self):
        for stage in ("post", "get", "store"):
            with self.subTest(stage=stage):
                self.configure(CONFIG)
                self.start()
                target = self.vault if stage == "store" else self.transport
                setattr(target, f"on_{stage}", self.flow.cancel)
                self.assertEqual(self.finish().status, AuthStatus.CANCELLED)
                self.assertEqual(self.vault.items, {})
                self.assertEqual(self.vault.stores, int(stage == "store"))
                self.assertEqual(self.vault.deletes, int(stage == "store"))
                self.assertEqual(self.finish().reason, "callback_rejected")
                self.assertEqual(len(self.transport.posts), 1)

    def test_simultaneous_callbacks_and_replay_redeem_code_only_once(self):
        self.start()
        entered, release = threading.Event(), threading.Event()
        self.transport.on_post = lambda: (entered.set(), release.wait(2))
        results = []
        thread = threading.Thread(target=lambda: results.append(self.finish()))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.finish().reason, "callback_rejected")
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(self.finish().reason, "callback_rejected")
        self.assertEqual(len(self.transport.posts), 1)
        self.assertEqual(self.vault.stores, 1)

    def test_expired_attempt_cannot_exchange_and_new_attempt_has_new_state(self):
        self.start()
        old = self.callback()
        self.monotonic += CONFIG.authorization_ttl_seconds
        self.assertEqual(self.flow.status().status, AuthStatus.EXPIRED)
        self.assertEqual(self.flow.complete_callback(old).reason, "callback_rejected")
        self.assertEqual(self.transport.posts, [])
        self.start()
        self.assertEqual(self.flow.complete_callback(old).reason, "callback_rejected")
        self.assertEqual(self.finish().status, AuthStatus.IDENTITY_VERIFIED)

    def test_authorization_and_exchange_request_no_unexpected_permissions(self):
        self.start()
        self.assertEqual(set(self.params["scope"].split()), set(CONFIG.scopes))
        self.assertEqual(self.params["response_type"], "code")
        self.assertEqual(self.params["response_mode"], "query")
        self.assertEqual(self.params["code_challenge_method"], "S256")
        self.assertEqual(self.params["prompt"], "select_account")
        self.finish()
        self.assertEqual(
            set(self.transport.posts[0]),
            {
                "grant_type",
                "code",
                "redirect_uri",
                "client_id",
                "code_verifier",
            },
        )
        self.assertEqual(self.transport.posts[0]["redirect_uri"], CONFIG.redirect_uri)
        self.assertNotIn("client_secret", self.transport.posts[0])
        self.assertEqual(len(self.transport.posts), 1)
        self.assertEqual(self.transport.gets, [CONFIG.jwks_endpoint])


if __name__ == "__main__":
    unittest.main()
