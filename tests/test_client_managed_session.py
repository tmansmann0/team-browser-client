"""Public-client contracts, invented data and mocked native HTTPS/Keychain only.

No imports of private API modules: snapshots below match the documented API
shapes. No provider requests, real Keychain, browser launch or network occurs.
"""

import io
import json
import os
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client import managed_session as managed
from team_browser.client import oidc_https as https
from team_browser.client import session_vault as vault
from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthStatus,
    HTTPResponse,
    ManagedSignIn,
    NativeSessionMaterial,
    TrustedOIDCConfiguration,
    entra_native_configuration,
)
from team_browser.local.macos_keychain import KeychainConfiguration, SecretNotFound


TENANT = "11111111-1111-4111-8111-111111111111"
API = "22222222-2222-4222-8222-222222222222"
DESKTOP = "33333333-3333-4333-8333-333333333333"
OIDC = entra_native_configuration(tenant_id=TENANT, desktop_client_id=DESKTOP, api_client_id=API)
BACKEND = managed.TrustedBackendConfiguration("https://api.example.test", OIDC)
KEYCHAIN = KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", vault.NAMESPACE)
SESSION = "SYNTHETIC_SESSION_REFERENCE_1234567890"
OTHER = "SYNTHETIC_OTHER_REFERENCE_12345678900"
ACCESS = "SYNTHETIC_ACCESS_NOT_A_CREDENTIAL"
ID_TOKEN = "SYNTHETIC_ID_NOT_A_CREDENTIAL"
DIAGNOSTIC = "SYNTHETIC_PRIVATE_NATIVE_DIAGNOSTIC"
PUBLIC = "93.184.216.34"
ME = {
    "id": "member-a",
    "org_id": "product-company-a",
    "display_name": "Synthetic Member",
    "role": "member",
}
PROFILES = [
    {
        "id": "profile-a",
        "name": "Synthetic profile",
        "preset_id": "preset-a",
        "assigned_user_id": "member-a",
        "revision": 1,
        "state": "unprovisioned",
    }
]
PRESETS = [
    {
        "id": "preset-a",
        "name": "Synthetic preset",
        "engine": "normal-browser",
        "locale": "en-US",
        "timezone": "UTC",
        "proxy_required": True,
        "revision": 1,
    }
]


def response(value=ME, *, status=200, body=None, extra=b"", content_type=b"application/json"):
    body = json.dumps(value).encode() if body is None else body
    return (
        f"HTTP/1.1 {status} Synthetic\r\n".encode()
        + b"Content-Type: "
        + content_type
        + b"\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + extra
        + b"\r\n"
        + body
    )


class FakeStore:
    def __init__(self):
        self.items = {}
        self.hook = None
        self.delete_ack = None

    def get(self, reference):
        if self.hook:
            self.hook("get", reference)
        if reference.account_id not in self.items:
            raise SecretNotFound()
        return self.items[reference.account_id]

    def put(self, reference, value):
        if self.hook:
            self.hook("put", reference)
        self.items[reference.account_id] = value
        return None

    def delete(self, reference):
        if self.hook:
            self.hook("delete", reference)
        self.items.pop(reference.account_id, None)
        return self.delete_ack


class FakeSocket:
    def __init__(self, data=b""):
        self.data = data
        self.sent = []
        self.peer = (PUBLIC, 443)
        self.destination = None
        self.fragment = 4096
        self.on_read = None
        self.on_handshake = None
        self.on_send = None
        self.on_close = None
        self.ack = {}
        self.alpn = "http/1.1"
        self.closed = 0

    def settimeout(self, value):
        return self.ack.get("settimeout")

    def connect(self, destination):
        self.destination = destination
        return self.ack.get("connect")

    def getpeername(self):
        return self.peer

    def do_handshake(self):
        if self.on_handshake:
            self.on_handshake()
        return self.ack.get("do_handshake")

    def selected_alpn_protocol(self):
        return self.alpn

    def sendall(self, value):
        self.sent.append(value)
        if self.on_send:
            self.on_send()
        return self.ack.get("sendall")

    def recv(self, maximum):
        if self.on_read:
            self.on_read()
        if "recv" in self.ack:
            return self.ack["recv"]
        size = min(maximum, self.fragment)
        value, self.data = self.data[:size], self.data[size:]
        return value

    def close(self):
        self.closed += 1
        if self.on_close:
            self.on_close()
        return self.ack.get("close")


class ManagedSessionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.wall, self.monotonic = float(int(time.time())), 1000.0
        clock = SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.monotonic)
        self.store = FakeStore()
        self.raw, self.wire = FakeSocket(), FakeSocket(response())
        self.tls = SimpleNamespace(
            verify_mode=ssl.CERT_REQUIRED,
            check_hostname=True,
            minimum_version=ssl.TLSVersion.TLSv1_2,
            keylog_filename=None,
            wrap_socket=Mock(return_value=self.wire),
        )
        for target, value in ((vault, "time"), (managed, "time"), (https, "time")):
            self.stack.enter_context(patch.object(target, value, clock))
        self.stack.enter_context(patch.object(vault, "_open_native_store", return_value=self.store))
        self.stack.enter_context(
            patch.object(vault, "_lease_directory", return_value=Path(self.temp) / "lease")
        )
        self.stack.enter_context(patch.object(https, "_context", return_value=self.tls))
        self.resolve = self.stack.enter_context(
            patch.object(https, "_resolve", return_value=[PUBLIC])
        )
        self.socket = self.stack.enter_context(
            patch.object(managed.socket, "socket", return_value=self.raw)
        )
        for name in ("create_connection", "getaddrinfo"):
            self.stack.enter_context(
                patch.object(managed.socket, name, side_effect=AssertionError("Network forbidden"))
            )
        self.vault = vault.MacOSSessionVault(KEYCHAIN, oidc_configuration=OIDC)
        self.stack.callback(self.vault.close)
        self.vault.recover_discard_all()
        self.vault.store_session(SESSION, self.material())
        self.client = managed.NativeManagedSession(BACKEND, vault=self.vault)

    def material(self, **changes):
        return replace(
            NativeSessionMaterial(
                AccountIdentity(OIDC.issuer, "native-subject"),
                ACCESS,
                ID_TOKEN,
                int(self.wall) + 300,
                OIDC.scopes,
            ),
            **changes,
        )

    def fresh(self, value=ME, **kwargs):
        self.wire.data = response(value, **kwargs)
        self.wire.on_send = None
        self.client = managed.NativeManagedSession(BACKEND, vault=self.vault)
        return self.client

    def expires(self):
        self.wall += 300
        self.monotonic += 300

    def test_configuration_is_exact_immutable_origin_with_delegated_policy(self):
        for origin in (
            None,
            {},
            "http://api.example.test",
            "https://localhost",
            "https://127.0.0.1",
            "https://api.example.test/",
            "https://api.example.test/v1",
            "https://api.example.test?x",
            "https://api.example.test#x",
            "https://api.example.test:444",
            "https://u:p@api.example.test",
            "https://api.example.test/../",
            "https://api.example.test/%2f",
            "https://api.internal",
            "https://api.local",
            "https://2130706433.0",
        ):
            with (
                self.subTest(origin=origin),
                self.assertRaises((ValueError, https.OIDCTransportError)),
            ):
                managed.TrustedBackendConfiguration(origin, OIDC)
        generic = TrustedOIDCConfiguration(
            "https://id.example.test",
            "client",
            "https://id.example.test/auth",
            "https://id.example.test/token",
            "https://id.example.test/keys",
            "http://127.0.0.1:43182/callback",
        )
        for config in ({}, None, generic):
            with self.assertRaises(ValueError):
                managed.TrustedBackendConfiguration(BACKEND.origin, config)
        with self.assertRaises(FrozenInstanceError):
            BACKEND.origin = "https://changed.example.test"
        self.resolve.assert_not_called()
        self.socket.assert_not_called()

    def test_construction_never_grants_membership_or_exposes_token_adapter(self):
        status = self.client.snapshot().public()
        self.assertFalse(status["managed_available"])
        self.assertIsNone(status["membership"])
        self.assertFalse(status["device_enrolled"])
        self.assertFalse(status["native_integration_verified"])
        for method in (self.client.profiles, self.client.presets):
            with self.assertRaisesRegex(managed.ManagedSessionError, "membership_required"):
                method()
        for kwargs in (
            {"transport": object()},
            {"vault": object()},
            {"configuration": {}},
            {"token": ACCESS},
        ):
            values = dict(configuration=BACKEND, vault=self.vault)
            values.update(kwargs)
            with self.assertRaises(TypeError):
                managed.NativeManagedSession(**values)
        self.assertFalse(
            any(
                hasattr(self.vault, name)
                for name in ("get", "get_token", "with_token", "get_session")
            )
        )
        self.resolve.assert_not_called()

    def test_policy_mismatch_and_absence_fail_before_network(self):
        for oidc in (
            replace(OIDC, local_session_ttl_seconds=60),
            replace(OIDC, scopes=tuple(reversed(OIDC.scopes))),
            entra_native_configuration(
                tenant_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                desktop_client_id=DESKTOP,
                api_client_id=API,
            ),
        ):
            with self.assertRaises(managed.ManagedSessionError):
                managed.NativeManagedSession(
                    replace(BACKEND, oidc_configuration=oidc), vault=self.vault
                )
        self.vault.delete_session(SESSION)
        with self.assertRaises(managed.ManagedSessionError):
            managed.NativeManagedSession(BACKEND, vault=self.vault)
        self.resolve.assert_not_called()

    def test_exact_three_operations_typed_projections_and_no_id_token(self):
        membership = self.client.me()
        self.assertIs(type(membership), managed.ManagedMembership)
        self.assertEqual(membership.tenant_id, ME["org_id"])
        self.assertNotEqual(membership.tenant_id, TENANT)
        self.assertEqual(membership.role, managed.MemberRole.MEMBER)
        for value, method, kind in (
            (PROFILES, self.client.profiles, managed.ManagedProfile),
            (PRESETS, self.client.presets, managed.ManagedPreset),
        ):
            self.wire.data = response(value)
            result = method()
            self.assertIs(type(result), tuple)
            self.assertIs(type(result[0]), kind)
            self.assertEqual(result[0].public(), value[0])
        self.assertEqual(
            [r.split(b"\r\n")[0] for r in self.wire.sent],
            [
                b"GET /v1/me HTTP/1.1",
                b"GET /v1/profiles HTTP/1.1",
                b"GET /v1/presets HTTP/1.1",
            ],
        )
        for request in self.wire.sent:
            self.assertIn(b"Authorization: Bearer " + ACCESS.encode() + b"\r\n", request)
            self.assertIn(b"Host: api.example.test\r\n", request)
            self.assertNotIn(ID_TOKEN.encode(), request)
            self.assertNotIn(b"Cookie:", request)
        self.assertEqual(self.raw.destination, (PUBLIC, 443))
        self.assertEqual(self.resolve.call_args.args[0], "api.example.test")
        self.assertEqual(
            self.tls.wrap_socket.call_args.kwargs["server_hostname"], "api.example.test"
        )

    def test_operation_allowlist_has_no_url_method_header_body_extension(self):
        for operation in (
            "/v1/me",
            "/v1/users",
            "POST",
            "https://evil.example.test/v1/me",
            {},
            None,
        ):
            with self.assertRaises(TypeError):
                self.vault._managed_read(self.client, operation)
        for operation in (
            lambda: self.client.me("https://evil.example.test"),
            lambda: self.client.profiles(headers={"Cookie": "x"}),
            lambda: self.client.presets(method="POST"),
        ):
            with self.assertRaises(TypeError):
                operation()
        self.resolve.assert_not_called()

    def test_each_role_is_server_derived_and_role_change_is_observed(self):
        for role in ("owner", "admin", "member", "auditor"):
            self.wire.data = response(dict(ME, role=role))
            self.assertEqual(self.client.me().role.value, role)
        self.assertEqual(self.client.snapshot().membership.role, managed.MemberRole.AUDITOR)

    def test_member_or_tenant_change_invalidates_without_publishing(self):
        for changes in ({"id": "member-b"}, {"org_id": "product-company-b"}):
            self.fresh().me()
            self.wire.data = response(dict(ME, **changes))
            with self.assertRaisesRegex(managed.ManagedSessionError, "membership_changed"):
                self.client.me()
            self.assertIsNone(self.client.snapshot().membership)
            self.assertFalse(self.client.snapshot().public()["managed_available"])

    def test_auth_failure_on_each_operation_immediately_clears_availability(self):
        for status in (401, 403):
            for name in ("me", "profiles", "presets"):
                self.fresh().me()
                self.wire.data = response(status=status, body=(ACCESS + DIAGNOSTIC).encode())
                with self.assertRaisesRegex(
                    managed.ManagedSessionError, "membership_denied"
                ) as result:
                    getattr(self.client, name)()
                self.assertNotIn(ACCESS, str(result.exception))
                self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.DENIED)
                calls = self.resolve.call_count
                with self.assertRaises(managed.ManagedSessionError):
                    self.client.me()
                self.assertEqual(self.resolve.call_count, calls)

    def test_redirects_server_errors_and_error_bodies_never_follow_or_retry(self):
        for code in (100, 204, 301, 302, 307, 308, 404, 429, 500, 503):
            self.fresh(
                status=code,
                extra=b"Location: https://elsewhere.example.test\r\n",
                body=b"x" * 70000,
            )
            count = self.resolve.call_count
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertEqual(self.resolve.call_count, count + 1)
            self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.UNAVAILABLE)
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertEqual(self.resolve.call_count, count + 1)

    def test_embedded_engine_metadata_is_distinct_and_does_not_grant_execution(self):
        self.fresh().me()
        self.wire.data = response([dict(PRESETS[0], engine="electron_chromium")])
        result = self.client.presets()
        self.assertEqual(result[0].engine, "electron_chromium")
        self.assertTrue(result[0].proxy_required)
        self.assertFalse(hasattr(result[0], "launch_available"))

    def test_malformed_membership_schema_and_disabled_marker_fail_closed(self):
        for value in (
            None,
            [],
            {},
            dict(ME, enabled=False),
            dict(ME, access_token=ACCESS),
            dict(ME, role="superadmin"),
            dict(ME, id="../a"),
            dict(ME, org_id=4),
            dict(ME, display_name="x" * 121),
            dict(ME, display_name="a\x00b"),
            dict(ME, display_name="a\u202eb"),
            dict(ME, role=[]),
        ):
            self.fresh(value)
            with self.subTest(value=value), self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertIsNone(self.client.snapshot().membership)

    def test_malformed_list_schema_limits_duplicate_ids_and_proxy_policy(self):
        cases = [
            (managed._Read.PROFILES, [dict(PROFILES[0], revision=True)]),
            (managed._Read.PROFILES, [dict(PROFILES[0], state="running")]),
            (managed._Read.PROFILES, [dict(PROFILES[0], org_id="elsewhere")]),
            (managed._Read.PROFILES, PROFILES * 2),
            (managed._Read.PROFILES, [{}] * 257),
            (managed._Read.PRESETS, [dict(PRESETS[0], proxy_required=False)]),
            (managed._Read.PRESETS, [dict(PRESETS[0], engine="arbitrary-command")]),
            (managed._Read.PRESETS, [dict(PRESETS[0], locale="../en")]),
            (managed._Read.PRESETS, [dict(PRESETS[0], revision=0)]),
            (managed._Read.PRESETS, {"rows": PRESETS}),
        ]
        for operation, value in cases:
            self.fresh().me()
            self.wire.data = response(value)
            with (
                self.subTest(operation=operation, value=value),
                self.assertRaises(managed.ManagedSessionError),
            ):
                (
                    self.client.profiles
                    if operation is managed._Read.PROFILES
                    else self.client.presets
                )()

    def test_duplicate_json_nan_depth_bad_encoding_and_body_bounds(self):
        for body in (
            b'{"id":"a","id":"b","org_id":"o","display_name":"d","role":"member"}',
            json.dumps(ME).replace('"Synthetic Member"', "NaN").encode(),
            b"[" * 1200 + b"]" * 1200,
            b"\xff",
            b"{}" + b" " * 65535,
            b"",
            b"null",
        ):
            self.fresh(body=body)
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()

    def test_success_framing_is_bounded_and_strict(self):
        for wire in (
            response(content_type=b"text/html"),
            response(extra=b"Content-Length: 2\r\n"),
            response(extra=b"Content-Encoding: gzip\r\n"),
            response() + b"trailing",
            response(extra=b"X-Large: " + b"a" * 5000 + b"\r\n"),
            b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 65 + b"\r\n",
            response(body=b"{}").replace(b"Content-Length: 2", b"Transfer-Encoding: chunked"),
        ):
            self.fresh()
            self.wire.data = wire
            self.wire.fragment = 1
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()

    def test_private_mixed_dns_tls_peer_and_alpn_fail_before_bearer_send(self):
        for answers in (["127.0.0.1"], [PUBLIC, "10.0.0.1"], ["169.254.169.254"], ["::1"]):
            self.fresh()
            self.resolve.return_value = answers
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
        self.resolve.return_value = [PUBLIC]
        for field, value in (
            ("verify_mode", ssl.CERT_NONE),
            ("check_hostname", False),
            ("keylog_filename", "/tmp/not-created"),
            ("minimum_version", ssl.TLSVersion.TLSv1_1),
        ):
            self.fresh()
            prior = getattr(self.tls, field)
            setattr(self.tls, field, value)
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            setattr(self.tls, field, prior)
        self.fresh()
        self.wire.peer = ("1.1.1.1", 443)
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.wire.peer = (PUBLIC, 443)
        self.fresh()
        self.wire.alpn = "h2"
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(self.wire.sent, [])

    def test_ambient_environment_does_not_select_destination_or_headers(self):
        with patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "http://u:p@127.0.0.1:8080",
                "SSLKEYLOGFILE": "/tmp/not-created",
                "SSL_CERT_FILE": "/tmp/not-created",
                "SSL_CERT_DIR": "/tmp/not-created",
            },
        ):
            self.client.me()
        request = self.wire.sent[0]
        self.assertNotIn(b"127.0.0.1", request)
        self.assertNotIn(b"Proxy-Authorization", request)
        self.assertEqual(self.raw.destination, (PUBLIC, 443))

    def test_uncertain_send_close_and_bad_native_ack_are_sanitized_without_retry(self):
        for target, ack in ((self.wire, "sendall"), (self.wire, "close"), (self.raw, "connect")):
            self.fresh()
            target.ack[ack] = False
            output = io.StringIO()
            with (
                redirect_stdout(output),
                redirect_stderr(output),
                self.assertRaises(managed.ManagedSessionError) as error,
            ):
                self.client.me()
            for secret in (ACCESS, ID_TOKEN, DIAGNOSTIC, SESSION):
                self.assertNotIn(
                    secret, str(error.exception) + output.getvalue() + repr(self.client.snapshot())
                )
            count = self.resolve.call_count
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertEqual(self.resolve.call_count, count)
            target.ack.clear()

    def test_no_tokens_in_projection_even_on_json_escaped_reflection(self):
        for token in (ACCESS, ID_TOKEN):
            self.fresh(
                body=json.dumps(dict(ME, display_name=token))
                .replace("SYNTHETIC", "\\u0053YNTHETIC")
                .encode()
            )
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertNotIn(token, json.dumps(self.client.snapshot().public()))

    def test_expiry_before_read_and_snapshot_discards_cached_membership(self):
        self.client.me()
        self.expires()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        count = self.resolve.call_count
        with self.assertRaises(managed.ManagedSessionError):
            self.client.profiles()
        self.assertEqual(self.resolve.call_count, count)

    def test_expiry_during_dns_or_handshake_sends_no_bearer(self):
        self.wire.on_handshake = self.expires
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(self.wire.sent, [])
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_slow_response_expiry_never_publishes_membership(self):
        self.wire.on_send = self.expires
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)

    def test_slow_success_json_parsing_rechecks_expiry(self):
        original = managed._projection

        def delayed(operation, result):
            value = original(operation, result)
            self.expires()
            return value

        with (
            patch.object(managed, "_projection", side_effect=delayed),
            self.assertRaises(managed.ManagedSessionError),
        ):
            self.client.me()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_changed_record_journal_clock_or_lease_invalidates_before_send(self):
        self.store.items[vault._PAYLOAD.account_id] += b" "
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(self.wire.sent, [])
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_lease_lost_after_response_does_not_publish(self):
        self.wire.on_send = lambda: self.vault._lease.close()
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_local_logout_only_current_record_no_provider_or_cookie_claim(self):
        self.store.items["unrelated-secret"] = b"SYNTHETIC_OTHER_FEATURE"
        self.client.me()
        calls = self.resolve.call_count
        result = self.client.logout().public()
        self.assertEqual(result["status"], "logged_out_locally")
        self.assertFalse(result["managed_available"])
        self.assertEqual(self.store.items["unrelated-secret"], b"SYNTHETIC_OTHER_FEATURE")
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertEqual(self.resolve.call_count, calls)
        self.assertEqual(self.client.logout().public(), result)
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertEqual(self.resolve.call_count, calls)

    def test_uncertain_logout_never_claims_deletion_or_retries(self):
        self.client.me()
        self.store.delete_ack = False
        with self.assertRaisesRegex(managed.ManagedSessionError, "local_logout_unconfirmed"):
            self.client.logout()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)
        self.assertTrue(self.vault._quarantined)
        self.assertIsNone(self.client.snapshot().membership)

    def test_old_consumer_cannot_read_or_delete_a_later_session(self):
        self.client.me()
        self.vault.delete_session(SESSION)
        self.vault.store_session(OTHER, self.material())
        with self.assertRaises(managed.ManagedSessionError):
            self.client.logout()
        self.assertIsNone(self.vault.assert_session_current(OTHER))
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()

    def test_recovery_epoch_cannot_rebind_old_consumer_even_same_reference(self):
        self.client.me()
        self.vault.recover_discard_all()
        self.vault.store_session(SESSION, self.material())
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.vault.assert_session_current(SESSION))

    def test_logout_waits_for_inflight_read_then_late_work_cannot_restore_membership(self):
        entered, release, logout_started = threading.Event(), threading.Event(), threading.Event()
        results, errors = [], []

        def block():
            entered.set()
            self.assertTrue(release.wait(3))

        self.wire.on_send = block

        def read():
            try:
                results.append(self.client.me())
            except Exception as error:
                errors.append(error)

        def logout():
            logout_started.set()
            results.append(self.client.logout())

        first = threading.Thread(target=read)
        second = threading.Thread(target=logout)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        self.assertTrue(logout_started.wait(2))
        self.assertEqual(results, [])
        release.set()
        first.join(3)
        second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.LOGGED_OUT)
        self.assertIsNone(self.client.snapshot().membership)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)

    def test_initial_me_unbound_then_every_read_sends_exact_pinned_organization(self):
        self.client.me()
        self.assertNotIn(b"X-TBM-Organization:", self.wire.sent[-1])
        for method, data in (
            (self.client.me, ME),
            (self.client.profiles, PROFILES),
            (self.client.presets, PRESETS),
        ):
            self.wire.data = response(data)
            method()
            self.assertEqual(self.wire.sent[-1].count(b"X-TBM-Organization:"), 1)
            self.assertIn(b"X-TBM-Organization: product-company-a\r\n", self.wire.sent[-1])
            self.assertNotIn(TENANT.encode(), self.wire.sent[-1])

    def test_server_tenant_binding_conflict_invalidates_all_later_operations(self):
        for name in ("me", "profiles", "presets"):
            self.fresh().me()
            self.wire.data = response(status=409)
            with self.assertRaisesRegex(managed.ManagedSessionError, "membership_changed"):
                getattr(self.client, name)()
            self.assertIsNone(self.client.snapshot().membership)
            self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.UNAVAILABLE)
            count = self.resolve.call_count
            with self.assertRaises(managed.ManagedSessionError):
                self.client.me()
            self.assertEqual(self.resolve.call_count, count)

    def test_snapshot_expiry_is_safe_bound_and_cached_public_clamps_wall_expiry(self):
        self.client.me()
        snapshot = self.client.snapshot()
        self.assertEqual(snapshot.expires_at, int(self.wall) + 300)
        self.assertEqual(snapshot.public()["expires_at"], int(self.wall) + 300)
        self.wall += 300
        self.assertFalse(snapshot.public()["managed_available"])
        self.assertIsNone(snapshot.public()["membership"])
        self.assertEqual(snapshot.public()["status"], "expired")

    def test_slow_final_lease_check_rechecks_deadline_before_network(self):
        original = self.vault._lease.assert_owned
        count = 0

        def slow():
            nonlocal count
            original()
            count += 1
            if count == 2:
                self.wall += 300

        with (
            patch.object(self.vault._lease, "assert_owned", side_effect=slow),
            self.assertRaisesRegex(managed.ManagedSessionError, "session_expired"),
        ):
            self.client.me()
        self.resolve.assert_not_called()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_slow_timeout_setting_cannot_emit_expired_bearer(self):
        original = self.wire.settimeout
        count = 0

        def slow(timeout):
            nonlocal count
            count += 1
            if count == 2:
                self.wall += 300
            return original(timeout)

        with (
            patch.object(self.wire, "settimeout", side_effect=slow),
            self.assertRaisesRegex(managed.ManagedSessionError, "session_expired"),
        ):
            self.client.me()
        self.assertEqual(self.wire.sent, [])
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_wall_only_expiry_after_handshake_retains_clean_expired_result(self):
        self.wire.on_handshake = lambda: setattr(self, "wall", self.wall + 300)
        with self.assertRaisesRegex(managed.ManagedSessionError, "session_expired"):
            self.client.me()
        self.assertEqual(self.wire.sent, [])
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_expiry_during_extra_payload_read_stops_before_network(self):
        count = 0

        def slow(operation, reference):
            nonlocal count
            if operation == "get" and reference == vault._PAYLOAD:
                count += 1
                if count == 2:
                    self.expires()

        self.store.hook = slow
        with self.assertRaisesRegex(managed.ManagedSessionError, "session_expired"):
            self.client.me()
        self.resolve.assert_not_called()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)

    def test_lost_lease_during_initial_native_read_stops_before_network(self):
        def slow(operation, reference):
            if operation == "get" and reference == vault._PAYLOAD:
                self.vault._lease.close()

        self.store.hook = slow
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.resolve.assert_not_called()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_changed_journal_after_response_discards_membership(self):
        self.wire.on_send = lambda: self.store.items.update({vault._JOURNAL.account_id: b"changed"})
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.assertIsNone(self.client.snapshot().membership)
        self.assertTrue(self.vault._quarantined)

    def test_clock_rollback_stops_before_network(self):
        self.wall -= 1
        with self.assertRaises(managed.ManagedSessionError):
            self.client.me()
        self.resolve.assert_not_called()
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)

    def test_snapshot_monotonic_expiry_without_wall_advance(self):
        self.client.me()
        self.monotonic += 300
        self.assertEqual(self.client.snapshot().status, managed.ManagedStatus.EXPIRED)
        self.assertEqual(self.client.logout().status, managed.ManagedStatus.LOGGED_OUT)

    def test_stale_logout_does_not_even_expire_a_later_session(self):
        self.vault.delete_session(SESSION)
        self.vault.store_session(OTHER, self.material(expires_at=int(self.wall) + 10))
        current_payload = self.store.items[vault._PAYLOAD.account_id]
        self.wall += 20
        with self.assertRaises(managed.ManagedSessionError):
            self.client.logout()
        self.assertEqual(self.store.items[vault._PAYLOAD.account_id], current_payload)
        self.assertFalse(self.vault._quarantined)

    def test_schema_errors_never_write_secret_files_or_emit_diagnostics(self):
        output = io.StringIO()
        self.wire.on_send = Mock(side_effect=RuntimeError(ACCESS + DIAGNOSTIC))
        with (
            redirect_stdout(output),
            redirect_stderr(output),
            self.assertRaises(managed.ManagedSessionError) as error,
        ):
            self.client.me()
        captured = output.getvalue() + str(error.exception) + repr(self.client)
        self.assertNotIn(ACCESS, captured)
        self.assertNotIn(DIAGNOSTIC, captured)
        files = [path for path in Path(self.temp).rglob("*") if path.is_file()]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "owner.lock")
        self.assertEqual(files[0].read_bytes(), b"")

    def test_synthetic_signed_identity_vault_and_managed_contract_composition(self):
        self.vault.delete_session(SESSION)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update(kid="synthetic", use="sig", alg="RS256")
        holder = {}
        wall = int(self.wall)

        class SyntheticOIDC:
            def post_form(inner, url, fields, **kwargs):
                token = jwt.encode(
                    {
                        "iss": OIDC.issuer,
                        "tid": TENANT,
                        "ver": "2.0",
                        "aud": DESKTOP,
                        "sub": "native-subject",
                        "iat": wall,
                        "exp": wall + 300,
                        "nonce": holder["nonce"],
                    },
                    key,
                    algorithm="RS256",
                    headers={"kid": "synthetic"},
                )
                return HTTPResponse(
                    200,
                    url,
                    json.dumps(
                        {
                            "access_token": ACCESS,
                            "id_token": token,
                            "token_type": "Bearer",
                            "expires_in": 300,
                            "scope": " ".join(OIDC.scopes),
                        }
                    ).encode(),
                )

            def get(inner, url, **kwargs):
                return HTTPResponse(200, url, json.dumps({"keys": [jwk]}).encode())

        core = ManagedSignIn(OIDC, transport=SyntheticOIDC(), vault=self.vault)
        authorization = core.begin()
        query = parse_qs(urlsplit(authorization.authorization_url).query)
        holder["nonce"] = query["nonce"][0]
        result = core.complete_callback(
            OIDC.redirect_uri
            + "?"
            + urlencode({"code": "SYNTHETIC_CODE", "state": query["state"][0]})
        )
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertFalse(result.public()["company_membership_verified"])
        client = managed.NativeManagedSession(BACKEND, vault=self.vault)
        self.assertFalse(client.snapshot().public()["managed_available"])
        self.assertEqual(client.me().member_id, ME["id"])
        self.assertTrue(client.snapshot().public()["managed_available"])
        self.assertEqual(client.logout().status, managed.ManagedStatus.LOGGED_OUT)


if __name__ == "__main__":
    unittest.main()
