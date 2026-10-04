"""Synthetic I/O only. No DNS queries, sockets, providers, credentials or browser."""

import io
import ipaddress
import json
import ssl
import subprocess
import threading
import time
import unittest
from contextlib import ExitStack
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client import oidc_https as https
from team_browser.client.auth_flow import (
    AuthStatus,
    HTTPResponse,
    ManagedSignIn,
    TrustedOIDCConfiguration,
)
from team_browser.client.oidc_https import NativeOIDCHTTPSTransport, OIDCTransportError


CONFIG = TrustedOIDCConfiguration(
    issuer="https://identity.example.test/tenant",
    client_id="synthetic-desktop-client",
    authorization_endpoint="https://identity.example.test/authorize",
    token_endpoint="https://identity.example.test/token",
    jwks_endpoint="https://keys.example.test/jwks",
    redirect_uri="http://127.0.0.1:43187/oidc/callback",
)
FIELDS = {
    "grant_type": "authorization_code",
    "code": "SYNTHETIC+CODE=&value",
    "redirect_uri": CONFIG.redirect_uri,
    "client_id": CONFIG.client_id,
    "code_verifier": "SYNTHETIC_VERIFIER_" + "x" * 43,
}
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def response(body=b'{"keys":[]}', headers=b"", status=b"200 OK", length=True):
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Type: application/json\r\n"
        + (b"Content-Length: " + str(len(body)).encode() + b"\r\n" if length else b"")
        + headers
        + b"\r\n"
        + body
    )


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeSocket:
    def __init__(self, data=b"", peer=(PUBLIC_V4, 443)):
        self.data = data
        self.peer = peer
        self.destination = None
        self.timeouts = []
        self.sent = []
        self.closes = 0
        self.read_sizes = []
        self.fragment = 4096
        self.on_read = None
        self.on_send = None
        self.on_connect = None
        self.on_close = None
        self.on_handshake = None
        self.alpn = "http/1.1"
        self.ack = {}

    def settimeout(self, value):
        self.timeouts.append(value)
        return self.ack.get("settimeout")

    def connect(self, destination):
        self.destination = destination
        if self.on_connect:
            self.on_connect()
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
        self.read_sizes.append(maximum)
        if self.on_read:
            self.on_read()
        if "recv" in self.ack:
            return self.ack["recv"]
        size = min(maximum, self.fragment)
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk

    def close(self):
        self.closes += 1
        if self.on_close:
            self.on_close()
        return self.ack.get("close")


class HTTPSContractTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.clock = Clock()
        self.raw = FakeSocket()
        self.wire = FakeSocket(response())
        self.tls = SimpleNamespace(
            verify_mode=ssl.CERT_REQUIRED,
            check_hostname=True,
            minimum_version=ssl.TLSVersion.TLSv1_2,
            keylog_filename=None,
            wrap_socket=Mock(return_value=self.wire),
        )
        self.stack.enter_context(patch.object(https, "_context", return_value=self.tls))
        self.stack.enter_context(patch.object(https.time, "monotonic", self.clock))
        self.resolve = self.stack.enter_context(
            patch.object(https, "_resolve", return_value=[PUBLIC_V4])
        )
        self.socket = self.stack.enter_context(
            patch.object(https.socket, "socket", return_value=self.raw)
        )
        self.transport = NativeOIDCHTTPSTransport(CONFIG)

    def get(self, **kwargs):
        return self.transport.get(
            kwargs.pop("url", CONFIG.jwks_endpoint),
            timeout_seconds=kwargs.pop("timeout_seconds", 10),
            follow_redirects=kwargs.pop("follow_redirects", False),
            **kwargs,
        )

    def post(self, fields=None, **kwargs):
        return self.transport.post_form(
            kwargs.pop("url", CONFIG.token_endpoint),
            FIELDS.copy() if fields is None else fields,
            timeout_seconds=kwargs.pop("timeout_seconds", 10),
            follow_redirects=kwargs.pop("follow_redirects", False),
            **kwargs,
        )

    def fresh(self):
        self.transport = NativeOIDCHTTPSTransport(CONFIG)
        self.wire.data = response()

    def test_get_connects_once_to_pinned_numeric_address_and_verifies_original_host(self):
        result = self.get()
        self.assertIs(type(result), HTTPResponse)
        self.assertEqual(result.url, CONFIG.jwks_endpoint)
        self.assertEqual(result.body, b'{"keys":[]}')
        self.assertIs(result.redirected, False)
        self.assertEqual(result.content_type, "application/json")
        self.resolve.assert_called_once_with("keys.example.test", 110.0)
        self.socket.assert_called_once_with(https.socket.AF_INET, https.socket.SOCK_STREAM, 6)
        self.assertEqual(self.raw.destination, (PUBLIC_V4, 443))
        self.tls.wrap_socket.assert_called_once_with(
            self.raw,
            server_hostname="keys.example.test",
            do_handshake_on_connect=False,
            suppress_ragged_eofs=False,
        )
        self.assertEqual(len(self.wire.sent), 1)
        self.assertTrue(self.wire.sent[0].startswith(b"GET /jwks HTTP/1.1\r\n"))
        self.assertIn(b"Host: keys.example.test\r\n", self.wire.sent[0])
        self.assertIn(b"Accept-Encoding: identity\r\n", self.wire.sent[0])
        self.assertIn(b"Connection: close\r\n", self.wire.sent[0])
        self.assertEqual(self.wire.closes, 1)
        self.assertEqual(self.raw.closes, 1)

    def test_post_form_escapes_values_and_has_no_secret_authentication_headers(self):
        self.post()
        self.resolve.assert_called_once_with("identity.example.test", 110.0)
        headers, body = self.wire.sent[0].split(b"\r\n\r\n", 1)
        self.assertIn(b"POST /token HTTP/1.1", headers)
        self.assertIn(b"Content-Type: application/x-www-form-urlencoded", headers)
        self.assertIn(f"Content-Length: {len(body)}".encode(), headers)
        self.assertEqual(parse_qs(body.decode()), {key: [value] for key, value in FIELDS.items()})
        for header in (b"Authorization:", b"Cookie:", b"Proxy-Authorization:"):
            self.assertNotIn(header, headers)

    def test_public_ipv6_uses_literal_sockaddr_with_original_sni(self):
        self.resolve.return_value = [PUBLIC_V6]
        self.raw.peer = self.wire.peer = (PUBLIC_V6, 443, 0, 0)
        self.get()
        self.assertEqual(self.raw.destination, (PUBLIC_V6, 443, 0, 0))
        self.assertEqual(self.socket.call_args.args[0], https.socket.AF_INET6)

    def test_ambient_proxy_environment_is_not_used(self):
        with patch.dict(
            https.os.environ,
            {
                "HTTPS_PROXY": "https://SYNTHETIC_PROXY_CREDENTIAL@127.0.0.1:8888",
                "ALL_PROXY": "socks5://127.0.0.1:9999",
                "NO_PROXY": "*",
            },
        ):
            self.get()
        self.assertEqual(self.raw.destination, (PUBLIC_V4, 443))
        self.assertNotIn(b"SYNTHETIC_PROXY", self.wire.sent[0])

    def test_exact_method_endpoint_allowlist_rejects_before_dns(self):
        for url in (
            CONFIG.token_endpoint,
            CONFIG.authorization_endpoint,
            CONFIG.issuer,
            CONFIG.jwks_endpoint + "/",
            CONFIG.jwks_endpoint + "?q=1",
            "https://keys.example.test:443/jwks",
            "http://keys.example.test/jwks",
            "https://unapproved.example.test/jwks",
            "https://127.0.0.1/jwks",
            None,
        ):
            with self.subTest(url=url), self.assertRaises(OIDCTransportError):
                self.get(url=url)
        with self.assertRaises(OIDCTransportError):
            self.post(url=CONFIG.jwks_endpoint)
        self.resolve.assert_not_called()
        self.socket.assert_not_called()

    def test_redirects_and_invalid_timeouts_rejected_before_dns(self):
        for timeout in (0, -1, 11, 100, True, 10.0, float("nan"), "10", None):
            with self.subTest(timeout=timeout), self.assertRaises(OIDCTransportError):
                self.get(timeout_seconds=timeout)
        for redirects in (True, None, 0, 1, "false"):
            with self.subTest(redirects=redirects), self.assertRaises(OIDCTransportError):
                self.get(follow_redirects=redirects)
        self.resolve.assert_not_called()

    def test_form_rejects_unknown_grants_secrets_scopes_and_wrong_binding(self):
        variants = [
            None,
            [],
            {},
            dict(FIELDS, client_secret="SYNTHETIC"),
            dict(FIELDS, grant_type="refresh_token"),
            dict(FIELDS, scope="email"),
            dict(FIELDS, client_id="other"),
            dict(FIELDS, redirect_uri="http://localhost/"),
            dict(FIELDS, code="x\r\nInjected: value"),
            dict(FIELDS, code="x" * 4097),
            dict(FIELDS, code=True),
            dict(FIELDS, code_verifier="short"),
            dict(FIELDS, code_verifier="x" * 129),
            dict(FIELDS, code_verifier="!" * 43),
        ]
        for fields in variants:
            with self.subTest(fields_type=type(fields)), self.assertRaises(OIDCTransportError):
                self.transport.post_form(
                    CONFIG.token_endpoint, fields, timeout_seconds=10, follow_redirects=False
                )
        self.resolve.assert_not_called()

    def test_configuration_is_native_typed_and_revalidated(self):
        for config in (None, {}, "https://identity.example.test"):
            with self.subTest(config_type=type(config)), self.assertRaises(OIDCTransportError):
                NativeOIDCHTTPSTransport(config)
        for host in ("identity.internal", "identity.home.arpa", "identity.onion", "127.1"):
            with self.subTest(host=host), self.assertRaises(OIDCTransportError):
                NativeOIDCHTTPSTransport(replace(CONFIG, token_endpoint=f"https://{host}/token"))
        with patch.object(https.sys, "platform", "win32"), self.assertRaises(OIDCTransportError):
            NativeOIDCHTTPSTransport(CONFIG)

    def test_frozen_or_unsupported_interpreters_are_rejected_before_network(self):
        for changes in (
            {"frozen": True},
            {"_MEIPASS": "/synthetic/bundle"},
            {"executable": "relative-python"},
            {"implementation": SimpleNamespace(name="unsupported")},
        ):
            with (
                patch.multiple(https.sys, create=True, **changes),
                self.subTest(changes=changes),
                self.assertRaises(OIDCTransportError),
            ):
                NativeOIDCHTTPSTransport(CONFIG)
        self.resolve.assert_not_called()
        self.socket.assert_not_called()

    def test_trailing_bytes_are_rejected_independently_of_fragment_size(self):
        for chunked in (False, True):
            for fragment in (1, 7, 4096):
                self.fresh()
                self.wire.fragment = fragment
                self.wire.data = (
                    response(
                        b"2\r\n{}\r\n0\r\n\r\n",
                        length=False,
                        headers=b"Transfer-Encoding: chunked\r\n",
                    )
                    if chunked
                    else response(b"{}")
                ) + b"TRAILING"
                with (
                    self.subTest(chunked=chunked, fragment=fragment),
                    self.assertRaises(OIDCTransportError),
                ):
                    self.get()

    def test_insecure_or_keylogging_tls_is_rejected_before_dns(self):
        for attr, value in (
            ("check_hostname", False),
            ("verify_mode", ssl.CERT_NONE),
            ("minimum_version", ssl.TLSVersion.TLSv1_1),
            ("keylog_filename", "forbidden"),
        ):
            old = getattr(self.tls, attr)
            setattr(self.tls, attr, value)
            with self.subTest(attr=attr), self.assertRaises(OIDCTransportError):
                self.get()
            setattr(self.tls, attr, old)
            self.fresh()
        self.resolve.assert_not_called()

    def test_chain_or_hostname_failure_sends_nothing_and_never_retries(self):
        self.wire.on_handshake = Mock(side_effect=ssl.SSLCertVerificationError("PRIVATE_PEER"))
        with self.assertRaises(OIDCTransportError) as caught:
            self.post()
        self.assertNotIn("PRIVATE_PEER", str(caught.exception))
        self.assertEqual(self.wire.sent, [])
        with self.assertRaises(OIDCTransportError):
            self.post()
        self.resolve.assert_called_once()
        self.socket.assert_called_once()

    def test_wrong_peer_or_alpn_fails_before_sending(self):
        for peer in (
            ("127.0.0.1", 443),
            (PUBLIC_V4, 80),
            (PUBLIC_V4, True),
            [PUBLIC_V4, 443],
            (PUBLIC_V4, 443, 0, 0),
        ):
            self.raw.peer = peer
            with self.subTest(peer=peer), self.assertRaises(OIDCTransportError):
                self.get()
            self.fresh()
        self.raw.peer = (PUBLIC_V4, 443)
        self.wire.peer = ("1.1.1.1", 443)
        with self.assertRaises(OIDCTransportError):
            self.get()
        self.fresh()
        self.wire.peer = (PUBLIC_V4, 443)
        for alpn in ("h2", False, b"http/1.1"):
            self.wire.alpn = alpn
            with self.subTest(alpn=alpn), self.assertRaises(OIDCTransportError):
                self.get()
            self.fresh()
        self.assertEqual(self.wire.sent, [])

    def test_all_dns_answers_are_checked_and_no_address_fallback_exists(self):
        self.resolve.return_value = [PUBLIC_V4, "127.0.0.1"]
        with self.assertRaises(OIDCTransportError):
            self.get()
        self.socket.assert_not_called()
        self.fresh()
        self.resolve.return_value = [PUBLIC_V4, "1.1.1.1"]
        self.raw.on_connect = Mock(side_effect=TimeoutError("PRIVATE_CONNECT"))
        with self.assertRaises(OIDCTransportError):
            self.get()
        self.socket.assert_called_once()
        self.assertEqual(self.wire.sent, [])

    def test_redirects_errors_and_informational_responses_are_not_followed(self):
        for status in (
            b"301 Moved",
            b"302 Found",
            b"303 See Other",
            b"307 Temporary",
            b"308 Permanent",
            b"400 Bad",
            b"401 Unauthorized",
            b"500 Error",
            b"100 Continue",
            b"101 Switching Protocols",
            b"2000 Invalid",
        ):
            self.wire.data = response(status=status, headers=b"Location: https://other.test/\r\n")
            with self.subTest(status=status), self.assertRaises(OIDCTransportError):
                self.post()
            self.fresh()
        self.assertEqual(len(self.wire.sent), 11)
        self.assertEqual(self.resolve.call_count, 11)

    def test_error_after_send_has_fixed_diagnostic_latches_and_does_not_retry(self):
        self.wire.on_send = Mock(side_effect=TimeoutError("SYNTHETIC_CODE PRIVATE_URL"))
        with self.assertRaises(OIDCTransportError) as caught:
            self.post()
        self.assertNotIn("SYNTHETIC", str(caught.exception))
        self.assertNotIn("PRIVATE", repr(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        with self.assertRaises(OIDCTransportError):
            self.post()
        self.assertEqual(len(self.wire.sent), 1)
        self.resolve.assert_called_once()

    def test_total_deadline_is_shared_across_dns_connect_tls_send_and_reads(self):
        def resolve(*_):
            self.clock.advance(2)
            return [PUBLIC_V4]

        self.resolve.side_effect = resolve
        self.raw.on_connect = lambda: self.clock.advance(2)
        self.wire.on_handshake = lambda: self.clock.advance(2)
        self.wire.on_send = lambda: self.clock.advance(2)
        self.wire.on_read = lambda: self.clock.advance(3)
        with self.assertRaises(OIDCTransportError):
            self.post()
        self.assertEqual(self.raw.timeouts, [8.0, 6.0])
        self.assertEqual(self.wire.timeouts, [6.0, 4.0, 2.0])
        self.assertEqual(self.wire.closes, 1)

    def test_deadline_does_not_reset_for_slow_drip_reads(self):
        self.wire.fragment = 1
        self.wire.on_read = lambda: self.clock.advance(0.25)
        with self.assertRaises(OIDCTransportError):
            self.get()
        self.assertLessEqual(len(self.wire.read_sizes), 40)
        self.assertLess(self.wire.timeouts[-1], self.wire.timeouts[0])

    def test_late_dns_tls_or_cleanup_results_never_become_success(self):
        for phase in ("dns", "tls", "cleanup"):
            self.clock.now = 100
            self.fresh()
            if phase == "dns":
                self.resolve.side_effect = lambda *_: self.clock.advance(11) or [PUBLIC_V4]
            elif phase == "tls":
                self.wire.on_handshake = lambda: self.clock.advance(11)
            else:
                self.wire.on_close = lambda: self.clock.advance(11)
            with self.subTest(phase=phase), self.assertRaises(OIDCTransportError):
                self.get()
            self.assertTrue(self.transport._failed)
            self.resolve.side_effect = None
            self.wire.on_handshake = None
        self.assertEqual(len(self.wire.sent), 1)

    def test_nonblocking_concurrency_gate(self):
        self.transport._lock.acquire()
        try:
            with self.assertRaises(OIDCTransportError):
                self.get()
        finally:
            self.transport._lock.release()
        self.resolve.assert_not_called()

    def test_malformed_native_void_acknowledgements_fail_closed(self):
        for target, method in (
            (self.raw, "connect"),
            (self.raw, "settimeout"),
            (self.wire, "do_handshake"),
            (self.wire, "sendall"),
            (self.wire, "close"),
        ):
            for acknowledgement in (False, True, 0, "success"):
                target.ack[method] = acknowledgement
                with (
                    self.subTest(method=method, ack=acknowledgement),
                    self.assertRaises(OIDCTransportError),
                ):
                    self.get()
                self.assertTrue(self.transport._failed)
                target.ack.clear()
                self.fresh()

    def test_malformed_native_reads_fail_closed(self):
        for value in (None, False, bytearray(b"HTTP/1.1"), "HTTP/1.1", b"x" * 20000):
            self.wire.ack["recv"] = value
            with self.subTest(value_type=type(value)), self.assertRaises(OIDCTransportError):
                self.get()
            self.fresh()

    def test_content_length_limit_and_exact_boundary(self):
        self.wire.data = response(b"x" * 65536)
        self.assertEqual(len(self.get().body), 65536)
        for data in (
            response(b"x" * 65537),
            response(b"x", headers=b"Content-Length: 1\r\n"),
            response(b"abc").replace(b"Content-Length: 3", b"Content-Length: 03"),
            response(b"abc").replace(b"Content-Length: 3", b"Content-Length: -1"),
            response(b"abc").replace(b"Content-Length: 3", b"Content-Length: 4"),
            response(b"abc") + b"TRAILING",
        ):
            self.fresh()
            self.wire.data = data
            with self.subTest(size=len(data)), self.assertRaises(OIDCTransportError):
                self.get()

    def test_header_size_count_line_and_syntax_bounds(self):
        for headers in (
            b"X-Long: " + b"x" * 4096 + b"\r\n",
            b"X: y\r\n" * 64,
            (b"X: " + b"a" * 2000 + b"\r\n") * 9,
            b" Folded: x\r\n",
            b"Missing-Colon\r\n",
            b"Bad Header: x\r\n",
            b"X: y\x00z\r\n",
            b"X: y\nz\r\n",
            b"X: \xff\r\n",
        ):
            self.fresh()
            self.wire.data = response(headers=headers)
            with self.subTest(size=len(headers)), self.assertRaises(OIDCTransportError):
                self.get()
        self.fresh()
        self.wire.data = b"HTTP/1.1 200 OK\r\n" + b"x" * 18000
        with self.assertRaises(OIDCTransportError):
            self.get()
        self.assertLessEqual(max(self.wire.read_sizes), 4096)

    def test_compression_mime_and_conflicting_framing_are_rejected(self):
        for data in (
            response(headers=b"Content-Encoding: gzip\r\n"),
            response(headers=b"Transfer-Encoding: chunked\r\n"),
            response(headers=b"Content-Type: application/json\r\n"),
            response().replace(b"application/json", b"text/plain"),
            response().replace(b"application/json", b"application/json; charset=latin1"),
            response().replace(b"Content-Type: application/json\r\n", b""),
            response(b"", headers=b"Transfer-Encoding: gzip, chunked\r\n", length=False),
        ):
            self.fresh()
            self.wire.data = data
            with self.subTest(size=len(data)), self.assertRaises(OIDCTransportError):
                self.get()

    def test_status_line_requires_http_grammar(self):
        for status in (
            b"HTTP/1.1 200",
            b"HTTP/1.1  200 OK",
            b"HTTP/1.1\t200 OK",
            b"HTTP/2 200 OK",
            b"HTTP/1.1 200 OK\tINJECTED",
        ):
            self.fresh()
            self.wire.data = response().replace(b"HTTP/1.1 200 OK", status)
            with self.subTest(status=status), self.assertRaises(OIDCTransportError):
                self.get()

    def test_json_charset_is_normalized_and_cookies_are_ignored(self):
        self.wire.data = response(headers=b"Set-Cookie: ignored=1\r\nSet-Cookie: ignored=2\r\n")
        self.wire.data = self.wire.data.replace(
            b"application/json", b'Application/JSON; charset="UTF-8"'
        )
        result = self.get()
        self.assertEqual(result.content_type, "application/json")
        self.wire.data = response()
        self.get()
        self.assertNotIn(b"Cookie:", self.wire.sent[1])

    def test_chunked_response_survives_fragmented_io(self):
        self.wire.data = response(
            b'4\r\n{"ke\r\n7\r\nys":[]}\r\n0\r\n\r\n',
            headers=b"Transfer-Encoding: chunked\r\n",
            length=False,
        )
        self.wire.fragment = 1
        self.assertEqual(self.get().body, b'{"keys":[]}')

    def test_chunked_body_exact_limit_and_overflow(self):
        self.wire.data = response(
            b"10000\r\n" + b"x" * 65536 + b"\r\n0\r\n\r\n",
            headers=b"Transfer-Encoding: chunked\r\n",
            length=False,
        )
        self.assertEqual(len(self.get().body), 65536)
        self.wire.data = response(
            b"10001\r\n", headers=b"Transfer-Encoding: chunked\r\n", length=False
        )
        with self.assertRaises(OIDCTransportError):
            self.get()

    def test_chunk_extensions_trailers_bad_framing_and_many_chunks_rejected(self):
        for chunks in (
            b"1;ext=yes\r\nx\r\n0\r\n\r\n",
            b"-1\r\nx\r\n0\r\n\r\n",
            b"1\r\nx\n0\r\n\r\n",
            b"0\r\nTrailer: yes\r\n\r\n",
            b"1\r\nx\r\n" * 1024 + b"0\r\n\r\n",
            b"0\r\n\r\nextra",
        ):
            self.fresh()
            self.wire.data = response(
                chunks, headers=b"Transfer-Encoding: chunked\r\n", length=False
            )
            with self.subTest(size=len(chunks)), self.assertRaises(OIDCTransportError):
                self.get()

    def test_clean_eof_delimited_response_and_bound(self):
        self.wire.data = response(b"x" * 65536, length=False)
        self.assertEqual(len(self.get().body), 65536)
        self.wire.data = response(b"x" * 65537, length=False)
        with self.assertRaises(OIDCTransportError):
            self.get()

    def test_unclean_tls_eof_does_not_accept_truncated_body(self):
        self.wire.on_read = Mock(side_effect=ssl.SSLEOFError("PRIVATE_TLS"))
        with self.assertRaises(OIDCTransportError):
            self.get()

    def test_real_core_completes_with_synthetic_signed_tokens_over_fake_wire(self):
        vault = SimpleNamespace(
            assert_available=Mock(return_value=None),
            store_session=Mock(return_value=None),
            delete_session=Mock(return_value=None),
        )
        core = ManagedSignIn(CONFIG, transport=self.transport, vault=vault, monotonic=self.clock)
        authorization = core.begin()
        query = parse_qs(urlsplit(authorization.authorization_url).query)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": CONFIG.issuer,
                "sub": "synthetic-subject",
                "aud": CONFIG.client_id,
                "nonce": query["nonce"][0],
                "iat": now,
                "exp": now + 300,
            },
            key,
            algorithm="RS256",
            headers={"kid": "synthetic-key"},
        )
        self.wire.data = response(
            json.dumps(
                {
                    "access_token": "SYNTHETIC_ACCESS",
                    "id_token": token,
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": "openid",
                }
            ).encode()
        )
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update(kid="synthetic-key", alg="RS256", use="sig")
        keys_wire = FakeSocket(response(json.dumps({"keys": [jwk]}).encode()))
        self.tls.wrap_socket.side_effect = [self.wire, keys_wire]
        callback = (
            CONFIG.redirect_uri
            + "?"
            + urlencode(
                {"code": "SYNTHETIC_CODE", "state": query["state"][0], "iss": CONFIG.issuer}
            )
        )
        result = core.complete_callback(callback)
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        vault.store_session.assert_called_once()
        self.assertEqual(self.resolve.call_count, 2)
        self.assertIn(b"POST /token HTTP/1.1", self.wire.sent[0])
        self.assertIn(b"GET /jwks HTTP/1.1", keys_wire.sent[0])
        self.assertFalse(result.public()["managed_access_available"])
        self.assertFalse(core.capabilities().native_integration_verified)
        self.assertNotIn("SYNTHETIC_ACCESS", json.dumps(result.public()))

    def test_core_latches_uncertain_post_and_never_redeems_same_code_again(self):
        vault = SimpleNamespace(
            assert_available=Mock(return_value=None),
            store_session=Mock(return_value=None),
            delete_session=Mock(return_value=None),
        )
        core = ManagedSignIn(CONFIG, transport=self.transport, vault=vault, monotonic=self.clock)
        query = parse_qs(urlsplit(core.begin().authorization_url).query)
        callback = (
            CONFIG.redirect_uri
            + "?"
            + urlencode(
                {"code": "SYNTHETIC_CODE", "state": query["state"][0], "iss": CONFIG.issuer}
            )
        )
        self.wire.on_send = Mock(side_effect=TimeoutError("PRIVATE_TOKEN_RESPONSE"))
        self.assertEqual(core.complete_callback(callback).status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(core.complete_callback(callback).status, AuthStatus.RECOVERY_REQUIRED)
        self.assertFalse(core.capabilities().can_begin)
        self.assertEqual(len(self.wire.sent), 1)
        vault.store_session.assert_not_called()

    def test_repr_contains_no_endpoint_or_synthetic_secret(self):
        result = self.post()
        for value in (repr(self.transport), repr(result)):
            self.assertNotIn("example.test", value)
            self.assertNotIn("SYNTHETIC", value)
            self.assertNotIn("keys", value)


class DestinationPolicyTests(unittest.TestCase):
    def test_public_unicast_is_allowed(self):
        self.assertEqual(
            https._addresses([PUBLIC_V4, PUBLIC_V6]),
            (ipaddress.ip_address(PUBLIC_V4), ipaddress.ip_address(PUBLIC_V6)),
        )

    def test_nonpublic_transition_metadata_and_reserved_ranges_rejected(self):
        for address in (
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:93.184.216.34",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::5db8:d822",
            "2001::1",
            "2001:20::1",
            "2001:db8::1",
            "2002:5db8:d822::",
            "3fff::1",
            "fe80::1%eth0",
        ):
            with self.subTest(address=address), self.assertRaises(OIDCTransportError):
                https._addresses([address])

    def test_malformed_or_duplicate_resolution_returns_rejected(self):
        for value in (
            None,
            True,
            (),
            {},
            [],
            [PUBLIC_V4] * 33,
            [PUBLIC_V4] * 2,
            [False],
            [PUBLIC_V4, "127.0.0.1"],
            [b"1.1.1.1"],
            ["not-an-ip"],
            ["x" * 46],
        ):
            with self.subTest(value_type=type(value)), self.assertRaises(OIDCTransportError):
                https._addresses(value)


class FakeChild:
    def __init__(self, output=None):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()
        self.returncode = 0
        self.output = (json.dumps([PUBLIC_V4]).encode(), None) if output is None else output
        self.communicate = Mock(side_effect=self._communicate)
        self.poll = Mock(side_effect=lambda: self.returncode)
        self.kill = Mock(side_effect=self._kill)
        self.wait = Mock(return_value=-9)
        self.error = None

    def _communicate(self, **kwargs):
        if self.error:
            raise self.error
        return self.output

    def _kill(self):
        self.returncode = -9


class ResolverIsolationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.clock = Clock()
        self.stack.enter_context(patch.object(https.time, "monotonic", self.clock))
        self.slot = threading.Lock()
        self.stack.enter_context(patch.object(https, "_DNS_SLOT", self.slot))
        self.stack.enter_context(patch.object(https, "_STRANDED_RESOLVER", None))
        self.child = FakeChild()
        self.popen = self.stack.enter_context(
            patch.object(https.subprocess, "Popen", return_value=self.child)
        )

    def test_helper_has_empty_environment_fixed_code_and_hostname_only_stdin(self):
        self.assertEqual(https._resolve("keys.example.test", 110), [PUBLIC_V4])
        arguments, kwargs = self.popen.call_args
        self.assertEqual(arguments[0], [https.sys.executable, "-I", "-S", "-c", https._DNS_PROGRAM])
        self.assertNotIn("keys.example.test", str(arguments))
        self.assertEqual(kwargs["env"], {})
        self.assertTrue(kwargs["close_fds"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.child.communicate.assert_called_once_with(input=b"keys.example.test", timeout=9.75)
        self.child.kill.assert_not_called()
        self.assertTrue(self.child.stdin.closed)
        self.assertTrue(self.child.stdout.closed)
        self.assertFalse(self.slot.locked())

    def test_timeout_kills_and_reaps_within_remaining_budget(self):
        self.child.returncode = None

        def timeout(**kwargs):
            self.clock.advance(9.75)
            raise subprocess.TimeoutExpired("fixed-helper", kwargs["timeout"])

        self.child.communicate.side_effect = timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            https._resolve("keys.example.test", 110)
        self.child.kill.assert_called_once_with()
        self.child.wait.assert_called_once_with(timeout=0.25)
        self.assertFalse(self.slot.locked())
        self.assertIsNone(https._STRANDED_RESOLVER)

    def test_unreapable_helper_quarantines_global_slot_without_starting_more(self):
        self.child.returncode = None
        self.child.error = subprocess.TimeoutExpired("fixed-helper", 9.75)
        self.child.wait.side_effect = subprocess.TimeoutExpired("fixed-helper", 0.25)
        with self.assertRaisesRegex(OIDCTransportError, "cleanup is uncertain"):
            https._resolve("keys.example.test", 110)
        self.assertIs(https._STRANDED_RESOLVER, self.child)
        self.assertTrue(self.slot.locked())
        with self.assertRaisesRegex(OIDCTransportError, "unavailable"):
            https._resolve("identity.example.test", 110)
        self.popen.assert_called_once()

    def test_creation_failure_releases_global_slot(self):
        self.popen.side_effect = OSError("SYNTHETIC_OS_ERROR")
        with self.assertRaises(OSError):
            https._resolve("keys.example.test", 110)
        self.assertFalse(self.slot.locked())

    def test_expired_call_never_starts_a_resolver(self):
        with self.assertRaises(OIDCTransportError):
            https._resolve("keys.example.test", 100)
        self.popen.assert_not_called()
        self.assertFalse(self.slot.locked())

    def test_late_process_startup_or_result_is_rejected_and_child_killed(self):
        for where in ("spawn", "result"):
            self.child = FakeChild()
            self.popen.return_value = self.child
            self.clock.now = 100
            if where == "spawn":

                def spawn(*_, **__):
                    self.clock.advance(11)
                    self.child.returncode = None
                    return self.child

                self.popen.side_effect = spawn
            else:
                self.popen.side_effect = None

                def result(**_):
                    self.clock.advance(11)
                    return self.child.output

                self.child.communicate.side_effect = result
            with self.subTest(where=where), self.assertRaises(OIDCTransportError):
                https._resolve("keys.example.test", 110)
            self.assertFalse(self.slot.locked())
        self.assertTrue(self.child.stdout.closed)

    def test_malformed_subprocess_results_rejected(self):
        for output in (
            False,
            (b"[]",),
            ("[]", None),
            (b"[]", b""),
            (b"x" * 4097, None),
            (b"{}", None),
            (b"true", None),
        ):
            self.child.output = output
            with self.subTest(output_type=type(output)), self.assertRaises(OIDCTransportError):
                https._resolve("keys.example.test", 110)
            self.assertFalse(self.slot.locked())
        for code in (True, False, 1, "0"):
            self.child.returncode = code
            with self.subTest(code=code), self.assertRaises(OIDCTransportError):
                https._resolve("keys.example.test", 110)
            # Noninteger process completion is deliberately quarantined.
            if type(code) is not int:
                break

    def test_resolver_script_uses_absolute_name_and_has_no_network_retry(self):
        fake_socket = SimpleNamespace(
            AF_UNSPEC=0,
            SOCK_STREAM=1,
            IPPROTO_TCP=6,
            AF_INET=2,
            AF_INET6=10,
            getaddrinfo=Mock(return_value=[(2, 1, 6, "", (PUBLIC_V4, 443))]),
        )
        fake_sys = SimpleNamespace(
            stdin=SimpleNamespace(buffer=io.BytesIO(b"keys.example.test")),
            stdout=SimpleNamespace(buffer=io.BytesIO()),
            exit=Mock(),
        )
        # Execute the actual fixed helper with fake stdlib imports, not DNS.
        with patch.dict("sys.modules", {"socket": fake_socket, "sys": fake_sys}):
            exec(https._DNS_PROGRAM, {})
        fake_socket.getaddrinfo.assert_called_once_with(
            "keys.example.test.", 443, family=0, type=1, proto=6
        )
        self.assertEqual(json.loads(fake_sys.stdout.buffer.getvalue()), [PUBLIC_V4])
        fake_sys.exit.assert_not_called()


class TrustContextTests(unittest.TestCase):
    def test_context_avoids_ambient_ca_overrides_and_keylog_file(self):
        context = Mock()
        paths = SimpleNamespace(openssl_cafile="/reviewed/ca.pem", openssl_capath="/reviewed/certs")
        with (
            patch.dict(
                https.os.environ,
                {
                    "SSLKEYLOGFILE": "/must-not-create",
                    "SSL_CERT_FILE": "/untrusted",
                    "SSL_CERT_DIR": "/untrusted",
                },
            ),
            patch.object(https.ssl, "SSLContext", return_value=context) as constructor,
            patch.object(https.ssl, "get_default_verify_paths", return_value=paths),
            patch.object(https.os.path, "isfile", return_value=True),
            patch.object(https.os.path, "isdir", return_value=True),
        ):
            self.assertIs(https._context(), context)
        constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations.assert_called_once_with(
            cafile="/reviewed/ca.pem", capath="/reviewed/certs"
        )
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        context.load_default_certs.assert_not_called()

    def test_absent_native_roots_fail_without_insecure_fallback(self):
        with (
            patch.object(https.os.path, "isfile", return_value=False),
            patch.object(https.os.path, "isdir", return_value=False),
            self.assertRaises(OIDCTransportError),
        ):
            https._context()


if __name__ == "__main__":
    unittest.main()
