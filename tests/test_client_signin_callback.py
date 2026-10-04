"""Disposable Linux loopback + synthetic core/provider/vault. No real login."""

import asyncio
import contextlib
import io
import json
import socket
import sys
import threading
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from team_browser.client import signin_callback as callback
from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthResult,
    AuthStatus,
    HTTPResponse,
    TrustedOIDCConfiguration,
    entra_native_configuration,
)
from team_browser.client.signin_callback import NativeSignInCoordinator


BASE = TrustedOIDCConfiguration(
    issuer="https://identity.example.test/tenant",
    client_id="synthetic-client",
    authorization_endpoint="https://identity.example.test/authorize",
    token_endpoint="https://identity.example.test/token",
    jwks_endpoint="https://identity.example.test/keys",
    redirect_uri="http://127.0.0.1:43821/callback",
)


def unused_port(host="127.0.0.1"):
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("Synthetic operation did not settle")


class Vault:
    def __init__(self):
        self.calls = 0
        self.records = {}
        self.on_available = None

    def assert_available(self):
        self.calls += 1
        if self.on_available:
            self.on_available()

    def store_session(self, session_id, material):
        self.records[session_id] = material

    def delete_session(self, session_id):
        self.records.pop(session_id, None)


class Transport:
    def __init__(self):
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.fail = False

    def post_form(self, url, fields, **kwargs):
        self.calls += 1
        self.entered.set()
        self.release.wait()
        if self.fail:
            raise TimeoutError("SECRET_TEST_PROVIDER_DIAGNOSTIC")
        return HTTPResponse(200, url, b"{}")

    def get(self, *args, **kwargs):
        raise AssertionError("Synthetic test did not supply a token")


class Harness:
    def __init__(self, config=None):
        self.config = config or replace(
            BASE, redirect_uri=f"http://127.0.0.1:{unused_port()}/callback"
        )
        self.transport, self.vault = Transport(), Vault()
        self.urls = []
        self.opened = threading.Event()
        self.on_open = None
        self.opener = patch.object(callback, "_launch_macos_authorization", side_effect=self.open)
        self.opener.start()
        self.coordinator = NativeSignInCoordinator(
            self.config, transport=self.transport, vault=self.vault
        )

    def open(self, url, endpoint):
        self.urls.append(url)
        if self.on_open:
            self.on_open(url, endpoint)
        self.opened.set()

    def begin(self):
        self.coordinator.start()
        if not self.opened.wait(3):
            raise AssertionError(self.coordinator.snapshot())

    def target(self, **values):
        params = parse_qs(urlsplit(self.urls[0]).query)
        query = {"state": params["state"][0], "iss": self.config.issuer, "code": "TEST_CODE"}
        query.update(values)
        if "error" in values:
            query.pop("code", None)
        return urlsplit(self.config.redirect_uri).path + "?" + urlencode(query)

    def request(self, target=None, *, method="GET", headers=(), raw=None):
        parts = urlsplit(self.config.redirect_uri)
        if raw is None:
            lines = [f"{method} {target or self.target()} HTTP/1.1", f"Host: {parts.netloc}"]
            lines.extend(headers)
            raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        with socket.create_connection((parts.hostname, parts.port), timeout=2) as connection:
            connection.sendall(raw)
            chunks = []
            while True:
                try:
                    data = connection.recv(4096)
                except ConnectionResetError:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)

    def close(self):
        self.transport.release.set()
        self.coordinator.shutdown()
        try:
            if not self.coordinator.wait_finished(3):
                raise AssertionError("Synthetic worker did not terminate")
        finally:
            self.opener.stop()

    def use_success(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk.update(kid="test-key", use="sig", alg="RS256")

        def post(url, fields, **kwargs):
            self.transport.calls += 1
            now = int(time.time())
            nonce = parse_qs(urlsplit(self.urls[0]).query)["nonce"][0]
            token = jwt.encode(
                {
                    "iss": self.config.issuer,
                    "aud": self.config.client_id,
                    "sub": "synthetic-subject",
                    "nonce": nonce,
                    "iat": now,
                    "exp": now + 300,
                },
                key,
                algorithm="RS256",
                headers={"kid": "test-key"},
            )
            body = {
                "token_type": "Bearer",
                "access_token": "SYNTHETIC_ACCESS",
                "id_token": token,
                "expires_in": 300,
                "scope": "openid",
            }
            return HTTPResponse(200, url, json.dumps(body).encode())

        self.transport.post_form = post
        self.transport.get = lambda url, **_: HTTPResponse(
            200, url, json.dumps({"keys": [jwk]}).encode()
        )


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.close)

    def assert_waiting(self):
        wait_until(lambda: not self.h.coordinator.snapshot().native_operations_pending)
        self.assertTrue(self.h.coordinator.snapshot().listener_open)
        self.assertFalse(self.h.coordinator.snapshot().finished)
        self.assertEqual(self.h.transport.calls, 0)

    def test_construct_is_inert_and_exact_typed_config_required(self):
        self.assertEqual(self.h.vault.calls, 0)
        self.assertEqual(self.h.urls, [])
        with self.assertRaises(TypeError):
            NativeSignInCoordinator({}, transport=self.h.transport, vault=self.h.vault)
        with self.assertRaises(TypeError):
            self.h.coordinator.start(expected_account={})

    def test_exact_socket_bound_before_core_begin_and_launch(self):
        observations = []

        def already_bound():
            parts = urlsplit(self.h.config.redirect_uri)
            with socket.socket() as sock:
                with self.assertRaises(OSError):
                    sock.bind((parts.hostname, parts.port))
            observations.append(True)

        self.h.vault.on_available = already_bound
        self.h.on_open = lambda *_: already_bound()
        self.h.begin()
        self.assertEqual(observations, [True, True])
        self.assertEqual(self.h.vault.calls, 1)
        for _ in range(5):
            self.h.coordinator.start()
        self.assertEqual(len(self.h.urls), 1)

    def test_port_conflict_never_begins_or_uses_alternate_port(self):
        port = urlsplit(self.h.config.redirect_uri).port
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", port))
            blocker.listen()
            self.h.coordinator.start()
            self.assertTrue(self.h.coordinator.wait_finished(3))
            self.assertEqual(self.h.coordinator.snapshot().result.reason, "callback_bind_failed")
            self.assertEqual(self.h.vault.calls, 0)
            self.assertEqual(self.h.urls, [])

    def test_denial_uses_fixed_safe_page_and_closes_listener(self):
        self.h.begin()
        page = self.h.request(
            self.h.target(error="access_denied", error_description="SECRET_DENIAL")
        )
        self.assertIn(b"200", page.split(b"\r\n", 1)[0])
        self.assertIn(b"cache-control: no-store", page)
        self.assertIn(b"default-src 'none'", page)
        self.assertIn(b"referrer-policy: no-referrer", page)
        self.assertNotIn(b"SECRET_DENIAL", page)
        self.assertNotIn(b"access-control-allow", page)
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.reason, "consent_denied")
        self.assertFalse(self.h.coordinator.snapshot().listener_open)
        self.assertEqual(self.h.transport.calls, 0)

    def test_invalid_state_and_issuer_do_not_consume_attempt(self):
        self.h.begin()
        for target in [
            self.h.target(state="wrong"),
            self.h.target(iss="https://wrong.example.test"),
        ]:
            self.h.request(target)
            self.assert_waiting()
        self.h.request(self.h.target(error="access_denied"))
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.reason, "consent_denied")

    def test_methods_hosts_paths_and_forwarded_headers_rejected(self):
        self.h.begin()
        parts = urlsplit(self.h.config.redirect_uri)
        cases = [
            {"method": "POST"},
            {"method": "HEAD"},
            {"method": "OPTIONS"},
            {"target": "/wrong?state=x&code=x"},
            {"target": "http://" + parts.netloc + self.h.target()},
            {"target": self.h.target() + "#fragment"},
            {"headers": ["Forwarded: host=trusted"]},
            {"headers": ["X-Forwarded-Host: trusted"]},
            {"headers": ["X-Forwarded-For: 127.0.0.1"]},
            {"headers": ["X-Real-IP: 127.0.0.1"]},
            {"headers": ["Authorization: Bearer SECRET"]},
            {"headers": ["Origin: https://attacker.example.test"]},
            {"headers": ["Content-Length: 0"]},
            {"headers": ["Content-Length: 9"]},
            {"headers": ["Transfer-Encoding: chunked"]},
            {"headers": ["Expect: 100-continue"]},
            {"headers": ["Upgrade: websocket"]},
            {"headers": ["Host: " + parts.netloc]},
        ]
        for case in cases:
            with self.subTest(case=case):
                response = self.h.request(**case)
                self.assertIn(b"400", response.split(b"\r\n", 1)[0])
                self.assert_waiting()
        for host in [
            "localhost:" + str(parts.port),
            "127.0.0.2:" + str(parts.port),
            "attacker.test",
            parts.netloc + ".",
        ]:
            raw = f"GET {self.h.target()} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
            self.assertIn(b"400", self.h.request(raw=raw).split(b"\r\n", 1)[0])
        self.assert_waiting()

    def test_wire_headers_query_and_parser_failures_are_bounded(self):
        self.h.begin()
        host = urlsplit(self.h.config.redirect_uri).netloc
        requests = [
            f"GET {self.h.target()} HTTP/1.0\r\nHost: {host}\r\n\r\n",
            f"GET {self.h.target()} HTTP/1.1\r\nHost: {host}\r\nX: ok\r\n folded\r\n\r\n",
            f"GET {self.h.target()} HTTP/1.1\r\nHost: {host}\r\nX: {'x' * 2049}\r\n\r\n",
            f"GET {self.h.target()} HTTP/1.1\r\nHost: {host}\r\n" + "X: v\r\n" * 48 + "\r\n",
            f"GET {self.h.target()} HTTP/1.1\r\nHost: {host}\r\n"
            + "X: "
            + "x" * 17000
            + "\r\n\r\n",
            f"GET {self.h.target()}&extra={'x' * 8192} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        ]
        for raw in requests:
            with self.subTest(size=len(raw)):
                self.assertIn(b"400", self.h.request(raw=raw.encode()).split(b"\r\n", 1)[0])
                self.assert_waiting()
        for suffix in ["&state=duplicate", "&extra=%ZZ", "&token_type=bearer", "&extra=1"]:
            self.h.request(self.h.target() + suffix)
            self.assert_waiting()

    def test_slow_request_does_not_block_valid_callback(self):
        self.h.begin()
        parts = urlsplit(self.h.config.redirect_uri)
        slow = socket.create_connection((parts.hostname, parts.port), timeout=2)
        self.addCleanup(slow.close)
        slow.sendall(b"GET /callback HTTP/1.1\r\nHost:")
        self.h.request(self.h.target(error="access_denied"))
        self.assertTrue(self.h.coordinator.wait_finished(3))

    def test_connection_count_is_bounded_and_overflow_cannot_start_auth(self):
        self.h.begin()
        parts = urlsplit(self.h.config.redirect_uri)
        sockets = []
        try:
            for _ in range(callback._MAX_CONNECTIONS):
                sock = socket.create_connection((parts.hostname, parts.port), timeout=2)
                sock.sendall(b"GET /callback HTTP/1.1\r\n")
                sockets.append(sock)
            wait_until(lambda: len(self.h.coordinator._handlers) == callback._MAX_CONNECTIONS)
            self.assertEqual(self.h.request(), b"")
            self.assertEqual(self.h.transport.calls, 0)
        finally:
            for sock in sockets:
                sock.close()

    def test_cancel_and_shutdown_before_start_are_final(self):
        self.assertTrue(self.h.coordinator.cancel().finished)
        self.h.coordinator.start()
        self.assertEqual(self.h.urls, [])
        self.assertEqual(self.h.vault.calls, 0)
        self.assertTrue(self.h.coordinator.shutdown().finished)

    def test_cancel_waiting_and_repeated_start_never_relaunch(self):
        self.h.begin()
        self.h.coordinator.cancel()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.CANCELLED)
        self.h.coordinator.start()
        self.assertEqual(len(self.h.urls), 1)

    def test_cancel_during_blocked_begin_returns_promptly_and_never_launches(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def block():
            entered.set()
            release.wait()

        self.h.vault.on_available = block
        self.h.coordinator.start()
        self.assertTrue(entered.wait(2))
        started = time.monotonic()
        snapshot = self.h.coordinator.cancel()
        self.assertLess(time.monotonic() - started, 0.1)
        self.assertTrue(snapshot.native_operations_pending)
        self.assertFalse(snapshot.finished)
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.urls, [])

    def test_exchange_cancel_does_not_abandon_uncertain_exchange(self):
        self.h.transport.release.clear()
        self.h.transport.fail = True
        self.h.begin()
        self.h.request()
        self.assertTrue(self.h.transport.entered.wait(2))
        started = time.monotonic()
        snapshot = self.h.coordinator.shutdown()
        self.assertLess(time.monotonic() - started, 0.1)
        self.assertTrue(snapshot.cancellation_requested)
        wait_until(lambda: self.h.coordinator.snapshot().result.status == AuthStatus.CANCELLING)
        self.assertFalse(self.h.coordinator.wait_finished(0.02))
        self.assertFalse(self.h.coordinator.snapshot().listener_open)
        self.h.transport.release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        result = self.h.coordinator.snapshot().result
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(result.reason, "token_exchange_uncertain")
        self.assertEqual(self.h.transport.calls, 1)
        self.assertEqual(self.h.vault.records, {})

    def test_concurrent_replay_exchanges_only_once(self):
        self.h.transport.release.clear()
        self.h.begin()
        self.h.request()
        self.assertTrue(self.h.transport.entered.wait(2))
        for _ in range(4):
            self.assertIn(b"409", self.h.request().split(b"\r\n", 1)[0])
        self.h.transport.release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.transport.calls, 1)

    def test_launch_failure_cancels_once_without_reflection_or_retry(self):
        def broken(*_):
            self.h.opened.set()
            raise RuntimeError("SECRET_LAUNCH_URL?state=private")

        self.h.on_open = broken
        self.h.begin()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        public = self.h.coordinator.snapshot().public()
        self.assertEqual(public["diagnostic"], "external_browser_launch_uncertain")
        self.assertEqual(public["status"], "cancelled")
        self.assertNotIn("SECRET", json.dumps(public))
        self.h.coordinator.start()
        self.assertEqual(len(self.h.urls), 1)

    def test_blocked_opener_is_retained_after_cancellation(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocked(*_):
            entered.set()
            release.wait()

        self.h.on_open = blocked
        self.h.coordinator.start()
        self.assertTrue(entered.wait(2))
        self.h.coordinator.cancel()
        wait_until(lambda: not self.h.coordinator.snapshot().listener_open)
        self.assertFalse(self.h.coordinator.wait_finished(0.02))
        self.assertTrue(self.h.coordinator.snapshot().native_operations_pending)
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))

    def test_no_callback_or_provider_data_in_logs_page_or_snapshot(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.h.begin()
            page = self.h.request(self.h.target(state="SECRET_CALLBACK_STATE"))
            self.assert_waiting()
        output = page.decode() + stdout.getvalue() + stderr.getvalue()
        output += json.dumps(self.h.coordinator.snapshot().public())
        self.assertNotIn("SECRET_CALLBACK_STATE", output)
        self.assertNotIn("TEST_CODE", output)
        self.assertNotIn("authorization_url", output)
        self.assertFalse(self.h.coordinator.snapshot().public()["native_integration_verified"])

    def test_account_binding_passes_to_same_native_core(self):
        wrong = AccountIdentity("https://other.example.test", "subject")
        self.h.coordinator.start(expected_account=wrong)
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.reason, "invalid_account_binding")
        self.assertEqual(self.h.urls, [])

    def test_expiration_closes_listener_without_ui_polling(self):
        self.h.begin()
        # Advance only the pinned core's injected clock, never wall-clock/DNS.
        with self.h.coordinator._core._lock:
            self.h.coordinator._core._monotonic = lambda: time.monotonic() + 601
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.EXPIRED)
        self.assertFalse(self.h.coordinator.snapshot().listener_open)

    def test_cached_success_hides_identity_at_expiry_without_native_io(self):
        identity = AccountIdentity(BASE.issuer, "synthetic-subject")
        self.h.coordinator._result = AuthResult(
            AuthStatus.IDENTITY_VERIFIED, "identity_verified", identity, int(time.time()) - 1
        )
        result = self.h.coordinator.snapshot().result
        self.assertEqual(result.status, AuthStatus.EXPIRED)
        self.assertIsNone(result.identity)
        self.assertEqual(self.h.vault.calls, 0)

    def test_independent_listener_ttl_also_bounds_blocked_startup(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        real_sleep = asyncio.sleep

        async def short_timer(delay):
            await real_sleep(0.05 if delay == self.h.config.authorization_ttl_seconds else delay)

        def blocked():
            entered.set()
            release.wait()

        self.h.vault.on_available = blocked
        with patch.object(callback.asyncio, "sleep", side_effect=short_timer):
            self.h.coordinator.start()
            self.assertTrue(entered.wait(2))
            wait_until(lambda: not self.h.coordinator.snapshot().listener_open)
            self.assertFalse(self.h.coordinator.snapshot().finished)
            self.assertTrue(self.h.coordinator.snapshot().native_operations_pending)
            release.set()
            self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.EXPIRED)
        self.assertEqual(self.h.urls, [])

    def test_ttl_closes_listener_but_retains_uncertain_exchange(self):
        self.h.transport.release.clear()
        self.h.transport.fail = True
        real_sleep = asyncio.sleep

        async def short_timer(delay):
            await real_sleep(0.15 if delay == self.h.config.authorization_ttl_seconds else delay)

        with patch.object(callback.asyncio, "sleep", side_effect=short_timer):
            self.h.begin()
            self.h.request()
            self.assertTrue(self.h.transport.entered.wait(2))
            wait_until(lambda: not self.h.coordinator.snapshot().listener_open)
            self.assertFalse(self.h.coordinator.snapshot().finished)
            self.h.transport.release.set()
            self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertEqual(self.h.transport.calls, 1)

    def test_synthetic_success_commits_to_vault_and_closes_listener(self):
        self.h.use_success()
        self.h.begin()
        page = self.h.request()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(len(self.h.vault.records), 1)
        self.assertEqual(self.h.transport.calls, 1)
        public = self.h.coordinator.snapshot().public()
        self.assertFalse(public["managed_access_available"])
        self.assertFalse(public["company_membership_verified"])
        self.assertNotIn("SYNTHETIC_ACCESS", page.decode() + json.dumps(public))

    def test_callback_waits_for_opener_and_cancel_prevents_exchange(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.h.use_success()

        def blocked(*_):
            entered.set()
            self.h.opened.set()
            release.wait()

        self.h.on_open = blocked
        self.h.begin()
        self.h.request()
        self.assertTrue(entered.is_set())
        self.assertEqual(self.h.transport.calls, 0)
        self.assertEqual(self.h.vault.records, {})
        self.assertTrue(self.h.coordinator.snapshot().can_cancel)
        self.h.coordinator.cancel()
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(self.h.coordinator.snapshot().result.status, AuthStatus.CANCELLED)
        self.assertEqual(self.h.transport.calls, 0)
        self.assertEqual(self.h.vault.records, {})

    def _cancel_at_unpublished_commit(self, *, deletion_fails=False):
        ready, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.h.use_success()
        original = self.h.coordinator._publish
        deletes = []
        original_delete = self.h.vault.delete_session

        def delete(session_id):
            deletes.append(session_id)
            if deletion_fails:
                raise RuntimeError("SECRET_NATIVE_DELETE_ERROR")
            return original_delete(session_id)

        async def pause_before_publication(result):
            if result.status == AuthStatus.IDENTITY_VERIFIED:
                ready.set()
                while not release.is_set():
                    await asyncio.sleep(0.005)
            await original(result)

        self.h.vault.delete_session = delete
        self.h.coordinator._publish = pause_before_publication
        self.h.begin()
        self.h.request()
        self.assertTrue(ready.wait(2))
        self.assertEqual(len(self.h.vault.records), 1)
        self.assertTrue(self.h.coordinator.cancel().cancellation_requested)
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(len(deletes), 1)
        return self.h.coordinator.snapshot()

    def test_accepted_cancel_discards_just_committed_unpublished_session(self):
        snapshot = self._cancel_at_unpublished_commit()
        self.assertEqual(snapshot.result.status, AuthStatus.CANCELLED)
        self.assertIsNone(snapshot.result.identity)
        self.assertEqual(self.h.vault.records, {})
        self.assertFalse(snapshot.can_cancel)

    def test_uncertain_unpublished_commit_cleanup_requires_recovery_no_retry(self):
        snapshot = self._cancel_at_unpublished_commit(deletion_fails=True)
        self.assertEqual(snapshot.result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(snapshot.result.identity)
        self.assertEqual(snapshot.result.reason, "vault_cleanup_uncertain")
        self.assertFalse(snapshot.can_cancel)
        self.assertNotIn("SECRET", json.dumps(snapshot.public()))

    def test_cancel_after_terminal_publication_is_explicit_noop(self):
        ready, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.h.use_success()
        original = self.h.coordinator._publish

        async def pause_after_publication(result):
            await original(result)
            if result.status == AuthStatus.IDENTITY_VERIFIED:
                ready.set()
                while not release.is_set():
                    await asyncio.sleep(0.005)

        self.h.coordinator._publish = pause_after_publication
        self.h.begin()
        self.h.request()
        self.assertTrue(ready.wait(2))
        snapshot = self.h.coordinator.cancel()
        self.assertFalse(snapshot.finished)
        self.assertFalse(snapshot.can_cancel)
        self.assertFalse(snapshot.cancellation_requested)
        self.assertEqual(snapshot.result.status, AuthStatus.IDENTITY_VERIFIED)
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        self.assertEqual(len(self.h.vault.records), 1)

    def test_no_success_until_accepted_callback_worker_settles(self):
        committed, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.h.use_success()
        original = self.h.coordinator._core.complete_callback

        def fail_after_commit(url):
            result = original(url)
            if result.status == AuthStatus.IDENTITY_VERIFIED:
                committed.set()
                release.wait()
                raise RuntimeError("SECRET_CALLBACK_WORKER_FAILURE")
            return result

        self.h.coordinator._core.complete_callback = fail_after_commit
        self.h.begin()
        self.h.request()
        self.assertTrue(committed.wait(2))
        self.assertFalse(self.h.coordinator.snapshot().finished)
        self.assertTrue(self.h.coordinator.snapshot().can_cancel)
        self.assertNotEqual(
            self.h.coordinator.snapshot().result.status, AuthStatus.IDENTITY_VERIFIED
        )
        release.set()
        self.assertTrue(self.h.coordinator.wait_finished(3))
        result = self.h.coordinator.snapshot().result
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(result.identity)
        self.assertNotIn("SECRET", json.dumps(self.h.coordinator.snapshot().public()))


class EntraAndIPv6Tests(unittest.TestCase):
    def test_entra_exact_issuer_bound_path_missing_issuer_and_extension(self):
        config = entra_native_configuration(
            tenant_id="11111111-1111-4111-8111-111111111111",
            desktop_client_id="22222222-2222-4222-8222-222222222222",
            api_client_id="33333333-3333-4333-8333-333333333333",
            loopback_port=unused_port(),
        )
        h = Harness(config)
        self.addCleanup(h.close)
        h.begin()
        params = parse_qs(urlsplit(h.urls[0]).query)
        self.assertEqual(params["scope"][0].split(), list(config.scopes))
        query = urlencode(
            {"state": params["state"][0], "error": "access_denied", "session_state": "SYNTHETIC"}
        )
        h.request(urlsplit(config.redirect_uri).path + "?" + query)
        self.assertTrue(h.coordinator.wait_finished(3))
        self.assertEqual(h.coordinator.snapshot().result.reason, "consent_denied")

    @unittest.skipUnless(socket.has_ipv6, "IPv6 is unavailable")
    def test_ipv6_literal_binding(self):
        try:
            port = unused_port("::1")
        except OSError:
            self.skipTest("IPv6 loopback is unavailable")
        h = Harness(replace(BASE, redirect_uri=f"http://[::1]:{port}/callback"))
        self.addCleanup(h.close)
        h.begin()
        h.request(h.target(error="access_denied"))
        self.assertTrue(h.coordinator.wait_finished(3))
        self.assertEqual(h.coordinator.snapshot().result.reason, "consent_denied")


class MacOSOpenerTests(unittest.TestCase):
    def test_linux_never_imports_or_launches_native_frameworks(self):
        with (
            patch.object(callback.sys, "platform", "linux"),
            patch("builtins.__import__", wraps=__import__) as imported,
        ):
            with self.assertRaises(callback.NativeBrowserError):
                callback._launch_macos_authorization(
                    BASE.authorization_endpoint + "?state=x", BASE.authorization_endpoint
                )
        self.assertFalse(
            any(
                call.args[0] in {"AppKit", "Foundation", "objc"} for call in imported.call_args_list
            )
        )

    def test_macos_api_contract_with_synthetic_frameworks_only(self):
        opened = Mock(return_value=True)
        modules = {
            "AppKit": SimpleNamespace(
                NSWorkspace=SimpleNamespace(
                    sharedWorkspace=lambda: SimpleNamespace(openURL_=opened)
                )
            ),
            "Foundation": SimpleNamespace(
                NSURL=SimpleNamespace(URLWithString_=lambda url: ("FAKE_NSURL", url))
            ),
            "objc": SimpleNamespace(autorelease_pool=contextlib.nullcontext),
        }
        url = BASE.authorization_endpoint + "?state=SYNTHETIC"
        with patch.object(callback.sys, "platform", "darwin"), patch.dict(sys.modules, modules):
            self.assertIsNone(
                callback._launch_macos_authorization(url, BASE.authorization_endpoint)
            )
            opened.assert_called_once_with(("FAKE_NSURL", url))
            for bad in [False, 1, None, "true"]:
                opened.return_value = bad
                with self.assertRaisesRegex(callback.NativeBrowserError, "launch_uncertain"):
                    callback._launch_macos_authorization(url, BASE.authorization_endpoint)
            before = opened.call_count
            for bad_url in [
                "http://identity.example.test/authorize?state=x",
                "https://wrong.example.test/?state=x",
                url + "#x",
                url + "\n",
                "file:///private",
                BASE.authorization_endpoint,
            ]:
                with self.assertRaises(callback.NativeBrowserError):
                    callback._launch_macos_authorization(bad_url, BASE.authorization_endpoint)
            self.assertEqual(opened.call_count, before)


if __name__ == "__main__":
    unittest.main()
