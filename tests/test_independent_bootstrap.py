"""Independent bootstrap contract checks, using fake .test cookies and memory-only keys."""

import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from team_browser.contracts.bootstrap import (
    BootstrapRejected,
    BootstrapScope,
    CookieRecord,
    open_bundle,
    seal,
)
from team_browser.contracts.replay import SQLiteReplayGuard


class RecordingReplayFixture:
    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def consume(self, *args):
        self.calls.append(args)
        return self.result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).decode()


class IndependentBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 16, 45, tzinfo=timezone.utc)
        self.scope = BootstrapScope(
            "qa-org",
            "qa-profile",
            "qa-device",
            "qa-recipient",
            "qa-signer",
            "qa-command",
            1,
            ("mail.example.test",),
            "qa-operator",
            self.now,
            self.now + timedelta(minutes=5),
        )
        self.cookie = CookieRecord("__Host-qa", "synthetic-only-not-a-session", "mail.example.test")
        self.recipient = X25519PrivateKey.generate()
        self.signer = Ed25519PrivateKey.generate()
        self.guard = RecordingReplayFixture()

    def valid_bundle(self, scope=None):
        return seal(
            scope or self.scope,
            (self.cookie,),
            recipient_key=self.recipient.public_key(),
            signer_key=self.signer,
            now=self.now,
        )

    def open(self, envelope, **kwargs):
        return open_bundle(
            envelope,
            expected_scope=kwargs.pop("scope", self.scope),
            recipient_key=self.recipient,
            trusted_signer=self.signer.public_key(),
            replay_guard=kwargs.pop("guard", self.guard),
            now=kwargs.pop("now", self.now),
            **kwargs,
        )

    def signed_payload(self, plaintext):
        """A permitted synthetic sender with malformed data must still fail decoder policy."""
        metadata = {
            "version": 1,
            "algorithm": "X25519-HKDF-SHA256-AES256GCM-Ed25519",
            **self.scope.metadata(),
        }
        aad = canonical(metadata)
        ephemeral = X25519PrivateKey.generate()
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"team-browser-bootstrap-v1\0" + aad,
        ).derive(ephemeral.exchange(self.recipient.public_key()))
        nonce = os.urandom(12)
        envelope = {
            "metadata": metadata,
            "ephemeral_public_key": b64(
                ephemeral.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ),
            "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(key).encrypt(nonce, plaintext, aad)),
        }
        return {**envelope, "signature": b64(self.signer.sign(canonical(envelope)))}

    def test_replay_guard_must_explicitly_confirm_atomic_consumption(self):
        for value in (False, None, 0, 1, "not-confirmed", [], {}):
            with self.subTest(value=value), self.assertRaises(BootstrapRejected):
                self.open(self.valid_bundle(), guard=RecordingReplayFixture(value))

    def test_replay_guard_receives_exact_authorized_identifiers(self):
        self.assertEqual(self.open(self.valid_bundle()), (self.cookie,))
        self.assertEqual(
            self.guard.calls,
            [
                (
                    "qa-org",
                    "qa-device",
                    "qa-command",
                    self.scope.expires_at,
                )
            ],
        )

    def test_unavailable_replay_store_never_releases_payload(self):
        class Unavailable:
            def consume(self, *args):
                raise OSError("Synthetic replay-store outage")

        with self.assertRaises(BootstrapRejected):
            self.open(self.valid_bundle(), guard=Unavailable())

    def test_bool_integer_scope_aliases_do_not_match_exact_metadata(self):
        for field in ("version", "profile_generation"):
            changed = self.valid_bundle()
            changed["metadata"][field] = True
            signed = {key: value for key, value in changed.items() if key != "signature"}
            changed["signature"] = b64(self.signer.sign(canonical(signed)))
            with self.subTest(field=field), self.assertRaises(BootstrapRejected):
                self.open(changed)
        self.assertEqual(self.guard.calls, [])

    def test_authenticated_malformed_cookie_payloads_are_rejected(self):
        valid = self.cookie.payload()
        payloads = [
            [],
            {"cookies": []},
            {"cookies": "not-a-list"},
            {"cookies": [None]},
            {"cookies": [dict(valid, domain="other.example.test")]},
            {"cookies": [dict(valid, partition_key="unsupported")]},
            {"cookies": [dict(valid, secure=1)]},
            {"cookies": [dict(valid, value=["synthetic"])]},
            {"cookies": [dict(valid, same_site="None", secure=False)]},
            {"cookies": [dict(valid, host_only=False)]},
            {"cookies": [valid, valid]},
            {"cookies": [valid], "execute": "forbidden"},
        ]
        for payload in payloads:
            with (
                self.subTest(payload_kind=type(payload).__name__),
                self.assertRaises(BootstrapRejected),
            ):
                self.open(self.signed_payload(canonical(payload)))
        self.assertEqual(self.guard.calls, [])

    def test_authenticated_invalid_json_rejected_before_replay(self):
        for payload in (b'{"cookies":', b"not-json", b"\xff\xff"):
            with self.subTest(payload=repr(payload)), self.assertRaises(BootstrapRejected):
                self.open(self.signed_payload(payload))
        self.assertEqual(self.guard.calls, [])

    def test_deep_authenticated_json_is_a_typed_rejection(self):
        nested = b'{"cookies":' + b"[" * 12_000 + b"0" + b"]" * 12_000 + b"}"
        with self.assertRaises(BootstrapRejected):
            self.open(self.signed_payload(nested))
        self.assertEqual(self.guard.calls, [])

    def test_recursive_malformed_envelope_is_a_typed_rejection(self):
        changed = self.valid_bundle()
        recursive = []
        recursive.append(recursive)
        changed["ciphertext"] = recursive
        with self.assertRaises(BootstrapRejected):
            self.open(changed)
        self.assertEqual(self.guard.calls, [])

    def test_concurrent_decrypt_releases_plaintext_once_and_survives_guard_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-replay.db"

            def factory():
                return sqlite3.connect(path, timeout=5)

            guard = SQLiteReplayGuard(factory)
            path.chmod(0o600)
            envelope = self.valid_bundle()

            def attempt(_):
                try:
                    return self.open(envelope, guard=guard)
                except BootstrapRejected:
                    return None

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(attempt, range(12)))
            self.assertEqual(results.count((self.cookie,)), 1)
            self.assertEqual(results.count(None), 11)
            with self.assertRaises(BootstrapRejected):
                self.open(envelope, guard=SQLiteReplayGuard(factory))
            self.assertNotIn(self.cookie.value.encode(), path.read_bytes())

    def test_scope_and_clock_boundaries(self):
        envelope = self.valid_bundle()
        for timestamp in (
            self.now - timedelta(microseconds=1),
            self.scope.expires_at,
            self.now.replace(tzinfo=None),
        ):
            with self.subTest(timestamp=timestamp), self.assertRaises(BootstrapRejected):
                self.open(envelope, now=timestamp)
        self.assertEqual(self.guard.calls, [])
        boundary_scope = replace(self.scope, expires_at=self.now + timedelta(minutes=10))
        self.assertEqual(
            self.open(self.valid_bundle(boundary_scope), scope=boundary_scope), (self.cookie,)
        )

    def test_domain_substitution_and_unsupported_scope_do_not_consume(self):
        envelope = self.valid_bundle()
        for domains in (
            ("mail.example.test", "mail.example.test"),
            ("*.example.test",),
            ("example.test",),
            ("mail.example.test.evil.test",),
            ("MAIL.example.test",),
        ):
            with self.subTest(domains=domains), self.assertRaises(BootstrapRejected):
                self.open(envelope, scope=replace(self.scope, approved_domains=domains))
        self.assertEqual(self.guard.calls, [])

    def test_truncated_crypto_fields_are_rejected_before_replay(self):
        envelope = self.valid_bundle()
        for field in ("ephemeral_public_key", "nonce", "ciphertext", "signature"):
            for replacement in ("", "!!invalid!!", b64(b"too-short")):
                changed = deepcopy(envelope)
                changed[field] = replacement
                with self.subTest(field=field), self.assertRaises(BootstrapRejected):
                    self.open(changed)
        self.assertEqual(self.guard.calls, [])

    def test_oversized_authenticated_plaintext_rejected_before_replay(self):
        payload = canonical({"cookies": [dict(self.cookie.payload(), value="x" * 1_048_576)]})
        with self.assertRaises(BootstrapRejected):
            self.open(self.signed_payload(payload))
        self.assertEqual(self.guard.calls, [])

    def test_exact_cookie_flags_survive_roundtrip(self):
        cookie = CookieRecord(
            "qa-non-host",
            "synthetic-only",
            "mail.example.test",
            "/synthetic",
            secure=True,
            http_only=False,
            same_site="Strict",
            host_only=False,
        )
        envelope = seal(
            self.scope,
            (cookie,),
            recipient_key=self.recipient.public_key(),
            signer_key=self.signer,
            now=self.now,
        )
        self.assertEqual(self.open(envelope), (cookie,))
        self.assertNotIn(cookie.value, json.dumps(envelope))
        self.assertNotIn(cookie.name, json.dumps(envelope))


if __name__ == "__main__":
    unittest.main()
