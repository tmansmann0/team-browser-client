"""Synthetic .test cookies only; ephemeral in-memory cryptographic keys."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from team_browser.contracts.bootstrap import (
    BootstrapRejected,
    BootstrapScope,
    CookieRecord,
    open_bundle,
    seal,
)


class MemoryReplayFixture:
    def __init__(self):
        self.consumed = set()

    def consume(self, organization_id, device_id, command_id, expires_at):
        key = (organization_id, device_id, command_id)
        if key in self.consumed:
            return False
        self.consumed.add(key)
        return True


class BootstrapContractTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 16, 0, tzinfo=timezone.utc)
        self.scope = BootstrapScope(
            "synthetic-org",
            "synthetic-profile",
            "synthetic-device",
            "recipient-fixture",
            "signer-fixture",
            "command-fixture",
            1,
            ("mail.example.test",),
            "synthetic-consenting-operator",
            self.now,
            self.now + timedelta(minutes=5),
        )
        self.cookies = (
            CookieRecord("__Host-synthetic", "fake-value-not-a-live-session", "mail.example.test"),
        )
        self.recipient = X25519PrivateKey.generate()
        self.signer = Ed25519PrivateKey.generate()
        self.replay = MemoryReplayFixture()

    def seal(self, **kwargs):
        return seal(
            kwargs.pop("scope", self.scope),
            kwargs.pop("cookies", self.cookies),
            recipient_key=self.recipient.public_key(),
            signer_key=self.signer,
            now=kwargs.pop("now", self.now),
            **kwargs,
        )

    def open(self, envelope, **kwargs):
        return open_bundle(
            envelope,
            expected_scope=kwargs.pop("scope", self.scope),
            recipient_key=kwargs.pop("recipient", self.recipient),
            trusted_signer=kwargs.pop("signer", self.signer.public_key()),
            replay_guard=self.replay,
            now=kwargs.pop("now", self.now),
            **kwargs,
        )

    def test_roundtrip_scoped_encrypted_fixture(self):
        envelope = self.seal()
        self.assertEqual(self.open(envelope), self.cookies)
        self.assertNotIn(self.cookies[0].value, json.dumps(envelope))
        self.assertNotIn(self.cookies[0].name, json.dumps(envelope))

    def test_cookie_value_hidden_from_repr(self):
        self.assertNotIn(self.cookies[0].value, repr(self.cookies[0]))

    def test_replay_denied(self):
        envelope = self.seal()
        self.open(envelope)
        with self.assertRaises(BootstrapRejected):
            self.open(envelope)

    def test_wrong_device_org_profile_generation_and_command_rejected(self):
        envelope = self.seal()
        for field, value in [
            ("organization_id", "other-org"),
            ("profile_id", "other-profile"),
            ("device_id", "other-device"),
            ("recipient_key_id", "other-key"),
            ("signer_key_id", "other-signer"),
            ("command_id", "other-command"),
            ("profile_generation", 2),
            ("approved_by", "other-operator"),
            ("approved_domains", ("other.example.test",)),
        ]:
            with self.subTest(field=field), self.assertRaises(BootstrapRejected):
                self.open(envelope, scope=replace(self.scope, **{field: value}))
        self.assertFalse(self.replay.consumed)

    def test_wrong_recipient_and_signer_rejected(self):
        envelope = self.seal()
        with self.assertRaises(BootstrapRejected):
            self.open(envelope, recipient=X25519PrivateKey.generate())
        with self.assertRaises(BootstrapRejected):
            self.open(envelope, signer=Ed25519PrivateKey.generate().public_key())
        self.assertFalse(self.replay.consumed)

    def test_ciphertext_signature_nonce_tamper(self):
        envelope = self.seal()
        for field in ("ciphertext", "signature", "nonce", "ephemeral_public_key"):
            changed = deepcopy(envelope)
            changed[field] = (
                "A" + changed[field][1:] if changed[field][0] != "A" else "B" + changed[field][1:]
            )
            with self.subTest(field=field), self.assertRaises(BootstrapRejected):
                self.open(changed)
        self.assertFalse(self.replay.consumed)

    def test_expiry_and_future_date_rejected(self):
        envelope = self.seal()
        with self.assertRaises(BootstrapRejected):
            self.open(envelope, now=self.now + timedelta(minutes=6))
        with self.assertRaises(BootstrapRejected):
            self.seal(now=self.now - timedelta(seconds=1))
        with self.assertRaises(BootstrapRejected):
            self.seal(scope=replace(self.scope, expires_at=self.now + timedelta(minutes=11)))

    def test_naive_dates_and_generation_rejected(self):
        for invalid in (
            replace(self.scope, issued_at=self.now.replace(tzinfo=None)),
            replace(self.scope, profile_generation=True),
            replace(self.scope, profile_generation=0),
        ):
            with self.assertRaises(BootstrapRejected):
                self.seal(scope=invalid)

    def test_explicit_domain_allowlist(self):
        for domain in (
            "other.example.test",
            ".example.test",
            "MAIL.example.test",
            "*",
            "https://mail.example.test",
        ):
            with self.subTest(domain=domain), self.assertRaises(BootstrapRejected):
                self.seal(cookies=(replace(self.cookies[0], domain=domain),))
        with self.assertRaises(BootstrapRejected):
            self.seal(scope=replace(self.scope, approved_domains=()))

    def test_cookie_prefix_and_flag_validation(self):
        for changed in (
            replace(self.cookies[0], secure=False),
            replace(self.cookies[0], host_only=False),
            replace(self.cookies[0], path="/sub"),
            replace(self.cookies[0], same_site="Bad"),
            replace(self.cookies[0], http_only="yes"),
            replace(self.cookies[0], value="bad\nvalue"),
        ):
            with self.assertRaises(BootstrapRejected):
                self.seal(cookies=(changed,))

    def test_duplicate_and_limit_rejected(self):
        with self.assertRaises(BootstrapRejected):
            self.seal(cookies=(self.cookies[0], self.cookies[0]))
        with self.assertRaises(BootstrapRejected):
            self.seal(cookies=())
        with self.assertRaises(BootstrapRejected):
            self.seal(
                cookies=tuple(replace(self.cookies[0], name=f"synthetic-{i}") for i in range(201))
            )
        with self.assertRaises(BootstrapRejected):
            self.seal(cookies=(replace(self.cookies[0], value="x" * 16385),))

    def test_unknown_envelope_field_rejected(self):
        envelope = self.seal()
        envelope["execute"] = "not-allowed"
        with self.assertRaises(BootstrapRejected):
            self.open(envelope)

    def test_separate_envelopes_are_randomized(self):
        first, second = self.seal(), self.seal()
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
