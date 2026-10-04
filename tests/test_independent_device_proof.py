"""Independent public-only proof tests. Ephemeral keys, no API imports or I/O."""

import base64
from dataclasses import replace
import json
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

from team_browser.contracts.device_proof import (
    DeviceProofRejected,
    ProofContext,
    encode_public_key,
    sign_device_proof,
    verify_device_proof,
)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class IndependentDeviceProofTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = encode_public_key(self.key.public_key())
        self.now = 1800000000
        self.context = ProofContext(
            "https://proof.example.test",
            "company-a",
            "member-a",
            "device-a",
            1,
            "POST",
            "/v1/agent/devices/device-a/poll",
            b'{"registration_generation":1}',
        )
        self.token = sign_device_proof(self.key, self.context, self.now)
        self.claims = jwt.decode(self.token, options={"verify_signature": False})

    def assert_rejected(self, token, context=None):
        with self.assertRaises(DeviceProofRejected):
            verify_device_proof(token, self.public, context or self.context, self.now)

    def raw_signature(self, header, payload):
        message = f"{b64(header)}.{b64(payload)}".encode("ascii")
        return message.decode("ascii") + "." + b64(self.key.sign(message))

    def test_lifetime_and_future_skew_boundaries_are_exact(self):
        for issued, accepted in (
            (self.now - 60, False),
            (self.now - 59, True),
            (self.now + 5, True),
            (self.now + 6, False),
        ):
            with self.subTest(issued=issued):
                token = sign_device_proof(self.key, self.context, issued)
                if accepted:
                    self.assertEqual(
                        verify_device_proof(token, self.public, self.context, self.now).expires_at,
                        issued + 60,
                    )
                else:
                    self.assert_rejected(token)

    def test_every_identity_target_and_payload_dimension_is_bound(self):
        for changes in (
            {"origin": "https://other.example.test"},
            {"organization_id": "company-b"},
            {"member_id": "member-b"},
            {"device_id": "device-b"},
            {"registration_generation": 2},
            {"path": "/v1/agent/devices/device-a/heartbeat"},
            {"body": b'{ "registration_generation": 1 }'},
            {"purpose": "enrollment", "nonce": "a" * 43},
        ):
            with self.subTest(changes=changes):
                self.assert_rejected(self.token, replace(self.context, **changes))

    def test_missing_extra_and_wrong_type_claims_fail_with_valid_signature(self):
        for claims in (
            {k: v for k, v in self.claims.items() if k != "nonce"},
            {**self.claims, "nbf": self.now},
            {**self.claims, "aud": [self.context.origin]},
            {**self.claims, "generation": 1.0},
            {**self.claims, "iat": True},
            {**self.claims, "exp": str(self.now + 60)},
            {**self.claims, "nonce": ""},
            {**self.claims, "jti": "00000000-0000-0000-0000-000000000000"},
        ):
            token = jwt.encode(
                claims, self.key, algorithm="EdDSA", headers={"typ": "tbm-device-proof+jwt"}
            )
            self.assert_rejected(token)

    def test_duplicate_header_and_unicode_aliased_claim_keys_are_rejected(self):
        header = b'{"alg":"EdDSA","typ":"tbm-device-proof+jwt"}'
        payload = json.dumps(self.claims).encode()
        self.assert_rejected(
            self.raw_signature(
                b'{"alg":"EdDSA","alg":"EdDSA","typ":"tbm-device-proof+jwt"}', payload
            )
        )
        duplicate = payload[:-1] + b',"\\u006f\\u0072\\u0067":"company-a"}'
        self.assert_rejected(self.raw_signature(header, duplicate))

    def test_noncanonical_signature_pad_bits_are_rejected(self):
        parts = self.token.split(".")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        index = alphabet.index(parts[2][-1])
        self.assertEqual(index % 16, 0)
        parts[2] = parts[2][:-1] + alphabet[index + 1]
        self.assert_rejected(".".join(parts))

    def test_unapproved_key_algorithm_and_token_selected_key_are_rejected(self):
        other = Ed25519PrivateKey.generate()
        self.assert_rejected(sign_device_proof(other, self.context, self.now))
        for headers in (
            {"typ": "tbm-device-proof+jwt", "kid": "selected-by-token"},
            {"typ": "tbm-device-proof+jwt", "crit": []},
            {"typ": "tbm-device-proof+jwt", "jwk": {"kty": "OKP"}},
        ):
            self.assert_rejected(
                jwt.encode(self.claims, self.key, algorithm="EdDSA", headers=headers)
            )
        self.assert_rejected(
            jwt.encode(
                self.claims, key=None, algorithm="none", headers={"typ": "tbm-device-proof+jwt"}
            )
        )

    def test_distinct_exact_wire_bodies_cannot_share_a_proof(self):
        base = replace(self.context, body=b'{"a":1,"b":2}')
        token = sign_device_proof(self.key, base, self.now)
        for body in (b'{"b":2,"a":1}', b'{"a":1,"b":2}\n', b'{"a":1.0,"b":2}'):
            self.assert_rejected(token, replace(base, body=body))

    def test_v2_member_binding_distinguishes_product_id_and_both_idp_subjects(self):
        product_id = self.context.member_id
        api_subject = "api-subject-distinct-b"
        desktop_subject = "desktop-pairwise-distinct-c"
        self.assertEqual(len({product_id, api_subject, desktop_subject}), 3)
        self.assertEqual(self.claims["ver"], 2)
        self.assertEqual(self.claims["sub"], product_id)
        self.assertEqual(
            verify_device_proof(self.token, self.public, self.context, self.now).jti,
            self.claims["jti"],
        )
        for subject in (api_subject, desktop_subject):
            with self.subTest(subject=subject):
                wrong = sign_device_proof(
                    self.key, replace(self.context, member_id=subject), self.now
                )
                self.assert_rejected(wrong)

    def test_v1_signed_proofs_have_no_product_id_or_idp_subject_downgrade(self):
        for subject in (self.context.member_id, "api-subject-distinct-b"):
            with self.subTest(subject=subject):
                prior_version = jwt.encode(
                    {**self.claims, "ver": 1, "sub": subject},
                    self.key,
                    algorithm="EdDSA",
                    headers={"typ": "tbm-device-proof+jwt"},
                )
                self.assert_rejected(prior_version)

    def test_member_id_has_bounded_product_identifier_syntax(self):
        for member_id in ("", "a" * 37, "../member", "member value", "mémbér", True):
            with self.subTest(member_id=member_id), self.assertRaises(DeviceProofRejected):
                replace(self.context, member_id=member_id).claims()

    def test_verification_does_not_itself_consume_replay_identifier(self):
        # The contract is deliberately stateless; the API must consume the JTI
        # atomically with the authorized operation. Repeated verification alone
        # must not be represented as a replay-protected acceptance decision.
        jti = str(uuid4())
        token = sign_device_proof(self.key, self.context, self.now, jti=jti)
        first = verify_device_proof(token, self.public, self.context, self.now)
        second = verify_device_proof(token, self.public, self.context, self.now)
        self.assertEqual(first, second)
        self.assertEqual(first.jti, jti)
