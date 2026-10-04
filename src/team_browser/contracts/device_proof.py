"""Versioned Ed25519 JWS request proofs; no API, database or key storage imports.

This is an application-specific proof profile, not an implementation of OAuth
DPoP. A caller supplies the exact wire body and a previously approved origin.
Signing never chooses a destination, sends a request, or grants device access.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import jwt

MAX_PROOF_BYTES = 8192
MAX_BODY_BYTES = 65536
PROOF_TTL_SECONDS = 60
CLOCK_SKEW_SECONDS = 5
PROOF_TYPE = "tbm-device-proof+jwt"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,35}$")
_PATH = re.compile(r"^/v1/[A-Za-z0-9_/-]{1,240}$")


class DeviceProofRejected(ValueError):
    """A malformed, stale, incorrectly scoped or incorrectly signed proof."""


def canonical_origin(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 255 or not value.isascii():
        raise ValueError("An explicit canonical HTTPS API origin is required")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid API origin port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != "https://" + parsed.netloc
        or parsed.netloc != parsed.netloc.lower()
        or port == 443
        or any(c.isspace() for c in value)
        or "\\" in value
        or not re.fullmatch(r"[a-z0-9.-]+(?::[1-9][0-9]{0,4})?", parsed.netloc)
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", parsed.hostname)
    ):
        raise ValueError("An explicit canonical HTTPS API origin is required")
    return value


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise DeviceProofRejected("Invalid base64url")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise DeviceProofRejected("Invalid base64url") from exc
    if _b64(result) != value:
        raise DeviceProofRejected("Noncanonical base64url")
    return result


def encode_public_key(key: Ed25519PublicKey) -> str:
    if not isinstance(key, Ed25519PublicKey):
        raise DeviceProofRejected("Ed25519 public key required")
    return _b64(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def decode_public_key(value: str) -> Ed25519PublicKey:
    if not isinstance(value, str) or len(value) != 43:
        raise DeviceProofRejected("Ed25519 public key required")
    raw = _decode(value)
    if len(raw) != 32:
        raise DeviceProofRejected("Ed25519 public key required")
    return Ed25519PublicKey.from_public_bytes(raw)


def key_fingerprint(value: str) -> str:
    decode_public_key(value)
    return hashlib.sha256(_decode(value)).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeviceProofRejected("Duplicate JSON property")
        result[key] = value
    return result


@dataclass(frozen=True)
class ProofContext:
    origin: str
    organization_id: str
    member_id: str
    device_id: str
    registration_generation: int
    method: str
    path: str
    body: bytes
    purpose: str = "request"
    nonce: str | None = None

    def claims(self) -> dict:
        canonical_origin(self.origin)
        if (
            any(
                not isinstance(v, str) or not _ID.fullmatch(v)
                for v in (self.organization_id, self.device_id)
            )
            or not isinstance(self.member_id, str)
            or not _ID.fullmatch(self.member_id)
            or type(self.registration_generation) is not int
            or not 1 <= self.registration_generation <= 2147483647
            or self.method != "POST"
            or not isinstance(self.path, str)
            or not _PATH.fullmatch(self.path)
            or "//" in self.path
            or not isinstance(self.body, bytes)
            or len(self.body) > MAX_BODY_BYTES
            or self.purpose not in ("request", "enrollment")
            or (self.purpose == "request" and self.nonce is not None)
            or (
                self.purpose == "enrollment"
                and (
                    not isinstance(self.nonce, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.nonce)
                )
            )
        ):
            raise DeviceProofRejected("Invalid proof scope")
        return {
            "ver": 2,
            "purpose": self.purpose,
            "aud": self.origin,
            "org": self.organization_id,
            "sub": self.member_id,
            "device": self.device_id,
            "generation": self.registration_generation,
            "htm": self.method,
            "htu": self.origin + self.path,
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "nonce": self.nonce,
        }


def sign_device_proof(
    key: Ed25519PrivateKey,
    context: ProofContext,
    issued_at: int,
    *,
    jti: str | None = None,
) -> str:
    """Sign a bounded exact request. Private-key lifecycle belongs to the caller."""
    if not isinstance(key, Ed25519PrivateKey) or type(issued_at) is not int:
        raise DeviceProofRejected("Ed25519 key and integer timestamp required")
    token_id = jti or str(uuid4())
    _token_id(token_id)
    return jwt.encode(
        {
            **context.claims(),
            "iat": issued_at,
            "exp": issued_at + PROOF_TTL_SECONDS,
            "jti": token_id,
        },
        key,
        algorithm="EdDSA",
        headers={"typ": PROOF_TYPE},
    )


def _token_id(value):
    if not isinstance(value, str) or len(value) != 36:
        raise DeviceProofRejected("Invalid proof identifier")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise DeviceProofRejected("Invalid proof identifier") from exc
    if str(parsed) != value or parsed.int == 0:
        raise DeviceProofRejected("Invalid proof identifier")


@dataclass(frozen=True)
class VerifiedProof:
    jti: str
    expires_at: int


def verify_device_proof(
    token: str, public_key: str, context: ProofContext, current_time: int
) -> VerifiedProof:
    """Verify Ed25519 signature, strict profile, exact scope and bounded freshness.

    Replay consumption is deliberately external, and must be transactional with
    the operation. No token-supplied key or URL is ever loaded or retrieved.
    """
    try:
        if not isinstance(token, str) or not 1 <= len(token) <= MAX_PROOF_BYTES:
            raise DeviceProofRejected("Invalid proof length")
        if type(current_time) is not int:
            raise DeviceProofRejected("Invalid verifier time")
        parts = token.split(".")
        if len(parts) != 3:
            raise DeviceProofRejected("Invalid compact JWS")
        header, claims = (
            json.loads(_decode(value), object_pairs_hook=_unique_object) for value in parts[:2]
        )
        if header != {"alg": "EdDSA", "typ": PROOF_TYPE} or len(_decode(parts[2])) != 64:
            raise DeviceProofRejected("Unsupported proof header")
        expected = context.claims()
        if not isinstance(claims, dict) or set(claims) != set(expected) | {"iat", "exp", "jti"}:
            raise DeviceProofRejected("Unsupported proof claims")
        if any(
            claims[name] != value or type(claims[name]) is not type(value)
            for name, value in expected.items()
        ):
            raise DeviceProofRejected("Proof scope mismatch")
        if (
            type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not current_time - PROOF_TTL_SECONDS
            <= claims["iat"]
            <= current_time + CLOCK_SKEW_SECONDS
            or not claims["iat"] < claims["exp"] <= claims["iat"] + PROOF_TTL_SECONDS
            or claims["exp"] <= current_time
        ):
            raise DeviceProofRejected("Proof is stale or has invalid lifetime")
        _token_id(claims["jti"])
        jwt.decode(
            token,
            decode_public_key(public_key),
            algorithms=["EdDSA"],
            options={"verify_aud": False, "verify_iat": False, "verify_exp": False},
        )
        return VerifiedProof(claims["jti"], claims["exp"])
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise DeviceProofRejected("Invalid device proof") from exc
