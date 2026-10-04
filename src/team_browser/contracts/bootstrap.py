"""Opt-in encrypted cookie bootstrap format, exercised only with synthetic fixtures.

This module never reads browser stores, retrieves live cookies, transmits data,
creates device grants or imports cookies into a browser. It seals an explicitly
provided payload for one recipient device and verifies its signed, short-lived
scope. Production identity/enrollment, consent UX and native cookie import must
be implemented and reviewed separately. Encryption cannot invalidate copies.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

MAX_COOKIES = 200
MAX_PLAINTEXT_BYTES = 1_048_576
MAX_TTL = timedelta(minutes=10)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class BootstrapRejected(ValueError):
    """Rejected without exposing plaintext or cryptographic details."""


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise BootstrapRejected("Invalid bootstrap identifier")
    return value


def _domain(value: str) -> str:
    if not isinstance(value, str) or value != value.lower() or len(value) > 253:
        raise BootstrapRejected("Cookie domains must be canonical lowercase hostnames")
    if value != "localhost" and not _DOMAIN.fullmatch(value):
        raise BootstrapRejected("Cookie domain is not supported")
    return value


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise BootstrapRejected("Timezone-aware timestamp required")
    return value.astimezone(timezone.utc)


def _json(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def _unb64(value: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise BootstrapRejected("Malformed bootstrap envelope")
    try:
        result = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise BootstrapRejected("Malformed bootstrap envelope") from exc
    if len(result) > maximum:
        raise BootstrapRejected("Bootstrap envelope exceeds limits")
    return result


@dataclass(frozen=True)
class CookieRecord:
    name: str
    value: str = field(repr=False)
    domain: str = "localhost"
    path: str = "/"
    secure: bool = True
    http_only: bool = True
    same_site: str = "Lax"
    host_only: bool = True

    def validate(self, allowed_domains: tuple[str, ...]) -> None:
        _domain(self.domain)
        if self.domain not in allowed_domains:
            raise BootstrapRejected("Cookie domain is outside the approved scope")
        if (
            not isinstance(self.name, str)
            or not 1 <= len(self.name) <= 256
            or re.search(r"[\x00-\x20\x7f;,=]", self.name)
        ):
            raise BootstrapRejected("Invalid cookie name")
        if (
            not isinstance(self.value, str)
            or len(self.value.encode()) > 16_384
            or re.search(r"[\x00\r\n]", self.value)
        ):
            raise BootstrapRejected("Invalid cookie value")
        if (
            not isinstance(self.path, str)
            or not self.path.startswith("/")
            or len(self.path) > 2048
            or re.search(r"[\x00\r\n]", self.path)
        ):
            raise BootstrapRejected("Invalid cookie path")
        if any(type(value) is not bool for value in (self.secure, self.http_only, self.host_only)):
            raise BootstrapRejected("Cookie flags must be booleans")
        if self.same_site not in ("Strict", "Lax", "None") or (
            self.same_site == "None" and not self.secure
        ):
            raise BootstrapRejected("Invalid cookie SameSite policy")
        if self.name.startswith("__Secure-") and not self.secure:
            raise BootstrapRejected("Secure cookie prefix requirements not met")
        if self.name.startswith("__Host-") and (
            not self.secure or not self.host_only or self.path != "/"
        ):
            raise BootstrapRejected("Host cookie prefix requirements not met")

    def payload(self) -> dict:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class BootstrapScope:
    organization_id: str
    profile_id: str
    device_id: str
    recipient_key_id: str
    signer_key_id: str
    command_id: str
    profile_generation: int
    approved_domains: tuple[str, ...]
    approved_by: str
    issued_at: datetime
    expires_at: datetime

    def validate(self, now: datetime) -> None:
        for name in (
            "organization_id",
            "profile_id",
            "device_id",
            "recipient_key_id",
            "signer_key_id",
            "command_id",
            "approved_by",
        ):
            _id(getattr(self, name))
        if type(self.profile_generation) is not int or self.profile_generation < 1:
            raise BootstrapRejected("Invalid profile generation")
        if (
            not self.approved_domains
            or len(self.approved_domains) > 20
            or len(set(self.approved_domains)) != len(self.approved_domains)
        ):
            raise BootstrapRejected("One bounded, explicit domain allowlist is required")
        for domain in self.approved_domains:
            _domain(domain)
        now, issued, expires = _aware(now), _aware(self.issued_at), _aware(self.expires_at)
        if issued > now or expires <= now or not timedelta(0) < expires - issued <= MAX_TTL:
            raise BootstrapRejected("Bootstrap expired, future-dated or outside allowed lifetime")

    def metadata(self) -> dict:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["approved_domains"] = list(self.approved_domains)
        result["issued_at"] = _aware(self.issued_at).isoformat()
        result["expires_at"] = _aware(self.expires_at).isoformat()
        return result


class ReplayGuard(Protocol):
    def consume(
        self, organization_id: str, device_id: str, command_id: str, expires_at: datetime
    ) -> bool:
        """Atomically return true once, durably across agent restart; false for replay."""
        ...


def _derive(shared_secret: bytes, metadata: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"team-browser-bootstrap-v1\0" + metadata,
    ).derive(shared_secret)


def seal(
    scope: BootstrapScope,
    cookies: tuple[CookieRecord, ...],
    *,
    recipient_key: X25519PublicKey,
    signer_key: Ed25519PrivateKey,
    now: datetime,
) -> dict:
    """Create encrypted bytes from a supplied, explicitly consent-scoped payload."""
    scope.validate(now)
    if not 1 <= len(cookies) <= MAX_COOKIES:
        raise BootstrapRejected("Cookie count exceeds the approved bootstrap format")
    identities = set()
    for cookie in cookies:
        cookie.validate(scope.approved_domains)
        identity = (cookie.name, cookie.domain, cookie.path)
        if identity in identities:
            raise BootstrapRejected("Duplicate cookie identity")
        identities.add(identity)
    plaintext = _json({"cookies": [cookie.payload() for cookie in cookies]})
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise BootstrapRejected("Cookie payload exceeds limits")
    metadata = {
        "version": 1,
        "algorithm": "X25519-HKDF-SHA256-AES256GCM-Ed25519",
        **scope.metadata(),
    }
    aad = _json(metadata)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_bytes = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(_derive(ephemeral.exchange(recipient_key), aad)).encrypt(
        nonce, plaintext, aad
    )
    signed = _json(
        {
            "metadata": metadata,
            "ephemeral_public_key": _b64(ephemeral_bytes),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
    )
    return {**json.loads(signed), "signature": _b64(signer_key.sign(signed))}


def open_bundle(
    envelope: dict,
    *,
    expected_scope: BootstrapScope,
    recipient_key: X25519PrivateKey,
    trusted_signer: Ed25519PublicKey,
    replay_guard: ReplayGuard,
    now: datetime,
) -> tuple[CookieRecord, ...]:
    """Verify/decrypt into transient memory; does not import or persist cookies.

    Expected scope and trusted signer come from locally approved enrollment/command
    policy, never copied unquestioningly from envelope metadata. Consume replay
    guard only after complete verification. Browser import must be an atomic staged
    operation; a failed import needs a newly authorized command rather than reuse.
    """
    expected_scope.validate(now)
    if not isinstance(envelope, dict) or set(envelope) != {
        "metadata",
        "ephemeral_public_key",
        "nonce",
        "ciphertext",
        "signature",
    }:
        raise BootstrapRejected("Malformed bootstrap envelope")
    expected_metadata = {
        "version": 1,
        "algorithm": "X25519-HKDF-SHA256-AES256GCM-Ed25519",
        **expected_scope.metadata(),
    }
    try:
        if _json(envelope["metadata"]) != _json(expected_metadata):
            raise BootstrapRejected("Bootstrap scope does not match the authorized command")
        signed = _json({key: value for key, value in envelope.items() if key != "signature"})
    except (ValueError, TypeError, RecursionError) as exc:
        raise BootstrapRejected("Malformed bootstrap envelope") from exc
    if len(signed) > MAX_PLAINTEXT_BYTES * 2:
        raise BootstrapRejected("Bootstrap envelope exceeds limits")
    try:
        signature = _unb64(envelope["signature"], 64)
        trusted_signer.verify(signature, signed)
        public = X25519PublicKey.from_public_bytes(_unb64(envelope["ephemeral_public_key"], 32))
        nonce = _unb64(envelope["nonce"], 12)
        if len(nonce) != 12:
            raise BootstrapRejected("Malformed bootstrap envelope")
        aad = _json(expected_metadata)
        plaintext = AESGCM(_derive(recipient_key.exchange(public), aad)).decrypt(
            nonce, _unb64(envelope["ciphertext"], MAX_PLAINTEXT_BYTES + 16), aad
        )
        payload = json.loads(plaintext)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"cookies"}
            or not isinstance(payload["cookies"], list)
        ):
            raise BootstrapRejected("Malformed cookie payload")
        if not 1 <= len(payload["cookies"]) <= MAX_COOKIES:
            raise BootstrapRejected("Cookie count exceeds limits")
        cookies = tuple(CookieRecord(**item) for item in payload["cookies"])
        identities = set()
        for cookie in cookies:
            cookie.validate(expected_scope.approved_domains)
            identity = (cookie.name, cookie.domain, cookie.path)
            if identity in identities:
                raise BootstrapRejected("Duplicate cookie identity")
            identities.add(identity)
    except (InvalidSignature, InvalidTag, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise BootstrapRejected("Bootstrap authentication or payload validation failed") from exc
    try:
        consumed = replay_guard.consume(
            expected_scope.organization_id,
            expected_scope.device_id,
            expected_scope.command_id,
            expected_scope.expires_at,
        )
    except Exception as exc:
        raise BootstrapRejected("Bootstrap replay ledger is unavailable") from exc
    if consumed is not True:
        raise BootstrapRejected("Bootstrap command was already consumed or not confirmed")
    return cookies
