"""Explicit native Ed25519 identity lifecycle; import is inert.

Only the signed app's fixed, non-synchronizing Keychain namespace holds key bytes.
No network, automatic generation/recovery, arbitrary signer, or browser bridge.
Fresh authorization evidence is a trusted native transport boundary, not a grant.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from team_browser.contracts.device_proof import (
    ProofContext,
    canonical_origin,
    encode_public_key,
    key_fingerprint,
    sign_device_proof,
)
from team_browser.local.macos_keychain import (
    KeychainConfiguration,
    MacOSKeychainStore,
    SecretNotFound,
)
from team_browser.local.secrets import SecretRef

from .managed_session import ManagedMembership, MemberRole
from .session_vault import _ProcessLease, _private
import pwd

NAMESPACE = "managed-device-keys"
_JOURNAL = SecretRef("managed-device-journal-v1")
_PAYLOAD = SecretRef("managed-device-payload-v1")
_DIRTY = "quarantined"
_MAX_RECORD = 4096
_EVIDENCE_TTL = 30
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,35}\Z", re.ASCII)
_HEX = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)


class DeviceKeyError(RuntimeError):
    """Only fixed diagnostics; never include key, proof, nonce or native text."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Native device identity: {reason}")


def _id(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise DeviceKeyError("invalid_binding")
    return value


def _uuid(value):
    if type(value) is not str or len(value) != 36:
        raise DeviceKeyError("invalid_binding")
    try:
        parsed = UUID(value)
        if str(parsed) != value or parsed.int == 0:
            raise ValueError
    except ValueError:
        raise DeviceKeyError("invalid_binding") from None
    return value


def _generation(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        raise DeviceKeyError("invalid_binding")
    return value


def _hex(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise DeviceKeyError("invalid_record")
    return value


def _clocks():
    values = time.time(), time.monotonic()
    if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        raise DeviceKeyError("invalid_clock")
    return values


@dataclass(frozen=True)
class TrustedDeviceScope:
    """Native installed settings + product IDs from authenticated /v1/me.

    Product member IDs never come from email or the desktop ID-token subject.
    One installed namespace owns one identity; changing this scope cannot migrate it.
    """

    origin: str
    organization_id: str
    member_id: str

    def __post_init__(self):
        if type(self.origin) is not str:
            raise DeviceKeyError("invalid_scope")
        canonical_origin(self.origin)
        _id(self.organization_id)
        _id(self.member_id)


@dataclass(frozen=True)
class ServerDeviceBinding:
    """Sanitized response from the approved backend's authenticated native API.

    Constructing this value does NOT authenticate a response. Native integration
    must check its origin, current bearer membership and complete response schema.
    """

    device_id: str
    request_id: str
    registration_generation: int
    key_fingerprint: str
    status: str
    enabled: bool

    def __post_init__(self):
        _id(self.device_id)
        _uuid(self.request_id)
        _generation(self.registration_generation)
        _hex(self.key_fingerprint)
        if self.status not in ("pending", "approved", "active") or type(self.status) is not str:
            raise DeviceKeyError("invalid_binding")
        if type(self.enabled) is not bool or self.enabled != (self.status == "active"):
            raise DeviceKeyError("invalid_binding")


@dataclass(frozen=True, repr=False)
class NativeDeviceAuthorization:
    """Native-only evidence, never decoded from UI JSON or persisted.

    Capture clocks BEFORE current authenticated membership/binding reads, then
    supply their exact results. Valid for at most 30 seconds, including read time.
    This module does not claim to authenticate caller-created evidence. The native
    transport and every server operation must still verify current authorization.
    """

    scope: TrustedDeviceScope
    membership: ManagedMembership
    binding: ServerDeviceBinding | None
    observed_at: float
    observed_monotonic: float
    expires_at: float

    def __post_init__(self):
        if (
            type(self.scope) is not TrustedDeviceScope
            or type(self.membership) is not ManagedMembership
        ):
            raise DeviceKeyError("invalid_authorization")
        replace(self.scope)
        member = self.membership
        if (
            member.tenant_id != self.scope.organization_id
            or member.member_id != self.scope.member_id
            or type(member.role) is not MemberRole
            or member.role not in (MemberRole.OWNER, MemberRole.ADMIN, MemberRole.MEMBER)
            or (self.binding is not None and type(self.binding) is not ServerDeviceBinding)
        ):
            raise DeviceKeyError("invalid_authorization")
        if self.binding is not None:
            replace(self.binding)
        values = self.observed_at, self.observed_monotonic, self.expires_at
        if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
            raise DeviceKeyError("invalid_authorization")
        if not 0 < self.expires_at - self.observed_at <= _EVIDENCE_TTL:
            raise DeviceKeyError("invalid_authorization")


@dataclass(frozen=True, repr=False)
class DeviceKeyHandle:
    """Opaque native instance handle; no key bytes and no serialization API."""

    _owner: object
    _epoch: str


@dataclass(frozen=True)
class DeviceKeyStatus:
    state: str
    public_key: str | None = None
    key_fingerprint: str | None = None

    def public(self):
        return {
            "state": self.state,
            "public_key": self.public_key,
            "key_fingerprint": self.key_fingerprint,
            "server_authoritative": True,
            "native_integration_verified": False,
        }


class AgentOperation(StrEnum):
    HEARTBEAT = "heartbeat"
    POLL = "poll"
    ACK = "ack"


@dataclass(frozen=True, repr=False)
class NativeSignedRequest:
    """Exact wire bytes for a trusted native caller only. Never expose to JS/logs.

    This is short-lived possession evidence, not a bearer or an authorization
    result. Caller must send these same bytes with its current managed bearer.
    """

    path: str
    body: bytes = field(repr=False)
    proof: str = field(repr=False)
    expires_at: int
    method: str = "POST"


def _open_native_store(configuration):
    return MacOSKeychainStore(configuration)  # signed-host gate; no fallback


def _lease_directory(configuration):
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)  # Ignore HOME/env/UI paths.
    digest = hashlib.sha256(
        (configuration.access_group + "\0" + configuration.service).encode("ascii")
    ).hexdigest()
    return home / "Library" / "Application Support" / "TeamBrowserDeviceKeys" / digest


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeviceKeyError("invalid_record")
        result[key] = value
    return result


def _constant(_):
    raise DeviceKeyError("invalid_record")


def _object(value, maximum=_MAX_RECORD):
    if type(value) is not bytes or not 1 <= len(value) <= maximum:
        raise DeviceKeyError("invalid_record")
    try:
        result = json.loads(
            value.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        if type(result) is not dict:
            raise ValueError
        stack, count = [(result, 0)], 0
        while stack:
            item, depth = stack.pop()
            count += 1
            if depth > 16 or count > 4096:
                raise ValueError
            if type(item) is dict:
                stack.extend((v, depth + 1) for v in item.values())
                stack.extend((k, depth + 1) for k in item)
            elif type(item) is list:
                stack.extend((v, depth + 1) for v in item)
            elif type(item) is str:
                item.encode("utf-8")
            elif type(item) is float and not math.isfinite(item):
                raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise DeviceKeyError("invalid_record") from None


class MacOSDeviceKeys:
    """One persistent identity for an exact native origin/company/member scope.

    Constructor verifies the signed host and takes a kernel lease. restore() only
    reads consistent authenticated OS records; it never restores server authority.
    All methods are synchronous, for native workers only. Rotation is unsupported.
    """

    def __init__(self, configuration: KeychainConfiguration, scope: TrustedDeviceScope):
        if type(configuration) is not KeychainConfiguration or configuration.namespace != NAMESPACE:
            raise TypeError("Exact trusted device-key Keychain configuration required")
        if type(scope) is not TrustedDeviceScope:
            raise TypeError("Exact trusted native device scope required")
        self._scope = replace(scope)
        self._lock = threading.RLock()
        self._owner = object()
        self._closed = False
        self._ready = False
        self._record = None
        self._expected = None
        self._clock = None
        self._store = _open_native_store(replace(configuration))
        self._lease = _ProcessLease(_lease_directory(configuration))

    def _owned(self):
        if self._closed:
            raise DeviceKeyError("closed")
        self._lease.assert_owned()

    def _now(self):
        now = _clocks()
        if self._clock and any(n < p for n, p in zip(now, self._clock, strict=True)):
            raise DeviceKeyError("clock_rollback")
        self._clock = now
        return now

    def _dirty_exists(self):
        self._owned()
        try:
            fd = os.open(
                _DIRTY,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=self._lease._directory_fd,
            )
        except FileNotFoundError:
            return False
        try:
            _private(os.fstat(fd), directory=False)
        finally:
            os.close(fd)
        return True

    def _quarantine(self):
        self._ready = False
        self._owned()
        flags = os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(_DIRTY, flags, 0o600, dir_fd=self._lease._directory_fd)
        except FileExistsError:
            if not self._dirty_exists():
                raise DeviceKeyError("quarantine_unconfirmed")
        else:
            try:
                _private(os.fstat(fd), directory=False)
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(self._lease._directory_fd)
        if not self._dirty_exists():
            raise DeviceKeyError("quarantine_unconfirmed")

    def _clean(self):
        # Every Keychain mutation and readback has already acknowledged success.
        # This file has no secret bytes; its absence can never bless uncertain OS I/O.
        self._owned()
        if not self._dirty_exists():
            raise DeviceKeyError("quarantine_changed")
        os.unlink(_DIRTY, dir_fd=self._lease._directory_fd)
        os.fsync(self._lease._directory_fd)
        if self._dirty_exists():
            raise DeviceKeyError("quarantine_changed")
        self._owned()
        self._ready = True

    def _fail(self):
        self._ready = False
        self._record = self._expected = None
        try:
            self._quarantine()
        except BaseException:
            pass  # No mutating operation proceeds unless quarantine was durable first.

    def _optional(self, reference):
        try:
            value = self._store.get(reference)
        except SecretNotFound:
            return None
        if type(value) is not bytes or not 1 <= len(value) <= _MAX_RECORD:
            raise DeviceKeyError("invalid_record")
        return value

    def _put(self, reference, value):
        self._owned()
        if self._store.put(reference, value) is not None:
            raise DeviceKeyError("invalid_acknowledgement")
        if self._optional(reference) != value:
            raise DeviceKeyError("write_unconfirmed")
        self._owned()

    def _scope_record(self):
        return {name: getattr(self._scope, name) for name in self._scope.__dataclass_fields__}

    def _lease_identity(self):
        self._owned()
        directory = os.fstat(self._lease._directory_fd)
        lock = os.fstat(self._lease._fd)
        return hashlib.sha256(
            _json(
                {
                    "directory": [directory.st_dev, directory.st_ino],
                    "lock": [lock.st_dev, lock.st_ino],
                }
            )
        ).hexdigest()

    def _validate_record(self, record):
        fields = {"version", "scope", "epoch", "state", "private_key", "public_key", "binding"}
        if set(record) != fields or type(record["version"]) is not int or record["version"] != 1:
            raise DeviceKeyError("invalid_record")
        if record["scope"] != self._scope_record():
            raise DeviceKeyError("scope_mismatch")
        _hex(record["epoch"])
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_hex(record["private_key"])))
        public = encode_public_key(key.public_key())
        if record["public_key"] != public or record["state"] not in ("pending", "active"):
            raise DeviceKeyError("invalid_record")
        binding = record["binding"]
        if binding is not None:
            if type(binding) is not dict or set(binding) != {
                "device_id",
                "request_id",
                "registration_generation",
                "key_fingerprint",
            }:
                raise DeviceKeyError("invalid_record")
            _id(binding["device_id"])
            _uuid(binding["request_id"])
            _generation(binding["registration_generation"])
            if binding["key_fingerprint"] != key_fingerprint(public):
                raise DeviceKeyError("invalid_record")
        elif record["state"] != "pending":
            raise DeviceKeyError("invalid_record")
        return record

    def _read_consistent(self):
        marker = self._optional(_JOURNAL)
        payload = self._optional(_PAYLOAD)
        if marker is None:
            if payload is not None:
                raise DeviceKeyError("orphan_record")
            return None, None
        journal = _object(marker)
        if (
            set(journal) != {"version", "state", "scope", "epoch", "digest", "lease"}
            or type(journal["version"]) is not int
            or journal["version"] != 1
            or journal["state"] != "ready"
            or journal["scope"] != self._scope_record()
            or journal["lease"] != self._lease_identity()
        ):
            raise DeviceKeyError("invalid_record")
        _hex(journal["epoch"])
        if payload is None:
            if journal["digest"] is not None:
                raise DeviceKeyError("missing_record")
            return marker, None
        if journal["digest"] != hashlib.sha256(payload).hexdigest():
            raise DeviceKeyError("record_changed")
        record = self._validate_record(_object(payload))
        if record["epoch"] != journal["epoch"]:
            raise DeviceKeyError("record_changed")
        return marker, record

    def _current(self, handle=None):
        self._owned()
        if not self._ready or self._dirty_exists():
            raise DeviceKeyError("recovery_required")
        self._now()
        marker, record = self._read_consistent()
        if marker != self._expected or record != self._record:
            raise DeviceKeyError("record_changed")
        self._owned()
        self._now()
        if handle is not None and (
            type(handle) is not DeviceKeyHandle
            or handle._owner is not self._owner
            or not record
            or handle._epoch != record["epoch"]
        ):
            raise DeviceKeyError("stale_handle")
        return record

    def _handle(self):
        return DeviceKeyHandle(self._owner, self._record["epoch"]) if self._record else None

    def _commit(self, record):
        self._quarantine()  # fsync BEFORE the first mutating OS call
        epoch = record["epoch"] if record else secrets.token_hex(32)
        journal = {
            "version": 1,
            "state": "quarantined",
            "scope": self._scope_record(),
            "epoch": epoch,
            "digest": None,
            "lease": self._lease_identity(),
        }
        self._put(_JOURNAL, _json(journal))
        if record is None:
            self._owned()
            if self._store.delete(_PAYLOAD) is not None:
                raise DeviceKeyError("invalid_acknowledgement")
            if self._optional(_PAYLOAD) is not None:
                raise DeviceKeyError("absence_unconfirmed")
        else:
            payload = _json(self._validate_record(record))
            if len(payload) > _MAX_RECORD:
                raise DeviceKeyError("invalid_record")
            self._put(_PAYLOAD, payload)
            journal["digest"] = hashlib.sha256(payload).hexdigest()
        journal["state"] = "ready"
        marker = _json(journal)
        self._put(_JOURNAL, marker)
        if self._read_consistent() != (marker, record):
            raise DeviceKeyError("commit_unconfirmed")
        self._expected, self._record = marker, record
        self._clean()

    def restore(self) -> DeviceKeyHandle | None:
        """Read consistent state, never activate keys, generate or recover implicitly."""
        with self._lock:
            try:
                self._owned()
                if self._ready:
                    self._current()
                else:
                    if self._dirty_exists():
                        raise DeviceKeyError("recovery_required")
                    self._expected, self._record = self._read_consistent()
                    self._owned()
                    self._now()
                    self._ready = True
                return self._handle()
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    def status(self) -> DeviceKeyStatus:
        with self._lock:
            if self._closed:
                return DeviceKeyStatus("closed")
            if not self._ready:
                return DeviceKeyStatus("recovery_required")
            try:
                record = self._current()
                if record is None:
                    return DeviceKeyStatus("empty")
                return DeviceKeyStatus(
                    record["state"], record["public_key"], key_fingerprint(record["public_key"])
                )
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                return DeviceKeyStatus("recovery_required")

    def _authorize(self, authority, *, binding_required):
        if type(authority) is not NativeDeviceAuthorization:
            raise DeviceKeyError("authorization_required")
        replace(authority)  # strict native types, role and bounded lifetimes
        now, mono = self._now()
        if (
            authority.scope != self._scope
            or not authority.observed_at <= now < authority.expires_at
            or not authority.observed_monotonic
            <= mono
            < authority.observed_monotonic + authority.expires_at - authority.observed_at
            or (binding_required and authority.binding is None)
        ):
            raise DeviceKeyError("authorization_stale_or_mismatched")
        return authority.binding

    def generate_pending(self, authority: NativeDeviceAuthorization) -> DeviceKeyHandle:
        """Explicit later user-approved first enrollment. Refuses any existing key."""
        with self._lock:
            try:
                self._current()
                self._authorize(authority, binding_required=False)
                if self._record is not None or authority.binding is not None:
                    raise DeviceKeyError("rotation_not_supported")
                key = Ed25519PrivateKey.generate()
                record = {
                    "version": 1,
                    "scope": self._scope_record(),
                    "epoch": secrets.token_hex(32),
                    "state": "pending",
                    "binding": None,
                    "private_key": key.private_bytes(
                        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                    ).hex(),
                    "public_key": encode_public_key(key.public_key()),
                }
                self._commit(record)
                self._authorize(authority, binding_required=False)
                return self._handle()
            except BaseException as error:
                if isinstance(error, DeviceKeyError) and error.reason == "rotation_not_supported":
                    raise
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    @staticmethod
    def _binding_record(binding):
        return {
            name: getattr(binding, name)
            for name in ("device_id", "request_id", "registration_generation", "key_fingerprint")
        }

    def _matching_binding(self, record, authority, statuses):
        binding = self._authorize(authority, binding_required=True)
        if binding.status not in statuses or binding.key_fingerprint != key_fingerprint(
            record["public_key"]
        ):
            raise DeviceKeyError("binding_mismatch")
        if record["binding"] is not None and record["binding"] != self._binding_record(binding):
            raise DeviceKeyError("binding_mismatch")
        return binding

    def validate_binding(
        self, handle: DeviceKeyHandle, authority: NativeDeviceAuthorization
    ) -> None:
        """Validate fresh native server evidence against the exact durable binding.

        Read-only; never infer binding from a public fingerprint alone. No key or
        stored record is returned, and a pending record is not promoted to active.
        """
        with self._lock:
            try:
                record = self._current(handle)
                if record is None or record["binding"] is None:
                    raise DeviceKeyError("binding_mismatch")
                binding = self._matching_binding(
                    record, authority, ("pending", "approved", "active")
                )
                if record["state"] == "active" and binding.status != "active":
                    raise DeviceKeyError("binding_mismatch")
                self._current(handle)
                self._authorize(authority, binding_required=True)
            except BaseException as error:
                if isinstance(error, DeviceKeyError) and error.reason in {
                    "authorization_required",
                    "invalid_authorization",
                    "authorization_stale_or_mismatched",
                    "binding_mismatch",
                    "stale_handle",
                }:
                    raise DeviceKeyError(error.reason) from None
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    def bind_pending(self, handle: DeviceKeyHandle, authority: NativeDeviceAuthorization) -> None:
        """Persist an acknowledged first request for this public key; no rotation."""
        self._transition(handle, authority, active=False)

    def mark_active(self, handle: DeviceKeyHandle, authority: NativeDeviceAuthorization) -> None:
        """Persist current server-confirmed completion; this does not enable a device."""
        self._transition(handle, authority, active=True)

    def _transition(self, handle, authority, *, active):
        with self._lock:
            try:
                record = self._current(handle)
                if record["state"] != "pending" or (active and record["binding"] is None):
                    raise DeviceKeyError("invalid_transition")
                binding = self._matching_binding(
                    record, authority, ("active",) if active else ("pending", "approved")
                )
                updated = {
                    **record,
                    "binding": self._binding_record(binding),
                    "state": "active" if active else "pending",
                }
                self._commit(updated)
                self._authorize(authority, binding_required=True)
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    def _sign(self, handle, authority, body, *, operation=None, command_id=None):
        with self._lock:
            try:
                record = self._current(handle)
                enrollment = operation is None
                if (
                    record["state"] != ("pending" if enrollment else "active")
                    or not record["binding"]
                ):
                    raise DeviceKeyError("wrong_key_purpose")
                binding = self._matching_binding(
                    record, authority, ("approved",) if enrollment else ("active",)
                )
                try:
                    row = _object(body, maximum=65536)
                except DeviceKeyError:
                    raise DeviceKeyError("invalid_request") from None
                if (
                    type(row.get("registration_generation")) is not int
                    or row.get("registration_generation") != binding.registration_generation
                ):
                    raise DeviceKeyError("request_generation_mismatch")
                nonce = None
                if enrollment:
                    if set(row) != {
                        "request_id",
                        "registration_generation",
                        "challenge_id",
                        "nonce",
                    }:
                        raise DeviceKeyError("invalid_request")
                    if row["request_id"] != binding.request_id:
                        raise DeviceKeyError("invalid_request")
                    _uuid(row["challenge_id"])
                    nonce = row["nonce"]
                    if type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
                        raise DeviceKeyError("invalid_request")
                    path = f"/v1/device-enrollments/{binding.device_id}/complete"
                else:
                    _agent_body(operation, row, command_id)
                    path = f"/v1/agent/devices/{binding.device_id}/"
                    path += (
                        f"commands/{command_id}/ack"
                        if operation is AgentOperation.ACK
                        else operation.value
                    )
                context = ProofContext(
                    self._scope.origin,
                    self._scope.organization_id,
                    self._scope.member_id,
                    binding.device_id,
                    binding.registration_generation,
                    "POST",
                    path,
                    body,
                    "enrollment" if enrollment else "request",
                    nonce,
                )
                issued_at = int(self._now()[0])
                key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(record["private_key"]))
                proof = sign_device_proof(key, context, issued_at)
                self._current(handle)  # recheck slow reads, changed lease, and concurrent state
                self._matching_binding(
                    record, authority, ("approved",) if enrollment else ("active",)
                )
                if self._now()[0] >= issued_at + 60:
                    raise DeviceKeyError("proof_expired")
                return NativeSignedRequest(path, body, proof, issued_at + 60)
            except BaseException as error:
                # Input/authorization rejection never destroys or rotates a key.
                if isinstance(error, DeviceKeyError) and error.reason in {
                    "authorization_required",
                    "invalid_authorization",
                    "authorization_stale_or_mismatched",
                    "binding_mismatch",
                    "stale_handle",
                    "wrong_key_purpose",
                    "request_generation_mismatch",
                    "invalid_request",
                    "invalid_binding",
                    "proof_expired",
                }:
                    raise DeviceKeyError(error.reason) from None
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    def sign_enrollment_completion(self, handle, authority, body: bytes) -> NativeSignedRequest:
        """Only exact completion JSON of this approved pending request."""
        return self._sign(handle, authority, body)

    def sign_agent_request(
        self,
        handle,
        authority,
        operation: AgentOperation,
        body: bytes,
        *,
        command_id: str | None = None,
    ) -> NativeSignedRequest:
        """Only heartbeat/poll/ack; caller cannot select origin/method/device/path."""
        if type(operation) is not AgentOperation:
            raise DeviceKeyError("invalid_request")
        return self._sign(handle, authority, body, operation=operation, command_id=command_id)

    def forget_local(self) -> None:
        """Explicit destructive local recovery, never server/browser revocation.

        Confirm exact payload absence, preserve a ready empty journal, invalidate
        all handles. Native UI must explain scope and obtain required approval.
        """
        with self._lock:
            try:
                self._owned()
                # Recovery is explicitly destructive but cannot use a different
                # product scope to erase an identifiable existing installation.
                marker = self._optional(_JOURNAL)
                if marker is not None:
                    try:
                        journal = _object(marker)
                    except DeviceKeyError:
                        journal = None  # Explicit recovery may discard corrupt records.
                    if journal and "scope" in journal and journal["scope"] != self._scope_record():
                        raise DeviceKeyError("scope_mismatch")
                self._owner = object()  # retire handles even if deletion is uncertain
                self._ready = False
                self._commit(None)
                self._clock = None
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise DeviceKeyError("recovery_required") from None

    def close(self) -> None:
        """Release ownership without deleting or quarantining a consistent key."""
        with self._lock:
            self._closed = True
            self._ready = False
            self._record = self._expected = None
            self._owner = object()
            self._lease.close()


def _agent_body(operation, row, command_id):
    fields = set(row) - {"registration_generation"}
    if operation is AgentOperation.POLL:
        if fields - {"max_commands"} or (
            "max_commands" in row
            and (type(row["max_commands"]) is not int or not 1 <= row["max_commands"] <= 20)
        ):
            raise DeviceKeyError("invalid_request")
    elif operation is AgentOperation.HEARTBEAT:
        if fields - {"agent_version", "profiles"} or type(row.get("agent_version")) is not str:
            raise DeviceKeyError("invalid_request")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", row["agent_version"]):
            raise DeviceKeyError("invalid_request")
        profiles = row.get("profiles", [])
        if type(profiles) is not list or len(profiles) > 200:
            raise DeviceKeyError("invalid_request")
        for report in profiles:
            if type(report) is not dict or set(report) != {"profile_id", "generation", "state"}:
                raise DeviceKeyError("invalid_request")
            _id(report["profile_id"])
            if (
                type(report["generation"]) is not int
                or not 1 <= report["generation"] < 2**63
                or report["state"] not in ("ready", "absent", "error")
            ):
                raise DeviceKeyError("invalid_request")
    elif operation is AgentOperation.ACK:
        _uuid(command_id)
        if (
            fields != {"lease_version", "outcome", "result_code"}
            or type(row["lease_version"]) is not int
            or not 1 <= row["lease_version"] < 2**63
            or row["outcome"] not in ("succeeded", "failed")
            or row["result_code"]
            not in (
                "local_metadata_ready",
                "local_data_removed",
                "execution_unavailable",
                "io_error",
                "generation_mismatch",
            )
        ):
            raise DeviceKeyError("invalid_request")
    else:
        raise DeviceKeyError("invalid_request")
    if operation is not AgentOperation.ACK and command_id is not None:
        raise DeviceKeyError("invalid_request")
