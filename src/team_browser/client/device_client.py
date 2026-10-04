"""Foreground native enrollment, using only the exact managed-session transport.

No native I/O on import/construction, public token/proof bridge, automatic retry,
server approval, rotation, command execution, browser activation or remote wipe.
Native consent values are trusted UI decisions, never deserialized web input.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from uuid import UUID

from .auth_flow import HTTPResponse
from .device_keys import (
    AgentOperation,
    MacOSDeviceKeys,
    NativeDeviceAuthorization,
    NativeSignedRequest,
    ServerDeviceBinding,
    TrustedDeviceScope,
)
from .managed_session import (
    ManagedMembership,
    ManagedSessionError,
    ManagedStatus,
    MemberRole,
    NativeManagedSession,
)
from ..contracts.device_proof import decode_public_key, key_fingerprint


class DeviceClientError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Native device client: {reason}")


class EnrollmentAction(StrEnum):
    REQUEST = "request_enrollment"
    ACTIVATE = "activate_enrollment"


def _clocks():
    values = time.time(), time.monotonic()
    if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in values):
        raise DeviceClientError("invalid_clock")
    return values


def _integer(value, low=1, high=2147483647):
    if type(value) is not int or not low <= value <= high:
        raise ManagedSessionError("invalid_response")
    return value


def _id(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,35}", value):
        raise ManagedSessionError("invalid_response")
    return value


def _uuid(value):
    if type(value) is not str:
        raise ManagedSessionError("invalid_response")
    try:
        parsed = UUID(value)
        if str(parsed) != value or parsed.int == 0:
            raise ValueError
    except ValueError:
        raise ManagedSessionError("invalid_response") from None
    return value


def _text(value, maximum=120):
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(unicodedata.category(c).startswith("C") for c in value)
    ):
        raise ManagedSessionError("invalid_response")
    return value


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ManagedSessionError("invalid_response")
    return value


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ManagedSessionError("invalid_response")
        result[name] = value
    return result


def _constant(_):
    raise ManagedSessionError("invalid_response")


def _decode(body):
    if type(body) is not bytes or not 1 <= len(body) <= 65536:
        raise ManagedSessionError("invalid_response")
    try:
        result = json.loads(
            body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        stack, count = [(result, 0)], 0
        while stack:
            value, depth = stack.pop()
            count += 1
            if count > 16384 or depth > 16:
                raise ValueError
            if type(value) is dict:
                stack.extend((v, depth + 1) for v in value.values())
                stack.extend((k, depth + 1) for k in value)
            elif type(value) is list:
                stack.extend((v, depth + 1) for v in value)
            elif type(value) is str:
                value.encode("utf-8")
            elif type(value) is float and not math.isfinite(value):
                raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise ManagedSessionError("invalid_response") from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _same_binding(left, right):
    return all(
        getattr(left, name) == getattr(right, name)
        for name in ("device_id", "request_id", "registration_generation", "key_fingerprint")
    )


@dataclass(frozen=True, repr=False)
class NativeEnrollmentApproval:
    """Exact decision from reviewed signed native UI, never a web JSON flag.

    The native approval surface shows destination/company/member, device label,
    persistent key storage and server activation consequences. Activation also
    displays the exact device/request/generation/fingerprint. This value does not
    authenticate its creator. Construction is not itself user consent.
    """

    action: EnrollmentAction
    scope: TrustedDeviceScope
    device_name: str
    approved: bool
    decision_id: str
    observed_at: float
    observed_monotonic: float
    expires_at: float
    binding: ServerDeviceBinding | None = None

    def __post_init__(self):
        if type(self.action) is not EnrollmentAction or type(self.scope) is not TrustedDeviceScope:
            raise DeviceClientError("native_approval_required")
        replace(self.scope)
        _text(self.device_name)
        _uuid(self.decision_id)
        if type(self.approved) is not bool:
            raise DeviceClientError("native_approval_required")
        if self.action is EnrollmentAction.REQUEST:
            if self.binding is not None:
                raise DeviceClientError("native_approval_required")
        elif type(self.binding) is not ServerDeviceBinding:
            raise DeviceClientError("native_approval_required")
        else:
            replace(self.binding)
        times = self.observed_at, self.observed_monotonic, self.expires_at
        if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in times):
            raise DeviceClientError("native_approval_required")
        if not 0 < self.expires_at - self.observed_at <= 300:
            raise DeviceClientError("native_approval_required")


@dataclass(frozen=True)
class EnrollmentRecord:
    device_id: str
    user_id: str
    request_id: str
    registration_generation: int
    name: str
    platform: str
    key_fingerprint: str
    status: str
    requested_at: int
    request_expires_at: int
    approved_by: str | None
    approval_expires_at: int | None
    enabled: bool

    def binding(self) -> ServerDeviceBinding:
        return ServerDeviceBinding(
            self.device_id,
            self.request_id,
            self.registration_generation,
            self.key_fingerprint,
            self.status,
            self.enabled,
        )


@dataclass(frozen=True, repr=False)
class _Challenge:
    challenge_id: str
    nonce: str = field(repr=False)
    expires_at: int
    request_id: str
    registration_generation: int


@dataclass(frozen=True)
class DeviceHeartbeat:
    id: str
    user_id: str
    name: str
    platform: str
    enabled: bool
    registration_generation: int
    agent_version: str
    last_seen_at: str
    connectivity: str
    synthetic_fixture: bool
    secure_enrollment_available: bool


@dataclass(frozen=True)
class DeviceClientSnapshot:
    state: str
    record: EnrollmentRecord | None = None
    heartbeat: DeviceHeartbeat | None = None
    observed_at: float | None = None
    observed_monotonic: float | None = None
    expires_at: float | None = None

    def public(self):
        try:
            wall, mono = _clocks()
            fresh = (
                self.observed_at is not None
                and self.observed_monotonic is not None
                and self.expires_at is not None
                and self.observed_at <= wall < self.expires_at
                and self.observed_monotonic
                <= mono
                < self.observed_monotonic + self.expires_at - self.observed_at
            )
        except Exception:
            fresh = False
        return {
            "state": self.state,
            "observation_current": fresh,
            "device_enrolled": self.state == "active" and fresh,
            "record": asdict(self.record) if self.record else None,
            "heartbeat": asdict(self.heartbeat) if self.heartbeat else None,
            "server_authoritative": True,
            "foreground_only": True,
            "native_integration_verified": False,
            "managed_browser_enabled": False,
            "remote_execution_enabled": False,
        }


class _DeviceOperation(StrEnum):
    INVENTORY = "inventory"
    REQUEST = "request"
    CHALLENGE = "challenge"
    COMPLETE = "complete"
    HEARTBEAT = "heartbeat"


@dataclass(frozen=True, repr=False)
class _DeviceWireRequest:
    """Private exact-operation transport value; no arbitrary destination or headers."""

    operation: _DeviceOperation
    body: bytes
    observed_at: float
    observed_monotonic: float
    expires_at: float
    device_id: str | None = None
    signed: NativeSignedRequest | None = field(default=None, repr=False)

    @property
    def path(self):
        if self.operation in (_DeviceOperation.INVENTORY, _DeviceOperation.REQUEST):
            return "/v1/device-enrollments"
        if self.operation is _DeviceOperation.HEARTBEAT:
            return f"/v1/agent/devices/{self.device_id}/heartbeat"
        return f"/v1/device-enrollments/{self.device_id}/{self.operation.value}"

    @property
    def method(self):
        return "GET" if self.operation is _DeviceOperation.INVENTORY else "POST"

    def __post_init__(self):
        if type(self.operation) is not _DeviceOperation or type(self.body) is not bytes:
            raise ManagedSessionError("invalid_native_request")
        times = self.observed_at, self.observed_monotonic, self.expires_at
        if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in times):
            raise ManagedSessionError("invalid_native_request")
        if not 0 < self.expires_at - self.observed_at <= 30:
            raise ManagedSessionError("invalid_native_request")
        if self.operation in (_DeviceOperation.INVENTORY, _DeviceOperation.REQUEST):
            if self.device_id is not None:
                raise ManagedSessionError("invalid_native_request")
        else:
            _id(self.device_id)
        if self.operation is _DeviceOperation.INVENTORY:
            if self.body != b"" or self.signed is not None:
                raise ManagedSessionError("invalid_native_request")
            return
        row = _decode(self.body)
        if self.operation is _DeviceOperation.REQUEST:
            _fields(row, "name platform public_key")
            _text(row["name"])
            if row["platform"] != "macos":
                raise ManagedSessionError("invalid_native_request")
            try:
                decode_public_key(row["public_key"])
            except (TypeError, ValueError):
                raise ManagedSessionError("invalid_native_request") from None
        elif self.operation is _DeviceOperation.CHALLENGE:
            _fields(row, "request_id registration_generation")
            _uuid(row["request_id"])
            _integer(row["registration_generation"])
        elif self.operation is _DeviceOperation.COMPLETE:
            _fields(row, "request_id registration_generation challenge_id nonce")
            _uuid(row["request_id"])
            _uuid(row["challenge_id"])
            _integer(row["registration_generation"])
            if type(row["nonce"]) is not str or not re.fullmatch(
                r"[A-Za-z0-9_-]{43}", row["nonce"]
            ):
                raise ManagedSessionError("invalid_native_request")
        else:
            _fields(row, "registration_generation agent_version profiles")
            _integer(row["registration_generation"])
            if (
                type(row["agent_version"]) is not str
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", row["agent_version"])
                or row["profiles"] != []
                or type(row["profiles"]) is not list
            ):
                raise ManagedSessionError("invalid_native_request")
        if self.operation in (_DeviceOperation.COMPLETE, _DeviceOperation.HEARTBEAT):
            signed = self.signed
            if (
                type(signed) is not NativeSignedRequest
                or signed.body != self.body
                or signed.path != self.path
                or signed.method != "POST"
                or type(signed.proof) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", signed.proof)
                or len(signed.proof) > 8192
                or type(signed.expires_at) is not int
                or signed.expires_at < self.expires_at
            ):
                raise ManagedSessionError("invalid_native_request")
        elif self.signed is not None:
            raise ManagedSessionError("invalid_native_request")

    def assert_current(self):
        replace(self)
        wall, mono = _clocks()
        if (
            not self.observed_at <= wall < self.expires_at
            or not self.observed_monotonic
            <= mono
            < self.observed_monotonic + self.expires_at - self.observed_at
            or (self.signed is not None and wall >= self.signed.expires_at)
        ):
            raise ManagedSessionError("device_evidence_expired")


def _record(value):
    row = _fields(value, " ".join(EnrollmentRecord.__dataclass_fields__))
    for name in ("device_id", "user_id"):
        _id(row[name])
    _uuid(row["request_id"])
    _integer(row["registration_generation"])
    _text(row["name"])
    if row["platform"] not in ("macos", "windows", "linux"):
        raise ManagedSessionError("invalid_response")
    if type(row["key_fingerprint"]) is not str or not re.fullmatch(
        r"[a-f0-9]{64}", row["key_fingerprint"]
    ):
        raise ManagedSessionError("invalid_response")
    if row["status"] not in ("pending", "approved", "active", "revoked"):
        raise ManagedSessionError("invalid_response")
    if type(row["enabled"]) is not bool or row["enabled"] != (row["status"] == "active"):
        raise ManagedSessionError("invalid_response")
    _integer(row["requested_at"], 0, 2**53 - 86401)
    _integer(row["request_expires_at"], 1, 2**53)
    if row["request_expires_at"] != row["requested_at"] + 86400:
        raise ManagedSessionError("invalid_response")
    if (row["approved_by"] is None) != (row["approval_expires_at"] is None):
        raise ManagedSessionError("invalid_response")
    if row["approved_by"] is not None:
        _id(row["approved_by"])
        _integer(
            row["approval_expires_at"], row["requested_at"] + 600, row["request_expires_at"] + 600
        )
    if row["status"] == "pending" and row["approved_by"] is not None:
        raise ManagedSessionError("invalid_response")
    if row["status"] in ("approved", "active") and row["approved_by"] is None:
        raise ManagedSessionError("invalid_response")
    return EnrollmentRecord(**row)


def _device_projection(request: _DeviceWireRequest, response: HTTPResponse):
    if (
        type(request) is not _DeviceWireRequest
        or type(response) is not HTTPResponse
        or type(response.status_code) is not int
        or response.redirected is not False
    ):
        raise ManagedSessionError("invalid_response")
    if response.status_code in (401, 403):
        raise ManagedSessionError("membership_denied")
    if response.status_code in (404, 409, 422, 429, 503):
        raise ManagedSessionError("device_request_rejected")
    expected = 201 if request.operation is _DeviceOperation.REQUEST else 200
    if response.status_code != expected or response.content_type != "application/json":
        raise ManagedSessionError("invalid_response")
    row = _decode(response.body)
    if request.operation is _DeviceOperation.INVENTORY:
        if type(row) is not list or len(row) > 1000:
            raise ManagedSessionError("invalid_response")
        records = tuple(_record(item) for item in row)
        if len({v.device_id for v in records}) != len(records) or len(
            {v.request_id for v in records}
        ) != len(records):
            raise ManagedSessionError("invalid_response")
        return records
    if request.operation is _DeviceOperation.CHALLENGE:
        row = _fields(row, "challenge_id nonce expires_at request_id registration_generation")
        _uuid(row["challenge_id"])
        _uuid(row["request_id"])
        _integer(row["registration_generation"])
        _integer(row["expires_at"], 1, 2**53)
        if type(row["nonce"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", row["nonce"]):
            raise ManagedSessionError("invalid_response")
        sent = _decode(request.body)
        if any(row[k] != sent[k] for k in ("request_id", "registration_generation")):
            raise ManagedSessionError("invalid_response")
        # The read can take time, but the server cannot issue >120 seconds ahead.
        wall, _ = _clocks()
        if not wall < row["expires_at"] <= wall + 120:
            raise ManagedSessionError("invalid_response")
        return _Challenge(**row)
    if request.operation is _DeviceOperation.HEARTBEAT:
        row = _fields(row, " ".join(DeviceHeartbeat.__dataclass_fields__))
        for name in ("id", "user_id"):
            _id(row[name])
        _text(row["name"])
        _text(row["last_seen_at"], 40)
        # Server emits an ISO UTC timestamp; no arbitrary reflected text accepted.
        from datetime import datetime, timezone

        try:
            observed = datetime.fromisoformat(row["last_seen_at"])
            wall, _ = _clocks()
            if observed.tzinfo is None or observed.utcoffset() != timezone.utc.utcoffset(observed):
                raise ValueError
            if not request.observed_at - 5 <= observed.timestamp() <= wall + 5:
                raise ValueError
        except ValueError:
            raise ManagedSessionError("invalid_response") from None
        _integer(row["registration_generation"])
        sent = _decode(request.body)
        if (
            row["id"] != request.device_id
            or row["platform"] != "macos"
            or row["enabled"] is not True
            or row["connectivity"] != "online"
            or row["synthetic_fixture"] is not False
            or row["secure_enrollment_available"] is not True
            or row["registration_generation"] != sent["registration_generation"]
            or row["agent_version"] != sent["agent_version"]
        ):
            raise ManagedSessionError("invalid_response")
        return DeviceHeartbeat(**row)
    result = _record(row)
    if request.operation is _DeviceOperation.REQUEST:
        sent = _decode(request.body)
        if (
            result.status != "pending"
            or result.registration_generation != 1
            or result.name != sent["name"]
            or result.platform != "macos"
            or result.key_fingerprint != key_fingerprint(sent["public_key"])
        ):
            raise ManagedSessionError("invalid_response")
    elif result.status != "active" or result.device_id != request.device_id:
        raise ManagedSessionError("invalid_response")
    return result


def _device_response_text(result):
    """Vault-only credential reflection check, including native-only challenge fields."""
    rows = [asdict(item) for item in result] if type(result) is tuple else asdict(result)
    return json.dumps(rows, ensure_ascii=True)


class NativeDeviceClient:
    """Synchronous native-worker API. No injected network or credential callback.

    Every operation needs the foreground managed session. No refresh token or
    unattended service is implemented. Explicitly restore before all operations.
    """

    def __init__(
        self, session: NativeManagedSession, keys: MacOSDeviceKeys, scope: TrustedDeviceScope
    ):
        if (
            type(session) is not NativeManagedSession
            or type(keys) is not MacOSDeviceKeys
            or type(scope) is not TrustedDeviceScope
        ):
            raise TypeError("Exact native session, key owner and scope required")
        self._scope = replace(scope)
        if session._configuration.origin != scope.origin or keys._scope != scope:
            raise DeviceClientError("scope_mismatch")
        self._session, self._keys = session, keys
        self._lock = threading.RLock()
        self._handle = None
        self._restored = False
        self._clock = None
        self._used_approvals = set()
        self._snapshot = DeviceClientSnapshot("not_restored")

    def _now(self):
        now = _clocks()
        if self._clock and any(n < old for n, old in zip(now, self._clock, strict=True)):
            raise DeviceClientError("clock_rollback")
        self._clock = now
        return now

    def snapshot(self) -> DeviceClientSnapshot:
        with self._lock:
            return self._snapshot

    def restore(self) -> DeviceClientSnapshot:
        with self._lock:
            try:
                self._now()
                self._handle = self._keys.restore()
                self._restored = True
                self._snapshot = DeviceClientSnapshot(
                    "empty" if self._handle is None else "unverified"
                )
                return self._snapshot
            except Exception:
                self._snapshot = DeviceClientSnapshot("recovery_required")
                raise DeviceClientError("local_recovery_required") from None

    def _ready(self):
        if not self._restored:
            raise DeviceClientError("restore_required")
        self._now()

    def _approval(self, approval, action, name, binding=None, *, consume=False):
        if type(approval) is not NativeEnrollmentApproval:
            raise DeviceClientError("native_approval_required")
        replace(approval)
        wall, mono = self._now()
        if (
            approval.approved is not True
            or approval.action is not action
            or approval.scope != self._scope
            or approval.device_name != name
            or approval.decision_id in self._used_approvals
            or not approval.observed_at <= wall < approval.expires_at
            or not approval.observed_monotonic
            <= mono
            < approval.observed_monotonic + approval.expires_at - approval.observed_at
            or (binding is not None and not _same_binding(approval.binding, binding))
        ):
            raise DeviceClientError("native_approval_required")
        if consume:
            if len(self._used_approvals) >= 64:
                raise DeviceClientError("native_approval_limit")
            self._used_approvals.add(approval.decision_id)

    def _membership(self):
        self._ready()
        wall, mono = self._now()  # Before all authenticated evidence reads.
        member = self._session.me()
        snapshot = self._session.snapshot()
        if (
            type(member) is not ManagedMembership
            or snapshot.status is not ManagedStatus.AVAILABLE
            or snapshot.membership != member
            or type(snapshot.expires_at) is not int
            or member.tenant_id != self._scope.organization_id
            or member.member_id != self._scope.member_id
            or member.role not in (MemberRole.OWNER, MemberRole.ADMIN, MemberRole.MEMBER)
        ):
            raise DeviceClientError("membership_required")
        return NativeDeviceAuthorization(
            self._scope, member, None, wall, mono, min(wall + 30, snapshot.expires_at)
        )

    def _wire(self, operation, authority, body=b"", device_id=None, signed=None):
        request = _DeviceWireRequest(
            operation,
            body,
            authority.observed_at,
            authority.observed_monotonic,
            authority.expires_at,
            device_id,
            signed,
        )
        request.assert_current()
        result = self._session._device_exchange(request)
        request.assert_current()
        self._now()
        return result

    def _evidence(self, authority, record, extra_expiry=None):
        if record.user_id != self._scope.member_id or record.platform != "macos":
            raise DeviceClientError("binding_mismatch")
        wall, _ = self._now()
        if record.requested_at > wall + 5:
            raise DeviceClientError("invalid_server_time")
        expires = authority.expires_at
        if record.status == "pending":
            expires = min(expires, record.request_expires_at)
        elif record.status == "approved":
            expires = min(expires, record.approval_expires_at)
        elif record.status != "active":
            raise DeviceClientError("device_inactive")
        if extra_expiry is not None:
            expires = min(expires, extra_expiry)
        if expires <= wall:
            raise DeviceClientError("enrollment_expired")
        return replace(authority, binding=record.binding(), expires_at=expires)

    def _current(self):
        if self._handle is None:
            raise DeviceClientError("local_key_required")
        authority = self._membership()
        records = self._wire(_DeviceOperation.INVENTORY, authority)
        status = self._keys.status()
        if status.state not in ("pending", "active"):
            raise DeviceClientError("local_recovery_required")
        matches = [
            row
            for row in records
            if row.user_id == self._scope.member_id
            and row.key_fingerprint == status.key_fingerprint
        ]
        if len(matches) != 1:
            raise DeviceClientError("binding_missing_or_ambiguous")
        record = matches[0]
        authority = self._evidence(authority, record)
        # The key owner checks its durable request/generation, without exposing keys.
        self._keys.validate_binding(self._handle, authority)
        return authority, record

    def _publish(self, authority, record, heartbeat=None):
        self._snapshot = DeviceClientSnapshot(
            record.status,
            record,
            heartbeat,
            authority.observed_at,
            authority.observed_monotonic,
            authority.expires_at,
        )
        return self._snapshot

    def request_enrollment(
        self, device_name: str, approval: NativeEnrollmentApproval
    ) -> DeviceClientSnapshot:
        with self._lock:
            self._ready()
            _text(device_name)
            self._approval(approval, EnrollmentAction.REQUEST, device_name)
            if self._handle is not None or self._keys.status().state != "empty":
                raise DeviceClientError("existing_key_requires_reconciliation")
            attempted = False
            try:
                authority = self._membership()
                self._approval(approval, EnrollmentAction.REQUEST, device_name, consume=True)
                authority = replace(
                    authority, expires_at=min(authority.expires_at, approval.expires_at)
                )
                attempted = True  # Local key storage can also have an uncertain outcome.
                self._handle = self._keys.generate_pending(authority)
                public_key = self._keys.status().public_key
                body = _json({"name": device_name, "platform": "macos", "public_key": public_key})
                attempted = True
                record = self._wire(_DeviceOperation.REQUEST, authority, body)
                authority = self._evidence(authority, record)
                self._keys.bind_pending(self._handle, authority)
                return self._publish(authority, record)
            except Exception:
                self._snapshot = DeviceClientSnapshot("uncertain" if attempted else "unavailable")
                raise DeviceClientError(
                    "request_outcome_uncertain" if attempted else "request_unavailable"
                ) from None

    def poll_enrollment(self) -> DeviceClientSnapshot:
        """Read current self inventory; never approve/activate or automatically retry."""
        with self._lock:
            try:
                authority, record = self._current()
                return self._publish(authority, record)
            except Exception:
                self._snapshot = DeviceClientSnapshot("unverified")
                raise DeviceClientError("current_binding_unverified") from None

    def activate(self, approval: NativeEnrollmentApproval) -> DeviceClientSnapshot:
        with self._lock:
            self._ready()
            # Require an exact decision before any challenge or activation work.
            if type(approval) is not NativeEnrollmentApproval or approval.binding is None:
                raise DeviceClientError("native_approval_required")
            self._approval(
                approval, EnrollmentAction.ACTIVATE, approval.device_name, approval.binding
            )
            attempted = False
            try:
                authority, record = self._current()
                if record.status not in ("approved", "active"):
                    raise DeviceClientError("server_approval_required")
                self._approval(
                    approval,
                    EnrollmentAction.ACTIVATE,
                    record.name,
                    authority.binding,
                    consume=True,
                )
                authority = replace(
                    authority, expires_at=min(authority.expires_at, approval.expires_at)
                )
                if record.status == "active":
                    if self._keys.status().state == "pending":
                        attempted = True
                        self._keys.mark_active(self._handle, authority)
                    return self._publish(authority, record)
                body = _json(
                    {
                        "request_id": record.request_id,
                        "registration_generation": record.registration_generation,
                    }
                )
                attempted = True
                challenge = self._wire(
                    _DeviceOperation.CHALLENGE, authority, body, record.device_id
                )
                if challenge.expires_at > record.approval_expires_at:
                    raise DeviceClientError("invalid_server_time")
                authority = self._evidence(authority, record, challenge.expires_at)
                body = _json(
                    {
                        "request_id": record.request_id,
                        "registration_generation": record.registration_generation,
                        "challenge_id": challenge.challenge_id,
                        "nonce": challenge.nonce,
                    }
                )
                signed = self._keys.sign_enrollment_completion(self._handle, authority, body)
                active = self._wire(
                    _DeviceOperation.COMPLETE, authority, signed.body, record.device_id, signed
                )
                if not _same_binding(active, record) or active.name != record.name:
                    raise DeviceClientError("binding_mismatch")
                authority = self._evidence(authority, active)
                self._keys.mark_active(self._handle, authority)
                return self._publish(authority, active)
            except Exception:
                self._snapshot = DeviceClientSnapshot("uncertain" if attempted else "unverified")
                raise DeviceClientError(
                    "activation_outcome_uncertain" if attempted else "activation_unavailable"
                ) from None

    def heartbeat(self, agent_version: str) -> DeviceClientSnapshot:
        """One explicit foreground presence heartbeat. Makes no replica/execution claims."""
        with self._lock:
            if type(agent_version) is not str or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,40}", agent_version
            ):
                raise DeviceClientError("invalid_agent_version")
            attempted = False
            try:
                authority, record = self._current()
                if record.status != "active" or self._keys.status().state != "active":
                    raise DeviceClientError("device_inactive")
                body = _json(
                    {
                        "registration_generation": record.registration_generation,
                        "agent_version": agent_version,
                        "profiles": [],
                    }
                )
                signed = self._keys.sign_agent_request(
                    self._handle, authority, AgentOperation.HEARTBEAT, body
                )
                attempted = True
                result = self._wire(
                    _DeviceOperation.HEARTBEAT, authority, signed.body, record.device_id, signed
                )
                if result.user_id != self._scope.member_id or result.name != record.name:
                    raise DeviceClientError("binding_mismatch")
                return self._publish(authority, record, result)
            except Exception:
                self._snapshot = DeviceClientSnapshot("uncertain" if attempted else "unverified")
                raise DeviceClientError(
                    "heartbeat_outcome_uncertain" if attempted else "heartbeat_unavailable"
                ) from None
