"""Native, backend-bound managed reads. No UI routes, credential getters or grants.

Construct only after the native sign-in coordinator publishes success. The OS
vault remains authoritative for local liveness; the API authorizes every read.
All methods are synchronous native-worker work, never JS-callable transports.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import threading
import time
import unicodedata
from dataclasses import dataclass, replace
from enum import StrEnum
from urllib.parse import urlsplit

from . import oidc_https as https
from .auth_flow import HTTPResponse, TrustedOIDCConfiguration, _https_url
from .session_vault import MacOSSessionVault, SessionExpired, SessionVaultError


class ManagedSessionError(RuntimeError):
    """Only fixed diagnostics. Never attach response bodies or native errors."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Native managed session: {reason}")


class ManagedStatus(StrEnum):
    UNVERIFIED = "membership_unverified"
    AVAILABLE = "available"
    DENIED = "membership_denied"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"
    RECOVERY_REQUIRED = "recovery_required"
    LOGGED_OUT = "logged_out_locally"


class MemberRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    AUDITOR = "auditor"


class _Read(StrEnum):
    ME = "/v1/me"
    PROFILES = "/v1/profiles"
    PRESETS = "/v1/presets"


@dataclass(frozen=True)
class TrustedBackendConfiguration:
    """Reviewed native/operator settings, never loaded from UI or token claims.

    Origin pins the HTTPS destination, not a certificate/public key. The exact
    Entra resource/issuer/scope/TTL configuration must also match the vault.
    """

    origin: str
    oidc_configuration: TrustedOIDCConfiguration

    def __post_init__(self) -> None:
        if type(self.origin) is not str:
            raise ValueError("An exact trusted backend HTTPS origin is required")
        _https_url(self.origin)
        if urlsplit(self.origin).path:
            raise ValueError("The backend must be an origin without a path")
        https._Endpoint.from_url(self.origin)
        if type(self.oidc_configuration) is not TrustedOIDCConfiguration:
            raise ValueError("An exact trusted native OIDC configuration is required")
        validated = replace(self.oidc_configuration)
        if validated.provider_policy is None:
            raise ValueError("A reviewed delegated custom API resource scope is required")
        object.__setattr__(self, "oidc_configuration", validated)


@dataclass(frozen=True)
class ManagedMembership:
    member_id: str
    tenant_id: str  # Product organization, never the Entra directory tenant.
    display_name: str
    role: MemberRole

    def public(self) -> dict:
        return {
            "member_id": self.member_id,
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "role": self.role.value,
        }


@dataclass(frozen=True)
class ManagedProfile:
    id: str
    name: str
    preset_id: str
    assigned_user_id: str | None
    revision: int
    state: str

    def public(self) -> dict:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class ManagedPreset:
    id: str
    name: str
    engine: str
    locale: str
    timezone: str
    proxy_required: bool
    revision: int

    def public(self) -> dict:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class ManagedSnapshot:
    status: ManagedStatus
    membership: ManagedMembership | None
    expires_at: int | None = None

    def public(self) -> dict:
        # A cached value is historical, never authority. Conservatively clamp
        # its wall-clock expiry too; a fresh snapshot also checks monotonic time.
        expired = self.status in (ManagedStatus.UNVERIFIED, ManagedStatus.AVAILABLE) and (
            self.expires_at is not None and time.time() >= self.expires_at
        )
        status = ManagedStatus.EXPIRED if expired else self.status
        return {
            "status": status.value,
            "managed_available": status == ManagedStatus.AVAILABLE,
            "membership": self.membership.public() if self.membership and not expired else None,
            "expires_at": self.expires_at,
            "server_authoritative": True,
            "native_integration_verified": False,
            "device_enrolled": False,
        }


def _text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(unicodedata.category(c).startswith("C") for c in value)
    ):
        raise ManagedSessionError("invalid_response")
    return value


def _id(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,36}", value):
        raise ManagedSessionError("invalid_response")
    return value


def _revision(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ManagedSessionError("invalid_response")
    return value


def _fields(value: object, names: str) -> dict:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ManagedSessionError("invalid_response")
    return value


def _pairs(pairs: list) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ManagedSessionError("invalid_response")
        result[name] = value
    return result


def _constant(_: str):
    raise ManagedSessionError("invalid_response")


def _projection(operation: _Read, response: HTTPResponse):
    if (
        type(response) is not HTTPResponse
        or type(response.status_code) is not int
        or response.redirected is not False
    ):
        raise ManagedSessionError("invalid_response")
    if response.status_code in (401, 403):
        raise ManagedSessionError("membership_denied")
    if response.status_code == 409:
        raise ManagedSessionError("membership_changed")
    if response.status_code != 200:
        raise ManagedSessionError("backend_unavailable")
    if (
        response.content_type != "application/json"
        or type(response.body) is not bytes
        or not 1 <= len(response.body) <= 65536
    ):
        raise ManagedSessionError("invalid_response")
    try:
        data = json.loads(
            response.body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        if operation is _Read.ME:
            row = _fields(data, "id org_id display_name role")
            return ManagedMembership(
                _id(row["id"]),
                _id(row["org_id"]),
                _text(row["display_name"], 120),
                MemberRole(row["role"]),
            )
        if type(data) is not list or len(data) > 256:
            raise ManagedSessionError("invalid_response")
        result = []
        ids = set()
        for row in data:
            if operation is _Read.PROFILES:
                row = _fields(row, "id name preset_id assigned_user_id revision state")
                state = _text(row["state"], 24)
                if state not in ("unprovisioned", "proxy-simulated"):
                    raise ManagedSessionError("invalid_response")
                item = ManagedProfile(
                    _id(row["id"]),
                    _text(row["name"], 120),
                    _id(row["preset_id"]),
                    _id(row["assigned_user_id"]) if row["assigned_user_id"] is not None else None,
                    _revision(row["revision"]),
                    state,
                )
            else:
                row = _fields(row, "id name engine locale timezone proxy_required revision")
                if (
                    row["engine"] not in ("normal-browser", "camoufox", "electron_chromium")
                    or row["proxy_required"] is not True
                    or not re.fullmatch(
                        r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", _text(row["locale"], 40)
                    )
                ):
                    raise ManagedSessionError("invalid_response")
                item = ManagedPreset(
                    _id(row["id"]),
                    _text(row["name"], 120),
                    row["engine"],
                    row["locale"],
                    _text(row["timezone"], 80),
                    True,
                    _revision(row["revision"]),
                )
            if item.id in ids:
                raise ManagedSessionError("invalid_response")
            ids.add(item.id)
            result.append(item)
        return tuple(result)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ManagedSessionError("invalid_response") from None


class _BackendReader(https._Reader):
    def response(self, url: str) -> HTTPResponse:
        # Reuse the reviewed 200 framing/body parser unchanged. Error responses
        # need only a bounded syntactically valid head: their body and metadata
        # are discarded, not drained, parsed, reflected or followed.
        head = self.until(b"\r\n\r\n", https._MAX_HEADERS)
        lines = head[:-4].split(b"\r\n")
        if len(lines) > 65 or any(len(line) > 4096 for line in lines):
            raise ManagedSessionError("invalid_response")
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", lines[0])
        if match is None:
            raise ManagedSessionError("invalid_response")
        for line in lines[1:]:
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line):
                raise ManagedSessionError("invalid_response")
        status = int(match[1])
        if status not in (200, 201):
            return HTTPResponse(status, url, b"", content_type="application/json", redirected=False)
        # Reuse the same strict bounded representation/framing parser for 201.
        # Preserve the real status after parsing; operation projection checks it.
        if status == 201:
            head = head.replace(b" 201 ", b" 200 ", 1)
        self.buffer[:0] = head
        return replace(super().response(url), status_code=status)


class _BackendHTTPS:
    """Private exact-operation transport, never a supported injectable adapter."""

    def __init__(self, owner: NativeManagedSession):
        https._supported_interpreter()
        self._owner = owner
        self._tls = https._context()
        self._failed = False
        self._check_tls()

    def _check_tls(self) -> None:
        if (
            self._tls.verify_mode != ssl.CERT_REQUIRED
            or self._tls.check_hostname is not True
            or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2
            or self._tls.keylog_filename is not None
        ):
            raise ManagedSessionError("verified_tls_required")

    def _get(self, operation: _Read, access_token: str) -> HTTPResponse:
        if type(operation) is not _Read:
            raise ManagedSessionError("invalid_native_request")
        return self._exchange(operation, access_token)

    def _device(self, request, access_token: str) -> HTTPResponse:
        from .device_client import _DeviceWireRequest

        if type(request) is not _DeviceWireRequest:
            raise ManagedSessionError("invalid_native_request")
        return self._exchange(request, access_token)

    def _exchange(self, operation, access_token: str) -> HTTPResponse:
        from .device_client import _DeviceWireRequest

        device = type(operation) is _DeviceWireRequest
        if (
            (type(operation) is not _Read and not device)
            or type(access_token) is not str
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,16384}={0,2}", access_token)
            or len(access_token) > 16384
        ):
            raise ManagedSessionError("invalid_native_request")
        if device:
            self._owner._assert_device_membership()
            operation.assert_current()
        path = operation.path if device else operation.value
        method = operation.method if device else "GET"
        body = operation.body if device else b""
        endpoint = https._Endpoint.from_url(self._owner._configuration.origin + path)
        deadline = time.monotonic() + 10
        raw = stream = None
        try:
            if self._failed:
                raise ManagedSessionError("transport_unavailable")
            self._check_tls()
            address = https._addresses(https._resolve(endpoint.host, deadline))[0]
            https._remaining(deadline)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            destination = (str(address), 443) if address.version == 4 else (str(address), 443, 0, 0)
            raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            https._none(raw.settimeout(https._remaining(deadline)))
            https._none(raw.connect(destination))
            https.NativeOIDCHTTPSTransport._peer(raw, address)
            https._none(raw.settimeout(https._remaining(deadline)))
            stream = self._tls.wrap_socket(
                raw,
                server_hostname=endpoint.host,
                do_handshake_on_connect=False,
                suppress_ragged_eofs=False,
            )
            https._none(stream.settimeout(https._remaining(deadline)))
            https._none(stream.do_handshake())
            https._remaining(deadline)
            self._check_tls()
            https.NativeOIDCHTTPSTransport._peer(stream, address)
            if stream.selected_alpn_protocol() not in (None, "http/1.1"):
                raise ManagedSessionError("invalid_tls_protocol")
            # DNS/connect/handshake can be slow. Recheck before bearer emission,
            # with the vault lock still owned by this exact native consumer.
            self._owner._vault._assert_managed_current(self._owner)
            binding = self._owner._member_binding
            organization = "" if binding is None else f"X-TBM-Organization: {_id(binding[0])}\r\n"
            device_headers = ""
            if device and method == "POST":
                device_headers = (
                    f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                )
                if operation.signed is not None:
                    device_headers += f"Device-Proof: {operation.signed.proof}\r\n"
            headers = (
                f"{method} {endpoint.path} HTTP/1.1\r\nHost: {endpoint.authority}\r\n"
                f"Authorization: Bearer {access_token}\r\n"
                f"{organization}{device_headers}"
                "Accept: application/json\r\nAccept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            https._none(stream.settimeout(https._remaining(deadline)))
            # The final socket operation can itself block or fail. Reconfirm
            # exact lease/record ownership after it, before any bearer bytes.
            self._owner._vault._assert_managed_current(self._owner)
            self._owner._vault._managed_deadline()
            https._remaining(deadline)
            if device:
                self._owner._assert_device_membership()
                operation.assert_current()
            https._none(stream.sendall(headers + body))
            del headers
            https._remaining(deadline)
            response = _BackendReader(stream, deadline).response(endpoint.url)
        except BaseException as error:
            self._failed = True
            if isinstance(error, (SessionVaultError, ManagedSessionError)):
                raise
            if not isinstance(error, Exception):
                raise
            raise ManagedSessionError("backend_request_uncertain") from None
        finally:
            cleanup_ok = True
            for connection in (stream, raw):
                if connection is not None:
                    try:
                        https._none(connection.close())
                    except BaseException:
                        cleanup_ok = False
            late = time.monotonic() >= deadline
            if not cleanup_ok or late:
                self._failed = True
                raise ManagedSessionError("backend_request_uncertain") from None
        return response


class NativeManagedSession:
    """Current-vault-session-bound native client, with three fixed read methods.

    Construction binds locally but grants no membership. Production has no
    adapter argument or fallback. Retire this object on any terminal failure;
    it never rebinds to a replacement/recovered session or retries a request.
    """

    def __init__(self, configuration: TrustedBackendConfiguration, *, vault: MacOSSessionVault):
        if (
            type(configuration) is not TrustedBackendConfiguration
            or type(vault) is not MacOSSessionVault
        ):
            raise TypeError("Exact trusted backend configuration and native vault required")
        self._configuration = replace(configuration)
        self._vault = vault
        self._lock = threading.RLock()
        self._status = ManagedStatus.UNVERIFIED
        self._membership: ManagedMembership | None = None
        self._member_binding: tuple[str, str] | None = None
        self._session_id: str | None = None
        self._epoch: str | None = None
        self._expires_at: int | None = None
        try:
            self._transport = _BackendHTTPS(self)
            vault._bind_managed_consumer(self)
        except Exception:
            raise ManagedSessionError("native_configuration_unavailable") from None

    def _fail(self, error: BaseException) -> None:
        self._membership = None
        if isinstance(error, SessionExpired):
            self._status = ManagedStatus.EXPIRED
        elif isinstance(error, SessionVaultError):
            self._status = ManagedStatus.RECOVERY_REQUIRED
        elif isinstance(error, ManagedSessionError) and error.reason == "membership_denied":
            self._status = ManagedStatus.DENIED
        else:
            self._status = ManagedStatus.UNAVAILABLE

    def _read(self, operation: _Read):
        if self._status not in (ManagedStatus.UNVERIFIED, ManagedStatus.AVAILABLE):
            raise ManagedSessionError("session_unavailable")
        if operation is not _Read.ME and self._membership is None:
            raise ManagedSessionError("membership_required")
        try:
            result = self._vault._managed_read(self, operation)
            if operation is _Read.ME:
                binding = result.tenant_id, result.member_id
                if self._member_binding is not None and binding != self._member_binding:
                    raise ManagedSessionError("membership_changed")
                self._member_binding = binding
                self._membership = result
                self._status = ManagedStatus.AVAILABLE
            return result
        except BaseException as error:
            self._fail(error)
            if not isinstance(error, Exception):
                raise
            reason = (
                "session_expired"
                if isinstance(error, SessionExpired)
                else (
                    "native_recovery_required"
                    if isinstance(error, SessionVaultError)
                    else (
                        error.reason
                        if isinstance(error, ManagedSessionError)
                        else "invalid_response"
                    )
                )
            )
            raise ManagedSessionError(reason) from None

    def _assert_device_membership(self) -> None:
        """Fence known membership/role changes before any device authority use.

        This does not replace the server's per-request authorization. The native
        transport must also honor a revocation/downgrade it has already observed.
        """
        member = self._membership
        if (
            self._status is not ManagedStatus.AVAILABLE
            or type(member) is not ManagedMembership
            or type(member.role) is not MemberRole
            or member.role not in (MemberRole.OWNER, MemberRole.ADMIN, MemberRole.MEMBER)
            or self._member_binding != (member.tenant_id, member.member_id)
        ):
            raise ManagedSessionError("membership_required")

    def _device_exchange(self, request):
        """Native-only exact enrollment/heartbeat operations; never a UI transport."""
        from .device_client import _DeviceWireRequest

        if type(request) is not _DeviceWireRequest:
            raise TypeError("An exact bounded native device operation is required")
        with self._lock, self._vault._lock:
            self._assert_device_membership()
            try:
                request.assert_current()
                result = self._vault._managed_device_exchange(self, request)
                self._assert_device_membership()
                request.assert_current()
                return result
            except BaseException as error:
                self._fail(error)
                if not isinstance(error, Exception):
                    raise
                reason = (
                    "session_expired"
                    if isinstance(error, SessionExpired)
                    else "native_recovery_required"
                    if isinstance(error, SessionVaultError)
                    else error.reason
                    if isinstance(error, ManagedSessionError)
                    else "invalid_response"
                )
                raise ManagedSessionError(reason) from None

    def me(self) -> ManagedMembership:
        with self._lock, self._vault._lock:
            return self._read(_Read.ME)

    def profiles(self) -> tuple[ManagedProfile, ...]:
        with self._lock, self._vault._lock:
            return self._read(_Read.PROFILES)

    def presets(self) -> tuple[ManagedPreset, ...]:
        with self._lock, self._vault._lock:
            return self._read(_Read.PRESETS)

    def snapshot(self) -> ManagedSnapshot:
        with self._lock, self._vault._lock:
            if self._status in (ManagedStatus.UNVERIFIED, ManagedStatus.AVAILABLE):
                try:
                    self._vault._assert_managed_current(self)
                except BaseException as error:
                    self._fail(error)
                    if not isinstance(error, Exception):
                        raise
            return ManagedSnapshot(self._status, self._membership, self._expires_at)

    def logout(self) -> ManagedSnapshot:
        """Wait for an in-flight read, then delete only this bound local record.

        No provider revocation, remote cancellation or browser-cookie deletion.
        Exact confirmed local absence is required before reporting success.
        """
        with self._lock, self._vault._lock:
            if self._status == ManagedStatus.LOGGED_OUT:
                return ManagedSnapshot(self._status, None)
            self._membership = None
            try:
                self._vault._logout_managed_consumer(self)
                self._status = ManagedStatus.LOGGED_OUT
            except BaseException as error:
                self._status = ManagedStatus.RECOVERY_REQUIRED
                if not isinstance(error, Exception):
                    raise
                raise ManagedSessionError("local_logout_unconfirmed") from None
            return ManagedSnapshot(self._status, None)
