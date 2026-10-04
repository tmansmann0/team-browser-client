"""Native-only OIDC public-client core. No HTTP, browser or vault implementation.

This module must never be exposed as an arbitrary JSON-configured web endpoint.
Only AuthResult.public() and AuthCapabilities are intended for a UI. Operator
configuration, AuthorizationRequest and adapter calls stay in trusted native
code. An identity result never proves company membership or device enrollment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Callable, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class AuthStatus(StrEnum):
    UNCONFIGURED = "unconfigured"
    READY = "ready"
    WAITING = "waiting_for_browser"
    EXCHANGING = "exchanging_code"
    CANCELLING = "cancelling"
    IDENTITY_VERIFIED = "identity_verified"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    ERROR = "error"
    RECOVERY_REQUIRED = "recovery_required"


def _plain(value: object, maximum: int = 2048) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and not any(ord(c) <= 32 or ord(c) >= 127 for c in value)
    )


def _https_url(value: str) -> None:
    try:
        if not _plain(value) or "\\" in value or "%" in value:
            raise ValueError
        url = urlsplit(value)
        host = url.hostname
        if (
            url.scheme != "https"
            or not host
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or "?" in value
            or "#" in value
            or url.port not in (None, 443)
            or url.netloc not in (host, f"{host}:443")
            or host.endswith(".")
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
            or "." not in host
            or host.endswith((".localhost", ".local"))
            or any(part in (".", "..") for part in url.path.split("/"))
        ):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in host.split(".")
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Use an operator-approved canonical HTTPS DNS endpoint") from None


def _loopback_url(value: str) -> None:
    try:
        url = urlsplit(value)
        if (
            not _plain(value)
            or url.scheme != "http"
            or url.hostname not in ("127.0.0.1", "::1")
            or url.username is not None
            or url.password is not None
            or url.port is None
            or not 1024 <= url.port <= 65535
            or not re.fullmatch(r"/[A-Za-z0-9_/-]+", url.path)
            or url.query
            or url.fragment
            or "?" in value
            or "#" in value
            or urlunsplit((url.scheme, url.netloc, url.path, "", "")) != value
        ):
            raise ValueError
        host = "[::1]" if url.hostname == "::1" else "127.0.0.1"
        if url.netloc != f"{host}:{url.port}":
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Use an exact fixed literal-loopback HTTP callback and port") from None


class AuthorizationResponseIssuer(StrEnum):
    """Operator-selected mix-up defense. Never inferred from a callback."""

    RFC9207_REQUIRED = "rfc9207_required"
    ISSUER_BOUND_REDIRECT = "issuer_bound_redirect"


def issuer_bound_loopback_redirect(issuer: str, *, port: int = 43821) -> str:
    """One deterministic redirect path per exact issuer, registered before use.

    Native listeners must dispatch only this exact path to this issuer's flow.
    The full SHA-256 digest prevents a shared human label from weakening the
    distinct-redirect defense. This function performs no registration or I/O.
    """
    _https_url(issuer)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("An explicit nonprivileged loopback port is required")
    binding = hashlib.sha256(issuer.encode("ascii")).hexdigest()
    return f"http://127.0.0.1:{port}/auth/callback/issuer/{binding}"


def _guid(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None
        and value != "00000000-0000-0000-0000-000000000000"
    )


@dataclass(frozen=True)
class EntraNativePolicy:
    """Reviewed public-cloud, single-tenant v2 contract, not a consent grant.

    Pin one API resource. OIDC scope aliases may be omitted from the token
    response; the fully qualified resource grant must be explicitly present.
    A bare `access_as_user` is an access-token scp claim, not accepted here as
    evidence of a qualified OAuth token-response scope.
    """

    tenant_id: str
    api_client_id: str

    def __post_init__(self) -> None:
        if not _guid(self.tenant_id) or not _guid(self.api_client_id):
            raise ValueError("Explicit canonical tenant and API client GUIDs are required")
        if self.api_client_id == "00000003-0000-0000-c000-000000000000":
            raise ValueError("Microsoft Graph is not the approved custom API resource")

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def api_scope(self) -> str:
        return f"api://{self.api_client_id}/access_as_user"

    @property
    def scopes(self) -> tuple[str, ...]:
        return ("openid", "profile", self.api_scope)

    def endpoints(self) -> tuple[str, str, str]:
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        return (
            f"{authority}/oauth2/v2.0/authorize",
            f"{authority}/oauth2/v2.0/token",
            f"{authority}/discovery/v2.0/keys",
        )


@dataclass(frozen=True)
class TrustedOIDCConfiguration:
    """Reviewed operator settings, never settings submitted by UI or discovery.

    Each endpoint is explicitly trusted, including endpoints on another origin.
    The legacy default is openid-only with a required RFC 9207 response issuer.
    Expanded behavior requires a typed, strictly validated provider policy.
    No supported policy requests or accepts refresh tokens.
    """

    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_endpoint: str
    redirect_uri: str
    scopes: tuple[str, ...] = ("openid",)
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    authorization_ttl_seconds: int = 180
    max_id_token_lifetime_seconds: int = 600
    max_access_token_lifetime_seconds: int = 3600
    clock_skew_seconds: int = 30
    local_session_ttl_seconds: int = 600
    authorization_response_issuer: AuthorizationResponseIssuer = (
        AuthorizationResponseIssuer.RFC9207_REQUIRED
    )
    provider_policy: EntraNativePolicy | None = None

    def __post_init__(self) -> None:
        for value in (
            self.issuer,
            self.authorization_endpoint,
            self.token_endpoint,
            self.jwks_endpoint,
        ):
            _https_url(value)
        _loopback_url(self.redirect_uri)
        if not _plain(self.client_id, 256):
            raise ValueError("An explicit public-client identifier is required")
        if type(self.authorization_response_issuer) is not AuthorizationResponseIssuer:
            raise ValueError("An explicit typed authorization-response issuer mode is required")
        if self.authorization_response_issuer == AuthorizationResponseIssuer.ISSUER_BOUND_REDIRECT:
            if self.redirect_uri != issuer_bound_loopback_redirect(
                self.issuer, port=urlsplit(self.redirect_uri).port
            ):
                raise ValueError("The distinct redirect must be mechanically bound to this issuer")
        if self.provider_policy is not None and type(self.provider_policy) is not EntraNativePolicy:
            raise ValueError("A reviewed typed provider policy is required")
        policy = self.provider_policy
        expected_scopes = policy.scopes if policy else ("openid",)
        if (
            type(self.scopes) is not tuple
            or any(type(scope) is not str for scope in self.scopes)
            or len(self.scopes) != len(expected_scopes)
            or set(self.scopes) != set(expected_scopes)
        ):
            raise ValueError(
                "Only the explicit reviewed OIDC and custom API scope set is supported"
            )
        if policy and (
            self.issuer != policy.issuer
            or (self.authorization_endpoint, self.token_endpoint, self.jwks_endpoint)
            != policy.endpoints()
            or not _guid(self.client_id)
            or self.client_id == policy.api_client_id
        ):
            raise ValueError(
                "Entra policy requires pinned tenant endpoints and a native client GUID"
            )
        if (
            type(self.algorithms) is not tuple
            or not self.algorithms
            or len(set(self.algorithms)) != len(self.algorithms)
            or not set(self.algorithms) <= {"RS256", "ES256"}
        ):
            raise ValueError("Explicit supported asymmetric signing algorithms are required")
        for value, minimum, maximum in (
            (self.authorization_ttl_seconds, 30, 600),
            (self.max_id_token_lifetime_seconds, 30, 3600),
            (self.max_access_token_lifetime_seconds, 30, 5400 if policy else 3600),
            (self.clock_skew_seconds, 0, 60),
            (self.local_session_ttl_seconds, 30, 600),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("Authentication time bounds must be explicit short integers")


def entra_native_configuration(
    *,
    tenant_id: str,
    desktop_client_id: str,
    api_client_id: str,
    loopback_port: int = 43821,
    local_session_ttl_seconds: int = 600,
) -> TrustedOIDCConfiguration:
    """Build reviewed settings using approved registration IDs. Performs no I/O.

    Public-cloud Entra v2 does not promise RFC 9207 on the code response. Select
    its distinct issuer-bound callback before registering or starting a flow;
    a wrong issuer is still rejected whenever present. This is not live setup.
    """
    policy = EntraNativePolicy(tenant_id=tenant_id, api_client_id=api_client_id)
    authorization, token, jwks = policy.endpoints()
    return TrustedOIDCConfiguration(
        issuer=policy.issuer,
        client_id=desktop_client_id,
        authorization_endpoint=authorization,
        token_endpoint=token,
        jwks_endpoint=jwks,
        redirect_uri=issuer_bound_loopback_redirect(policy.issuer, port=loopback_port),
        scopes=policy.scopes,
        algorithms=("RS256",),
        max_id_token_lifetime_seconds=3600,
        max_access_token_lifetime_seconds=5400,
        local_session_ttl_seconds=local_session_ttl_seconds,
        authorization_response_issuer=AuthorizationResponseIssuer.ISSUER_BOUND_REDIRECT,
        provider_policy=policy,
    )


@dataclass(frozen=True)
class AccountIdentity:
    issuer: str
    subject: str

    def __post_init__(self) -> None:
        _https_url(self.issuer)
        if not _plain(self.subject, 255):
            raise ValueError("An exact issuer/subject account binding is required")


@dataclass(frozen=True)
class AuthResult:
    status: AuthStatus
    reason: str
    identity: AccountIdentity | None = None
    expires_at: int | None = None

    def public(self) -> dict:
        """The only result serialization intended for a web/JS presentation layer."""
        return {
            "status": self.status.value,
            "reason": self.reason,
            "identity": (
                {"issuer": self.identity.issuer, "subject": self.identity.subject}
                if self.identity
                else None
            ),
            "expires_at": self.expires_at,
            "company_membership_verified": False,
            "device_enrolled": False,
            "managed_access_available": False,
        }


@dataclass(frozen=True)
class AuthCapabilities:
    configured: bool
    can_begin: bool
    blockers: tuple[str, ...]
    scopes: tuple[str, ...] = ("openid",)
    company_membership_verified: bool = False
    device_enrolled: bool = False
    managed_access_available: bool = False
    # Only real target-platform acceptance may establish adapter readiness.
    native_integration_verified: bool = False


@dataclass(frozen=True)
class AuthorizationRequest:
    """Native browser-launch instruction. Do not serialize to JS, logs or disk."""

    result: AuthResult
    authorization_url: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class HTTPResponse:
    """Transport attestation: redirects must be disabled before sending anything."""

    status_code: int
    url: str = field(repr=False)
    body: bytes = field(repr=False)
    content_type: str = "application/json"
    redirected: bool = False


class OIDCTransport(Protocol):
    """Vetted native HTTPS transport with certificate checks and bounded bodies.

    Never follow redirects, retry code POSTs, log bodies/URLs, trust environment
    proxies, or downgrade TLS. Enforce timeouts, destination/DNS egress policy
    and response-size limits while reading, before constructing HTTPResponse.
    """

    def get(self, url: str, *, timeout_seconds: int, follow_redirects: bool) -> HTTPResponse: ...

    def post_form(
        self, url: str, fields: dict[str, str], *, timeout_seconds: int, follow_redirects: bool
    ) -> HTTPResponse: ...


@dataclass(frozen=True)
class NativeSessionMaterial:
    """Secret native-vault input. Never use dataclasses.asdict or general logging."""

    identity: AccountIdentity
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    expires_at: int
    scopes: tuple[str, ...] = ("openid",)


class SessionVault(Protocol):
    """OS-protected native storage only; no file/environment/in-memory fallback.

    store_session must commit atomically or raise; delete_session must confirm
    absence or raise. Persist an operation/quarantine marker before committing
    so a crash or uncertain write cannot expose material on restart. Enforce
    expires_at on every read. Records may be consumed only by a vetted native
    caller, never a web bridge. Every successful void operation returns exactly
    None; any other acknowledgement is a protocol violation requiring recovery.
    No production implementation is supplied here.
    """

    def assert_available(self) -> None: ...
    def store_session(self, session_id: str, material: NativeSessionMaterial) -> None: ...
    def delete_session(self, session_id: str) -> None: ...


@dataclass
class _Attempt:
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    verifier: str = field(repr=False)
    session_id: str = field(repr=False)
    started_at: float
    deadline: float
    expected_account: AccountIdentity | None
    cancelled: bool = False


class _Rejected(Exception):
    pass


class _WrongAccount(_Rejected):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise _Rejected
        result[name] = value
    return result


def _json_response(response: HTTPResponse, expected_url: str) -> dict:
    if (
        not isinstance(response, HTTPResponse)
        or response.url != expected_url
        or response.redirected is not False
        or response.status_code != 200
        or response.content_type.split(";", 1)[0].strip().lower() != "application/json"
        or type(response.body) is not bytes
        or len(response.body) > 65536
    ):
        raise _Rejected
    try:
        value = json.loads(response.body, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError):
        raise _Rejected from None
    if type(value) is not dict:
        raise _Rejected
    return value


class ManagedSignIn:
    """One native flow at a time. Exchange/storage never hold the state lock.

    Cancellation can therefore win during transport/vault I/O. A matching
    callback consumes state before any exchange; no timeout or replay retries
    an authorization code. Unknown transport or vault outcomes fail closed.
    """

    def __init__(
        self,
        config: TrustedOIDCConfiguration | None = None,
        *,
        transport: OIDCTransport | None = None,
        vault: SessionVault | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if config is not None and not isinstance(config, TrustedOIDCConfiguration):
            raise TypeError("Trusted typed operator configuration is required")
        self._config, self._transport, self._vault = config, transport, vault
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._attempt: _Attempt | None = None
        self._session_id: str | None = None
        self._result = AuthResult(AuthStatus.READY, "ready")
        if config is None or transport is None or vault is None:
            self._result = AuthResult(AuthStatus.UNCONFIGURED, "native_adapters_required")

    def capabilities(self) -> AuthCapabilities:
        with self._lock:
            result = self.status()
            blockers = []
            if self._config is None:
                blockers.append("trusted_operator_configuration_required")
            if self._transport is None:
                blockers.append("native_transport_required")
            if self._vault is None:
                blockers.append("native_vault_required")
            if result.status in (AuthStatus.WAITING, AuthStatus.EXCHANGING, AuthStatus.CANCELLING):
                blockers.append("sign_in_in_progress")
            if result.status == AuthStatus.IDENTITY_VERIFIED:
                blockers.append("identity_already_verified")
            if result.status == AuthStatus.RECOVERY_REQUIRED:
                blockers.append("native_reconciliation_required")
            return AuthCapabilities(
                configured=all(x is not None for x in (self._config, self._transport, self._vault)),
                can_begin=not blockers,
                blockers=tuple(blockers),
                scopes=self._config.scopes if self._config else ("openid",),
            )

    def status(self) -> AuthResult:
        with self._lock:
            if (
                self._result.status == AuthStatus.WAITING
                and self._attempt is not None
                and self._monotonic() >= self._attempt.deadline
            ):
                self._attempt = None
                self._result = AuthResult(AuthStatus.EXPIRED, "authorization_expired")
            if (
                self._result.status == AuthStatus.IDENTITY_VERIFIED
                and self._result.expires_at is not None
                and time.time() >= self._result.expires_at
            ):
                self._result = AuthResult(AuthStatus.EXPIRED, "identity_expired")
                session_id, self._session_id = self._session_id, None
                if session_id and not self._delete_session(session_id):
                    self._result = AuthResult(
                        AuthStatus.RECOVERY_REQUIRED, "vault_cleanup_uncertain"
                    )
            return self._result

    def begin(self, *, expected_account: AccountIdentity | None = None) -> AuthorizationRequest:
        with self._lock:
            if not self.capabilities().can_begin:
                return AuthorizationRequest(self.status())
            config = self._config
            assert config is not None and self._vault is not None
            if expected_account is not None and (
                not isinstance(expected_account, AccountIdentity)
                or expected_account.issuer != config.issuer
            ):
                return AuthorizationRequest(AuthResult(AuthStatus.ERROR, "invalid_account_binding"))
            try:
                acknowledgement = self._vault.assert_available()
            except Exception:
                self._result = AuthResult(AuthStatus.ERROR, "vault_unavailable")
                return AuthorizationRequest(self._result)
            if acknowledgement is not None:
                self._result = AuthResult(AuthStatus.RECOVERY_REQUIRED, "vault_health_uncertain")
                return AuthorizationRequest(self._result)
            state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            self._attempt = _Attempt(
                state,
                nonce,
                verifier,
                secrets.token_urlsafe(32),
                time.time(),
                self._monotonic() + config.authorization_ttl_seconds,
                expected_account,
            )
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
                .rstrip(b"=")
                .decode("ascii")
            )
            params = {
                "response_type": "code",
                "client_id": config.client_id,
                "redirect_uri": config.redirect_uri,
                "scope": " ".join(config.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_mode": "query",
                "prompt": "select_account",
            }
            self._result = AuthResult(AuthStatus.WAITING, "external_browser_required")
            return AuthorizationRequest(
                self._result, config.authorization_endpoint + "?" + urlencode(params)
            )

    def cancel(self) -> AuthResult:
        with self._lock:
            self.status()
            if self._attempt is None:
                return self._result
            self._attempt.cancelled = True
            if self._result.status == AuthStatus.WAITING:
                self._attempt = None
                self._result = AuthResult(AuthStatus.CANCELLED, "cancelled")
            elif self._result.status in (AuthStatus.EXCHANGING, AuthStatus.CANCELLING):
                self._result = AuthResult(AuthStatus.CANCELLING, "waiting_for_native_cleanup")
            return self._result

    def _callback(self, callback_url: str) -> dict[str, str]:
        config = self._config
        assert config is not None
        try:
            if not _plain(callback_url, 8192) or "\\" in callback_url or "#" in callback_url:
                raise _Rejected
            url = urlsplit(callback_url)
            if urlunsplit((url.scheme, url.netloc, url.path, "", "")) != config.redirect_uri:
                raise _Rejected
            if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                raise _Rejected
            pairs = parse_qsl(
                url.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=32 if config.provider_policy else 8,
                encoding="utf-8",
                errors="strict",
            )
            critical = {"code", "state", "iss", "error", "error_description", "error_uri"}
            result = {}
            for name, value in pairs:
                if config.provider_policy:
                    # OAuth extension fields are bounded, ignored and never
                    # reflected. Token-bearing/hybrid responses are not an
                    # extension to this code-only public-client flow.
                    if (
                        not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
                        or len(value) > (4096 if name == "code" else 2048)
                        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
                        or name
                        in {
                            "access_token",
                            "id_token",
                            "refresh_token",
                            "token_type",
                            "expires_in",
                            "code_verifier",
                            "client_secret",
                            "response",
                        }
                    ):
                        raise _Rejected
                    if name not in critical:
                        continue
                elif name not in critical - {"error_uri"}:
                    raise _Rejected
                if name in result:
                    raise _Rejected
                result[name] = value
            if not _plain(result.get("state"), 128):
                raise _Rejected
            if "iss" in result:
                if not _plain(result["iss"]) or result["iss"] != config.issuer:
                    raise _Rejected
            elif (
                config.authorization_response_issuer == AuthorizationResponseIssuer.RFC9207_REQUIRED
            ):
                raise _Rejected
            if ("code" in result) == ("error" in result):
                raise _Rejected
            if "code" in result and (
                not _plain(result["code"], 4096)
                or "error_description" in result
                or "error_uri" in result
            ):
                raise _Rejected
            if "error" in result and not _plain(result["error"], 128):
                raise _Rejected
            return result
        except (ValueError, TypeError, UnicodeError):
            raise _Rejected from None

    def complete_callback(self, callback_url: str) -> AuthResult:
        with self._lock:
            self.status()
            if self._result.status != AuthStatus.WAITING or self._attempt is None:
                return AuthResult(self._result.status, "callback_rejected")
            attempt = self._attempt
            config = self._config
            assert config is not None and self._transport is not None and self._vault is not None
            try:
                params = self._callback(callback_url)
                if not hmac.compare_digest(params["state"], attempt.state):
                    raise _Rejected
            except _Rejected:
                return AuthResult(AuthStatus.WAITING, "callback_rejected")
            # The lock and phase transition make state one-use, including errors.
            self._result = AuthResult(AuthStatus.EXCHANGING, "exchanging_code")
            attempt.state = ""
            if "error" in params:
                self._attempt = None
                self._result = AuthResult(
                    AuthStatus.CANCELLED
                    if params["error"] == "access_denied"
                    else AuthStatus.ERROR,
                    "consent_denied" if params["error"] == "access_denied" else "provider_error",
                )
                return self._result
        try:
            response = self._transport.post_form(
                config.token_endpoint,
                {
                    "grant_type": "authorization_code",
                    "code": params["code"],
                    "redirect_uri": config.redirect_uri,
                    "client_id": config.client_id,
                    "code_verifier": attempt.verifier,
                },
                timeout_seconds=10,
                follow_redirects=False,
            )
        except Exception:
            # The server may have issued a token. Never replay this code.
            return self._finish_failure(attempt, "token_exchange_uncertain", uncertain=True)
        finally:
            attempt.verifier = ""
        received_at = time.time()
        if self._cancelled_or_expired(attempt):
            return self.status()
        try:
            payload = _json_response(response, config.token_endpoint)
        except Exception:
            return self._finish_failure(attempt, "token_exchange_uncertain", uncertain=True)
        try:
            material = self._verify_tokens(payload, attempt, received_at=received_at)
        except _WrongAccount:
            return self._finish_failure(attempt, "wrong_account")
        except Exception:
            # Do not surface provider text, JWT exceptions, body or token values.
            return self._finish_failure(attempt, "token_validation_failed")
        if self._cancelled_or_expired(attempt):
            return self.status()
        try:
            acknowledgement = self._vault.store_session(attempt.session_id, material)
        except Exception:
            cleaned = self._delete_session(attempt.session_id)
            return self._finish_failure(
                attempt,
                "vault_store_failed" if cleaned else "vault_cleanup_uncertain",
                uncertain=not cleaned,
            )
        if acknowledgement is not None:
            # A malformed acknowledgement cannot establish a committed write.
            # One cleanup attempt is allowed, but even confirmed absence does
            # not restore trust in this adapter or allow a fresh flow.
            cleaned = self._delete_session(attempt.session_id)
            return self._finish_failure(
                attempt,
                "vault_store_uncertain" if cleaned else "vault_cleanup_uncertain",
                uncertain=True,
            )
        with self._lock:
            if attempt.cancelled or self._monotonic() >= attempt.deadline:
                cleaned = self._delete_session(attempt.session_id)
                self._attempt = None
                self._result = AuthResult(
                    (AuthStatus.CANCELLED if attempt.cancelled else AuthStatus.EXPIRED)
                    if cleaned
                    else AuthStatus.RECOVERY_REQUIRED,
                    ("cancelled" if attempt.cancelled else "authorization_expired")
                    if cleaned
                    else "vault_cleanup_uncertain",
                )
            elif time.time() >= material.expires_at:
                cleaned = self._delete_session(attempt.session_id)
                self._attempt = None
                self._result = AuthResult(
                    AuthStatus.EXPIRED if cleaned else AuthStatus.RECOVERY_REQUIRED,
                    "identity_expired" if cleaned else "vault_cleanup_uncertain",
                )
            else:
                self._session_id = attempt.session_id
                self._attempt = None
                self._result = AuthResult(
                    AuthStatus.IDENTITY_VERIFIED,
                    "membership_and_enrollment_required",
                    material.identity,
                    material.expires_at,
                )
            return self._result

    def _delete_session(self, session_id: str) -> bool:
        assert self._vault is not None
        try:
            return self._vault.delete_session(session_id) is None
        except Exception:
            return False

    def _finish_failure(self, attempt: _Attempt, reason: str, *, uncertain=False) -> AuthResult:
        with self._lock:
            self._attempt = None
            status = AuthStatus.RECOVERY_REQUIRED if uncertain else AuthStatus.ERROR
            if attempt.cancelled and not uncertain:
                status, reason = AuthStatus.CANCELLED, "cancelled"
            self._result = AuthResult(status, reason)
            return self._result

    def _cancelled_or_expired(self, attempt: _Attempt) -> bool:
        with self._lock:
            expired = self._monotonic() >= attempt.deadline
            if attempt.cancelled or expired:
                self._attempt = None
                self._result = AuthResult(
                    AuthStatus.CANCELLED if attempt.cancelled else AuthStatus.EXPIRED,
                    "cancelled" if attempt.cancelled else "authorization_expired",
                )
                return True
            return False

    def _verify_tokens(
        self, payload: dict, attempt: _Attempt, *, received_at: float
    ) -> NativeSessionMaterial:
        config = self._config
        assert config is not None and self._transport is not None
        access, encoded = payload.get("access_token"), payload.get("id_token")
        lifetime = payload.get("expires_in")
        if (
            "error" in payload
            or payload.get("token_type") != "Bearer"
            or not _plain(access, 16384)
            or not _plain(encoded, 16384)
            or "refresh_token" in payload
            or not self._approved_response_scopes(payload)
            or type(lifetime) is not int
            or not 1 <= lifetime <= config.max_access_token_lifetime_seconds
        ):
            raise _Rejected
        header = jwt.get_unverified_header(encoded)
        algorithm, kid = header.get("alg"), header.get("kid")
        if (
            algorithm not in config.algorithms
            or not _plain(kid, 128)
            or header.get("typ", "JWT") != "JWT"
            or set(header) - {"alg", "kid", "typ"}
        ):
            raise _Rejected
        response = self._transport.get(
            config.jwks_endpoint, timeout_seconds=10, follow_redirects=False
        )
        jwks = _json_response(response, config.jwks_endpoint)
        keys = jwks.get("keys")
        if type(keys) is not list or not 1 <= len(keys) <= 32:
            raise _Rejected
        matching = [key for key in keys if type(key) is dict and key.get("kid") == kid]
        if len(matching) != 1:
            raise _Rejected
        jwk = matching[0]
        if (
            jwk.get("alg", algorithm) != algorithm
            or jwk.get("use", "sig") != "sig"
            or jwk.get("key_ops", ["verify"]) != ["verify"]
            or set(jwk) & {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        ):
            raise _Rejected
        key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
        if algorithm == "RS256" and (not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048):
            raise _Rejected
        if algorithm == "ES256" and (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise _Rejected
        claims = jwt.decode(
            encoded,
            key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=config.issuer,
            leeway=config.clock_skew_seconds,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"], "strict_aud": True},
        )
        if config.provider_policy is not None and (
            claims.get("tid") != config.provider_policy.tenant_id or claims.get("ver") != "2.0"
        ):
            raise _Rejected
        now = time.time()
        issued, expires = claims["iat"], claims["exp"]
        if (
            claims["iss"] != config.issuer
            or claims["aud"] != config.client_id
            or type(issued) is not int
            or type(expires) is not int
            or not 0 < expires - issued <= config.max_id_token_lifetime_seconds
            or expires <= now
            # A nonce-bound code flow establishes this attempt's binding. Entra
            # iat need not be within 30 seconds of browser launch, and does not
            # establish that the person just entered credentials. Retain the
            # stricter legacy contract when no reviewed provider is selected.
            or (
                config.provider_policy is None
                and issued < attempt.started_at - config.clock_skew_seconds
            )
            or issued > now + config.clock_skew_seconds
            or ("nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] >= expires))
            or not _plain(claims["nonce"], 128)
            or not hmac.compare_digest(claims["nonce"], attempt.nonce)
            or claims.get("azp", config.client_id) != config.client_id
        ):
            raise _Rejected
        # OIDC at_hash is optional for code flow, but must match when supplied.
        if "at_hash" in claims:
            expected_hash = (
                base64.urlsafe_b64encode(hashlib.sha256(access.encode("ascii")).digest()[:16])
                .rstrip(b"=")
                .decode("ascii")
            )
            if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(
                claims["at_hash"], expected_hash
            ):
                raise _Rejected
        identity = AccountIdentity(claims["iss"], claims["sub"])
        if attempt.expected_account is not None and identity != attempt.expected_account:
            raise _WrongAccount
        access_expires = int(received_at) + lifetime
        if access_expires <= now:
            raise _Rejected
        local_expires = int(received_at) + config.local_session_ttl_seconds
        if local_expires <= now:
            raise _Rejected
        return NativeSessionMaterial(
            identity, access, encoded, min(expires, access_expires, local_expires), config.scopes
        )

    def _approved_response_scopes(self, payload: dict) -> bool:
        config = self._config
        assert config is not None
        if config.provider_policy is None:
            # RFC 6749 permits omission when the granted scopes are unchanged.
            return payload.get("scope", "openid") == "openid"
        value = payload.get("scope")
        if (
            type(value) is not str
            or not 1 <= len(value) <= 2048
            or not re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*", value)
        ):
            return False
        granted = set(value.split(" "))
        # Entra token responses can omit the OIDC aliases. Their omission does
        # not expand access: require the sole fully qualified API grant, the
        # signed ID token, and the exact nonce. The API independently validates
        # aud/tid/scp/azp; this metadata never proves resource authorization.
        return config.provider_policy.api_scope in granted and granted <= set(config.scopes)
