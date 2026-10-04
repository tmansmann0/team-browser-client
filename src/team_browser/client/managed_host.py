"""Explicit native composition; no native I/O until a user action is queued.

Only public snapshots may cross the same-origin web bridge. Configuration and
all owned adapters stay native. No provider activation is supplied here.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum

from ..local.macos_keychain import KeychainConfiguration
from .auth_flow import AuthStatus, TrustedOIDCConfiguration
from .managed_session import (
    ManagedMembership,
    ManagedPreset,
    ManagedProfile,
    ManagedSessionError,
    ManagedStatus,
    NativeManagedSession,
    TrustedBackendConfiguration,
)
from .oidc_https import NativeOIDCHTTPSTransport
from .session_vault import MacOSSessionVault
from .signin_callback import NativeSignInCoordinator


class HostStatus(StrEnum):
    UNCONFIGURED = "unconfigured"
    PREPARATION_REQUIRED = "preparation_required"
    PREPARING = "preparing"
    READY = "ready"
    SIGNING_IN = "signing_in"
    CANCELLING = "cancelling"
    MEMBERSHIP_UNVERIFIED = "membership_unverified"
    AVAILABLE = "available"
    REFRESHING = "refreshing"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    MEMBERSHIP_DENIED = "membership_denied"
    UNAVAILABLE = "unavailable"
    RECOVERY_REQUIRED = "recovery_required"
    SIGNING_OUT = "signing_out"
    SIGNED_OUT = "signed_out_locally"
    SHUTTING_DOWN = "shutting_down"
    CLOSED = "closed"


class HostReason(StrEnum):
    UNCONFIGURED = "native_host_unconfigured"
    PREPARE_REQUIRED = "explicit_prepare_required"
    PREPARING = "preparing_native_vault"
    READY = "native_ready"
    STARTING = "starting_native_sign_in"
    WAITING = "waiting_for_browser"
    EXCHANGING = "exchanging_code"
    CANCELLING = "cancellation_pending"
    CANCELLED = "sign_in_cancelled"
    SIGN_IN_FAILED = "sign_in_failed"
    MEMBERSHIP_PENDING = "membership_check_pending"
    MEMBERSHIP_VERIFIED = "membership_verified"
    REFRESHING = "records_refresh_pending"
    REFRESHED = "records_refreshed"
    DENIED = "membership_denied"
    CHANGED = "membership_changed"
    EXPIRED = "session_expired"
    UNAVAILABLE = "native_operation_failed"
    RECOVERY_REQUIRED = "recovery_required"
    SIGNING_OUT = "local_sign_out_pending"
    SIGNED_OUT = "signed_out_locally"
    SHUTDOWN = "native_shutdown_pending"
    CLOSED = "native_host_closed"


def _clocks() -> tuple[float, float]:
    values = time.time(), time.monotonic()
    if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("invalid_clock")
    return values


@dataclass(frozen=True)
class ManagedHostSnapshot:
    """Bounded presentation observation, never an offline authorization grant."""

    status: HostStatus
    reason: HostReason
    configured: bool = True
    identity_verified: bool = False
    expires_at: int | None = None
    pending_operation: str | None = None
    native_operations_pending: bool = False
    can_cancel: bool = False
    cancellation_requested: bool = False
    shutting_down: bool = False
    closed: bool = False
    can_prepare: bool = False
    can_sign_in: bool = False
    can_refresh_records: bool = False
    can_sign_out: bool = False
    records_loaded: bool = False
    membership: ManagedMembership | None = None
    profiles: tuple[ManagedProfile, ...] = ()
    presets: tuple[ManagedPreset, ...] = ()
    _deadline: float | None = field(default=None, repr=False)
    _observed_clock: tuple[float, float] | None = field(default=None, repr=False)

    def public(self) -> dict:
        expired = False
        if self.identity_verified:
            try:
                wall, monotonic = _clocks()
                expired = (
                    self.expires_at is None
                    or self._deadline is None
                    or wall >= self.expires_at
                    or monotonic >= self._deadline
                    or self._observed_clock is None
                    or wall < self._observed_clock[0]
                    or monotonic < self._observed_clock[1]
                )
            except Exception:
                expired = True
        status = HostStatus.EXPIRED if expired else self.status
        membership = self.membership if not expired else None
        available = (
            status in (HostStatus.AVAILABLE, HostStatus.REFRESHING) and membership is not None
        )
        return {
            "status": status.value,
            "reason": (HostReason.EXPIRED if expired else self.reason).value,
            "configured": self.configured,
            "identity_verified": self.identity_verified and not expired,
            "company_membership_verified": available,
            "managed_access_available": available,
            "device_enrolled": False,
            "native_integration_verified": False,
            "server_authoritative": True,
            "expires_at": self.expires_at if not expired else None,
            "pending_operation": self.pending_operation,
            "native_operations_pending": self.native_operations_pending,
            "can_cancel": self.can_cancel,
            "cancellation_requested": self.cancellation_requested,
            "shutting_down": self.shutting_down,
            "closed": self.closed,
            "capabilities": {
                "can_prepare": self.can_prepare,
                "can_sign_in": self.can_sign_in,
                "can_cancel_sign_in": self.can_cancel,
                "can_refresh_records": self.can_refresh_records and not expired,
                "can_sign_out": self.can_sign_out,
            },
            "records_loaded": self.records_loaded and available,
            "membership": membership.public() if membership else None,
            "profiles": [row.public() for row in self.profiles] if available else [],
            "presets": [row.public() for row in self.presets] if available else [],
        }


def unconfigured_snapshot() -> ManagedHostSnapshot:
    return ManagedHostSnapshot(HostStatus.UNCONFIGURED, HostReason.UNCONFIGURED, configured=False)


class NativeManagedHost:
    """One exclusive lifecycle, one worker, one queued action and retirement intent.

    Public actions do not wait for native workers. Never call wait_closed from
    an application/UI thread. OS blocking can delay settlement indefinitely;
    ownership is retained and no replacement session is admitted meanwhile.
    """

    def __init__(
        self,
        oidc_configuration: TrustedOIDCConfiguration,
        backend_configuration: TrustedBackendConfiguration,
        keychain_configuration: KeychainConfiguration,
    ):
        if (
            type(oidc_configuration) is not TrustedOIDCConfiguration
            or type(backend_configuration) is not TrustedBackendConfiguration
            or type(keychain_configuration) is not KeychainConfiguration
        ):
            raise TypeError("Exact reviewed native configurations are required")
        self._oidc = replace(oidc_configuration)
        self._backend = replace(backend_configuration)
        self._keychain = replace(keychain_configuration)
        if self._backend.oidc_configuration != self._oidc:
            raise ValueError("Native OIDC and backend configurations must match")
        if self._keychain.namespace != "managed-signin":
            raise ValueError("The reserved managed-signin namespace is required")
        self._condition = threading.Condition(threading.RLock())
        self._closed_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._queued: str | None = None
        self._active: str | None = None
        self._retire = False
        self._closing = False
        self._generation = 0
        self._prepared = False
        self._uncertain = False
        self._cleanup_attempted = False
        self._vault: MacOSSessionVault | None = None
        self._coordinator: NativeSignInCoordinator | None = None
        self._session: NativeManagedSession | None = None
        self._status = HostStatus.PREPARATION_REQUIRED
        self._reason = HostReason.PREPARE_REQUIRED
        self._identity = False
        self._membership: ManagedMembership | None = None
        self._records_loaded = False
        self._profiles: tuple[ManagedProfile, ...] = ()
        self._presets: tuple[ManagedPreset, ...] = ()
        self._expires_at: int | None = None
        self._deadline: float | None = None
        self._clock: tuple[float, float] | None = None
        self._attempt_clock: tuple[float, float] | None = None

    def _hide(self) -> None:
        self._identity = False
        self._membership = None
        self._records_loaded = False
        self._profiles = ()
        self._presets = ()
        self._expires_at = self._deadline = None

    def _expire(self) -> None:
        if not self._identity:
            return
        try:
            now = _clocks()
            expired = (
                self._expires_at is None
                or self._deadline is None
                or now[0] >= self._expires_at
                or now[1] >= self._deadline
                or self._clock is None
                or any(n < p for n, p in zip(now, self._clock, strict=True))
            )
            self._clock = now
        except Exception:
            expired = True
        if expired:
            self._generation += 1
            self._hide()
            self._prepared = False
            self._status, self._reason = HostStatus.EXPIRED, HostReason.EXPIRED

    def snapshot(self) -> ManagedHostSnapshot:
        # Only clocks and cached/coordinator memory are inspected here. No vault,
        # consumer.snapshot, thread join, Keychain, socket or browser operation.
        with self._condition:
            self._expire()
            callback = self._coordinator.snapshot() if self._coordinator else None
            idle = self._active is None and self._queued is None and not self._retire
            live = not self._closing and not self._closed_event.is_set()
            can_cancel = bool(live and callback and callback.can_cancel and not self._retire)
            can_prepare = (
                live
                and idle
                and self._status
                not in (
                    HostStatus.AVAILABLE,
                    HostStatus.READY,
                )
            )
            return ManagedHostSnapshot(
                status=self._status,
                reason=self._reason,
                identity_verified=self._identity,
                expires_at=self._expires_at,
                pending_operation=("shutdown" if self._closing else "sign_out")
                if self._retire
                else self._active or self._queued,
                native_operations_pending=not idle,
                can_cancel=can_cancel,
                cancellation_requested=bool(callback and callback.cancellation_requested),
                shutting_down=self._closing,
                closed=self._closed_event.is_set(),
                can_prepare=can_prepare,
                can_sign_in=live
                and idle
                and self._prepared
                and not self._uncertain
                and self._session is None
                and self._coordinator is None,
                can_refresh_records=live and idle and self._status == HostStatus.AVAILABLE,
                can_sign_out=live
                and not self._retire
                and (self._session is not None or self._coordinator is not None or not idle),
                records_loaded=self._records_loaded,
                membership=self._membership,
                profiles=self._profiles,
                presets=self._presets,
                _deadline=self._deadline,
                _observed_clock=self._clock,
            )

    def _enqueue(self, operation: str) -> None:
        self._queued = operation
        if self._thread is None:
            try:
                self._thread = threading.Thread(
                    target=self._run, name="native-managed-host", daemon=False
                )
                self._thread.start()
            except BaseException:
                # Thread creation can fail before any native work begins. A
                # possibly started worker remains owned; no automatic retry.
                if self._thread is not None and not self._thread.is_alive():
                    self._thread = None
                self._queued = None
                self._fail(HostReason.RECOVERY_REQUIRED, uncertain=True)
        self._condition.notify_all()

    def prepare(self) -> ManagedHostSnapshot:
        """Explicitly discard this feature's prior payload; never restore login."""
        with self._condition:
            if self.snapshot().can_prepare:
                self._generation += 1
                self._hide()
                self._prepared = False
                self._status, self._reason = HostStatus.PREPARING, HostReason.PREPARING
                self._enqueue("prepare")
            return self.snapshot()

    def recover(self) -> ManagedHostSnapshot:
        return self.prepare()

    def sign_in(self) -> ManagedHostSnapshot:
        with self._condition:
            if self.snapshot().can_sign_in:
                self._generation += 1
                self._status, self._reason = HostStatus.SIGNING_IN, HostReason.STARTING
                self._enqueue("sign_in")
            return self.snapshot()

    def cancel_sign_in(self) -> ManagedHostSnapshot:
        with self._condition:
            if self._coordinator is not None and not self._retire and not self._closing:
                # The coordinator atomically decides whether cancellation still
                # applies; a terminal no-op must never become logout.
                callback = self._coordinator.cancel()
                if callback.cancellation_requested and callback.can_cancel:
                    self._status, self._reason = HostStatus.CANCELLING, HostReason.CANCELLING
            return self.snapshot()

    def refresh_records(self) -> ManagedHostSnapshot:
        with self._condition:
            if self.snapshot().can_refresh_records:
                self._status, self._reason = HostStatus.REFRESHING, HostReason.REFRESHING
                self._enqueue("refresh_records")
            return self.snapshot()

    def _request_retirement(self) -> None:
        self._generation += 1
        self._hide()
        self._retire = True
        self._queued = None
        if self._coordinator is not None:
            self._coordinator.cancel()  # Its terminal/can_cancel rule is authoritative.
        self._condition.notify_all()

    def sign_out(self) -> ManagedHostSnapshot:
        with self._condition:
            if self.snapshot().can_sign_out:
                self._request_retirement()
                self._status, self._reason = HostStatus.SIGNING_OUT, HostReason.SIGNING_OUT
            return self.snapshot()

    def shutdown(self) -> ManagedHostSnapshot:
        with self._condition:
            if not self._closing and not self._closed_event.is_set():
                self._closing = True
                self._request_retirement()
                self._status, self._reason = HostStatus.SHUTTING_DOWN, HostReason.SHUTDOWN
                if self._thread is None:
                    self._retire = False
                    self._status, self._reason = HostStatus.CLOSED, HostReason.CLOSED
                    self._closed_event.set()
            return self.snapshot()

    def wait_closed(self, timeout: float | None = None) -> bool:
        """Blocking ownership settlement, exclusively for a native worker/tests."""
        return self._closed_event.wait(timeout)

    def _current(self, generation: int) -> bool:
        with self._condition:
            self._expire()
            return generation == self._generation and not self._retire and not self._closing

    def _fail(self, reason: HostReason, *, uncertain: bool = False) -> None:
        with self._condition:
            self._hide()
            self._prepared = False
            self._uncertain |= uncertain
            if not self._retire and not self._closing:
                self._reason = reason
                self._status = {
                    HostReason.RECOVERY_REQUIRED: HostStatus.RECOVERY_REQUIRED,
                    HostReason.DENIED: HostStatus.MEMBERSHIP_DENIED,
                    HostReason.EXPIRED: HostStatus.EXPIRED,
                }.get(reason, HostStatus.UNAVAILABLE)

    def _run(self) -> None:
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._retire or self._queued is not None)
                operation = "sign_out" if self._retire else self._queued
                self._queued = None
                self._active = operation
                generation = self._generation
            try:
                if operation == "prepare":
                    self._prepare(generation)
                elif operation == "sign_in":
                    self._sign_in(generation)
                elif operation == "refresh_records":
                    self._read(generation, records=True)
                else:
                    self._sign_out()
            except BaseException:
                # A native exception/trace may contain credentials. Never let it
                # escape as a thread traceback or a JS diagnostic.
                self._fail(HostReason.RECOVERY_REQUIRED, uncertain=True)
            with self._condition:
                self._active = None
                close = self._closing and not self._retire
                self._condition.notify_all()
            if close:
                with self._condition:
                    self._active = "shutdown"
                self._close()
                return

    def _prepare(self, generation: int) -> None:
        # Previous workers are settled. Explicit recovery retires their objects;
        # a recovery operation, unlike sign-out, intentionally clears the one
        # reserved payload even if the previous result was uncertain.
        self._session = None
        self._coordinator = None
        if self._vault is None:
            self._vault = MacOSSessionVault(self._keychain, oidc_configuration=self._oidc)
        if self._vault.recover_discard_all() is not None:
            raise RuntimeError("native_preparation_uncertain")
        with self._condition:
            self._uncertain = False
            self._cleanup_attempted = False
            self._prepared = True
            if self._current(generation):
                self._status, self._reason = HostStatus.READY, HostReason.READY

    def _sign_in(self, generation: int) -> None:
        if not self._current(generation):
            return
        self._cleanup_attempted = False
        self._attempt_clock = _clocks()
        transport = NativeOIDCHTTPSTransport(self._oidc)
        coordinator = NativeSignInCoordinator(self._oidc, transport=transport, vault=self._vault)
        with self._condition:
            self._coordinator = coordinator
            if not self._current(generation):
                coordinator.cancel()  # Handles cancellation before start exactly.
            else:
                coordinator.start()
        while not coordinator.wait_finished(0.05):
            callback = coordinator.snapshot()
            with self._condition:
                if self._current(generation):
                    self._status = (
                        HostStatus.CANCELLING
                        if callback.cancellation_requested
                        else HostStatus.SIGNING_IN
                    )
                    self._reason = (
                        HostReason.CANCELLING
                        if callback.cancellation_requested
                        else HostReason.EXCHANGING
                        if callback.result.status == AuthStatus.EXCHANGING
                        else HostReason.WAITING
                    )
        callback = coordinator.snapshot()
        if callback.native_operations_pending or not callback.finished:
            raise RuntimeError("native_workers_unsettled")
        if not self._current(generation):
            # The retirement operation owns exact cleanup after all workers settle.
            if callback.result.status == AuthStatus.RECOVERY_REQUIRED:
                self._uncertain = True
            return
        if callback.result.status == AuthStatus.IDENTITY_VERIFIED:
            try:
                expiry = callback.result.expires_at
                now = _clocks()
                if type(expiry) is not int or self._attempt_clock is None:
                    raise ValueError
                deadline = min(
                    self._attempt_clock[1] + expiry - self._attempt_clock[0],
                    self._attempt_clock[1] + self._oidc.local_session_ttl_seconds,
                )
                if (
                    now[0] >= expiry
                    or now[1] >= deadline
                    or any(n < p for n, p in zip(now, self._attempt_clock, strict=True))
                ):
                    self._fail(HostReason.EXPIRED)
                    return
                with self._condition:
                    if not self._current(generation):
                        return
                    self._identity = True
                    self._expires_at, self._deadline, self._clock = expiry, deadline, now
                    self._status = HostStatus.MEMBERSHIP_UNVERIFIED
                    self._reason = HostReason.MEMBERSHIP_PENDING
                # Constructor performs native vault I/O and MUST remain on this worker.
                self._session = NativeManagedSession(self._backend, vault=self._vault)
            except BaseException:
                self._fail(HostReason.RECOVERY_REQUIRED, uncertain=True)
                return
            self._read(generation, records=False)
        elif callback.result.status == AuthStatus.CANCELLED:
            with self._condition:
                if self._current(generation):
                    self._coordinator = None
                    self._status, self._reason = HostStatus.CANCELLED, HostReason.CANCELLED
        elif callback.result.status == AuthStatus.EXPIRED:
            self._fail(HostReason.EXPIRED)
        elif callback.result.status == AuthStatus.RECOVERY_REQUIRED:
            self._fail(HostReason.RECOVERY_REQUIRED, uncertain=True)
        else:
            self._fail(HostReason.SIGN_IN_FAILED)

    def _read(self, generation: int, *, records: bool) -> None:
        session = self._session
        if session is None or not self._current(generation):
            return
        try:
            membership = session.me()
            if not self._current(generation):
                return
            profiles, presets = (), ()
            if records:
                profiles = session.profiles()
                if not self._current(generation):
                    return
                presets = session.presets()
                if not self._current(generation):
                    return
            observed = session.snapshot()
            if observed.status != ManagedStatus.AVAILABLE:
                raise ManagedSessionError(
                    {
                        ManagedStatus.EXPIRED: "session_expired",
                        ManagedStatus.RECOVERY_REQUIRED: "native_recovery_required",
                        ManagedStatus.DENIED: "membership_denied",
                    }.get(observed.status, "session_unavailable")
                )
            with self._condition:
                if not self._current(generation):
                    return
                self._membership = membership
                if records:
                    self._profiles, self._presets = profiles, presets
                    self._records_loaded = True
                self._status = HostStatus.AVAILABLE
                self._reason = HostReason.REFRESHED if records else HostReason.MEMBERSHIP_VERIFIED
        except BaseException as error:
            reason = {
                "membership_denied": HostReason.DENIED,
                "membership_changed": HostReason.CHANGED,
                "session_expired": HostReason.EXPIRED,
                "native_recovery_required": HostReason.RECOVERY_REQUIRED,
            }.get(
                error.reason if isinstance(error, ManagedSessionError) else None,
                HostReason.UNAVAILABLE,
            )
            # Do not republish even an error over a winning logout/new generation.
            if self._current(generation):
                self._fail(reason, uncertain=reason == HostReason.RECOVERY_REQUIRED)
            elif reason == HostReason.RECOVERY_REQUIRED:
                self._uncertain = True

    def _sign_out(self) -> None:
        try:
            if self._cleanup_attempted and self._uncertain:
                raise RuntimeError("native_cleanup_already_uncertain")
            if self._session is not None:
                self._cleanup_attempted = True
                if self._session.logout().status != ManagedStatus.LOGGED_OUT:
                    raise RuntimeError("native_logout_uncertain")
                self._uncertain = False
            elif self._coordinator is not None:
                callback = self._coordinator.snapshot()
                if not callback.finished or callback.native_operations_pending:
                    raise RuntimeError("native_workers_unsettled")
                if callback.result.status in (AuthStatus.IDENTITY_VERIFIED, AuthStatus.EXPIRED):
                    self._cleanup_attempted = True
                    # An expired cached callback may still own a committed
                    # payload. Require exact cleanup or report recovery.
                    # Private composition boundary: coordinator owns this exact
                    # committed handle. Host never reads it or uses broad recovery.
                    if self._coordinator._vault.discard_unpublished_commit() is not None:
                        raise RuntimeError("native_logout_uncertain")
                elif callback.result.status == AuthStatus.RECOVERY_REQUIRED:
                    self._uncertain = True
            if self._uncertain:
                raise RuntimeError("native_cleanup_uncertain")
            self._session = self._coordinator = None
            with self._condition:
                self._status, self._reason = (
                    (HostStatus.SHUTTING_DOWN, HostReason.SHUTDOWN)
                    if self._closing
                    else (HostStatus.SIGNED_OUT, HostReason.SIGNED_OUT)
                )
        except BaseException:
            self._uncertain = True
            self._prepared = False
            with self._condition:
                self._status, self._reason = (
                    HostStatus.RECOVERY_REQUIRED,
                    HostReason.RECOVERY_REQUIRED,
                )
        finally:
            with self._condition:
                self._retire = False

    def _close(self) -> None:
        # Reached only after callback ownership and all serial native work settle.
        try:
            if self._vault is not None and self._vault.close() is not None:
                raise RuntimeError("native_close_uncertain")
        except BaseException:
            self._uncertain = True
        with self._condition:
            self._hide()
            if self._uncertain:
                self._status, self._reason = (
                    HostStatus.RECOVERY_REQUIRED,
                    HostReason.RECOVERY_REQUIRED,
                )
            else:
                self._status, self._reason = HostStatus.CLOSED, HostReason.CLOSED
            self._active = None
            self._closed_event.set()
            self._condition.notify_all()
