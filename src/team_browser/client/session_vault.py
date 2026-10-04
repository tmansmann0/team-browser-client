"""Opt-in native, single-session Keychain vault. Importing performs no I/O.

Two reserved OS records form a quarantine protocol, NOT a multi-item transaction.
A kernel lease and current-process commit evidence gate every operation. Each new
instance requires explicit discard/recovery; previous login is never restored.
No public method returns credentials. See docs/session-vault.md.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pwd
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from team_browser.local.macos_keychain import (
    MAX_SECRET_BYTES,
    KeychainConfiguration,
    MacOSKeychainStore,
    SecretNotFound,
)
from team_browser.local.secrets import SecretRef

from .auth_flow import AccountIdentity, NativeSessionMaterial, TrustedOIDCConfiguration

try:
    import fcntl
except ImportError:  # pragma: no cover - unsupported native platform
    fcntl = None


NAMESPACE = "managed-signin"
_JOURNAL = SecretRef("managed-signin-journal-v1")
_PAYLOAD = SecretRef("managed-signin-payload-v1")
_MAX_SESSIONS_PER_EPOCH = 128
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)


class SessionVaultError(RuntimeError):
    """Fixed, secret-free reason; never include native errors or record contents."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Native session vault: {reason}")


class SessionExpired(SessionVaultError):
    def __init__(self):
        super().__init__("session_expired")


def _open_native_store(configuration: KeychainConfiguration) -> MacOSKeychainStore:
    # Tests patch this private seam. Production cannot supply a fallback adapter.
    return MacOSKeychainStore(configuration)


def _lease_directory(configuration: KeychainConfiguration) -> Path:
    # Ignore HOME and workspace/JS paths. Every cooperating host using this exact
    # Keychain service/access group must use the same per-user kernel lock.
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    scope = hashlib.sha256(
        (configuration.access_group + "\0" + configuration.service).encode("ascii")
    ).hexdigest()
    return home / "Library" / "Application Support" / "TeamBrowserSessionVault" / scope


def _private(info: os.stat_result, *, directory: bool) -> None:
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not valid_type
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or (not directory and (info.st_nlink != 1 or info.st_size != 0))
    ):
        raise SessionVaultError("unsafe_lease")


def _open_directory(path: Path, *, create: bool) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise SessionVaultError("unsafe_lease")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _private(os.fstat(fd), directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


class _ProcessLease:
    """Empty, permanent lock inode; never stores a token, identifier or journal."""

    def __init__(self, path: Path):
        self._fd: int | None = None
        self._directory_fd: int | None = None
        self._path, self._pid = path, os.getpid()
        try:
            if fcntl is None:
                raise SessionVaultError("lease_unavailable")
            self._directory_fd = _open_directory(path, create=True)
            self._fd = os.open(
                "owner.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600,
                dir_fd=self._directory_fd,
            )
            _private(os.fstat(self._fd), directory=False)
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_owned()
        except BaseException as error:
            self.close()
            if not isinstance(error, Exception):
                raise
            raise SessionVaultError("lease_unavailable") from None

    def assert_owned(self) -> None:
        if self._fd is None or self._directory_fd is None or self._pid != os.getpid():
            raise SessionVaultError("lease_lost")
        opened = _open_directory(self._path, create=False)
        try:
            current, held = os.fstat(opened), os.fstat(self._directory_fd)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise SessionVaultError("lease_lost")
            actual = os.fstat(self._fd)
            named = os.stat("owner.lock", dir_fd=opened, follow_symlinks=False)
            _private(actual, directory=False)
            _private(named, directory=False)
            if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino):
                raise SessionVaultError("lease_lost")
        finally:
            os.close(opened)

    def close(self) -> None:
        # Never LOCK_UN an inherited descriptor: that would unlock the parent.
        for name in ("_fd", "_directory_fd"):
            fd = getattr(self, name, None)
            setattr(self, name, None)
            if fd is not None:
                os.close(fd)

    def __del__(self):  # pragma: no cover - explicit close is the host contract
        self.close()


@dataclass(frozen=True)
class _SessionPolicy:
    """Immutable native snapshot; never derived from incoming session material."""

    issuer: str | None
    scopes: tuple[str, ...]
    max_ttl_seconds: int

    @classmethod
    def from_configuration(cls, configuration: TrustedOIDCConfiguration | None) -> _SessionPolicy:
        if configuration is None:
            # Compatibility with the original openid-only core. New integrations
            # should supply a pinned config; expanded scopes have no default.
            return cls(None, ("openid",), 3600)
        if type(configuration) is not TrustedOIDCConfiguration:
            raise TypeError("An exact trusted native OIDC configuration is required")
        # Re-run the immutable configuration's existing provider/endpoint/scope/
        # lifetime validation before any native construction or record access.
        validated = replace(configuration)
        return cls(validated.issuer, validated.scopes, validated.local_session_ttl_seconds)


@dataclass(frozen=True, repr=False)
class _CurrentSession:
    session_id: str
    digest: bytes
    expires_at: int
    deadline: float


def _session_id(value: str) -> None:
    if type(value) is not str or not _SESSION_ID.fullmatch(value):
        raise SessionVaultError("invalid_session_reference")


def _plain(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and value.isascii()
        and all(32 < ord(character) < 127 for character in value)
    )


class MacOSSessionVault:
    """Concrete SessionVault for trusted, signed native construction only.

    Synchronous OS calls belong on a native worker. No constructor injection,
    bridge serialization, arbitrary namespace, persisted-login restore, refresh
    tokens or provider revocation. Call recover_discard_all explicitly on each
    start, before constructing a sign-in core; call close when that core retires.
    Pass the same trusted oidc_configuration to this vault and ManagedSignIn to
    pin issuer, exact scopes and local TTL. Omission is legacy openid-only mode.
    """

    def __init__(
        self,
        configuration: KeychainConfiguration,
        *,
        oidc_configuration: TrustedOIDCConfiguration | None = None,
    ):
        if type(configuration) is not KeychainConfiguration or configuration.namespace != NAMESPACE:
            raise TypeError("Trusted Keychain configuration with managed-signin namespace required")
        self._policy = _SessionPolicy.from_configuration(oidc_configuration)
        self._lock = threading.RLock()
        self._closed = False
        self._quarantined = True
        self._expected_journal: bytes | None = None
        self._current: _CurrentSession | None = None
        self._used: set[str] = set()
        self._epoch = ""
        self._revision = 0
        self._last_clock: tuple[float, float] | None = None
        self._store = _open_native_store(configuration)  # verifies host; fails closed on Linux
        self._lease = _ProcessLease(_lease_directory(configuration))
        # No OS record read here. Even an apparently clean old marker is not
        # permission to expose previous-process data or infer successful cleanup.

    def _fail(self) -> None:
        self._quarantined = True
        self._expected_journal = None
        self._current = None

    def _owned(self) -> None:
        if self._closed:
            raise SessionVaultError("closed")
        self._lease.assert_owned()

    def _clock(self) -> tuple[float, float]:
        wall, monotonic = time.time(), time.monotonic()
        if any(
            type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in (wall, monotonic)
        ):
            raise SessionVaultError("invalid_clock")
        if self._last_clock is not None and any(
            new < old for new, old in zip((wall, monotonic), self._last_clock, strict=True)
        ):
            raise SessionVaultError("clock_rollback")
        self._last_clock = wall, monotonic
        return wall, monotonic

    def _optional(self, reference: SecretRef) -> bytes | None:
        try:
            value = self._store.get(reference)
        except SecretNotFound:
            return None
        if type(value) is not bytes or not 1 <= len(value) <= MAX_SECRET_BYTES:
            raise SessionVaultError("invalid_record")
        return value

    def _put(self, reference: SecretRef, value: bytes) -> None:
        if self._store.put(reference, value) is not None:
            raise SessionVaultError("invalid_acknowledgement")
        if self._optional(reference) != value:
            raise SessionVaultError("write_unconfirmed")

    def _erase_payload(self) -> None:
        if self._store.delete(_PAYLOAD) is not None:
            raise SessionVaultError("invalid_acknowledgement")
        if self._optional(_PAYLOAD) is not None:
            raise SessionVaultError("absence_unconfirmed")

    def _journal(self, state: str, digest: bytes | None = None) -> bytes:
        self._revision += 1
        return json.dumps(
            {
                "version": 1,
                "epoch": self._epoch,
                "revision": self._revision,
                "state": state,
                "digest": digest.hex() if digest else None,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    def _quarantine(self) -> None:
        self._quarantined = True
        self._put(_JOURNAL, self._journal("quarantined"))

    def _commit(self, session: _CurrentSession | None) -> None:
        marker = self._journal("ready", session.digest if session else None)
        self._put(_JOURNAL, marker)
        self._expected_journal = marker
        self._current = session
        self._quarantined = False

    def _ready(self) -> None:
        self._owned()
        if self._quarantined or self._expected_journal is None:
            raise SessionVaultError("recovery_required")
        self._clock()
        if self._optional(_JOURNAL) != self._expected_journal:
            raise SessionVaultError("journal_changed")

    def _delete_current(self) -> None:
        self._quarantine()  # durable acknowledgement BEFORE every payload mutation
        self._erase_payload()
        self._commit(None)

    def _check_payload(self) -> None:
        current = self._current
        wall, monotonic = self._clock()
        if current and (wall >= current.expires_at or monotonic >= current.deadline):
            self._delete_current()
            raise SessionExpired()
        value = self._optional(_PAYLOAD)
        if current is None:
            if value is not None:
                raise SessionVaultError("unexpected_record")
        elif value is None or hashlib.sha256(value).digest() != current.digest:
            raise SessionVaultError("record_changed")
        # A blocked Keychain read must not extend validity past its deadline.
        wall, monotonic = self._clock()
        if current and (wall >= current.expires_at or monotonic >= current.deadline):
            self._delete_current()
            raise SessionExpired()

    def recover_discard_all(self) -> None:
        """Explicit native recovery; discard this vault's one reserved payload.

        Never call automatically after an uncertain operation. Retire the old
        sign-in core first: this does not clear its recovery_required state or
        revoke anything at the provider. Recovery never reads an old payload.
        """
        with self._lock:
            try:
                self._owned()
                self._fail()
                self._last_clock = None
                self._clock()
                self._epoch = secrets.token_hex(32)
                self._revision = 0
                self._used.clear()
                self._quarantine()
                self._erase_payload()
                self._commit(None)
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
        return None

    def assert_available(self) -> None:
        with self._lock:
            try:
                self._ready()
                self._check_payload()
            except SessionExpired:
                # Exact cleanup is complete; there is simply no current record.
                return None
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
        return None

    def store_session(self, session_id: str, material: NativeSessionMaterial) -> None:
        _session_id(session_id)
        if (
            type(material) is not NativeSessionMaterial
            or type(material.identity) is not AccountIdentity
            or not _plain(material.access_token, 16384)
            or not _plain(material.id_token, 16384)
            or type(material.expires_at) is not int
            or type(material.scopes) is not tuple
            or any(type(scope) is not str for scope in material.scopes)
            or material.scopes != self._policy.scopes
            or (self._policy.issuer is not None and material.identity.issuer != self._policy.issuer)
        ):
            raise SessionVaultError("invalid_material")
        with self._lock:
            try:
                self._ready()
                self._check_payload()
                if self._current or session_id in self._used:
                    raise SessionVaultError("session_replay_or_occupied")
                if len(self._used) >= _MAX_SESSIONS_PER_EPOCH:
                    raise SessionVaultError("epoch_exhausted")
                wall, monotonic = self._clock()
                if not 0 < material.expires_at - wall <= self._policy.max_ttl_seconds:
                    raise SessionVaultError("invalid_expiry")
                payload = json.dumps(
                    {
                        "version": 1,
                        "epoch": self._epoch,
                        "session_id": session_id,
                        "issuer": material.identity.issuer,
                        "subject": material.identity.subject,
                        "access_token": material.access_token,
                        "id_token": material.id_token,
                        "expires_at": material.expires_at,
                        "scopes": list(material.scopes),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                if len(payload) > MAX_SECRET_BYTES:
                    raise SessionVaultError("invalid_material")
                self._used.add(session_id)
                current = _CurrentSession(
                    session_id,
                    hashlib.sha256(payload).digest(),
                    material.expires_at,
                    monotonic + (material.expires_at - wall),
                )
                self._quarantine()
                self._put(_PAYLOAD, payload)
                self._commit(current)
                self._check_payload()
            except SessionExpired:
                raise  # confirmed cleanup; no record escaped this method
            except BaseException as error:
                self._fail()  # core cleanup must not turn uncertainty into ERROR/READY
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
        return None

    def delete_session(self, session_id: str) -> None:
        _session_id(session_id)
        with self._lock:
            try:
                self._ready()
                if self._current and self._current.session_id == session_id:
                    self._delete_current()
                else:
                    # Confirm the bounded slot is absent or belongs to a different
                    # current session. Never interpret an unknown ID as its key.
                    self._check_payload()
            except SessionExpired:
                return None  # exact reserved payload absence was confirmed
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
        return None

    def assert_session_current(self, session_id: str) -> None:
        """Native-only liveness check. Returns no tokens or session material.

        There is deliberately no general get-token/with-token API. The private
        managed-session consumer below can perform only three backend reads.
        """
        _session_id(session_id)
        with self._lock:
            try:
                self._ready()
                self._check_payload()
                if self._current is None or self._current.session_id != session_id:
                    raise SessionVaultError("session_not_found")
            except SessionExpired:
                raise
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
        return None

    def _managed_consumer(self, consumer) -> None:
        # A single exact reviewed backend client, never an arbitrary callback or
        # duck-typed transport receiving credentials. Imports avoid a module cycle.
        from .managed_session import NativeManagedSession

        if type(consumer) is not NativeManagedSession or consumer._vault is not self:
            raise TypeError("An exact native managed consumer is required")
        policy = _SessionPolicy.from_configuration(consumer._configuration.oidc_configuration)
        if self._policy != policy or policy.issuer is None:
            raise SessionVaultError("managed_policy_mismatch")

    def _managed_deadline(self) -> None:
        # Call only while holding the vault lock. Native lease checks can also
        # be slow, so finish with clocks rather than with another OS read.
        current = self._current
        wall, monotonic = self._clock()
        if current and (wall >= current.expires_at or monotonic >= current.deadline):
            self._delete_current()
            raise SessionExpired()

    def _bind_managed_consumer(self, consumer) -> None:
        self._managed_consumer(consumer)
        with self._lock:
            try:
                self._ready()
                self._check_payload()
                self._owned()  # Recheck lease after potentially slow native reads.
                self._managed_deadline()
            except SessionExpired:
                raise
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
            if self._current is None:
                raise SessionVaultError("session_not_found")
            consumer._session_id = self._current.session_id
            consumer._epoch = self._epoch
            consumer._expires_at = self._current.expires_at

    def _assert_managed_current(self, consumer) -> None:
        self._managed_consumer(consumer)
        with self._lock:
            try:
                self._ready()
                if (
                    consumer._epoch != self._epoch
                    or self._current is None
                    or consumer._session_id != self._current.session_id
                ):
                    # Reject stale bindings before even expiry cleanup of a
                    # later owner's payload. Never delete/poison a later login.
                    raise SessionVaultError("session_not_current")
                self._check_payload()
                self._owned()  # Lease can change during a slow native store read.
                self._managed_deadline()
            except SessionExpired:
                raise
            except BaseException as error:
                if isinstance(error, SessionVaultError) and error.reason == "session_not_current":
                    raise
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None

    def _managed_read(self, consumer, operation):
        from .managed_session import _Read

        if type(operation) is not _Read:
            raise TypeError("An exact backend-bound read operation is required")
        return self._managed_exchange(consumer, operation)

    def _managed_device_exchange(self, consumer, operation):
        from .device_client import _DeviceWireRequest

        if type(operation) is not _DeviceWireRequest:
            raise TypeError("An exact backend-bound device operation is required")
        return self._managed_exchange(consumer, operation)

    def _managed_exchange(self, consumer, operation):
        from .managed_session import _BackendHTTPS, _Read, _projection, ManagedSessionError
        from .device_client import _DeviceWireRequest, _device_projection, _device_response_text

        self._managed_consumer(consumer)
        device = type(operation) is _DeviceWireRequest
        if (type(operation) is not _Read and not device) or type(
            consumer._transport
        ) is not _BackendHTTPS:
            raise TypeError("An exact backend-bound operation is required")
        if device and (consumer._membership is None or consumer._member_binding is None):
            raise ManagedSessionError("membership_required")
        with self._lock:
            self._assert_managed_current(consumer)
            try:
                value = self._optional(_PAYLOAD)
                if value is None or hashlib.sha256(value).digest() != self._current.digest:
                    raise SessionVaultError("record_changed")
                record = json.loads(value)
                if (
                    record["epoch"] != self._epoch
                    or record["session_id"] != consumer._session_id
                    or record["issuer"] != self._policy.issuer
                    or record["scopes"] != list(self._policy.scopes)
                    or record["expires_at"] != self._current.expires_at
                    or not _plain(record["access_token"], 16384)
                    or not _plain(record["id_token"], 16384)
                ):
                    raise SessionVaultError("record_changed")
            except BaseException as error:
                self._fail()
                if not isinstance(error, Exception):
                    raise
                raise SessionVaultError("recovery_required") from None
            # Includes the extra potentially slow record read. The fixed
            # transport checks again after DNS/TLS and before sending a bearer.
            self._assert_managed_current(consumer)
            try:
                if device:
                    operation.assert_current()
                    response = consumer._transport._device(operation, record["access_token"])
                    path = operation.path
                else:
                    response = consumer._transport._get(operation, record["access_token"])
                    path = operation.value
                if response.url != consumer._configuration.origin + path:
                    raise ManagedSessionError("invalid_response")
                result = (
                    _device_projection(operation, response)
                    if device
                    else _projection(operation, response)
                )
                # Defensively reject credential reflection even in otherwise
                # valid schema fields, including native-only challenge values.
                if device:
                    encoded = _device_response_text(result)
                else:
                    public = (
                        [item.public() for item in result]
                        if type(result) is tuple
                        else result.public()
                    )
                    encoded = json.dumps(public, ensure_ascii=True)
                if any(
                    json.dumps(record[name])[1:-1] in encoded
                    for name in ("access_token", "id_token")
                ):
                    raise ManagedSessionError("invalid_response")
            except SessionExpired:
                # The trusted pre-send check already confirmed scoped deletion.
                # A second check must not misreport that clean expiry as recovery.
                raise
            except BaseException:
                self._assert_managed_current(consumer)
                raise
            # Covers slow responses, parsing, changed journals and lease loss.
            self._assert_managed_current(consumer)
            return result

    def _logout_managed_consumer(self, consumer) -> None:
        self._managed_consumer(consumer)
        with self._lock:
            try:
                self._assert_managed_current(consumer)
            except SessionExpired:
                return None  # Expiry already confirmed this payload's deletion.
            except SessionVaultError as error:
                if (
                    error.reason == "session_not_current"
                    and self._current is None
                    and consumer._epoch == self._epoch
                ):
                    # Check absence again rather than trusting an empty Python
                    # slot after external native-store changes.
                    return self.assert_available()
                raise
            return self.delete_session(consumer._session_id)

    def close(self) -> None:
        """Release ownership, retaining OS records for explicit next-start discard."""
        with self._lock:
            self._closed = True
            self._fail()
            self._lease.close()

    def __enter__(self) -> MacOSSessionVault:
        self._owned()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
