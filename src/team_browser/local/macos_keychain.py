"""Explicit native SecretStore using Security.framework through PyObjC.

Importing this module is inert. Construction requires reviewed app identity,
macOS and the optional PyObjC frameworks; it verifies the signed host before
any Keychain operation. There is no shell, alternate backend, login prompt,
access-list modification, or implicit migration. See docs/macos-keychain.md.

This is a byte SecretStore, NOT the managed sign-in SessionVault contract.
"""

from __future__ import annotations

import re
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterator

from .errors import SecretStoreUnavailable
from .secrets import SecretRef
from .storage import validate_identifier


MAX_SECRET_BYTES = 65536
_SUCCESS = 0
_DUPLICATE = -25299
_NOT_FOUND = -25300
_BUNDLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+")


class KeychainFailure(StrEnum):
    UNAVAILABLE = "unavailable"
    HOST_REJECTED = "host_rejected"
    NOT_FOUND = "not_found"
    INTERACTION_REQUIRED = "interaction_required"
    AUTHORIZATION_DENIED = "authorization_denied"
    MISSING_ENTITLEMENT = "missing_entitlement"
    INVALID_ACKNOWLEDGEMENT = "invalid_acknowledgement"
    INVALID_RECORD = "invalid_record"
    CONCURRENT_CHANGE = "concurrent_change"
    NATIVE_FAILURE = "native_failure"
    ABSENCE_UNCONFIRMED = "absence_unconfirmed"


class KeychainError(SecretStoreUnavailable):
    """Only operation, bounded reason and numeric OSStatus; never native text.

    For a failed mutation, do not infer that no write happened. This interface
    does not persist recovery/quarantine records or make cross-call guarantees.
    """

    def __init__(self, operation: str, reason: KeychainFailure, status: int | None = None):
        self.operation, self.reason, self.status = operation, reason, status
        super().__init__(f"macOS Keychain {operation} failed: {reason.value}")


class SecretNotFound(KeychainError):
    """The exact, non-synchronizing, app-private item was not found."""

    def __init__(self) -> None:
        super().__init__("get", KeychainFailure.NOT_FOUND, _NOT_FOUND)


@dataclass(frozen=True)
class KeychainConfiguration:
    """Trusted installed-app settings, never supplied by a browser/JSON bridge.

    The access group is always the app's own identifier; arbitrary shared groups
    cannot be selected. namespace separates uses such as proxy credentials.
    """

    team_id: str
    bundle_id: str
    namespace: str

    def __post_init__(self) -> None:
        if type(self.team_id) is not str or not re.fullmatch(r"[A-Z0-9]{10}", self.team_id):
            raise ValueError("An explicit Apple signing team identifier is required")
        if (
            type(self.bundle_id) is not str
            or len(self.bundle_id) > 180
            or not _BUNDLE_ID.fullmatch(self.bundle_id)
        ):
            raise ValueError("An explicit reverse-DNS application identifier is required")
        if type(self.namespace) is not str:
            raise ValueError("An explicit opaque Keychain namespace is required")
        validate_identifier(self.namespace)

    @property
    def access_group(self) -> str:
        return f"{self.team_id}.{self.bundle_id}"

    @property
    def service(self) -> str:
        return f"{self.bundle_id}.keychain.v1.{self.namespace}"


@dataclass(frozen=True, repr=False)
class _Frameworks:
    security: object
    foundation: object
    local_authentication: object
    objc: object


def _load_frameworks() -> _Frameworks:
    # Never probe alternate keyrings or import Objective-C frameworks on Linux.
    if sys.platform != "darwin":
        raise KeychainError("open", KeychainFailure.UNAVAILABLE)
    try:
        import Foundation
        import LocalAuthentication
        import objc
        import Security

        return _Frameworks(Security, Foundation, LocalAuthentication, objc)
    except Exception:
        raise KeychainError("open", KeychainFailure.UNAVAILABLE) from None


def _status(value: object, operation: str) -> int:
    # False is not errSecSuccess; neither a float nor a truthy wrapper is OSStatus.
    if type(value) is not int or not -(2**31) <= value < 2**31:
        raise KeychainError(operation, KeychainFailure.INVALID_ACKNOWLEDGEMENT)
    return value


def _pair(value: object, operation: str) -> tuple[int, object]:
    if type(value) is not tuple or len(value) != 2:
        raise KeychainError(operation, KeychainFailure.INVALID_ACKNOWLEDGEMENT)
    return _status(value[0], operation), value[1]


def _failure(operation: str, status: int) -> KeychainError:
    reason = {
        -25308: KeychainFailure.INTERACTION_REQUIRED,
        -25293: KeychainFailure.AUTHORIZATION_DENIED,
        -128: KeychainFailure.AUTHORIZATION_DENIED,
        -34018: KeychainFailure.MISSING_ENTITLEMENT,
        -25291: KeychainFailure.UNAVAILABLE,
    }.get(status, KeychainFailure.NATIVE_FAILURE)
    return KeychainError(operation, reason, status)


class MacOSKeychainStore:
    """Native-only, explicit opt-in implementation of SecretStore.

    Configuration and construction belong to a signed, reviewed native host.
    Synchronous calls must run off the UI thread. One instance serializes its
    operations; there is deliberately no claim of cross-process transactions.
    The private framework loader is mocked by Linux tests, never by production.
    """

    def __init__(self, configuration: KeychainConfiguration):
        if type(configuration) is not KeychainConfiguration:
            raise TypeError("Trusted typed Keychain configuration is required")
        self._configuration = configuration
        self._frameworks = _load_frameworks()
        self._lock = threading.RLock()
        with self._guard("open"):
            self._verify_host()

    @contextmanager
    def _guard(self, operation: str) -> Iterator[None]:
        try:
            with self._lock, self._frameworks.objc.autorelease_pool():
                yield
        except KeychainError:
            raise
        except Exception:
            # Native exceptions may contain query data. Never chain/format them.
            raise KeychainError(operation, KeychainFailure.NATIVE_FAILURE) from None

    def _dictionary(self, value: object) -> bool:
        return isinstance(value, (dict, self._frameworks.foundation.NSDictionary))

    def _required_output(self, value: object) -> object:
        status, result = _pair(value, "open")
        if status != _SUCCESS or result is None:
            raise KeychainError("open", KeychainFailure.HOST_REJECTED, status)
        return result

    def _verify_host(self) -> None:
        """Check running host + signed resources and a constrained app identity.

        This is not a replacement for installer/notarization/provisioning QA.
        PyObjC uses the host executable's entitlements, not this module's path.
        """
        sec = self._frameworks.security
        config = self._configuration
        requirement_text = (
            f'anchor apple generic and identifier "{config.bundle_id}" '
            f'and certificate leaf[subject.OU] = "{config.team_id}"'
        )
        requirement = self._required_output(
            sec.SecRequirementCreateWithString(requirement_text, sec.kSecCSDefaultFlags, None)
        )
        code = self._required_output(sec.SecCodeCopySelf(sec.kSecCSDefaultFlags, None))
        status = _status(
            sec.SecCodeCheckValidity(code, sec.kSecCSDefaultFlags, requirement), "open"
        )
        if status != _SUCCESS:
            raise KeychainError("open", KeychainFailure.HOST_REJECTED, status)
        static = self._required_output(
            sec.SecCodeCopyStaticCode(code, sec.kSecCSDefaultFlags, None)
        )
        status = _status(
            sec.SecStaticCodeCheckValidity(static, sec.kSecCSStrictValidate, requirement), "open"
        )
        if status != _SUCCESS:
            raise KeychainError("open", KeychainFailure.HOST_REJECTED, status)
        info = self._required_output(
            sec.SecCodeCopySigningInformation(static, sec.kSecCSSigningInformation, None)
        )
        if not self._dictionary(info):
            raise KeychainError("open", KeychainFailure.HOST_REJECTED)
        # Merely omitting runtime exception entitlements is insufficient if the
        # executable never enabled hardened runtime in its signature flags.
        flags = info.get(sec.kSecCodeInfoFlags)
        if (
            type(flags) is not int
            or not 0 <= flags < 2**32
            or not flags & sec.kSecCodeSignatureRuntime
        ):
            raise KeychainError("open", KeychainFailure.HOST_REJECTED)
        entitlements = info.get(sec.kSecCodeInfoEntitlementsDict)
        if (
            not self._dictionary(entitlements)
            or info.get(sec.kSecCodeInfoIdentifier) != config.bundle_id
            or info.get(sec.kSecCodeInfoTeamIdentifier) != config.team_id
            or entitlements.get("com.apple.application-identifier") != config.access_group
        ):
            raise KeychainError("open", KeychainFailure.HOST_REJECTED)
        groups = entitlements.get("keychain-access-groups", ())
        if not isinstance(groups, (list, tuple, self._frameworks.foundation.NSArray)):
            raise KeychainError("open", KeychainFailure.HOST_REJECTED)
        if len(groups) > 1 or any(group != config.access_group for group in groups):
            raise KeychainError("open", KeychainFailure.HOST_REJECTED)
        for name in (
            "get-task-allow",
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
        ):
            if entitlements.get(name, False) is not False:
                raise KeychainError("open", KeychainFailure.HOST_REJECTED)

    @contextmanager
    def _context(self, operation: str) -> Iterator[object]:
        context = self._frameworks.local_authentication.LAContext.alloc().init()
        if context is None:
            raise KeychainError(operation, KeychainFailure.UNAVAILABLE)
        try:
            acknowledgement = context.setInteractionNotAllowed_(True)
            if acknowledgement is not None or context.interactionNotAllowed() is not True:
                raise KeychainError(operation, KeychainFailure.INVALID_ACKNOWLEDGEMENT)
            yield context
        finally:
            # The context is not cached and never evaluates a policy/prompt.
            if context.invalidate() is not None:
                raise KeychainError(operation, KeychainFailure.INVALID_ACKNOWLEDGEMENT)

    @staticmethod
    def _account(reference: SecretRef) -> str:
        if type(reference) is not SecretRef:
            raise TypeError("An opaque SecretRef is required")
        validate_identifier(reference.account_id)
        return f"v1:{reference.account_id}"

    def _query(self, account: str, context: object) -> dict:
        sec = self._frameworks.security
        return {
            sec.kSecClass: sec.kSecClassGenericPassword,
            sec.kSecAttrService: self._configuration.service,
            sec.kSecAttrAccount: account,
            sec.kSecAttrAccessGroup: self._configuration.access_group,
            sec.kSecAttrSynchronizable: False,
            sec.kSecUseDataProtectionKeychain: True,
            sec.kSecUseAuthenticationContext: context,
        }

    def put(self, reference: SecretRef, value: bytes) -> None:
        account = self._account(reference)
        if type(value) is not bytes or not 1 <= len(value) <= MAX_SECRET_BYTES:
            raise ValueError("Secret values must be 1–65536 bytes")
        with self._guard("put"), self._context("put") as context:
            sec = self._frameworks.security
            data = self._frameworks.foundation.NSData.dataWithBytes_length_(value, len(value))
            if not isinstance(data, self._frameworks.foundation.NSData):
                raise KeychainError("put", KeychainFailure.INVALID_ACKNOWLEDGEMENT)
            attributes = self._query(account, context)
            attributes[sec.kSecAttrAccessible] = sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            attributes[sec.kSecValueData] = data
            status, result = _pair(sec.SecItemAdd(attributes, None), "put")
            if result is not None:
                raise KeychainError("put", KeychainFailure.INVALID_ACKNOWLEDGEMENT)
            if status == _SUCCESS:
                return None
            if status != _DUPLICATE:
                raise _failure("put", status)
            # No delete-and-add gap, no retry loop, no weakening an old record.
            query = self._query(account, context)
            query[sec.kSecAttrAccessible] = sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            # The server's update path rejects match-query attributes. The full
            # generic-password primary key already identifies at most one item.
            status = _status(sec.SecItemUpdate(query, {sec.kSecValueData: data}), "put")
            if status == _NOT_FOUND:
                raise KeychainError("put", KeychainFailure.CONCURRENT_CHANGE, status)
            if status != _SUCCESS:
                raise _failure("put", status)
            return None

    def get(self, reference: SecretRef) -> bytes:
        account = self._account(reference)
        with self._guard("get"), self._context("get") as context:
            sec = self._frameworks.security
            query = self._query(account, context)
            query.update(
                {
                    sec.kSecReturnAttributes: True,
                    sec.kSecReturnData: True,
                    sec.kSecMatchLimit: sec.kSecMatchLimitOne,
                }
            )
            status, result = _pair(sec.SecItemCopyMatching(query, None), "get")
            if status != _SUCCESS:
                if result is not None:
                    raise KeychainError("get", KeychainFailure.INVALID_ACKNOWLEDGEMENT)
                if status == _NOT_FOUND:
                    raise SecretNotFound()
                raise _failure("get", status)
            if not self._dictionary(result):
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            expected = {
                sec.kSecAttrService: self._configuration.service,
                sec.kSecAttrAccount: account,
                sec.kSecAttrAccessGroup: self._configuration.access_group,
                sec.kSecAttrAccessible: sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            }
            if any(result.get(key) != value for key, value in expected.items()):
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            if result.get(sec.kSecAttrSynchronizable) is not False:
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            data = result.get(sec.kSecValueData)
            if not isinstance(data, self._frameworks.foundation.NSData):
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            size = data.length()
            if type(size) is not int or not 1 <= size <= MAX_SECRET_BYTES:
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            value = bytes(data)
            if len(value) != size:
                raise KeychainError("get", KeychainFailure.INVALID_RECORD)
            return value

    def delete(self, reference: SecretRef) -> None:
        account = self._account(reference)
        with self._guard("delete"), self._context("delete") as context:
            sec = self._frameworks.security
            query = self._query(account, context)
            # The data-protection server rejects a finite delete match limit.
            # Exact generic-password primary-key attributes bound this delete;
            # retain MatchLimitOne only on the subsequent absence query.
            status = _status(sec.SecItemDelete(query), "delete")
            if status not in (_SUCCESS, _NOT_FOUND):
                raise _failure("delete", status)
            # Confirm exact scoped absence without reading any credential bytes.
            query = self._query(account, context)
            query[sec.kSecMatchLimit] = sec.kSecMatchLimitOne
            query[sec.kSecReturnAttributes] = True
            status, result = _pair(sec.SecItemCopyMatching(query, None), "delete")
            if status == _NOT_FOUND and result is None:
                return None
            if status != _SUCCESS and status != _NOT_FOUND:
                raise _failure("delete", status)
            raise KeychainError("delete", KeychainFailure.ABSENCE_UNCONFIRMED, status)
