"""OS-keychain-only secret boundary. No environment/file/plaintext fallback.

SecretRef is safe configuration metadata. Secret bytes belong only in the
approved backend and transient process memory, never logs, launch arguments,
profile manifests, API payloads, or repository files. Python cannot guarantee
zeroization of immutable bytes; callers must minimize their lifetime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .errors import SecretStoreUnavailable
from .storage import validate_identifier


@dataclass(frozen=True)
class SecretRef:
    account_id: str

    def __post_init__(self) -> None:
        validate_identifier(self.account_id)


class SecretStore(Protocol):
    """Implement with a vetted native Keychain binding, not a generic fallback."""

    def put(self, reference: SecretRef, value: bytes) -> None: ...

    def get(self, reference: SecretRef) -> bytes: ...

    def delete(self, reference: SecretRef) -> None: ...


class MacOSKeychainStore:
    """Explicit integration placeholder, intentionally incapable of storing data.

    A production implementation must use Security.framework (or a vetted binding)
    with an appropriate access-control policy. It must not shell out with secrets
    on the command line or let keyring select an insecure alternate backend.
    """

    @staticmethod
    def _unavailable() -> None:
        raise SecretStoreUnavailable("macOS Keychain integration has not been configured")

    def put(self, reference: SecretRef, value: bytes) -> None:
        self._unavailable()

    def get(self, reference: SecretRef) -> bytes:
        self._unavailable()
        raise AssertionError("unreachable")

    def delete(self, reference: SecretRef) -> None:
        self._unavailable()
