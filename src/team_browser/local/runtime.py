"""Pinned runtime identity gate. Does not download, import, or execute engines.

Pins must come from an independently reviewed release policy, not a manifest
downloaded beside an untrusted binary. Passing a hash check alone never suffices.
Signature checking is an injected, trusted OS-specific adapter; the default
macOS adapter fails closed until implemented and independently exercised.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

from .errors import RuntimeVerificationError
from .storage import validate_identifier


def _valid_digest(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is not None


@dataclass(frozen=True)
class RuntimePolicy:
    engine_id: str
    version: str
    sha256: str
    signer_identity: str
    require_notarization: bool = True

    def __post_init__(self) -> None:
        validate_identifier(self.engine_id)
        if not self.version or len(self.version) > 128 or any(c.isspace() for c in self.version):
            raise ValueError("A bounded, exact runtime version is required")
        if not _valid_digest(self.sha256):
            raise ValueError("An exact lowercase SHA-256 runtime pin is required")
        if not self.signer_identity or len(self.signer_identity) > 256:
            raise ValueError("An exact expected signing identity is required")


@dataclass(frozen=True)
class SignatureEvidence:
    """Evidence returned by trusted platform verification, never caller assertion."""

    artifact_sha256: str
    signer_identity: str
    signature_valid: bool
    notarized: bool
    checked_at: datetime


class SignatureVerifier(Protocol):
    def verify(self, executable: Path, expected_sha256: str) -> SignatureEvidence: ...


class MacOSSignatureVerifier:
    def verify(self, executable: Path, expected_sha256: str) -> SignatureEvidence:
        raise RuntimeVerificationError("macOS signature/notarization adapter is not configured")


@dataclass(frozen=True)
class VerifiedRuntime:
    engine_id: str
    version: str
    executable: Path
    sha256: str
    signer_identity: str
    verified_at: datetime
    # File identity is evidence, not a transferable permission to execute later.
    file_identity: tuple[int, int, int, int]


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _hash_regular_file(path: Path) -> tuple[str, tuple[int, int, int, int]]:
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeVerificationError("Runtime path must be absolute without '..'")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeVerificationError("Safe runtime file inspection is unavailable")
    try:
        # Directory-relative opens avoid a symlink-check/open race in parents.
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
        parent_fd = os.open(path.anchor, flags)
        try:
            for component in path.parts[1:-1]:
                child_fd = os.open(component, flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = child_fd
            # Nonblocking ensures a FIFO cannot hang verification before fstat.
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeVerificationError("Runtime must be a regular file")
            if stat.S_IMODE(before.st_mode) & 0o022:
                raise RuntimeVerificationError("Runtime must not be group/world writable")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
            if _file_identity(before) != _file_identity(after):
                raise RuntimeVerificationError("Runtime changed while being inspected")
            return digest, _file_identity(after)
    except OSError as exc:
        raise RuntimeVerificationError("Runtime file cannot be safely inspected") from exc


class RuntimeGate:
    def __init__(self, verifier: SignatureVerifier | None = None):
        self._verifier = verifier if verifier is not None else MacOSSignatureVerifier()

    def verify(
        self,
        executable: Path,
        *,
        observed_version: str,
        policy: RuntimePolicy,
        now: datetime | None = None,
    ) -> VerifiedRuntime:
        """Check reviewed version+hash pins and OS-signature evidence.

        observed_version comes from trusted package inventory. Never execute an
        unknown binary with --version to discover it. Hash pins bind exact bits;
        production verification also needs the full signed app bundle checked.
        """
        now = now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError("An aware timestamp is required")
        if observed_version != policy.version:
            raise RuntimeVerificationError("Runtime version does not match the pinned version")
        executable = Path(executable)
        digest, identity = _hash_regular_file(executable)
        if not hmac.compare_digest(digest, policy.sha256):
            raise RuntimeVerificationError("Runtime SHA-256 does not match the reviewed pin")
        try:
            evidence = self._verifier.verify(executable, digest)
        except RuntimeVerificationError:
            raise
        except Exception as exc:
            raise RuntimeVerificationError("Runtime signature verification failed") from exc
        if (
            evidence.signature_valid is not True
            or evidence.signer_identity != policy.signer_identity
            or evidence.artifact_sha256 != digest
            or (policy.require_notarization and evidence.notarized is not True)
        ):
            raise RuntimeVerificationError("Runtime signing evidence did not satisfy policy")
        if evidence.checked_at.utcoffset() is None:
            raise RuntimeVerificationError("Runtime signing evidence lacks a timezone")
        age = now - evidence.checked_at
        if age < timedelta(seconds=-5) or age > timedelta(minutes=5):
            raise RuntimeVerificationError("Runtime signing evidence is stale or future-dated")
        # Rehash after signature verification to catch replacement/mutation there.
        checked_digest, checked_identity = _hash_regular_file(executable)
        if checked_identity != identity or not hmac.compare_digest(checked_digest, digest):
            raise RuntimeVerificationError("Runtime changed during signature verification")
        return VerifiedRuntime(
            policy.engine_id,
            policy.version,
            executable,
            digest,
            policy.signer_identity,
            now,
            identity,
        )

    @staticmethod
    def is_unchanged(runtime: VerifiedRuntime) -> bool:
        """A recheck only; production execution still needs atomic supervision."""
        try:
            digest, identity = _hash_regular_file(runtime.executable)
            return identity == runtime.file_identity and hmac.compare_digest(digest, runtime.sha256)
        except RuntimeVerificationError:
            return False
