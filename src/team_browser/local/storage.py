"""Private, persistent profile directories and crash-released POSIX leases.

The lock descriptor, not a PID file or age threshold, owns a lease. Never
unlink lock files: doing so could give two clients locks on different inodes.
This protects cooperating clients on a local filesystem, not hostile processes
running as the same OS user, network filesystems, or a detached browser child.
An eventual process supervisor must retain the lease for the browser lifetime.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import LocalClientError, ProfileInUseError, UnsafePathError

try:
    import fcntl
except ImportError:  # pragma: no cover - explicit fail-closed on Windows
    fcntl = None  # type: ignore[assignment]


_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)


def validate_identifier(value: str) -> str:
    """Accept opaque lowercase IDs only; IDs never double as file paths."""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Identifier must be 1–64 lowercase ASCII letters, digits, '_' or '-'")
    return value


def default_profile_root() -> Path:
    """Mac-first location; non-macOS callers must choose an explicit test root."""
    if sys.platform != "darwin":
        raise LocalClientError("An explicit profile root is required outside macOS")
    return Path.home() / "Library" / "Application Support" / "TeamBrowserManager" / "profiles"


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise UnsafePathError("This platform lacks required safe directory operations")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _check_private(fd: int, *, directory: bool) -> None:
    info = os.fstat(fd)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_uid != os.getuid():
        raise UnsafePathError("Local storage must be owned by the current OS user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UnsafePathError("Local storage must not be accessible to group or other users")
    if not directory and info.st_nlink != 1:
        raise UnsafePathError("Hard-linked state files are not allowed")


def _open_private_root(path: Path) -> int:
    """Walk absolute components through directory FDs, refusing every symlink."""
    if not path.is_absolute() or ".." in path.parts:
        raise UnsafePathError("Profile root must be an absolute path without '..'")
    flags = _directory_flags()
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _check_private(fd, directory=True)
        return fd
    except (OSError, UnsafePathError) as exc:
        os.close(fd)
        if isinstance(exc, UnsafePathError):
            raise
        raise UnsafePathError("Cannot safely open the profile root") from exc


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafePathError("Cannot safely open a profile directory") from exc
    try:
        _check_private(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True)
class ProfilePaths:
    profile_id: str
    directory: Path
    browser_data: Path


class ProfileLease:
    """An exclusive open-descriptor lease; release is idempotent.

    Stale metadata is diagnostic only. Kernel lock availability is the sole
    crash-recovery decision, so an unknown or reused PID is never killed.
    """

    def __init__(self, fd: int, paths: ProfilePaths, prior: dict[str, Any] | None):
        self._fd: int | None = fd
        self.paths = paths
        self.token = uuid.uuid4().hex
        self.previous_metadata = prior
        self.recovered_unclean_lease = prior is not None and prior.get("state") == "active"
        self._owner_pid = os.getpid()
        self._write_state("active")

    @property
    def active(self) -> bool:
        return self._fd is not None and self._owner_pid == os.getpid()

    def _write_state(self, state: str) -> None:
        assert self._fd is not None
        payload = json.dumps(
            {
                "schema": 1,
                "state": state,
                "lease_id": self.token,
                "pid": self._owner_pid,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.ftruncate(self._fd, 0)
        written = 0
        while written < len(payload):
            written += os.write(self._fd, payload[written:])
        os.fsync(self._fd)

    def release(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        if self._owner_pid != os.getpid():
            # Do not unlock a descriptor inherited from the owning parent.
            self._fd = None
            os.close(fd)
            return
        try:
            self._write_state("released")
        finally:
            self._fd = None
            os.close(fd)  # Close releases flock; never remove its inode.

    def __enter__(self) -> ProfileLease:
        if not self.active:
            raise LocalClientError("The profile lease is not active in this process")
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


class ProfileStore:
    """Local metadata only. Never synchronizes browser data or credentials."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root is not None else default_profile_root()
        # Validate/create immediately; existing unsafe permissions are not changed.
        fd = _open_private_root(self.root)
        os.close(fd)

    def _open_profile(self, profile_id: str) -> tuple[int, ProfilePaths]:
        validate_identifier(profile_id)
        root_fd = _open_private_root(self.root)
        try:
            fd = _open_child_directory(root_fd, profile_id)
        finally:
            os.close(root_fd)
        try:
            data_fd = _open_child_directory(fd, "browser-data")
            os.close(data_fd)
        except BaseException:
            os.close(fd)
            raise
        directory = self.root / profile_id
        return fd, ProfilePaths(profile_id, directory, directory / "browser-data")

    def prepare(self, profile_id: str) -> ProfilePaths:
        fd, paths = self._open_profile(profile_id)
        os.close(fd)
        return paths

    def acquire(self, profile_id: str) -> ProfileLease:
        if fcntl is None:
            raise LocalClientError("POSIX advisory locking is required")
        directory_fd, paths = self._open_profile(profile_id)
        fd: int | None = None
        try:
            fd = os.open(
                ".lease.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600,
                dir_fd=directory_fd,
            )
            _check_private(fd, directory=False)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ProfileInUseError("The profile is already in use") from exc
            raw = os.read(fd, 4097)
            prior = None
            if len(raw) <= 4096:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        prior = parsed
                except (ValueError, UnicodeError):
                    pass  # Torn crash metadata is not an authority or a blocker.
            lease = ProfileLease(fd, paths, prior)
            fd = None  # Ownership transfers to the lease.
            return lease
        except OSError as exc:
            raise UnsafePathError("Cannot safely acquire the profile lease") from exc
        finally:
            os.close(directory_fd)
            if fd is not None:
                os.close(fd)
