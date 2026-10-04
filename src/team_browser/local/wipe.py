"""Scoped local-data removal primitive, not a remote authorization endpoint.

Only app-owned profile data under a held lease is eligible. The caller must be
an authenticated managed command executor with exact tenant/device/generation
binding and must supply a trusted supervisor stop check. This module does not
accept a filesystem path, read cookies, revoke site tokens or erase other copies.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shutil
import stat
from typing import Callable
from uuid import uuid4

from .errors import LocalClientError
from .storage import ProfileLease, _open_private_root


class WipeRejected(LocalClientError):
    pass


@dataclass(frozen=True)
class WipeResult:
    profile_id: str
    local_data_removed: bool
    removed_generations: int
    limitation: str = "Browser profile files only; vault entries, copied data and website session tokens are not revoked."


def wipe_profile_data(
    lease: ProfileLease, *, confirm_stopped: Callable[[ProfileLease], bool]
) -> WipeResult:
    """Remove browser-data and previous interrupted wipe tombstones safely.

    confirm_stopped is trusted local supervisor code, never a request body flag.
    It must establish no live owned browser process before deletion. Disk-level
    secure erasure is not promised. Failures keep data quarantined for an explicit
    retry and must not be acknowledged as a successful remote wipe.
    """
    if not lease.active:
        raise WipeRejected("An active profile lease is required")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise WipeRejected("Safe directory removal is unavailable on this platform")
    try:
        stopped = confirm_stopped(lease)
    except Exception as exc:
        raise WipeRejected("Process termination could not be confirmed") from exc
    if stopped is not True:
        raise WipeRejected("Process termination must be positively confirmed")
    try:
        directory_fd = _open_private_root(lease.paths.directory)
    except LocalClientError as exc:
        raise WipeRejected("Profile directory is not safely accessible") from exc
    try:
        # Confirm that the held lock is still the exact lock in this directory.
        lock_info = os.stat(".lease.lock", dir_fd=directory_fd, follow_symlinks=False)
        if lease._fd is None:
            raise WipeRejected("Profile lease ended before removal")
        held_info = os.fstat(lease._fd)
        if (lock_info.st_dev, lock_info.st_ino) != (held_info.st_dev, held_info.st_ino):
            raise WipeRejected("Profile directory changed after lease acquisition")
        data_info = os.stat("browser-data", dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(data_info.st_mode) or data_info.st_uid != os.getuid():
            raise WipeRejected("Browser data is not an owned directory")
        tombstone = ".wipe-" + uuid4().hex
        os.rename("browser-data", tombstone, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.mkdir("browser-data", mode=0o700, dir_fd=directory_fd)
        os.fsync(directory_fd)
        removed = 0
        for name in os.listdir(directory_fd):
            if not re.fullmatch(r"\.wipe-[0-9a-f]{32}", name):
                continue
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise WipeRejected("Unsafe interrupted-wipe entry requires manual review")
            shutil.rmtree(name, dir_fd=directory_fd)
            removed += 1
        os.fsync(directory_fd)
        return WipeResult(lease.paths.profile_id, True, removed)
    except OSError as exc:
        raise WipeRejected(
            "Local data removal was not confirmed; retry through the approved workflow"
        ) from exc
    finally:
        os.close(directory_fd)
