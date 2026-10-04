"""Debian Chromium package provenance for an explicitly reviewed local pilot.

The operator's independent SHA-256 pin binds the executable. The trusted local
dpkg database establishes installed-package identity and checks package content.
These are not vendor-signature or notarization claims. This path never installs
software, fabricates native acceptance, or weakens browser/host protections.
"""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimePolicy, VerifiedRuntime, _hash_regular_file


CHROMIUM = Path("/usr/lib/chromium/chromium")
DPKG = Path("/usr/bin/dpkg")
QUERY = Path("/usr/bin/dpkg-query")
DATABASE = Path("/var/lib/dpkg")
PACKAGE_NAMES = frozenset({"chromium", "chromium-common", "chromium-sandbox"})
PROVENANCE = "debian-installed-package:chromium"
_PACKAGE = re.compile(r"(chromium(?:-common|-sandbox)?):([a-z0-9][a-z0-9-]*)\Z")
_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
_MAX_OUTPUT = 4 * 1024 * 1024


def _bounded_run(command, **kwargs):
    """Drain both pipes with a real aggregate byte limit and wall-clock bound."""
    timeout = kwargs.pop("timeout")
    for name in ("capture_output", "text", "encoding", "errors", "check"):
        kwargs.pop(name)
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    ) as process:
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        deadline = time.monotonic() + timeout
        total = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream in streams:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > _MAX_OUTPUT:
                            raise RuntimeVerificationError(
                                "Linux package inventory output exceeds its safe limit"
                            )
                        streams[key.fileobj].extend(chunk)
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        return subprocess.CompletedProcess(
            command,
            code,
            bytes(streams[process.stdout]).decode("utf-8", errors="strict"),
            bytes(streams[process.stderr]).decode("utf-8", errors="strict"),
        )


def _system_path(path: Path, *, directory: bool = False) -> None:
    """Require fixed, non-symlinked system paths not writable by this user."""
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeVerificationError("Linux runtime paths must be absolute without traversal")
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except OSError:
            raise RuntimeVerificationError(
                f"Required Linux system path is unavailable: {path}"
            ) from None
        if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeVerificationError(
                "Linux system paths cannot be symlinked or publicly writable"
            )
        if component != Path(component.anchor) and info.st_uid != 0:
            raise RuntimeVerificationError(
                "Debian package provenance requires root-owned system paths"
            )
        if component != Path(component.anchor) and os.access(component, os.W_OK):
            raise RuntimeVerificationError(
                "Linux runtime provenance must not be writable by the client"
            )
    # The loop ends at the root; inspect the selected path separately.
    selected = path.lstat()
    valid_kind = stat.S_ISDIR(selected.st_mode) if directory else stat.S_ISREG(selected.st_mode)
    if not valid_kind:
        raise RuntimeVerificationError("Linux system path has an unexpected file type")


def _manifest(raw: str) -> dict[str, str]:
    """Reject malformed/ambiguous checksums; dpkg can otherwise skip coverage."""
    result: dict[str, str] = {}
    for line in raw.splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  (.+)", line)
        if match is None:
            raise RuntimeVerificationError("Installed package checksum metadata is malformed")
        digest, name = match.groups()
        path = Path(name)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or str(path) != name
            or name in result
        ):
            raise RuntimeVerificationError("Installed package checksum paths are ambiguous")
        result[name] = digest
    if not result:
        raise RuntimeVerificationError("Installed package checksum coverage is missing")
    return result


@dataclass(frozen=True)
class LinuxPackageMetadata:
    version: str
    executable_name: str
    package_inventory: tuple[tuple[str, str, str, str], ...]


class LinuxPackageRuntimeGate:
    """Explicit Linux provenance gate, deliberately separate from SignatureEvidence.

    The narrow supported layout is Debian's Chromium, chromium-common and
    chromium-sandbox, with exact architecture-qualified package/version pins.
    OS libraries and the package database remain part of the trusted host.
    """

    def __init__(self, package_versions: dict[str, str], *, runner=None, path_checker=None):
        if not isinstance(package_versions, dict) or len(package_versions) != 3:
            raise ValueError("Pin Chromium, chromium-common and chromium-sandbox packages")
        parsed = [_PACKAGE.fullmatch(name) for name in package_versions]
        if (
            any(match is None for match in parsed)
            or {match[1] for match in parsed if match} != PACKAGE_NAMES
            or len({match[2] for match in parsed if match}) != 1
        ):
            raise ValueError("Pin all three Debian Chromium packages for one exact architecture")
        for version in package_versions.values():
            if (
                not isinstance(version, str)
                or not version
                or len(version) > 128
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in version)
            ):
                raise ValueError("Every Linux package needs an exact bounded version")
        self.package_versions = dict(package_versions)
        self.primary = next(name for name in package_versions if name.split(":")[0] == "chromium")
        self.runner = runner or _bounded_run
        self.path_checker = path_checker or _system_path

    def _command(self, tool: Path, *args: str) -> str:
        self.path_checker(tool)
        if not os.access(tool, os.X_OK):
            raise RuntimeVerificationError("Linux package inventory tool is not executable")
        try:
            result = self.runner(
                [str(tool), "--root=/", f"--admindir={DATABASE}", *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=20,
                check=False,
                shell=False,
                cwd="/",
                env=dict(_ENVIRONMENT),
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise RuntimeVerificationError(
                "Linux package inventory check could not complete"
            ) from None
        if (
            result.returncode != 0
            or result.stderr
            or not isinstance(result.stdout, str)
            or len(result.stdout) > _MAX_OUTPUT
        ):
            raise RuntimeVerificationError(
                "Linux Chromium package provenance is unavailable or inconsistent; "
                "a registered reviewed Debian installation is required"
            )
        return result.stdout

    def observe(self, executable: Path) -> LinuxPackageMetadata:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise RuntimeVerificationError("Linux package runtime requires a non-root Linux client")
        if Path(executable) != CHROMIUM:
            raise RuntimeVerificationError(
                "Linux package runtime supports only Debian's installed Chromium path"
            )
        self.path_checker(CHROMIUM)
        if not os.access(CHROMIUM, os.X_OK):
            raise RuntimeVerificationError("Linux runtime executable permission is missing")
        try:
            fd = os.open(CHROMIUM, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.read(fd, 4) != b"\x7fELF":
                    raise RuntimeVerificationError(
                        "Linux runtime must be the actual installed ELF executable"
                    )
            finally:
                os.close(fd)
        except OSError:
            raise RuntimeVerificationError(
                "Linux runtime executable cannot be safely inspected"
            ) from None
        self.path_checker(DATABASE, directory=True)
        self.path_checker(DATABASE / "info", directory=True)
        self.path_checker(DATABASE / "status")
        inventory = []
        manifests = {}
        for package, pinned_version in sorted(self.package_versions.items()):
            summary = self._command(
                QUERY,
                "--show",
                "--showformat=${Package}\n${Architecture}\n${Version}\n${db:Status-Status}\n${db:Status-Eflag}\n",
                package,
            ).splitlines()
            name, architecture = package.split(":")
            if summary != [name, architecture, pinned_version, "installed", "ok"]:
                raise RuntimeVerificationError(
                    "Installed Linux package identity/version does not match the reviewed policy"
                )
            control_path = self._command(QUERY, "--control-path", package, "md5sums")
            expected_paths = {
                str(DATABASE / "info" / f"{package}.md5sums"),
                str(DATABASE / "info" / f"{name}.md5sums"),
            }
            if control_path.rstrip("\n") not in expected_paths or control_path.count("\n") > 1:
                raise RuntimeVerificationError("Installed package checksum location is unexpected")
            self.path_checker(Path(control_path.rstrip("\n")))
            raw = self._command(QUERY, "--control-show", package, "md5sums")
            manifests[package] = _manifest(raw)
            # .list is dpkg's internal inventory, not a --control-path item.
            # Derive its exact sibling from the already validated control path.
            list_path = Path(control_path.rstrip("\n")).with_suffix(".list")
            self.path_checker(list_path)
            files = self._command(QUERY, "--listfiles", package)
            entries = files.splitlines()
            if not entries or len(set(entries)) != len(entries):
                raise RuntimeVerificationError(
                    "Installed package file inventory is missing or ambiguous"
                )
            for entry in entries:
                if entry in {"/.", "/"}:
                    continue
                if (
                    not entry.startswith("/")
                    or str(Path(entry)) != entry
                    or ".." in Path(entry).parts
                ):
                    raise RuntimeVerificationError(
                        "Installed package file inventory paths are malformed"
                    )
            for payload in manifests[package]:
                payload_path = Path("/") / payload
                if str(payload_path) not in entries:
                    raise RuntimeVerificationError(
                        "Installed package checksum file is absent from its file inventory"
                    )
                self.path_checker(payload_path)
            inventory.append(
                (
                    package,
                    pinned_version,
                    hashlib.sha256(raw.encode()).hexdigest(),
                    hashlib.sha256(files.encode()).hexdigest(),
                )
            )
        selected = str(CHROMIUM).lstrip("/")
        if selected not in manifests[self.primary]:
            raise RuntimeVerificationError(
                "The installed executable has no package checksum coverage"
            )
        ownership = self._command(QUERY, "--search", str(CHROMIUM)).splitlines()
        if ownership not in (
            [f"{self.primary}: {CHROMIUM}"],
            [f"chromium: {CHROMIUM}"],
        ):
            raise RuntimeVerificationError(
                "Linux executable package ownership is ambiguous or diverted"
            )
        return LinuxPackageMetadata(
            self.package_versions[self.primary], CHROMIUM.name, tuple(inventory)
        )

    def verify(
        self,
        executable: Path,
        *,
        observed_version: str,
        policy: RuntimePolicy,
        now: datetime | None = None,
    ) -> VerifiedRuntime:
        now = now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError("An aware timestamp is required")
        if (
            policy.engine_id != "chromium"
            or policy.signer_identity != PROVENANCE
            or policy.require_notarization
        ):
            raise RuntimeVerificationError(
                "Linux package provenance cannot satisfy a vendor-signature policy"
            )
        metadata = self.observe(executable)
        if observed_version != metadata.version or policy.version != metadata.version:
            raise RuntimeVerificationError(
                "Linux installed package version does not match the reviewed pin"
            )
        digest, identity = _hash_regular_file(executable)
        if digest != policy.sha256:
            raise RuntimeVerificationError(
                "Linux runtime SHA-256 does not match the independently reviewed pin"
            )
        for package in sorted(self.package_versions):
            # dpkg returns zero even for changed/missing files; ANY output fails.
            if self._command(DPKG, "--verify", package):
                raise RuntimeVerificationError(
                    "Linux runtime package files are modified or missing"
                )
        if self.observe(executable) != metadata:
            raise RuntimeVerificationError("Linux package metadata changed during verification")
        after_digest, after_identity = _hash_regular_file(executable)
        if (after_digest, after_identity) != (digest, identity):
            raise RuntimeVerificationError("Linux executable changed during verification")
        return VerifiedRuntime(
            "chromium", metadata.version, Path(executable), digest, PROVENANCE, now, identity
        )
