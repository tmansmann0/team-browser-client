"""Trusted installed Chromium execution boundary; no downloads or web configuration.

The CLI-supported macOS path combines a private reviewed runtime policy, system
signature verification and an optional built-in Playwright pipe supervisor.
Only explicitly selected local-direct networking is currently enabled. Default
app wiring has no policy and therefore cannot launch an unreviewed executable.

A separate POSIX subprocess-group implementation is Linux-only and requires an
acceptance record bound to the exact signed runtime pin. Such a record must come
from actual lifetime/window tests, never synthetic contracts. Unknown native
ownership retains the profile lease. No sandbox or security-update flags are
disabled. No existing user's browser data is used.
"""

from __future__ import annotations

import os
import hashlib
import plistlib
import signal
import stat
import subprocess
import sys
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from team_browser.local.proxy import (
    ProxyConfiguration,
    ProxyExpectations,
    ProxyProbe,
)
from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, VerifiedRuntime
from team_browser.local.storage import ProfileStore, _check_private

from .lifecycle import GMAIL_INBOX_URL, LaunchContext, ProcessHandle, ProcessStatus
from .store import WorkspaceError


@dataclass(frozen=True)
class InstalledBundleMetadata:
    version: str
    executable_name: str
    info_identity: tuple[int, int, int, int, int]
    info_sha256: str


def read_macos_bundle_metadata(executable: Path) -> InstalledBundleMetadata:
    """Read bounded Info.plist bytes through directory FDs, never execute --version.

    This is an observation of bundle contents, not proof of authenticity. The
    caller must bind it to a successful whole-bundle signature/Gatekeeper check.
    Every path component refuses symlinks; the file must be an unwritable-to-
    other-users regular file with stable identity/content while it is read.
    """
    executable = Path(executable)
    if not executable.is_absolute() or ".." in executable.parts:
        raise RuntimeVerificationError("Installed browser path must be absolute without traversal")
    bundle = next((parent for parent in executable.parents if parent.suffix == ".app"), None)
    if bundle is None or executable.parent != bundle / "Contents" / "MacOS":
        raise RuntimeVerificationError("Installed browser must belong to a macOS app bundle")
    info_path = bundle / "Contents" / "Info.plist"
    max_bytes = 1024 * 1024
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = None
    fd = None
    try:
        parent_fd = os.open(info_path.anchor, directory_flags)
        for component in info_path.parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        fd = os.open(
            info_path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= max_bytes
        ):
            raise RuntimeVerificationError("Bundle Info.plist is not a safe bounded regular file")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        if (
            len(raw) > max_bytes
            or len(raw) != before.st_size
            or identity(before) != identity(after)
        ):
            raise RuntimeVerificationError("Bundle Info.plist changed while being read")
        try:
            values = plistlib.loads(raw)
        except Exception:
            raise RuntimeVerificationError("Bundle Info.plist is malformed") from None
        if not isinstance(values, dict):
            raise RuntimeVerificationError("Bundle Info.plist must contain a dictionary")
        version = values.get("CFBundleShortVersionString")
        executable_name = values.get("CFBundleExecutable")
        if (
            not isinstance(version, str)
            or not version
            or len(version) > 128
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in version)
        ):
            raise RuntimeVerificationError("Bundle version must be a bounded nonempty string")
        if (
            not isinstance(executable_name, str)
            or executable_name != executable.name
            or any(ord(c) < 32 or ord(c) == 127 for c in executable_name)
        ):
            raise RuntimeVerificationError("CFBundleExecutable does not match the selected browser")
        return InstalledBundleMetadata(
            version, executable_name, identity(after), hashlib.sha256(raw).hexdigest()
        )
    except OSError:
        raise RuntimeVerificationError("Bundle Info.plist cannot be safely inspected") from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


class NativeVaultHealth(Protocol):
    """A vetted OS-native implementation only; no plaintext/environment fallback."""

    def assert_available(self) -> None: ...


class NativeWindows(Protocol):
    """Controller observes and addresses the exact owned profile window."""

    def ready(self, profile_id: str, leader_pid: int) -> bool: ...
    def focus(self, profile_id: str, leader_pid: int) -> bool: ...
    def open_gmail(self, profile_id: str, leader_pid: int) -> bool: ...


@dataclass(frozen=True)
class SupervisionAcceptance:
    runtime_sha256: str
    platform: str
    acceptance_test_id: str

    def validate(self, runtime: VerifiedRuntime) -> None:
        if (
            self.platform != sys.platform
            or self.platform != "linux"
            or self.runtime_sha256 != runtime.sha256
            or not self.acceptance_test_id.strip()
        ):
            raise WorkspaceError(
                "supervisor_unverified", "This runtime/platform has no accepted lifetime test"
            )


@dataclass(frozen=True)
class VerifiedProxyRoute:
    configuration: ProxyConfiguration
    expectations: ProxyExpectations
    probe: ProxyProbe


class ProxyRoutes(Protocol):
    def for_profile(self, profile_id: str) -> VerifiedProxyRoute: ...


class OwnedProcessHandle:
    def __init__(
        self,
        process: subprocess.Popen,
        context: LaunchContext,
        windows: NativeWindows,
        *,
        timeout: float = 3.0,
    ):
        self.process, self.context, self.windows = process, context, windows
        self.timeout = timeout
        self._ended = False

    def _group_alive(self) -> bool:
        if self._ended:
            return False
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            raise WorkspaceError(
                "process_state_unknown", "Owned process-group access changed"
            ) from None
        return True

    def status(self) -> ProcessStatus:
        if self._ended:
            return ProcessStatus(False)
        code = self.process.poll()
        group_alive = self._group_alive()
        if code is not None and group_alive:
            # Do not signal a possibly orphaned/reused PID based on persisted metadata.
            raise WorkspaceError(
                "process_state_unknown", "Browser leader exited with unresolved descendants"
            )
        if code is None and not group_alive:
            raise WorkspaceError("process_state_unknown", "Browser left its owned process group")
        if code is not None and not group_alive:
            self._ended = True
        return ProcessStatus(
            group_alive,
            group_alive and self.windows.ready(self.context.profile_id, self.process.pid),
            safe_to_stop=False,
        )

    def focus(self) -> bool:
        state = self.status()
        return (
            state.alive
            and state.ready
            and self.windows.focus(self.context.profile_id, self.process.pid)
        )

    def open_gmail(self) -> bool:
        state = self.status()
        return (
            state.alive
            and state.ready
            and self.windows.open_gmail(self.context.profile_id, self.process.pid)
        )

    def stop(self) -> bool:
        if self._ended:
            return True
        # Only a current live child can authorize signaling its owned group.
        if self.process.poll() is not None:
            return not self._group_alive()
        if os.getpgid(self.process.pid) != self.process.pid:
            return False
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                ended = self.process.poll() is not None
                self._ended = ended
                return ended
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                self.process.poll()  # Reap the supervised leader before testing its group.
                if not self._group_alive():
                    ended = self.process.poll() is not None
                    self._ended = ended
                    return ended
                time.sleep(0.02)
            # If the leader vanished but descendants remain, identity/lifetime is
            # uncertain. Keep the lease and require platform-specific recovery.
            if self.process.poll() is not None:
                return False
        return False


class LinuxSubprocessSupervisor:
    """Atomic executable-fd launch plus bounded, accepted process-group lifetime.

    An acceptance record is trusted operator configuration, never an API payload.
    Until real target-platform tests establish process-tree/window behavior for
    an exact runtime release, callers must leave acceptance unset.
    """

    def __init__(
        self, windows: NativeWindows | None = None, acceptance: SupervisionAcceptance | None = None
    ):
        self.windows, self.acceptance = windows, acceptance

    def check(self, runtime: VerifiedRuntime) -> None:
        if self.windows is None or self.acceptance is None:
            raise WorkspaceError(
                "supervisor_unverified",
                "Verified window control and lifetime acceptance are required",
            )
        self.acceptance.validate(runtime)
        if not Path("/proc/self/fd").is_dir():
            raise WorkspaceError(
                "supervisor_unverified", "Atomic executable descriptor launch is unavailable"
            )

    def launch(
        self, runtime: VerifiedRuntime, context: LaunchContext, argv: tuple[str, ...], *, home: Path
    ) -> ProcessHandle:
        self.check(runtime)
        # RuntimeGate already refuses symlink path components and checks signing.
        fd = os.open(runtime.executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        process = None
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            if (
                not stat.S_ISREG(info.st_mode)
                or identity != runtime.file_identity
                or not RuntimeGate.is_unchanged(runtime)
            ):
                raise WorkspaceError(
                    "runtime_changed", "Installed browser changed before execution"
                )
            environment = {"HOME": str(home), "PATH": os.defpath, "LANG": "C.UTF-8"}
            for name in (
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XDG_RUNTIME_DIR",
                "XAUTHORITY",
                "DBUS_SESSION_BUS_ADDRESS",
            ):
                if name in os.environ:
                    environment[name] = os.environ[name]
            process = subprocess.Popen(
                argv,
                executable=f"/proc/self/fd/{fd}",
                pass_fds=(fd,),
                shell=False,
                close_fds=True,
                start_new_session=True,
                cwd=context.browser_data,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
            )
        finally:
            os.close(fd)
        assert process is not None and self.windows is not None
        return OwnedProcessHandle(process, context, self.windows)


class InstalledBrowserAdapter:
    execution_kind = "installed"

    def __init__(
        self,
        *,
        profile_store: ProfileStore,
        executable: Path,
        observed_version: str | None,
        policy: RuntimePolicy,
        runtime_gate: RuntimeGate,
        supervisor: LinuxSubprocessSupervisor,
        vault: NativeVaultHealth | None = None,
        proxy_routes: ProxyRoutes | None = None,
        metadata_observer: Callable[[Path], InstalledBundleMetadata] | None = None,
    ):
        if policy.engine_id != "chromium":
            raise ValueError("The installed adapter supports Chromium-family runtimes only")
        self.profile_store, self.executable = profile_store, Path(executable)
        self.observed_version, self.policy, self.gate = observed_version, policy, runtime_gate
        self.supervisor, self.vault, self.proxy_routes = supervisor, vault, proxy_routes
        self.metadata_observer = metadata_observer
        self._approved: dict[
            str,
            tuple[VerifiedRuntime, dict[str, Any], tuple[str, ...], InstalledBundleMetadata | None],
        ] = {}
        self._runtime_cache: VerifiedRuntime | None = None
        self._runtime_metadata: InstalledBundleMetadata | None = None
        self._verification_lock = threading.Lock()

    def shutdown(self) -> None:
        shutdown = getattr(self.supervisor, "shutdown", None)
        if shutdown is not None:
            shutdown()

    def _runtime_evidence(
        self, *, fresh_launch: bool = False
    ) -> tuple[VerifiedRuntime, InstalledBundleMetadata | None]:
        with self._verification_lock:
            metadata = self.metadata_observer(self.executable) if self.metadata_observer else None
            observed_version = metadata.version if metadata is not None else self.observed_version
            if observed_version is None:
                raise RuntimeVerificationError(
                    "The installed browser version has not been observed"
                )
            if observed_version != self.policy.version:
                raise RuntimeVerificationError(
                    "Installed bundle version does not match the reviewed policy"
                )
            cached = self._runtime_cache
            if cached is not None and not fresh_launch:
                info = self.executable.stat(follow_symlinks=False)
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                age = (datetime.now(timezone.utc) - cached.verified_at).total_seconds()
                if (
                    identity == cached.file_identity
                    and metadata == self._runtime_metadata
                    and 0 <= age <= 30
                ):
                    return cached, metadata
            # Each new process launch deliberately bypasses this short status-only
            # cache. Signing covers changed resources/frameworks as well as the
            # executable, and runs outside the workspace lock in preflight.
            runtime = self.gate.verify(
                self.executable, observed_version=observed_version, policy=self.policy
            )
            after = self.metadata_observer(self.executable) if self.metadata_observer else None
            if after != metadata:
                raise RuntimeVerificationError(
                    "Bundle metadata changed during signature verification"
                )
            self._runtime_cache, self._runtime_metadata = runtime, metadata
            return runtime, metadata

    def _runtime(self) -> VerifiedRuntime:
        return self._runtime_evidence()[0]

    def global_blockers(self) -> tuple[str, ...]:
        try:
            runtime = self._runtime()
        except Exception as exc:
            from team_browser.local.errors import LocalClientError

            reason = (
                str(exc)
                if isinstance(exc, LocalClientError)
                else "Installed runtime provenance could not be verified"
            )
            return (reason,)
        try:
            self.supervisor.check(runtime)
        except WorkspaceError as exc:
            return (exc.message,)
        except Exception:
            return ("The installed-browser lifetime supervisor is unavailable.",)
        return ()

    def _route(self, profile: dict[str, Any], runtime: VerifiedRuntime) -> tuple[str, ...]:
        policy = profile.get("network_policy", "unconfigured")
        origin = profile.get("origin", "local")
        if origin == "managed" and policy != "verified_proxy":
            raise WorkspaceError(
                "proxy_required", "Managed profiles require a verified proxy route"
            )
        if policy == "local_direct" and origin == "local":
            return ("--no-proxy-server",)
        if policy != "verified_proxy":
            raise WorkspaceError(
                "network_choice_required",
                "Choose local direct networking explicitly or configure a verified proxy",
            )
        # A one-time route probe cannot prove ongoing direct-fallback prevention.
        # Keep all proxy-required native paths disabled until the actual continuous
        # enforcement/authentication integration has passed target-platform tests.
        raise WorkspaceError(
            "proxy_enforcement_unavailable",
            "Continuous proxy enforcement is not implemented; "
            "proxy-required and managed launches remain disabled",
        )

    def _ensure_engine_binding(self, profile_id: str) -> None:
        directory_fd, _paths = self.profile_store._open_profile(profile_id)
        try:
            for marker in (".camoufox-identity.json", ".camoufox-engine-identity.json"):
                try:
                    os.stat(marker, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise WorkspaceError(
                    "profile_engine_mismatch",
                    "This profile belongs to Camoufox. Create a separate Chromium profile; browser data is not interchangeable.",
                )
        finally:
            os.close(directory_fd)

    def blockers(self, profile: dict[str, Any]) -> tuple[str, ...]:
        self._approved.pop(profile["id"], None)
        try:
            self._ensure_engine_binding(profile["id"])
        except WorkspaceError as exc:
            return (exc.message,)
        blockers = []
        if profile["engine_id"] != "chromium":
            blockers.append("The selected profile engine has no trusted installed adapter.")
        if profile.get("network_policy", "unconfigured") == "unconfigured":
            blockers.append(
                "Choose local direct networking explicitly or configure a verified proxy."
            )
        if blockers:
            return tuple(blockers)
        try:
            runtime, metadata = self._runtime_evidence(fresh_launch=True)
            self.supervisor.check(runtime)
            flags = self._route(profile, runtime)
            self._approved[profile["id"]] = (runtime, dict(profile), flags, metadata)
        except WorkspaceError as exc:
            return (exc.message, *exc.details.get("blockers", ()))
        except RuntimeVerificationError as exc:
            return (str(exc),)
        except Exception:
            return ("Installed browser launch checks could not be completed safely.",)
        return ()

    def start(self, context: LaunchContext) -> ProcessHandle:
        approved = self._approved.pop(context.profile_id, None)
        if approved is None:
            raise WorkspaceError(
                "launch_not_approved", "A fresh profile-bound launch check is required"
            )
        runtime, profile, flags, metadata = approved
        if (
            self.metadata_observer is not None
            and self.metadata_observer(self.executable) != metadata
        ):
            raise WorkspaceError(
                "runtime_changed", "Installed bundle metadata changed after launch approval"
            )
        if context.engine_id != runtime.engine_id or context.initial_url not in (
            "about:blank",
            GMAIL_INBOX_URL,
        ):
            raise WorkspaceError(
                "launch_context_mismatch", "Launch target or engine does not match"
            )
        self._ensure_engine_binding(context.profile_id)
        paths = self.profile_store.prepare(context.profile_id)
        if context.lease is None or not context.lease.active or context.lease.paths != paths:
            raise WorkspaceError(
                "profile_lease_required", "An active matching profile lease is required"
            )
        if context.browser_data != paths.browser_data:
            raise WorkspaceError(
                "launch_context_mismatch",
                "Only this application's private profile directory is allowed",
            )
        fd = os.open(paths.browser_data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _check_private(fd, directory=True)
        finally:
            os.close(fd)
        # The supervisor rehashes just before process creation; it must never use
        # this cached metadata as authority to execute changed bits.
        # Direct profiles hold no application proxy/OAuth secrets. Native browser
        # storage remains enabled; no unused app-vault requirement blocks them.
        # Credentialed proxy routes remain blocked until a vetted bridge exists.
        flags = self._route(profile, runtime)
        argv = (
            str(runtime.executable),
            f"--user-data-dir={paths.browser_data}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-mode",
            *flags,
            context.initial_url,
        )
        return self.supervisor.launch(runtime, context, argv, home=self.profile_store.root.parent)


class MacOSCodeSignatureVerifier:
    """System codesign + Gatekeeper checks; no shell, downloads or credential arguments.

    Trust policy signer_identity is exactly '<TeamIdentifier>:<bundle Identifier>'.
    The real macOS path is unverified in this Linux environment. Command-contract
    tests use fixed synthetic output and do not certify a vendor distribution.
    """

    def __init__(self, runner=None):
        self.runner = runner if runner is not None else subprocess.run

    def verify(self, executable: Path, expected_sha256: str):
        from team_browser.local.errors import RuntimeVerificationError
        from team_browser.local.runtime import SignatureEvidence

        if sys.platform != "darwin":
            raise RuntimeVerificationError("macOS system signature verification requires macOS")
        bundle = next((parent for parent in executable.parents if parent.suffix == ".app"), None)
        if bundle is None or executable.parent != bundle / "Contents" / "MacOS":
            raise RuntimeVerificationError(
                "Installed Chrome executable must belong to a signed app bundle"
            )

        def run(command):
            try:
                result = self.runner(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                    shell=False,
                    env={"PATH": "/usr/bin:/usr/sbin:/bin"},
                )
            except Exception:
                raise RuntimeVerificationError(
                    "System signature verification could not complete"
                ) from None
            if result.returncode != 0:
                raise RuntimeVerificationError(
                    "System signature or Gatekeeper verification rejected the browser"
                )
            return result.stdout + "\n" + result.stderr

        run(("/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)))
        gatekeeper = run(
            ("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(bundle))
        )
        identity = run(("/usr/bin/codesign", "--display", "--verbose=4", str(bundle)))
        values = {}
        for line in identity.splitlines():
            key, sep, value = line.partition("=")
            if sep and key in {"TeamIdentifier", "Identifier"}:
                if key in values:
                    raise RuntimeVerificationError("Signing identity output was ambiguous")
                values[key] = value.strip()
        if not values.get("TeamIdentifier") or not values.get("Identifier"):
            raise RuntimeVerificationError("Signing identity was not established")
        return SignatureEvidence(
            expected_sha256,
            values["TeamIdentifier"] + ":" + values["Identifier"],
            True,
            "source=Notarized Developer ID" in gatekeeper,
            datetime.now(timezone.utc),
        )


def load_installed_adapter(
    config_path: Path, profile_store: ProfileStore
) -> InstalledBrowserAdapter:
    """Read an operator-owned, private local runtime policy file, never web input.

    The default policy selects macOS signing. An explicit debian-package policy
    selects separate installed-package provenance on Linux; it never creates
    vendor-signature evidence. Both use the official Playwright pipe supervisor.
    Proxy credentials, browser flags and trust booleans are never accepted.
    """
    import json
    from typing import Literal

    from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

    class PolicyFile(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        executable: StrictStr
        engine_id: StrictStr = "chromium"
        version: StrictStr
        sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
        signer_identity: StrictStr
        require_notarization: StrictBool = True

    class LinuxPolicyFile(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        provenance: Literal["debian-package"]
        executable: StrictStr
        engine_id: Literal["chromium"] = "chromium"
        version: StrictStr
        sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
        package_versions: dict[StrictStr, StrictStr]

    class LinuxPilotPolicyFile(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        provenance: Literal["owner-approved-linux-pilot"]
        scope: Literal["synthetic-local-only"]
        executable: Literal["/usr/lib/chromium/chromium"]
        engine_id: Literal["chromium"] = "chromium"
        version: StrictStr
        sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
        manifest_path: StrictStr
        approved_manifest_sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
        approval_reference: StrictStr
        approved_at: StrictStr
        expires_at: StrictStr
        workspace: StrictStr
        allow_public_example: StrictBool = False

    path = Path(config_path)
    if not path.is_absolute() or ".." in path.parts:
        raise WorkspaceError(
            "unsafe_configuration", "Runtime policy path must be absolute", status=422
        )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _check_private(fd, directory=False)
        if os.fstat(fd).st_size > 16384:
            raise WorkspaceError("unsafe_configuration", "Runtime policy is too large", status=422)
        raw = os.read(fd, 16385)
        values = json.loads(raw)
        linux = isinstance(values, dict) and values.get("provenance") == "debian-package"
        pilot = (
            isinstance(values, dict) and values.get("provenance") == "owner-approved-linux-pilot"
        )
        model = LinuxPilotPolicyFile if pilot else LinuxPolicyFile if linux else PolicyFile
        config = model.model_validate(values)
    except Exception:
        raise WorkspaceError(
            "unsafe_configuration",
            "Runtime policy must be a private, valid reviewed JSON file",
            status=422,
        ) from None
    finally:
        os.close(fd)
    executable = Path(config.executable)
    if not executable.is_absolute() or ".." in executable.parts:
        raise WorkspaceError(
            "unsafe_configuration", "Installed runtime path must be absolute", status=422
        )
    from .playwright_supervisor import PlaywrightSupervisor

    if pilot:
        from .linux_pilot import load_pilot_adapter

        return load_pilot_adapter(config, profile_store)

    if linux:
        from .linux_runtime import LinuxPackageRuntimeGate, PROVENANCE

        try:
            gate = LinuxPackageRuntimeGate(config.package_versions)
            policy = RuntimePolicy("chromium", config.version, config.sha256, PROVENANCE, False)
        except ValueError as exc:
            raise WorkspaceError("unsafe_configuration", str(exc), status=422) from None
        return InstalledBrowserAdapter(
            profile_store=profile_store,
            executable=executable,
            observed_version=None,
            policy=policy,
            runtime_gate=gate,
            supervisor=PlaywrightSupervisor(),
            vault=None,
            metadata_observer=gate.observe,
        )

    policy = RuntimePolicy(
        config.engine_id,
        config.version,
        config.sha256,
        config.signer_identity,
        config.require_notarization,
    )
    return InstalledBrowserAdapter(
        profile_store=profile_store,
        executable=executable,
        observed_version=None,
        policy=policy,
        runtime_gate=RuntimeGate(MacOSCodeSignatureVerifier()),
        supervisor=PlaywrightSupervisor(),
        vault=None,
        metadata_observer=read_macos_bundle_metadata,
    )
