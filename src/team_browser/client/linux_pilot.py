"""Explicitly owner-approved, short-lived Linux artifact pilot, not vendor trust.

Observation never grants execution. The separate private approval policy must
be written only after the owner approves its exact manifest and bounded scope.
Neither this module nor the CLI creates approval records automatically.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimePolicy, VerifiedRuntime, _hash_regular_file
from team_browser.local.storage import _check_private

ROOT = Path("/usr/lib/chromium")
EXECUTABLE = ROOT / "chromium"
PILOT_PROVENANCE = "owner-approved-linux-pilot"
MAX_FILES = 2048
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _protected(path: Path) -> None:
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeVerificationError(
                "Pilot runtime paths cannot be symlinked or publicly writable"
            )
        if component != Path(component.anchor) and os.access(component, os.W_OK):
            raise RuntimeVerificationError("Pilot runtime paths cannot be writable by the client")


def observe_artifact(*, version: str, with_hashes: bool = True) -> dict:
    """Read the fixed supplied runtime only; never run it or approve it."""
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeVerificationError("The Linux pilot requires a non-root Linux client")
    if not version or len(version) > 128 or any(c.isspace() or ord(c) < 32 for c in version):
        raise RuntimeVerificationError("A bounded observed runtime version is required")
    _protected(ROOT)
    paths = [ROOT, *sorted(ROOT.rglob("*"))]
    if len(paths) > MAX_FILES:
        raise RuntimeVerificationError("Pilot runtime inventory exceeds the bounded scope")
    entries = []
    for path in paths:
        _protected(path)
        before = path.lstat()
        regular = stat.S_ISREG(before.st_mode)
        if not regular and not stat.S_ISDIR(before.st_mode):
            raise RuntimeVerificationError("Pilot runtime contains an unsupported file type")
        entry = {
            "path": "." if path == ROOT else str(path.relative_to(ROOT)),
            "kind": "file" if regular else "directory",
            "mode": stat.S_IMODE(before.st_mode),
            "uid": before.st_uid,
            "gid": before.st_gid,
            "identity": _identity(before),
        }
        if regular and with_hashes:
            entry["sha256"] = _hash_regular_file(path)[0]
        if _identity(path.lstat()) != _identity(before):
            raise RuntimeVerificationError("Pilot runtime changed during observation")
        entries.append(entry)
    if [str(path) for path in [ROOT, *sorted(ROOT.rglob("*"))]] != [str(path) for path in paths]:
        raise RuntimeVerificationError("Pilot runtime inventory changed during observation")
    indexed = {entry["path"]: entry for entry in entries}
    for name in ("chromium", "chrome-sandbox", "chrome_crashpad_handler", "icudtl.dat"):
        if indexed.get(name, {}).get("kind") != "file":
            raise RuntimeVerificationError(
                "Pilot runtime is missing a required executable/support file"
            )
    if not os.access(EXECUTABLE, os.X_OK):
        raise RuntimeVerificationError("Pilot Chromium is not executable")
    return {"format": 1, "root": str(ROOT), "version": version, "entries": entries}


def manifest_digest(manifest: dict) -> str:
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def read_private_manifest(path: Path) -> dict:
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeVerificationError("Pilot manifest path must be absolute without traversal")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _check_private(fd, directory=False)
        if os.fstat(fd).st_size > MAX_MANIFEST_BYTES:
            raise RuntimeVerificationError("Pilot artifact manifest is too large")
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeVerificationError("Pilot artifact manifest is malformed") from None
    if not isinstance(value, dict):
        raise RuntimeVerificationError("Pilot artifact manifest must be an object")
    return value


@dataclass(frozen=True)
class PilotMetadata:
    version: str
    executable_name: str
    manifest_sha256: str
    approval_reference: str


class LinuxPilotRuntimeGate:
    def __init__(
        self,
        *,
        manifest: dict,
        approved_manifest_sha256: str,
        approval_reference: str,
        approved_at: datetime,
        expires_at: datetime,
        workspace: Path,
    ):
        if (
            not approval_reference
            or len(approval_reference) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in approval_reference)
            or approved_at.utcoffset() is None
            or expires_at.utcoffset() is None
            or not timedelta(0) < expires_at - approved_at <= timedelta(hours=2)
            or not workspace.is_absolute()
            or ".." in workspace.parts
        ):
            raise RuntimeVerificationError(
                "A specific short-lived owner approval and workspace are required"
            )
        if manifest_digest(manifest) != approved_manifest_sha256:
            raise RuntimeVerificationError(
                "Pilot manifest does not match the owner-approved digest"
            )
        self.manifest = manifest
        self.digest = approved_manifest_sha256
        self.reference = approval_reference
        self.approved_at, self.expires_at = approved_at, expires_at
        self.workspace = workspace

    def _check_approval(self, now=None):
        now = now or datetime.now(timezone.utc)
        if not self.approved_at <= now < self.expires_at:
            raise RuntimeVerificationError(
                "The bounded Linux pilot approval is inactive or expired"
            )

    def observe(self, executable: Path) -> PilotMetadata:
        self._check_approval()
        if Path(executable) != EXECUTABLE:
            raise RuntimeVerificationError(
                "Pilot approval covers only the fixed installed Chromium"
            )
        expected = json.loads(json.dumps(self.manifest))
        try:
            for entry in expected["entries"]:
                entry.pop("sha256", None)
            actual = observe_artifact(version=expected["version"], with_hashes=False)
        except (KeyError, TypeError):
            raise RuntimeVerificationError("Pilot artifact manifest schema is invalid") from None
        if actual != expected:
            raise RuntimeVerificationError("The owner-approved Linux runtime metadata has changed")
        return PilotMetadata(actual["version"], EXECUTABLE.name, self.digest, self.reference)

    def verify(self, executable: Path, *, observed_version: str, policy: RuntimePolicy, now=None):
        now = now or datetime.now(timezone.utc)
        self._check_approval(now)
        metadata = self.observe(executable)
        if (
            policy.engine_id != "chromium"
            or policy.signer_identity != PILOT_PROVENANCE
            or policy.require_notarization
            or policy.version != observed_version
            or policy.version != metadata.version
        ):
            raise RuntimeVerificationError(
                "Exact-artifact pilot approval cannot satisfy vendor/package policy"
            )
        actual = observe_artifact(version=metadata.version, with_hashes=True)
        if actual != self.manifest or manifest_digest(actual) != self.digest:
            raise RuntimeVerificationError(
                "Owner-approved Linux runtime bytes or support resources changed"
            )
        digest, identity = _hash_regular_file(executable)
        if digest != policy.sha256:
            raise RuntimeVerificationError(
                "Pilot executable does not match the owner-approved hash"
            )
        self._check_approval()
        return VerifiedRuntime(
            "chromium", metadata.version, Path(executable), digest, PILOT_PROVENANCE, now, identity
        )


def load_pilot_adapter(config, profile_store):
    """Called only by the private operator-policy loader, never a web API."""
    from .installed_browser import InstalledBrowserAdapter
    from .playwright_supervisor import PlaywrightSupervisor
    from .store import WorkspaceError

    manifest = read_private_manifest(Path(config.manifest_path))
    gate = LinuxPilotRuntimeGate(
        manifest=manifest,
        approved_manifest_sha256=config.approved_manifest_sha256,
        approval_reference=config.approval_reference,
        approved_at=datetime.fromisoformat(config.approved_at),
        expires_at=datetime.fromisoformat(config.expires_at),
        workspace=Path(config.workspace),
    )
    if profile_store.root.parent != gate.workspace:
        raise WorkspaceError(
            "pilot_scope_mismatch", "Pilot approval belongs to a different fresh workspace"
        )
    if any(profile_store.root.iterdir()):
        raise WorkspaceError(
            "pilot_scope_mismatch", "The bounded pilot requires a fresh profile workspace"
        )
    gate.allow_public_example = config.allow_public_example
    policy = RuntimePolicy("chromium", config.version, config.sha256, PILOT_PROVENANCE, False)

    class PilotHandle:
        def __init__(self, delegate):
            self.delegate = delegate

        def __getattr__(self, name):
            return getattr(self.delegate, name)

        def focus(self):
            gate._check_approval()
            return self.delegate.focus()

        def tab_snapshot(self, valid):
            gate._check_approval()
            return self.delegate.tab_snapshot(valid)

        def focus_tabs(self, valid, **kwargs):
            gate._check_approval()
            return self.delegate.focus_tabs(valid, **kwargs)

        def set_selected(self, selected):
            gate._check_approval()
            return self.delegate.set_selected(selected)

        def open_gmail(self):
            raise WorkspaceError(
                "pilot_scope_mismatch", "The bounded pilot does not authorize account sign-in"
            )

    class PilotAdapter(InstalledBrowserAdapter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self._pilot_profiles = set()
            delay = max(0, (gate.expires_at - datetime.now(timezone.utc)).total_seconds())
            self._expiry_timer = threading.Timer(delay, self._expire)
            self._expiry_timer.daemon = True
            self._expiry_timer.start()

        def _expire(self):
            for handle in list(self.supervisor._handles):
                try:
                    handle.stop()
                except Exception:
                    pass
            self.supervisor.shutdown()

        def shutdown(self):
            self._expiry_timer.cancel()
            # Closing the pilot manager must not cancel its deadline while
            # leaving a known synthetic browser running without a close request.
            self._expire()

        def start(self, context):
            gate._check_approval()
            if context.initial_url != "about:blank":
                raise WorkspaceError(
                    "pilot_scope_mismatch",
                    "The bounded pilot starts only a blank synthetic profile",
                )
            if context.profile_id not in self._pilot_profiles and any(
                context.browser_data.iterdir()
            ):
                raise WorkspaceError(
                    "pilot_scope_mismatch",
                    "Pilot profiles must begin without existing browser data",
                )
            handle = super().start(context)
            self._pilot_profiles.add(context.profile_id)
            return PilotHandle(handle)

    return PilotAdapter(
        profile_store=profile_store,
        executable=EXECUTABLE,
        observed_version=None,
        policy=policy,
        runtime_gate=gate,
        supervisor=PlaywrightSupervisor(),
        vault=None,
        metadata_observer=gate.observe,
    )
