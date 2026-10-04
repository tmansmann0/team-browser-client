"""Authenticated, offline Camoufox deployment input; never a web trust loader.

An administrator separately provisions an Ed25519 public trust anchor and an
independent release reviewer signs a bounded receipt. This module neither makes
keys nor claims that an operator signature is an upstream publisher signature.
Only the first, explicitly accepted Linux local-direct distribution is supported
by the declarative loader. Native proxy integrations keep their existing gates.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from team_browser.local.runtime import RuntimePolicy, VerifiedRuntime, _hash_regular_file
from team_browser.local.storage import _check_private
from .camoufox_runtime import (
    CamoufoxAcceptance,
    CamoufoxIdentityProgramAcceptance,
    CamoufoxIdentityProperties,
    CamoufoxRuntimeMetadata,
)
from .engine_identity import AcceptedDisplay, GeneratorProvenance
from .identity_probe import PROBE_ID
from .store import WorkspaceError

MAX_BYTES = 2 * 1024 * 1024
DEFAULT_TRUST = Path("/etc/team-browser/camoufox-authorities.json")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @model_validator(mode="before")
    @classmethod
    def exact_schema_integer(cls, value):
        # Literal equality alone accepts True and 1.0 even in strict mode.
        if isinstance(value, dict) and "schema_version" in value:
            if type(value["schema_version"]) is not int:
                raise ValueError("Schema version must be an exact integer")
        return value


class TrustAnchor(StrictModel):
    schema_version: Literal[1]
    authority_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    public_key_hex: str = Field(pattern=r"^[a-f0-9]{64}$")
    host_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{16,128}$")
    platform: Literal["linux"]


class AcceptedProfileTemplate(StrictModel):
    preset_id: Literal["isolated"]
    locale: str = Field(pattern=r"^[a-z]{2,3}-[A-Z]{2}$")
    timezone_id: str = Field(min_length=1, max_length=80)
    network_policy: Literal["local_direct"]


class ProfileSelection(StrictModel):
    profile_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    profile_binding_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    preset_id: Literal["isolated"]
    locale: str = Field(pattern=r"^[a-z]{2,3}-[A-Z]{2}$")
    timezone_id: str = Field(min_length=1, max_length=80)
    network_policy: Literal["local_direct"]


class SetupConfiguration(StrictModel):
    schema_version: Literal[1]
    receipt_file: str = Field(min_length=1, max_length=4096)
    profiles: list[ProfileSelection] = Field(default_factory=list, max_length=100)
    use_accepted_profile_defaults: bool = False


class DisplayRecord(StrictModel):
    width: int
    height: int
    avail_width: int
    avail_height: int
    color_depth: int
    device_pixel_ratio: float


class ProvenanceRecord(StrictModel):
    generator_version: str
    implementation_sha256: str
    packages_sha256: str
    catalogue_name: str
    catalogue_sha256: str


class NativeQualification(StrictModel):
    report_id: str = Field(min_length=1, max_length=128)
    # These affirmative scope attestations must come from the authenticated
    # independent reviewer, never a request or a client-generated success bit.
    normal_sandbox_and_security_defaults: Literal[True]
    controlled_updates: Literal[True]
    owned_launch_close_and_two_profile_persistence: Literal[True]
    fixed_probe_and_identity_surfaces: Literal[True]
    accepted_unrestricted_local_direct_egress: Literal[True]
    generator: ProvenanceRecord
    probe_id: str = Field(min_length=1, max_length=128)

    @field_validator(
        "normal_sandbox_and_security_defaults",
        "controlled_updates",
        "owned_launch_close_and_two_profile_persistence",
        "fixed_probe_and_identity_surfaces",
        "accepted_unrestricted_local_direct_egress",
        mode="before",
    )
    @classmethod
    def exact_affirmative_boolean(cls, value):
        if type(value) is not bool or value is not True:
            raise ValueError("Qualification requires an exact affirmative boolean")
        return value


class DistributionRecord(StrictModel):
    schema_version: Literal[1]
    authority_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    host_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{16,128}$")
    platform: Literal["linux"]
    issued_at: str
    valid_until: str
    source_url: str = Field(min_length=1, max_length=2048)
    archive_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    root: str = Field(min_length=1, max_length=4096)
    engine_version: str = Field(min_length=1, max_length=128)
    firefox_version: str = Field(pattern=r"^[0-9]{3}(?:\.[0-9A-Za-z]+)+$")
    gecko_build_id: str = Field(pattern=r"^[0-9]{14}$")
    camoufox_release: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    executable: Literal["camoufox-bin"]
    metadata: Literal["application.ini"]
    properties: Literal["properties.json"]
    files: dict[str, str] = Field(min_length=3, max_length=8192)
    display: DisplayRecord
    profile_defaults: AcceptedProfileTemplate
    native_qualification: NativeQualification | None = None


class SignedEnvelope(StrictModel):
    payload: str = Field(min_length=1, max_length=MAX_BYTES)
    signature_hex: str = Field(pattern=r"^[a-f0-9]{128}$")


def _failure(code="camoufox_setup_unverified"):
    return WorkspaceError(
        code,
        "Camoufox deployment evidence is missing, expired or changed; ask the release administrator to review setup.",
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


def _json(raw):
    return json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")),
    )


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read(path: Path, *, private=False, protected=False, maximum=MAX_BYTES):
    """Descriptor-relative no-follow traversal and bounded fresh content read."""
    if not path.is_absolute() or ".." in path.parts:
        raise _failure()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open(path.anchor, flags | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
            if protected:
                info = os.fstat(directory)
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise _failure("camoufox_trust_anchor_unsafe")
        fd = os.open(path.name, flags | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        if private:
            _check_private(fd, directory=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise _failure()
        if protected and (before.st_uid != 0 or os.geteuid() == 0):
            raise _failure("camoufox_trust_anchor_unsafe")
        raw = bytearray()
        while chunk := os.read(fd, min(65536, maximum + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > maximum:
                raise _failure()
        after = os.fstat(fd)
        if _identity(before) != _identity(after):
            raise _failure()
        return bytes(raw), _identity(after)
    finally:
        os.close(fd)


class AuthenticatedDeployment:
    """Fresh receipt validity and exact protected complete-distribution observation."""

    def __init__(self, config_path: Path, trust_path: Path = DEFAULT_TRUST):
        self.config_path, self.trust_path = Path(config_path), Path(trust_path)
        self._verified_inventory = None
        self.config_raw = _read(self.config_path, private=True)[0]
        self.configuration = SetupConfiguration.model_validate(_json(self.config_raw))
        ids = [item.profile_id for item in self.configuration.profiles]
        if len(ids) != len(set(ids)):
            raise _failure()
        self.anchor_raw = _read(self.trust_path, protected=True)[0]
        self.anchor = TrustAnchor.model_validate(_json(self.anchor_raw))
        self.receipt_path = Path(self.configuration.receipt_file)
        self.receipt_raw = _read(self.receipt_path, private=True)[0]
        envelope = SignedEnvelope.model_validate(_json(self.receipt_raw))
        data = _json(envelope.payload)
        if (
            json.dumps(
                data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            )
            != envelope.payload
        ):
            raise _failure()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.anchor.public_key_hex)).verify(
            bytes.fromhex(envelope.signature_hex), envelope.payload.encode("ascii")
        )
        self.record = DistributionRecord.model_validate(data)
        record = self.record
        self.valid_until = datetime.fromisoformat(record.valid_until)
        self.issued_at = datetime.fromisoformat(record.issued_at)
        self.root = Path(record.root)
        if (
            not self.root.is_absolute()
            or ".." in self.root.parts
            or not re.fullmatch(
                r"https://github\.com/daijro/camoufox/releases/download/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\.zip",
                record.source_url,
            )
            or record.authority_id != self.anchor.authority_id
            or record.host_id != self.anchor.host_id
            or record.platform != sys.platform
            or record.platform != self.anchor.platform
            or record.engine_version
            != f"{record.firefox_version}+{record.camoufox_release}.{record.gecko_build_id}"
        ):
            raise _failure()
        for name, digest in record.files.items():
            if (
                not name
                or Path(name).is_absolute()
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or str(Path(name)) != name
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or not re.fullmatch(r"[a-f0-9]{64}", digest)
            ):
                raise _failure()
        if not {record.executable, record.metadata, record.properties} <= record.files.keys():
            raise _failure()
        self.display = AcceptedDisplay(**record.display.model_dump())
        self.executable = self.root / record.executable
        self.policy = RuntimePolicy(
            "camoufox",
            record.engine_version,
            record.files[record.executable],
            f"deployment-ed25519:{record.authority_id}",
            False,
        )
        self.current()

    def current(self):
        now = datetime.now(timezone.utc)
        if (
            self.issued_at.utcoffset() is None
            or self.valid_until.utcoffset() is None
            or not self.issued_at <= now < self.valid_until
            or self.valid_until - self.issued_at > timedelta(days=30)
            or _read(self.trust_path, protected=True)[0] != self.anchor_raw
            or _read(self.config_path, private=True)[0] != self.config_raw
            or _read(self.receipt_path, private=True)[0] != self.receipt_raw
        ):
            raise _failure()

    def _observed(self, name, maximum):
        self.current()
        raw, identity = _read(self.root / name, protected=True, maximum=maximum)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != self.record.files[name]:
            raise _failure("camoufox_distribution_changed")
        return raw, identity, digest

    def _inventory_stamp(self):
        """Bounded complete metadata snapshot, including replacement-sensitive ctime.

        Privileged updates are not atomic with path-based native spawning. The
        accepted installation policy must forbid concurrent updates; these fresh
        snapshots detect changes instead of treating the first hash as a lease.
        """
        result = {}
        paths = [(".", self.root)]
        for root, directories, files in os.walk(self.root, followlinks=False):
            for name in (*directories, *files):
                path = Path(root) / name
                paths.append((str(path.relative_to(self.root)), path))
                if len(paths) > 32768:
                    raise _failure()
        actual_files = set()
        for name, path in paths:
            info = path.lstat()
            directory = stat.S_ISDIR(info.st_mode)
            regular = stat.S_ISREG(info.st_mode)
            if (
                not (directory or regular)
                or info.st_uid != 0
                or info.st_mode & 0o022
                or (regular and info.st_nlink != 1)
            ):
                raise _failure("camoufox_distribution_changed")
            if regular:
                actual_files.add(name)
            result[name] = (*_identity(info), info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
        if actual_files != self.record.files.keys():
            raise _failure("camoufox_distribution_changed")
        return result

    def _guard_inventory(self):
        if (
            self._verified_inventory is not None
            and self._inventory_stamp() != self._verified_inventory
        ):
            raise _failure("camoufox_distribution_changed")

    def metadata(self, executable):
        if Path(executable) != self.executable:
            raise _failure()
        self._guard_inventory()
        raw, identity, digest = self._observed(self.record.metadata, 65536)
        ini = configparser.ConfigParser(interpolation=None, strict=True)
        ini.read_string(raw.decode("utf-8"))
        if (
            ini["App"]["Version"] != self.record.firefox_version
            or ini["App"]["BuildID"] != self.record.gecko_build_id
        ):
            raise _failure("runtime_metadata_mismatch")
        self._guard_inventory()
        return CamoufoxRuntimeMetadata(
            self.record.engine_version, self.root / self.record.metadata, identity, digest
        )

    def properties(self, executable):
        if Path(executable) != self.executable:
            raise _failure()
        raw, identity, digest = self._observed(self.record.properties, 262144)
        return CamoufoxIdentityProperties(self.root / self.record.properties, identity, digest, raw)

    def verify(self, executable, *, observed_version, policy, now=None):
        """Distinct reviewed-distribution provenance, never fabricated SignatureEvidence."""
        self.current()
        if (
            Path(executable) != self.executable
            or policy != self.policy
            or observed_version != policy.version
        ):
            raise _failure()
        before_inventory = self._inventory_stamp()
        actual = set()
        entry_count = 0
        # The layout is protected/root-owned and every regular resource is pinned.
        # Symlinks/devices/FIFOs and resources outside the exact inventory fail.
        for root, directories, files in os.walk(self.root, followlinks=False):
            entry_count += len(directories) + len(files)
            if entry_count > 32768:
                raise _failure()
            for name in directories:
                info = (Path(root) / name).lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise _failure()
            for name in files:
                path = Path(root) / name
                relative = str(path.relative_to(self.root))
                if relative not in self.record.files:
                    raise _failure("camoufox_distribution_changed")
                # Protected parent checks without reading large native bytes here.
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                    raise _failure()
                digest, _ = _hash_regular_file(path)
                if digest != self.record.files[relative]:
                    raise _failure("camoufox_distribution_changed")
                actual.add(relative)
                if len(actual) > 8192:
                    raise _failure()
        if actual != self.record.files.keys() or not os.access(self.executable, os.X_OK):
            raise _failure()
        after_inventory = self._inventory_stamp()
        if before_inventory != after_inventory:
            raise _failure("camoufox_distribution_changed")
        self._verified_inventory = after_inventory
        self.metadata(executable)
        digest, identity = _hash_regular_file(self.executable)
        self.current()
        self._guard_inventory()
        return VerifiedRuntime(
            "camoufox",
            observed_version,
            self.executable,
            digest,
            policy.signer_identity,
            datetime.now(timezone.utc),
            identity,
        )

    def acceptance(self):
        qualification = self.record.native_qualification
        if qualification is None:
            return None
        return CamoufoxAcceptance(
            self.policy.sha256,
            self.policy.version,
            sys.platform,
            qualification.report_id,
            self.valid_until,
        )

    def program(self):
        qualification = self.record.native_qualification
        if qualification is None:
            raise WorkspaceError(
                "native_qualification_required",
                "The release reviewer must approve native security, display and fixed-probe qualification before validation.",
            )
        if qualification.probe_id != PROBE_ID:
            raise _failure("identity_probe_changed")
        return CamoufoxIdentityProgramAcceptance(
            self.policy.sha256,
            self.policy.version,
            int(self.record.firefox_version.split(".")[0]),
            sys.platform,
            self.display,
            GeneratorProvenance(**qualification.generator.model_dump()),
            self.record.files[self.record.properties],
            PROBE_ID,
            qualification.report_id,
            self.valid_until,
        )
