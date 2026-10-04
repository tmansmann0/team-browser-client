"""Generate a bounded Camoufox identity once; reuse its immutable private artifact.

No browser, installer, geo-IP query, user profile adoption, or native acceptance
is performed here. The concrete generator runs reviewed PyPI functions in a
short-lived, offline Python helper. See docs/engine-identity.md for scope/gates.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

# -I deliberately ignores PYTHONPATH; this is our own installed module directory.
if __name__ == "__main__" and sys.argv[1:] == ["--offline-worker"]:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from team_browser.local.storage import (
    ProfileLease,
    ProfileStore,
    _check_private,
    validate_identifier,
)

SCHEMA = 1
GENERATOR_VERSION = "tbm-camoufox-preset-v3"
# Audited configuration conversions, NOT native-engine compatibility/admission.
# The pinned modern catalogue contains source majors 149 through 152. Upstream
# from_preset explicitly normalizes both Firefox/ and rv: to the supplied major.
# A later major needs a new review/version, never an open-ended numeric fallback.
_CONVERSION_SOURCE_MAJORS = frozenset(range(149, 153))
_CONVERSION_TARGET_MAJORS = frozenset(range(149, 157))
ARTIFACT_NAME = ".camoufox-engine-identity.json"
MAX_ARTIFACT_BYTES = 262144
MAX_CONFIG_BYTES = 131072
_HOST_OS = {"darwin": "macos", "linux": "linux", "win32": "windows"}
_OS_SHORT = {"macos": "mac", "linux": "lin", "windows": "win"}
# SHA-256 of canonical {wheel_member_name: SHA-256(bytes)} for every package
# member, excluding dist-info. Review source wheels, not mutable Git branches.
_REVIEWED_PACKAGES = {
    "camoufox": ("0.5.6", "16d89de4021771212e6e9edc5391a66e1c51efb097a9ac56d207235a18c0acb0"),
    "browserforge": ("1.2.4", "6dec5059cd284be5a8c7446e2f0cedd714ce5cc755721e7d9c8ef37347c88976"),
    "apify_fingerprint_datapoints": (
        "0.15.0",
        "a9b73171cf54d47d4e7e118e75ea022554408b29031c361c105b131e2a2b4a23",
    ),
}
_CATALOGUES = {
    "fingerprint-presets.json": "f9d85a5a122ba27130151427047029333fa443204bc149e07a43506387f94db4",
    "fingerprint-presets-v150.json": "b731ded7ce8f2e75173560a2d17c781485bd30e42bc59a55a7512030c2cb9314",
}
# Includes transitive imported modules. Exact versions/content are recorded and
# bound, rather than claiming an unreviewed environment is release-approved.
_ENVIRONMENT_PACKAGES = (
    "camoufox",
    "browserforge",
    "apify_fingerprint_datapoints",
    "playwright",
    "pyee",
    "greenlet",
    "numpy",
    "orjson",
    "platformdirs",
    "pyyaml",
    "requests",
    "certifi",
    "charset_normalizer",
    "idna",
    "urllib3",
    "rich",
    "pygments",
    "markdown_it_py",
    "mdurl",
    "typing_extensions",
    "screeninfo",
    "language_tags",
    "lxml",
    "ua_parser",
    "ua_parser_builtins",
    "pysocks",
    "inquirer",
    "blessed",
    "editor",
    "readchar",
    "wcwidth",
    "rich_click",
    "click",
    "runs",
    "xmod",
)


class EngineIdentityError(RuntimeError):
    """Fixed diagnostics only; no upstream exceptions, paths, or profile data."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Engine identity: {reason}")


def _fail(reason: str) -> None:
    raise EngineIdentityError(reason)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _hash(value: object) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[a-f0-9]{64}", value))


def _text(value: object, maximum: int = 512) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(ord(char) >= 32 and ord(char) != 127 for char in value)
    )


def _int(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _pairs(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            _fail("invalid_artifact")
        result[key] = value
    return result


def _load(raw: bytes, maximum: int = MAX_ARTIFACT_BYTES) -> Any:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        _fail("invalid_artifact")
    try:
        return json.loads(
            raw, object_pairs_hook=_pairs, parse_constant=lambda _: _fail("invalid_artifact")
        )
    except (ValueError, UnicodeError, RecursionError):
        raise EngineIdentityError("invalid_artifact") from None


@dataclass(frozen=True)
class AcceptedDisplay:
    """Trusted CSS-pixel display observations, never guessed from this process."""

    width: int
    height: int
    avail_width: int
    avail_height: int
    color_depth: int
    device_pixel_ratio: float

    def __post_init__(self) -> None:
        if (
            not _int(self.width, 320, 16384)
            or not _int(self.height, 240, 16384)
            or not _int(self.avail_width, 1, self.width)
            or not _int(self.avail_height, 1, self.height)
            or self.color_depth not in (24, 30, 32)
            or type(self.color_depth) is not int
            or type(self.device_pixel_ratio) not in (int, float)
            or not math.isfinite(self.device_pixel_ratio)
            or not 0.5 <= self.device_pixel_ratio <= 4
        ):
            raise ValueError("An explicit bounded accepted display is required")
        object.__setattr__(self, "device_pixel_ratio", float(self.device_pixel_ratio))


@dataclass(frozen=True)
class IdentityBinding:
    profile_id: str
    profile_binding_sha256: str
    preset_id: str
    engine_version: str
    engine_sha256: str
    firefox_major: int
    platform: str
    target_os: str
    display: AcceptedDisplay
    locale: str
    timezone_id: str
    proxy_fingerprint: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id)
        validate_identifier(self.preset_id)
        if (
            not _hash(self.profile_binding_sha256)
            or not _hash(self.engine_sha256)
            or not _text(self.engine_version, 128)
            or any(c.isspace() for c in self.engine_version)
            or not _int(self.firefox_major, 100, 999)
            or self.platform not in _HOST_OS
            or self.target_os != _HOST_OS[self.platform]
            or type(self.display) is not AcceptedDisplay
            or type(self.locale) is not str
            or not re.fullmatch(r"[a-z]{2,3}-[A-Z]{2}", self.locale)
            or not _text(self.timezone_id, 80)
            or (self.proxy_fingerprint is not None and not _hash(self.proxy_fingerprint))
        ):
            raise ValueError(
                "An exact profile, runtime, same-OS display and route binding is required"
            )
        ZoneInfo(self.timezone_id)

    @property
    def sha256(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class GeneratorProvenance:
    generator_version: str
    implementation_sha256: str
    packages_sha256: str
    catalogue_name: str
    catalogue_sha256: str

    def __post_init__(self) -> None:
        if (
            not _text(self.generator_version, 80)
            or not _hash(self.implementation_sha256)
            or not _hash(self.packages_sha256)
            or not _text(self.catalogue_name, 80)
            or not _hash(self.catalogue_sha256)
        ):
            raise ValueError("Exact generator and catalogue provenance is required")

    @property
    def sha256(self) -> str:
        return _digest(asdict(self))


class IdentityGenerator(Protocol):
    def provenance(self, binding: IdentityBinding) -> GeneratorProvenance: ...

    def generate(self, binding: IdentityBinding) -> tuple[dict, dict, str]:
        """Return config, identity-only Firefox preferences and selected preset hash."""
        ...


_STRING_KEYS = frozenset(
    (
        "navigator.userAgent",
        "navigator.platform",
        "navigator.oscpu",
        "navigator.appVersion",
        "timezone",
        "locale:language",
        "locale:region",
        "navigator.language",
        "headers.Accept-Language",
        "webGl:vendor",
        "webGl:renderer",
    )
)
_INTEGER_KEYS = frozenset(
    (
        "navigator.hardwareConcurrency",
        "navigator.maxTouchPoints",
        "screen.width",
        "screen.height",
        "screen.availWidth",
        "screen.availHeight",
        "screen.colorDepth",
        "screen.pixelDepth",
        "fonts:spacing_seed",
        "audio:seed",
        "canvas:seed",
    )
)
_WEBGL_KEYS = frozenset(
    f"{prefix}:{name}"
    for prefix in ("webGl", "webGl2")
    for name in ("parameters", "shaderPrecisionFormats", "contextAttributes", "supportedExtensions")
)
_ALLOWED_KEYS = (
    _STRING_KEYS
    | _INTEGER_KEYS
    | _WEBGL_KEYS
    | {"fonts", "voices", "voices:blockIfNotDefined", "navigator.languages"}
)


def _json_tree(value: Any, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return -(2**65) < value < 2**65
    if type(value) is float:
        return math.isfinite(value) and abs(value) < 2**65
    if type(value) is str:
        return _text(value, 2048)
    if type(value) is list:
        return len(value) <= 512 and all(_json_tree(v, depth + 1) for v in value)
    if type(value) is dict:
        return len(value) <= 512 and all(
            _text(k, 128) and _json_tree(v, depth + 1) for k, v in value.items()
        )
    return False


_WEBGL_CONTEXT_BOOLEANS = frozenset(
    (
        "alpha",
        "antialias",
        "depth",
        "failIfMajorPerformanceCaveat",
        "premultipliedAlpha",
        "preserveDrawingBuffer",
        "stencil",
    )
)
_WEBGL_PRECISION_KEYS = frozenset(
    f"{shader},{precision}" for shader in (35632, 35633) for precision in range(36336, 36342)
)
# GL parameter shape categories, not fingerprint values. Keep nested engine
# dictionaries typed; a top-level `dict` in properties.json is insufficient.
_WEBGL_BOOL_PARAMETERS = frozenset(
    "2884 2929 2930 2960 3024 3042 3089 32823 32926 32928 32939 35977 "
    "36387 36388 37440 37441".split()
)
_WEBGL_STRING_PARAMETERS = frozenset("7936 7937 7938 35724 37445 37446".split())
_WEBGL_ARRAY_PARAMETERS = {
    "2928": (2, "number"),
    "2978": (4, "int"),
    "3088": (4, "int"),
    "3106": (4, "number"),
    "3107": (4, "bool"),
    "3386": (2, "int"),
    "32773": (4, "number"),
    "33901": (2, "number"),
    "33902": (2, "number"),
}


def _validate_webgl(config: dict) -> None:
    for prefix in ("webGl", "webGl2"):
        context = config[f"{prefix}:contextAttributes"]
        if (
            type(context) is not dict
            or set(context) != _WEBGL_CONTEXT_BOOLEANS | {"powerPreference"}
            or any(type(context[key]) is not bool for key in _WEBGL_CONTEXT_BOOLEANS)
            or type(context["powerPreference"]) is not str
            or context["powerPreference"] not in ("default", "high-performance", "low-power")
        ):
            _fail("invalid_identity_config")
        precision = config[f"{prefix}:shaderPrecisionFormats"]
        if type(precision) is not dict or set(precision) != _WEBGL_PRECISION_KEYS:
            _fail("invalid_identity_config")
        for value in precision.values():
            if (
                type(value) is not dict
                or set(value) != {"rangeMin", "rangeMax", "precision"}
                or any(not _int(v, 0, 1024) for v in value.values())
            ):
                _fail("invalid_identity_config")
        parameters = config[f"{prefix}:parameters"]
        if type(parameters) is not dict or not parameters:
            _fail("invalid_identity_config")
        for key, value in parameters.items():
            if not re.fullmatch(r"[1-9][0-9]{0,5}", key):
                _fail("invalid_identity_config")
            if value is None:
                continue  # Unsupported GL enums and unbound GL objects are null.
            if key in _WEBGL_BOOL_PARAMETERS:
                valid = type(value) is bool
            elif key in _WEBGL_STRING_PARAMETERS:
                valid = _text(value, 2048)
            elif key in _WEBGL_ARRAY_PARAMETERS:
                count, kind = _WEBGL_ARRAY_PARAMETERS[key]
                item_types = {"bool": (bool,), "int": (int,), "number": (int, float)}[kind]
                valid = (
                    type(value) is list
                    and len(value) == count
                    and all(type(item) in item_types for item in value)
                )
            else:
                valid = type(value) in (int, float)
            if not valid:
                _fail("invalid_identity_config")
        extensions = config[f"{prefix}:supportedExtensions"]
        if (
            type(extensions) is not list
            or not extensions
            or any(not _text(v, 128) for v in extensions)
            or len(set(extensions)) != len(extensions)
        ):
            _fail("invalid_identity_config")


def _navigator_match(user_agent: object, target_os: str):
    # Accept only the known desktop token families in the pinned catalogues.
    # Keeping the match structural also rejects mixed-OS tokens and injected
    # extra UA products rather than merely finding the expected OS substring.
    patterns = {
        "macos": r"Macintosh; (?P<oscpu>Intel Mac OS X [0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "windows": r"(?P<oscpu>Windows NT [0-9]+\.[0-9]+; Win64; x64)",
        "linux": r"X11; (?P<distro>Ubuntu; )?(?P<oscpu>Linux x86_64)",
    }
    if not _text(user_agent):
        return None
    return re.fullmatch(
        r"Mozilla/5\.0 \("
        + patterns[target_os]
        + r"; rv:(?P<major>[1-9][0-9]{2})\.0\) Gecko/20100101 Firefox/(?P=major)\.0",
        user_agent,
    )


def _app_version(target_os: str, match) -> str:
    app_version = {"macos": "5.0 (Macintosh)", "windows": "5.0 (Windows)", "linux": "5.0 (X11)"}[
        target_os
    ]
    if target_os == "linux" and match["distro"]:
        app_version = "5.0 (X11; Ubuntu)"
    return app_version


def _validate_navigator(config: dict, binding: IdentityBinding) -> None:
    match = _navigator_match(config["navigator.userAgent"], binding.target_os)
    if (
        match is None
        or int(match["major"]) != binding.firefox_major
        or config["navigator.oscpu"] != match["oscpu"]
        or config["navigator.appVersion"] != _app_version(binding.target_os, match)
    ):
        _fail("incoherent_identity")


def validate_identity(config: dict, preferences: dict, binding: IdentityBinding) -> None:
    """Strict app allowlist. Never relay arbitrary launch options or preferences."""
    if type(config) is not dict or set(config) != _ALLOWED_KEYS or not _json_tree(config):
        _fail("invalid_identity_config")
    if len(_canonical(config).encode()) > MAX_CONFIG_BYTES:
        _fail("invalid_identity_config")
    if not all(_text(config[k]) for k in _STRING_KEYS):
        _fail("invalid_identity_config")
    if not all(type(config[k]) is int for k in _INTEGER_KEYS):
        _fail("invalid_identity_config")
    if not all(
        _int(config[k], 1, 2**32 - 1) for k in ("fonts:spacing_seed", "audio:seed", "canvas:seed")
    ):
        _fail("invalid_identity_config")
    if not _int(config["navigator.hardwareConcurrency"], 1, 256) or not _int(
        config["navigator.maxTouchPoints"], 0, 20
    ):
        _fail("invalid_identity_config")
    expected_platform = {"macos": "MacIntel", "windows": "Win32", "linux": "Linux x86_64"}[
        binding.target_os
    ]
    if config["navigator.platform"] != expected_platform:
        _fail("incoherent_identity")
    _validate_navigator(config, binding)
    display = binding.display
    for key, expected in {
        "screen.width": display.width,
        "screen.height": display.height,
        "screen.availWidth": display.avail_width,
        "screen.availHeight": display.avail_height,
        "screen.colorDepth": display.color_depth,
        "screen.pixelDepth": display.color_depth,
        "timezone": binding.timezone_id,
        "locale:language": binding.locale.split("-")[0],
        "locale:region": binding.locale.split("-")[1],
        "navigator.language": binding.locale,
        "headers.Accept-Language": binding.locale,
        "navigator.languages": [binding.locale],
        "voices:blockIfNotDefined": True,
    }.items():
        if config[key] != expected:
            _fail("incoherent_identity")
    if config["voices:blockIfNotDefined"] is not True:
        _fail("invalid_identity_config")
    fonts, voices = config["fonts"], config["voices"]
    if (
        type(fonts) is not list
        or not 4 <= len(fonts) <= 512
        or not all(_text(font, 160) for font in fonts)
        or len(set(fonts)) != len(fonts)
    ):
        _fail("invalid_identity_config")
    if type(voices) is not list or not 1 <= len(voices) <= 512:
        _fail("invalid_identity_config")
    for voice in voices:
        if (
            type(voice) is not dict
            or set(voice) != {"lang", "name", "voiceUri", "isDefault", "isLocalService"}
            or not all(_text(voice[key], 512) for key in ("lang", "name", "voiceUri"))
            or type(voice["isDefault"]) is not bool
            or type(voice["isLocalService"]) is not bool
        ):
            _fail("invalid_identity_config")
    defaults = [v for v in voices if v["isDefault"]]
    if len(defaults) != 1 or defaults[0]["lang"].split("-")[0] != binding.locale.split("-")[0]:
        _fail("unsupported_locale_voices")
    _validate_webgl(config)
    if (
        type(preferences) is not dict
        or set(preferences) != {"webgl.enable-webgl2", "webgl.force-enabled"}
        or type(preferences["webgl.enable-webgl2"]) is not bool
        or preferences["webgl.force-enabled"] is not True
    ):
        _fail("invalid_identity_preferences")


@dataclass(frozen=True)
class EngineIdentity:
    """Only immutable canonical strings leave storage; properties return copies."""

    artifact_json: str

    @property
    def config_json(self) -> str:
        return _canonical(json.loads(self.artifact_json)["config"])

    @property
    def config_sha256(self) -> str:
        return hashlib.sha256(self.config_json.encode()).hexdigest()

    @property
    def artifact_sha256(self) -> str:
        return hashlib.sha256(self.artifact_json.encode()).hexdigest()

    @property
    def firefox_user_prefs(self) -> dict:
        return json.loads(self.artifact_json)["firefox_user_prefs"]

    def validate_engine_properties(self, properties_json: bytes, expected_sha256: str) -> None:
        """Call on freshly observed accepted-engine properties.json before launch.

        A digest is a content binding, not publisher authenticity or native proof.
        Unknown keys/types fail; upstream's silent skipping is not used.
        """
        if (
            type(properties_json) is not bytes
            or not _hash(expected_sha256)
            or hashlib.sha256(properties_json).hexdigest() != expected_sha256
        ):
            _fail("engine_properties_changed")
        rows = _load(properties_json)
        if type(rows) is not list or not 1 <= len(rows) <= 2048:
            _fail("invalid_engine_properties")
        types = {}
        for row in rows:
            if (
                type(row) is not dict
                or not _text(row.get("property"))
                or not _text(row.get("type"))
            ):
                _fail("invalid_engine_properties")
            if row["property"] in types:
                _fail("invalid_engine_properties")
            types[row["property"]] = row["type"]
        for key, value in json.loads(self.config_json).items():
            kind = types.get(key)
            checks = {
                "str": lambda: type(value) is str,
                "int": lambda: type(value) is int and -(2**31) <= value < 2**31,
                "uint": lambda: type(value) is int and 0 <= value <= 2**32 - 1,
                "double": lambda: type(value) in (int, float),
                "bool": lambda: type(value) is bool,
                "array": lambda: type(value) is list,
                "dict": lambda: type(value) is dict,
            }
            if kind not in checks or not checks[kind]():
                _fail("engine_property_unsupported")


class EngineIdentityStore:
    """POSIX, local-filesystem, cooperating-client immutability; not hostile-user isolation."""

    def __init__(self, store: ProfileStore):
        self.store = store

    @staticmethod
    def _lease(directory_fd: int, lease: ProfileLease, paths: Any) -> None:
        if type(lease) is not ProfileLease or not lease.active or lease.paths != paths:
            _fail("profile_lease_required")
        try:
            held = os.fstat(lease._fd)
            _check_private(lease._fd, directory=False)
            named = os.stat(".lease.lock", dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(named.st_mode) or (held.st_dev, held.st_ino) != (
                named.st_dev,
                named.st_ino,
            ):
                _fail("profile_lease_changed")
        except (OSError, TypeError):
            raise EngineIdentityError("profile_lease_changed") from None

    def _still_owned(self, fd: int, lease: ProfileLease, binding: IdentityBinding) -> None:
        current, paths = self.store._open_profile(binding.profile_id)
        try:
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (
                os.fstat(current).st_dev,
                os.fstat(current).st_ino,
            ):
                _fail("profile_directory_changed")
            self._lease(current, lease, paths)
        finally:
            os.close(current)

    @staticmethod
    def _read(directory_fd: int) -> bytes | None:
        try:
            fd = os.open(
                ARTIFACT_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        try:
            _check_private(fd, directory=False)
            before = os.fstat(fd)
            if before.st_size > MAX_ARTIFACT_BYTES:
                _fail("invalid_artifact")
            raw = os.read(fd, MAX_ARTIFACT_BYTES + 1)
            after = os.fstat(fd)

            def fields(s):
                return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

            named = os.stat(ARTIFACT_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if fields(before) != fields(after) or fields(after) != fields(named):
                _fail("artifact_changed")
            return raw
        finally:
            os.close(fd)

    @staticmethod
    def _fresh(directory_fd: int) -> None:
        try:
            os.stat(".camoufox-identity.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("identity_migration_required")
        fd = os.open(
            "browser-data",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            _check_private(fd, directory=True)
            if os.listdir(fd):
                _fail("profile_not_fresh")
        finally:
            os.close(fd)

    def load_or_create(
        self, lease: ProfileLease, binding: IdentityBinding, generator: IdentityGenerator
    ) -> EngineIdentity:
        """Missing artifact + fresh directory is the only generation path.

        Existing invalid/old/changed artifacts are never removed or regenerated.
        A torn creation remains a blocker. No migration/reset method is exposed.
        """
        if type(binding) is not IdentityBinding:
            _fail("invalid_binding")
        directory_fd, paths = self.store._open_profile(binding.profile_id)
        try:
            self._lease(directory_fd, lease, paths)
            provenance = generator.provenance(binding)
            if type(provenance) is not GeneratorProvenance:
                _fail("invalid_generator_provenance")
            raw = self._read(directory_fd)
            if raw is None:
                self._fresh(directory_fd)
                config, prefs, selected = generator.generate(binding)
                validate_identity(config, prefs, binding)
                if not _hash(selected):
                    _fail("invalid_generator_provenance")
                if generator.provenance(binding) != provenance:
                    _fail("generator_changed")
                self._still_owned(directory_fd, lease, binding)
                self._fresh(directory_fd)
                payload = {
                    "schema": SCHEMA,
                    "engine_id": "camoufox",
                    "binding": asdict(binding),
                    "generator": asdict(provenance),
                    "generator_sha256": provenance.sha256,
                    "selected_preset_sha256": selected,
                    "config": config,
                    "firefox_user_prefs": prefs,
                    "config_sha256": _digest(config),
                }
                payload["payload_sha256"] = _digest(payload)
                raw = _canonical(payload).encode()
                if len(raw) > MAX_ARTIFACT_BYTES:
                    _fail("invalid_artifact")
                # O_EXCL creates the final immutable name. On interrupted I/O it
                # stays invalid and blocks; no new identity can silently replace it.
                fd = os.open(
                    ARTIFACT_NAME,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    _check_private(fd, directory=False)
                    remaining = memoryview(raw)
                    while remaining:
                        written = os.write(fd, remaining)
                        if written <= 0:
                            _fail("artifact_write_failed")
                        remaining = remaining[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory_fd)
                if self._read(directory_fd) != raw:
                    _fail("artifact_changed")
            payload = _load(raw)
            expected_keys = {
                "schema",
                "engine_id",
                "binding",
                "generator",
                "generator_sha256",
                "selected_preset_sha256",
                "config",
                "firefox_user_prefs",
                "config_sha256",
                "payload_sha256",
            }
            if type(payload) is not dict or set(payload) != expected_keys:
                _fail("invalid_artifact")
            if (
                type(payload["schema"]) is not int
                or payload["schema"] != SCHEMA
                or payload["engine_id"] != "camoufox"
                or _canonical(payload["binding"]) != _canonical(asdict(binding))
                or payload["generator"] != asdict(provenance)
                or payload["generator_sha256"] != provenance.sha256
            ):
                _fail("identity_migration_required")
            if (
                not _hash(payload["selected_preset_sha256"])
                or payload["config_sha256"] != _digest(payload["config"])
                or payload["payload_sha256"]
                != _digest({k: v for k, v in payload.items() if k != "payload_sha256"})
                or _canonical(payload).encode() != raw
            ):
                _fail("invalid_artifact")
            validate_identity(payload["config"], payload["firefox_user_prefs"], binding)
            self._still_owned(directory_fd, lease, binding)
            return EngineIdentity(raw.decode("ascii"))
        except EngineIdentityError:
            raise
        except Exception:
            raise EngineIdentityError("identity_storage_unavailable") from None
        finally:
            os.close(directory_fd)


def _package_manifest(name: str) -> tuple[str, dict, Path]:
    """No imports: bounded reads of installed distribution package files."""
    distribution = importlib.metadata.distribution(name)
    prefix = name.replace("-", "_") + "/"
    members = {}
    for file in distribution.files or ():
        filename = str(file)
        if (
            not filename.startswith(prefix)
            or filename.endswith(".pyc")
            or "/__pycache__/" in filename
        ):
            continue
        path = Path(distribution.locate_file(file))
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 67108864:
            _fail("generator_package_changed")
        members[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not members:
        _fail("generator_package_changed")
    return distribution.version, members, Path(distribution.locate_file(prefix))


def _catalogue_name(binding: IdentityBinding) -> str:
    if binding.firefox_major >= 149:
        if binding.firefox_major not in _CONVERSION_TARGET_MAJORS:
            _fail("unsupported_engine_conversion")
        return "fingerprint-presets-v150.json"
    return "fingerprint-presets.json"


def _installed_provenance(binding: IdentityBinding) -> GeneratorProvenance:
    try:
        catalogue = _catalogue_name(binding)
        for name, (expected_version, expected_digest) in _REVIEWED_PACKAGES.items():
            version, members, _ = _package_manifest(name)
            if version != expected_version or _digest(members) != expected_digest:
                _fail("generator_package_changed")
        if importlib.metadata.version("playwright") != "1.62.0":
            _fail("generator_package_changed")
        environment = {}
        for name in _ENVIRONMENT_PACKAGES:
            dist = importlib.metadata.distribution(name)
            record = dist.read_text("RECORD")
            if not record:
                _fail("generator_package_changed")
            environment[name] = {
                "version": dist.version,
                "record_sha256": hashlib.sha256(record.encode()).hexdigest(),
            }
        return GeneratorProvenance(
            GENERATOR_VERSION,
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            _digest(environment),
            catalogue,
            _CATALOGUES[catalogue],
        )
    except EngineIdentityError:
        raise
    except Exception:
        raise EngineIdentityError("generator_unavailable") from None


# -S suppresses site/.pth/sitecustomize startup; -B alone only suppresses writes.
# Compile .py directly and remove sourceless/zip loaders, so accepted cached
# bytecode cannot replace the package source bytes checked by our manifest.
# Standard-library bootstrap code and native extensions still require a trusted
# interpreter/environment; this is not an OS sandbox or publisher attestation.
_WORKER_BOOTSTRAP = r"""
import sys, os, resource, importlib.machinery
resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
def _deny_side_effects(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")) or event in {
        "os.system", "os.fork", "os.forkpty", "os.mkdir", "os.remove", "os.rmdir",
        "os.rename", "os.link", "os.symlink", "os.chmod", "os.chown", "os.truncate",
        "os.utime", "os.setxattr", "os.removexattr"
    }:
        raise RuntimeError("offline_operation_denied")
    if event == "open":
        path, mode, flags = args
        if ((isinstance(path, str) and path.endswith((".pyc", ".pyo")))
            or (isinstance(path, bytes) and path.endswith((b".pyc", b".pyo")))
            or (isinstance(mode, str) and any(c in mode for c in "wax+"))
            or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))):
            raise RuntimeError("offline_operation_denied")
    if event == "sqlite3.connect" and (type(args[0]) is not str or not args[0].endswith("?mode=ro&immutable=1")):
        raise RuntimeError("offline_operation_denied")
sys.addaudithook(_deny_side_effects)
class _SourceOnly(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)
sys.path_hooks[:] = [importlib.machinery.FileFinder.path_hook(
    (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
    (_SourceOnly, importlib.machinery.SOURCE_SUFFIXES),
)]
sys.path_importer_cache.clear()
_script, _roots = sys.argv[1], sys.argv[2:]
if len(_roots) > 8 or any(not os.path.isabs(p) or len(p) > 4096 for p in _roots):
    raise RuntimeError("offline_generator_failed")
sys.path.extend(_roots)
sys.argv = [_script, "--offline-worker"]
with open(_script, "rb") as _source:
    _code = compile(_source.read(), _script, "exec")
exec(_code, {"__name__": "__main__", "__file__": _script})
"""


def _dependency_roots() -> tuple[Path, ...]:
    # The parent has already verified package provenance. Reuse those observed
    # installation roots without invoking site.addsitedir or running .pth files.
    roots = tuple(
        dict.fromkeys(
            Path(importlib.metadata.distribution(name).locate_file("")).resolve()
            for name in _ENVIRONMENT_PACKAGES
        )
    )
    if not 1 <= len(roots) <= 8 or any(not root.is_dir() for root in roots):
        _fail("generator_unavailable")
    return roots


def _worker_command(script: Path, roots: tuple[Path, ...]) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        _WORKER_BOOTSTRAP,
        str(script.resolve()),
        *(str(root.resolve()) for root in roots),
    ]


class OfflineCamoufoxGenerator:
    """Concrete official-preset adapter. No install/fetch fallback on missing dependencies."""

    def provenance(self, binding: IdentityBinding) -> GeneratorProvenance:
        return _installed_provenance(binding)

    def generate(self, binding: IdentityBinding) -> tuple[dict, dict, str]:
        provenance = self.provenance(binding)
        request = _canonical(
            {"binding": asdict(binding), "provenance": asdict(provenance)}
        ).encode()
        try:
            # File-backed stdout bounds memory even if a dependency unexpectedly
            # prints. Errors are discarded; only our fixed status is returned.
            with tempfile.TemporaryFile() as output:
                result = subprocess.run(
                    _worker_command(Path(__file__), _dependency_roots()),
                    input=request,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                    env={
                        "PATH": os.defpath,
                        "LC_ALL": "C",
                        "TZ": "UTC",
                        "OPENBLAS_NUM_THREADS": "1",
                    },
                )
                output.seek(0)
                raw = output.read(MAX_ARTIFACT_BYTES + 1)
            data = _load(raw)
            if result.returncode or type(data) is not dict:
                _fail("offline_generator_failed")
            if set(data) == {"error"}:
                reason = data["error"]
                if reason in {
                    "catalogue_match_unavailable",
                    "unsupported_engine_conversion",
                    "unsupported_locale_voices",
                    "generator_changed",
                    "generator_package_changed",
                    "incoherent_identity",
                }:
                    _fail(reason)
                _fail("offline_generator_failed")
            if set(data) != {"config", "firefox_user_prefs", "selected_preset_sha256"}:
                _fail("offline_generator_failed")
            validate_identity(data["config"], data["firefox_user_prefs"], binding)
            if not _hash(data["selected_preset_sha256"]):
                _fail("offline_generator_failed")
            return data["config"], data["firefox_user_prefs"], data["selected_preset_sha256"]
        except EngineIdentityError:
            raise
        except Exception:
            raise EngineIdentityError("offline_generator_failed") from None


def _offline_guard(event: str, args: tuple) -> None:
    """Defense-in-depth audit policy, not a malicious-native-code sandbox."""
    if event.startswith(
        ("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")
    ) or event in {
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.mkdir",
        "os.remove",
        "os.rmdir",
        "os.rename",
        "os.link",
        "os.symlink",
        "os.chmod",
        "os.chown",
        "os.truncate",
        "os.utime",
        "os.setxattr",
        "os.removexattr",
    }:
        _fail("offline_operation_denied")
    if event == "open":
        mode, flags = args[1], args[2]
        if (type(mode) is str and any(c in mode for c in "wax+")) or (
            type(flags) is int
            and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        ):
            _fail("offline_operation_denied")
    if event == "sqlite3.connect" and (
        type(args[0]) is not str or not args[0].endswith("?mode=ro&immutable=1")
    ):
        _fail("offline_operation_denied")


def _preset_source_major(preset: dict, binding: IdentityBinding) -> int | None:
    """Admit a same-OS catalogue anchor, without drawing seeds or changing it.

    Only available-screen geometry may differ from the independently accepted
    display. Physical CSS dimensions, color depth and native DPR stay exact.
    The old catalogue retains exact-major behavior; the modern one permits only
    the versioned, forward-only configuration-conversion range above.
    """
    try:
        nav, screen = preset["navigator"], preset["screen"]
        source_display = AcceptedDisplay(
            screen["width"],
            screen["height"],
            screen["availWidth"],
            screen["availHeight"],
            screen["colorDepth"],
            screen["devicePixelRatio"],
        )
        for field in ("width", "height", "color_depth", "device_pixel_ratio"):
            if getattr(source_display, field) != getattr(binding.display, field):
                return None
        match = _navigator_match(nav["userAgent"], binding.target_os)
        if match is None:
            return None
        major = int(match["major"])
        if binding.firefox_major >= 149:
            if (
                binding.firefox_major not in _CONVERSION_TARGET_MAJORS
                or major not in _CONVERSION_SOURCE_MAJORS
                or major > binding.firefox_major
            ):
                return None
        elif major != binding.firefox_major:
            return None
        platform, fallback_oscpu = {
            "macos": ("MacIntel", "Intel Mac OS X 10.15"),
            "windows": ("Win32", "Windows NT 10.0; Win64; x64"),
            "linux": ("Linux x86_64", "Linux x86_64"),
        }[binding.target_os]
        if (
            nav["platform"] != platform
            or nav.get("oscpu", fallback_oscpu) != match["oscpu"]
            or nav.get("appVersion", _app_version(binding.target_os, match))
            != _app_version(binding.target_os, match)
            or not _int(nav["hardwareConcurrency"], 1, 256)
            or not _int(nav["maxTouchPoints"], 0, 20)
        ):
            return None
        return major
    except (KeyError, TypeError, ValueError):
        return None


def _catalogue_graphics_supported(graphics: dict, gpu: dict) -> bool:
    """Filter sparse/incoherent DB records before the one identity draw."""
    try:
        if (
            type(graphics) is not dict
            or set(graphics) != _WEBGL_KEYS | {"webGl:vendor", "webGl:renderer", "webGl2Enabled"}
            or not _json_tree(graphics)
            or graphics["webGl2Enabled"] is not True
            or not _text(gpu["unmaskedVendor"])
            or not _text(gpu["unmaskedRenderer"])
            or graphics["webGl:vendor"] != gpu["unmaskedVendor"]
            or graphics["webGl:renderer"] != gpu["unmaskedRenderer"]
        ):
            return False
        _validate_webgl(graphics)
        for prefix in ("webGl", "webGl2"):
            if (
                graphics[f"{prefix}:parameters"].get("37445") != gpu["unmaskedVendor"]
                or graphics[f"{prefix}:parameters"].get("37446") != gpu["unmaskedRenderer"]
            ):
                return False
        return True
    except (EngineIdentityError, KeyError, TypeError, ValueError):
        return False


def _generate_offline(binding: IdentityBinding) -> tuple[dict, dict, str]:
    # Every listed function is from the pinned/reviewed package. Importing its
    # BrowserForge generator reads packaged model files; it downloads nothing.
    from camoufox import fingerprints as fp
    import camoufox.webgl.sample as webgl
    import sqlite3
    from unittest.mock import patch
    from secrets import choice

    _, _, package_root = _package_manifest("camoufox")
    catalogue = _catalogue_name(binding)
    presets = _load((package_root / catalogue).read_bytes(), 1048576)["presets"][binding.target_os]
    display = binding.display
    database = package_root / "webgl" / "webgl_data.db"
    connect = sqlite3.connect

    def readonly_connect(path, *args, **kwargs):
        if Path(path) != database or args or kwargs:
            _fail("offline_operation_denied")
        return connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)

    candidates = []
    with readonly_connect(database) as connection:
        for preset in presets:
            major = _preset_source_major(preset, binding)
            if major is None:
                continue
            gpu = preset.get("webgl", {})
            row = connection.execute(
                "SELECT data FROM webgl_fingerprints WHERE vendor=? AND renderer=? AND "
                + _OS_SHORT[binding.target_os]
                + ">0",
                (gpu.get("unmaskedVendor"), gpu.get("unmaskedRenderer")),
            ).fetchone()
            if row and _catalogue_graphics_supported(json.loads(row[0]), gpu):
                candidates.append((major, preset))
    if not candidates:
        _fail("catalogue_match_unavailable")
    # Prefer the newest eligible source cohort, never a future/down-converted
    # identity. Invalid candidates are filtered before any seeds are generated.
    newest = max(major for major, _ in candidates)
    preset = choice([preset for major, preset in candidates if major == newest])
    config = fp.from_preset(preset, str(binding.firefox_major))
    fp.fix_navigator_arch(config, _OS_SHORT[binding.target_os])
    # The trusted native observation is authoritative, including auto-hidden
    # panels/full available screens. Do not call fix_screen_no_taskbar: its
    # guessed panel height would contradict that independently accepted fact.
    config["screen.availWidth"] = display.avail_width
    config["screen.availHeight"] = display.avail_height
    fp.clamp_window_dimensions(config)
    fp.clamp_window_position(config)
    with patch.object(sqlite3, "connect", readonly_connect):
        graphics = webgl.sample_webgl(
            _OS_SHORT[binding.target_os], config["webGl:vendor"], config["webGl:renderer"]
        )
    if not _catalogue_graphics_supported(graphics, preset["webgl"]):
        _fail("catalogue_match_unavailable")
    enabled = graphics.pop("webGl2Enabled")
    config.update(graphics)
    config["voices"] = fp._generate_random_voice_subset(binding.target_os, binding.locale)
    config["voices:blockIfNotDefined"] = True
    config.update(
        {
            "timezone": binding.timezone_id,
            "locale:language": binding.locale.split("-")[0],
            "locale:region": binding.locale.split("-")[1],
            "navigator.language": binding.locale,
            "navigator.languages": [binding.locale],
            "headers.Accept-Language": binding.locale,
        }
    )
    prefs = {"webgl.enable-webgl2": enabled, "webgl.force-enabled": True}
    validate_identity(config, prefs, binding)
    return config, prefs, _digest(preset)


def _worker_main() -> None:
    sys.dont_write_bytecode = True
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
        sys.addaudithook(_offline_guard)
        request = _load(sys.stdin.buffer.read(16385), 16384)
        raw_binding = request["binding"]
        raw_binding["display"] = AcceptedDisplay(**raw_binding["display"])
        binding = IdentityBinding(**raw_binding)
        before = _installed_provenance(binding)
        if asdict(before) != request["provenance"]:
            _fail("generator_changed")
        config, prefs, selected = _generate_offline(binding)
        if _installed_provenance(binding) != before:
            _fail("generator_changed")
        result = {"config": config, "firefox_user_prefs": prefs, "selected_preset_sha256": selected}
    except EngineIdentityError as error:
        result = {"error": error.reason}
    except Exception:
        result = {"error": "offline_generator_failed"}
    sys.stdout.write(_canonical(result))


if __name__ == "__main__" and sys.argv[1:] == ["--offline-worker"]:
    _worker_main()
