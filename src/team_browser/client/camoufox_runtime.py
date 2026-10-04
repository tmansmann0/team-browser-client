"""Reviewed Camoufox persistent-context adapter with a fail-closed proxy route.

Programmatic integration only. No policy JSON/web API can certify real native
acceptance. No browser fetch, geo-IP, addon download, random identity generation,
OS network changes, or credentials passed to Camoufox/Playwright are performed.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
import re
import secrets as identity_secrets
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from zoneinfo import ZoneInfo

from team_browser.local.proxy import (
    ProxyConfiguration,
    ProxyExpectations,
    ProxyProbeEvidence,
    validate_proxy_preflight,
)
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, VerifiedRuntime
from team_browser.local.secrets import SecretStore
from team_browser.local.storage import ProfileStore, _check_private, validate_identifier

from .engine_identity import (
    SCHEMA as IDENTITY_SCHEMA,
    ARTIFACT_NAME,
    AcceptedDisplay,
    EngineIdentity,
    EngineIdentityStore,
    GeneratorProvenance,
    IdentityBinding,
    IdentityGenerator,
    validate_identity as validate_generated_config,
)
from .lifecycle import GMAIL_INBOX_URL, LaunchContext
from .playwright_supervisor import PlaywrightHandle, PlaywrightSupervisor
from .proxy_relay import HTTPSConnectTransport, ProxyRelay, diagnostic_authorities
from .store import WorkspaceError


CAMOUFOX_VERSION = "0.5.6"
PLAYWRIGHT_VERSION = "1.62.0"
# Keys are real Gecko preferences. Setting a preference is NOT proof that a
# particular Camoufox build honors it. Exact-build acceptance remains mandatory.
ROUTE_PREFS = {
    "network.proxy.type": 1,
    "network.proxy.socks": "127.0.0.1",
    "network.proxy.socks_version": 5,
    "network.proxy.socks_remote_dns": True,
    "network.proxy.socks5_remote_dns": True,
    "network.proxy.no_proxies_on": "",
    "network.proxy.autoconfig_url": "",
    "network.proxy.failover_direct": False,
    "network.proxy.allow_bypass": False,
    "network.proxy.allow_hijacking_localhost": True,
    "network.proxy.http": "",
    "network.proxy.ssl": "",
    "network.proxy.share_proxy_settings": False,
    "network.dns.disablePrefetch": True,
    "network.dns.disablePrefetchFromHTTPS": True,
    "network.dns.disableIPv6": True,
    "network.prefetch-next": False,
    "network.predictor.enabled": False,
    "network.http.speculative-parallel-limit": 0,
    "network.http.http3.enable": False,
    "network.trr.mode": 5,
    "media.peerconnection.enabled": False,
    "browser.startup.page": 0,
    "browser.startup.homepage": "about:blank",
    "browser.sessionstore.resume_from_crash": False,
    "browser.sessionstore.resume_session_once": False,
    "browser.sessionstore.max_resumed_crashes": 0,
}
ROUTE_PREFS_SHA256 = hashlib.sha256(
    json.dumps(ROUTE_PREFS, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def profile_policy_binding(profile: dict[str, Any]) -> str:
    """Bind configuration fields only; lifecycle/name/favorite revisions are not identity.

    The coordinator still revision-fences the complete metadata before admission.
    A trusted provider can project this binding from the current metadata without
    requiring another identity review merely because a profile was selected.
    """
    return hashlib.sha256(
        json.dumps(
            [
                profile["id"],
                profile["engine_id"],
                profile["preset_id"],
                profile.get("network_policy", "unconfigured"),
                profile.get("origin", "local"),
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class CamoufoxProfilePolicy:
    """Trusted settings bound to stable profile configuration, not UI revisions.

    This slice uses the engine's native identity plus explicit stable locale and
    timezone. It never asks the SDK to generate a fingerprint at startup. Future
    richer identity presets need their own persistence and exact-build tests.
    """

    profile_id: str
    profile_binding_sha256: str
    preset_id: str
    locale: str
    timezone_id: str
    proxy_fingerprint: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id)
        validate_identifier(self.preset_id)
        if not isinstance(self.profile_binding_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.profile_binding_sha256
        ):
            raise ValueError("Profile policy requires a stable configuration binding")
        if not re.fullmatch(r"[a-z]{2,3}-[A-Z]{2}", self.locale):
            raise ValueError("An explicit language-region locale is required")
        ZoneInfo(self.timezone_id)
        if self.proxy_fingerprint is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.proxy_fingerprint
        ):
            raise ValueError("Proxy assignment fingerprint is invalid")

    @property
    def config_json(self) -> str:
        language, region = self.locale.split("-")
        return json.dumps(
            {
                "timezone": self.timezone_id,
                "locale:language": language,
                "locale:region": region,
                "navigator.language": self.locale,
                "navigator.languages": [self.locale],
                "headers.Accept-Language": self.locale,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def check(self, profile: dict[str, Any]) -> None:
        if (self.profile_id, self.profile_binding_sha256, self.preset_id) != (
            profile["id"],
            profile_policy_binding(profile),
            profile["preset_id"],
        ):
            raise WorkspaceError("profile_policy_stale", "Camoufox profile settings need review")


class ProfilePolicies(Protocol):
    def for_profile(self, profile_id: str) -> CamoufoxProfilePolicy: ...


class BrowserContextProbe(Protocol):
    async def collect(
        self, context: Any, configuration: ProxyConfiguration, expectations: ProxyExpectations
    ) -> ProxyProbeEvidence:
        """Probe the exact owned context, including DNS/IPv6/UDP/outage behavior.

        A production implementation must be trusted and non-destructive for the
        active context. Dangerous outage tests belong to native acceptance; live
        observations must verify its enforcement still holds, not repeat a cached
        HTTP IP-echo result. No implementation is fabricated by this module.
        """
        ...


@dataclass(frozen=True)
class CamoufoxProxyRoute:
    configuration: ProxyConfiguration
    expectations: ProxyExpectations
    probe: BrowserContextProbe
    diagnostic_targets: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        diagnostic_authorities(self.diagnostic_targets)


class CamoufoxRoutes(Protocol):
    def for_profile(self, profile_id: str) -> CamoufoxProxyRoute: ...


@dataclass(frozen=True)
class CamoufoxAcceptance:
    """Trusted real-device test record; absent by default, never user/API data."""

    runtime_sha256: str
    engine_version: str
    platform: str
    test_id: str
    valid_until: datetime
    camoufox_version: str = CAMOUFOX_VERSION
    playwright_version: str = PLAYWRIGHT_VERSION
    proxy_preferences_sha256: str | None = None
    trusted_single_user_host: bool = False

    def check(self, runtime: VerifiedRuntime, *, proxy: bool = False) -> None:
        now = datetime.now(timezone.utc)
        if (
            runtime.engine_id != "camoufox"
            or self.runtime_sha256 != runtime.sha256
            or self.engine_version != runtime.version
            or self.platform != sys.platform
            or not self.test_id.strip()
            or self.valid_until.utcoffset() is None
            or not now < self.valid_until <= now + timedelta(days=30)
            or (self.camoufox_version, self.playwright_version)
            != (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION)
        ):
            raise WorkspaceError(
                "camoufox_unverified", "Exact Camoufox native acceptance is required"
            )
        if proxy and (
            self.proxy_preferences_sha256 != ROUTE_PREFS_SHA256
            or self.trusted_single_user_host is not True
        ):
            raise WorkspaceError(
                "proxy_unverified",
                "Exact proxy leak/failure and trusted single-user-host acceptance is required",
            )


@dataclass(frozen=True)
class CamoufoxRuntimeMetadata:
    """Fresh evidence from an independently reviewed distribution observer.

    This record is not authenticity evidence by itself. The trusted observer
    must use bounded, no-symlink reads and map the selected distribution's signed
    metadata to its exact engine/build version. No vendor mapping is guessed or
    implemented here, and no default observer is supplied.
    """

    version: str
    source_path: Path
    source_identity: tuple[int, int, int, int, int]
    source_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or not self.version
            or len(self.version) > 128
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.version)
            or not isinstance(self.source_path, Path)
            or not self.source_path.is_absolute()
            or ".." in self.source_path.parts
            or not isinstance(self.source_identity, tuple)
            or len(self.source_identity) != 5
            or any(type(value) is not int or value < 0 for value in self.source_identity)
            or not isinstance(self.source_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.source_sha256)
        ):
            raise ValueError("Exact bounded Camoufox metadata evidence is required")


def installed_dependency_versions() -> tuple[str, str]:
    try:
        return importlib.metadata.version("camoufox"), importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        raise WorkspaceError(
            "camoufox_dependencies_missing",
            "Reviewed Camoufox and Playwright packages are required",
        ) from None


IDENTITY_PROBE_SCHEMA = "camoufox-stable-surfaces-v1"
_IDENTITY_CORE_KEYS = (
    "navigator.userAgent",
    "navigator.platform",
    "navigator.oscpu",
    "navigator.appVersion",
    "navigator.hardwareConcurrency",
    "navigator.maxTouchPoints",
    "navigator.language",
    "navigator.languages",
    "screen.width",
    "screen.height",
    "screen.availWidth",
    "screen.availHeight",
    "screen.colorDepth",
    "screen.pixelDepth",
    "timezone",
)
IDENTITY_SIGNAL_NAMES = ("canvas", "voices", "webgl", "webgl2")
IDENTITY_WEBGL_PARAMETERS = (3379, 3386, 34921, 34930)
_IDENTITY_SIGNALS = IDENTITY_SIGNAL_NAMES


def _identity_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def identity_voices_sha256(voices: list[dict]) -> str:
    """Digest normalized Camoufox voice objects, order-independent and lossless."""
    return _identity_sha(
        sorted(
            voices,
            key=lambda voice: json.dumps(
                voice, sort_keys=True, separators=(",", ":"), allow_nan=False
            ),
        )
    )


def expected_identity_core(artifact: EngineIdentity, display: AcceptedDisplay) -> dict:
    """Exact measured subset for the fixed v1 collector; no inferred hardware."""
    config = json.loads(artifact.config_json)
    result = {key: config[key] for key in _IDENTITY_CORE_KEYS}
    result["devicePixelRatio"] = float(display.device_pixel_ratio)
    result["voices.sha256"] = identity_voices_sha256(config["voices"])
    for prefix in ("webGl", "webGl2"):
        result[f"{prefix}:vendor"] = config["webGl:vendor"]
        result[f"{prefix}:renderer"] = config["webGl:renderer"]
        for enum in IDENTITY_WEBGL_PARAMETERS:
            result[f"{prefix}:parameter:{enum}"] = config[f"{prefix}:parameters"][str(enum)]
    return result


def _identity_hash(value: Any) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[a-f0-9]{64}", value))


def _identity_expiry(value: datetime) -> bool:
    now = datetime.now(timezone.utc)
    return (
        type(value) is datetime
        and value.utcoffset() is not None
        and now < value <= now + timedelta(days=30)
    )


@dataclass(frozen=True)
class CamoufoxIdentityProperties:
    """Trusted fresh, bounded, no-follow properties.json observation.

    Like runtime metadata, source selection/authenticity belongs to the accepted
    native observer. No path or JSON content from the web API becomes authority.
    """

    source_path: Path
    source_identity: tuple[int, int, int, int, int]
    source_sha256: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            type(self.source_path) is not Path
            and not isinstance(self.source_path, Path)
            or not self.source_path.is_absolute()
            or ".." in self.source_path.parts
            or type(self.source_identity) is not tuple
            or len(self.source_identity) != 5
            or any(type(n) is not int or n < 0 for n in self.source_identity)
            or type(self.content) is not bytes
            or not 0 < len(self.content) <= 262144
            or not _identity_hash(self.source_sha256)
            or hashlib.sha256(self.content).hexdigest() != self.source_sha256
            or self.source_identity[2] != len(self.content)
        ):
            raise ValueError("Exact trusted engine-property evidence is required")


@dataclass(frozen=True)
class CamoufoxIdentityProgramAcceptance:
    """Reviewed native engine/generator/probe envelope, not per-profile proof."""

    runtime_sha256: str
    engine_version: str
    firefox_major: int
    platform: str
    display: AcceptedDisplay
    provenance: GeneratorProvenance
    properties_sha256: str
    probe_id: str
    test_id: str
    valid_until: datetime
    identity_schema: int = IDENTITY_SCHEMA
    probe_schema: str = IDENTITY_PROBE_SCHEMA

    @property
    def sha256(self) -> str:
        value = asdict(self)
        value["valid_until"] = self.valid_until.isoformat()
        return _identity_sha(value)

    def check(
        self, runtime: VerifiedRuntime, binding: IdentityBinding, provenance: GeneratorProvenance
    ) -> None:
        if (
            type(self.identity_schema) is not int
            or self.identity_schema != IDENTITY_SCHEMA
            or self.probe_schema != IDENTITY_PROBE_SCHEMA
            or not _identity_hash(self.properties_sha256)
            or not isinstance(self.probe_id, str)
            or not 1 <= len(self.probe_id) <= 128
            or not isinstance(self.test_id, str)
            or not self.test_id.strip()
            or not _identity_expiry(self.valid_until)
            or self.runtime_sha256 != runtime.sha256
            or self.engine_version != runtime.version
            or self.platform != sys.platform
            or self.platform != binding.platform
            or self.firefox_major != binding.firefox_major
            or type(self.firefox_major) is not int
            or self.display != binding.display
            or self.provenance != provenance
        ):
            raise WorkspaceError(
                "identity_program_unverified",
                "Exact native identity engine/generator/display acceptance is required",
            )


@dataclass(frozen=True)
class CamoufoxIdentityObservation:
    """Fresh exact-context observations from the accepted fixed native probe.

    core_json contains observed browser values, never configuration echoed as
    measurements. V1 signals hash fixed canvas, voice-list, WebGL and WebGL2
    fixtures. Audio/font/worker outputs remain separate native acceptance limits.
    The probe implementation and fixtures are identified by probe_id.
    """

    probe_id: str
    challenge: str
    artifact_sha256: str
    observed_at: datetime
    core_json: str
    signals: tuple[tuple[str, str], ...]
    schema: str = IDENTITY_PROBE_SCHEMA

    def checked_digest(
        self, policy, artifact: EngineIdentity, challenge: str, started_at: datetime
    ) -> str:
        now = datetime.now(timezone.utc)
        if (
            self.probe_id != policy.program.probe_id
            or self.schema != IDENTITY_PROBE_SCHEMA
            or self.challenge != challenge
            or self.artifact_sha256 != artifact.artifact_sha256
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or not started_at <= self.observed_at <= now + timedelta(seconds=1)
            or now - self.observed_at > timedelta(seconds=10)
            or type(self.core_json) is not str
            or len(self.core_json) > 8192
            or type(self.signals) is not tuple
            or tuple(name for name, _ in self.signals) != _IDENTITY_SIGNALS
            or not all(_identity_hash(digest) for _, digest in self.signals)
        ):
            raise WorkspaceError(
                "identity_probe_invalid", "Fresh owned-context identity evidence is required"
            )
        expected = expected_identity_core(artifact, policy.binding.display)
        # Canonical exact text prevents duplicate fields, NaN and bool/int type
        # substitutions without trusting an observer's loosely typed dict.
        if self.core_json != json.dumps(
            expected, sort_keys=True, separators=(",", ":"), allow_nan=False
        ):
            raise WorkspaceError(
                "identity_surface_mismatch",
                "The owned context does not expose the prepared identity",
            )
        return _identity_sha({"core_json": self.core_json, "signals": self.signals})


class CamoufoxIdentityProbe(Protocol):
    probe_id: str

    async def collect(
        self, context: Any, challenge: str, artifact: EngineIdentity
    ) -> CamoufoxIdentityObservation:
        """Read fixed accepted fixtures in the exact owned context; no arbitrary URL/script input."""
        ...


@dataclass(frozen=True)
class CamoufoxProfileIdentityAdmission:
    """Typed result of supervised validation, never deserialized from UI/JSON."""

    profile_id: str
    binding_sha256: str
    artifact_sha256: str
    config_sha256: str
    program_sha256: str
    surfaces_sha256: str
    validation_lease_token: str
    validation_id: str
    observed_at: datetime
    valid_until: datetime

    def check(self, policy, artifact: EngineIdentity | None = None) -> None:
        now = datetime.now(timezone.utc)
        if (
            self.profile_id != policy.binding.profile_id
            or self.binding_sha256 != policy.binding.sha256
            or self.artifact_sha256 != policy.artifact_sha256
            or self.program_sha256 != policy.program.sha256
            or not all(
                _identity_hash(value)
                for value in (
                    self.binding_sha256,
                    self.artifact_sha256,
                    self.config_sha256,
                    self.program_sha256,
                    self.surfaces_sha256,
                )
            )
            or type(self.validation_lease_token) is not str
            or not re.fullmatch(r"[a-f0-9]{32}", self.validation_lease_token)
            or type(self.validation_id) is not str
            or not re.fullmatch(r"[a-f0-9]{32}", self.validation_id)
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.observed_at > now
            or not _identity_expiry(self.valid_until)
            or self.valid_until > policy.program.valid_until
            or (
                artifact is not None
                and (
                    self.artifact_sha256 != artifact.artifact_sha256
                    or self.config_sha256 != artifact.config_sha256
                )
            )
        ):
            raise WorkspaceError(
                "profile_identity_unverified",
                "This exact prepared identity needs native validation",
            )


@dataclass(frozen=True)
class CamoufoxGeneratedIdentityPolicy:
    """Trusted native preparation/admission, separate from six-key legacy mode."""

    binding: IdentityBinding
    artifact_sha256: str
    generator: IdentityGenerator
    program: CamoufoxIdentityProgramAcceptance
    properties_observer: Callable[[Path], CamoufoxIdentityProperties]
    probe: CamoufoxIdentityProbe
    admission: CamoufoxProfileIdentityAdmission | None = None

    def check(self, runtime, profile, settings, *, validation: bool = False) -> None:
        binding = self.binding
        if (
            type(binding) is not IdentityBinding
            or not _identity_hash(self.artifact_sha256)
            or (binding.profile_id, binding.profile_binding_sha256, binding.preset_id)
            != (profile["id"], profile_policy_binding(profile), settings.preset_id)
            or (binding.locale, binding.timezone_id, binding.proxy_fingerprint)
            != (settings.locale, settings.timezone_id, settings.proxy_fingerprint)
            or (binding.engine_version, binding.engine_sha256) != (runtime.version, runtime.sha256)
            or self.probe.probe_id != self.program.probe_id
        ):
            raise WorkspaceError(
                "generated_identity_stale", "Prepared identity or native observation policy changed"
            )
        self.program.check(runtime, binding, self.generator.provenance(binding))
        if not validation:
            if type(self.admission) is not CamoufoxProfileIdentityAdmission:
                raise WorkspaceError(
                    "profile_identity_unverified",
                    "Prepare and natively validate this exact identity before normal use",
                )
            self.admission.check(self)


class CamoufoxGeneratedIdentities(Protocol):
    def for_profile(self, profile_id: str) -> CamoufoxGeneratedIdentityPolicy: ...


class _ExistingIdentityGenerator:
    """Load-only adapter: a deleted/missing artifact cannot trigger regeneration."""

    def __init__(self, generator):
        self.generator = generator

    def provenance(self, binding):
        return self.generator.provenance(binding)

    def generate(self, binding):
        raise WorkspaceError(
            "identity_not_prepared", "Prepare this identity offline before native validation"
        )


def _identity_environment(config_json: str) -> dict[str, str]:
    if (
        type(config_json) is not str
        or not config_json.isascii()
        or not 0 < len(config_json) <= 131072
    ):
        raise WorkspaceError(
            "identity_config_invalid", "Identity configuration is not bounded canonical ASCII"
        )
    # Native process environment string limits differ. This matches the reviewed
    # Camoufox chunk convention and never inherits ambient CAMOU_CONFIG values.
    width = 2047 if sys.platform == "win32" else 32767
    return {
        f"CAMOU_CONFIG_{i // width + 1}": config_json[i : i + width]
        for i in range(0, len(config_json), width)
    }


class CamoufoxHandle(PlaywrightHandle):
    def __init__(self, owner, context):
        super().__init__(owner, context)
        self.relay: ProxyRelay | None = None
        self.monitor_task: asyncio.Task | None = None
        self.route_failed = False
        self.spawn_attempted = False
        self.route_guard: Callable[[], bool] | None = None
        self.runtime_guard: Callable[[], bool] | None = None
        self.identity_guard: Callable[[], bool] | None = None
        self.identity: EngineIdentity | None = None
        self.identity_policy: CamoufoxGeneratedIdentityPolicy | None = None
        self.validating_identity = False
        self.identity_validation_cancelled = False
        self.identity_close_task: asyncio.Task | None = None
        self.identity_admission: CamoufoxProfileIdentityAdmission | None = None

    def _on_close(self, *_: object) -> None:
        super()._on_close()
        if self.ownership_uncertain:
            if self.monitor_task is not None:
                self.monitor_task.cancel()
            if self.relay is not None:
                self.relay.fail_closed()

    def stop(self) -> bool:
        if self.validating_identity and self.identity_admission is None:
            self.identity_validation_cancelled = True
        return super().stop()

    def _route_failure(self) -> None:
        self.route_failed = True
        self.stop()

    async def _stop(self) -> bool:
        if self.relay is not None:
            await self.relay.stop()
        if self.monitor_task is not None:
            self.monitor_task.cancel()
        if self.ownership_uncertain:
            self._set_phase("unknown")
            return False
        if self.launch_future is not None and not self.launch_future.done():
            try:
                await asyncio.wrap_future(self.launch_future)
            except (Exception, asyncio.CancelledError):
                pass
        if self.phase == "stopped":
            return True
        if self.context is None:
            if not self.spawn_attempted:
                self._set_phase("stopped")
                return True
            self.ownership_uncertain = True
            self._set_phase("unknown")
            return False
        try:
            # Public in the pinned Playwright version. An already-closing/closed
            # context can make close() a no-op, including when its close event
            # preceded our listener. That is not proof the owned process exited.
            if self.ownership_uncertain or self.context.is_closed():
                self.ownership_uncertain = True
                self._set_phase("unknown")
                return False
            self.close_requested = True
            await self.context.close()
            if not self.context.is_closed():
                self.ownership_uncertain = True
                self._set_phase("unknown")
                return False
        except Exception:
            self.ownership_uncertain = True
            self._set_phase("unknown")
            return False
        self._set_phase("stopped")
        return True


class CamoufoxSupervisor(PlaywrightSupervisor):
    """One owner loop, persistent contexts, fixed intents, sticky proxy failures."""

    def __init__(
        self,
        *,
        acceptance: CamoufoxAcceptance | None = None,
        factory=None,
        launcher=None,
        dependencies: Callable[[], tuple[str, str]] = installed_dependency_versions,
        secrets: SecretStore | None = None,
        transport_factory=None,
    ):
        super().__init__(factory=factory)
        self.acceptance, self.launcher, self.dependencies = acceptance, launcher, dependencies
        self.secrets, self.transport_factory = secrets, transport_factory

    def check(self, runtime: VerifiedRuntime, *, proxy: bool = False) -> None:
        if self.acceptance is None:
            raise WorkspaceError(
                "camoufox_unverified", "Exact Camoufox native acceptance is required"
            )
        self.acceptance.check(runtime, proxy=proxy)
        if self.dependencies() != (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION):
            raise WorkspaceError(
                "camoufox_dependencies_changed", "Reviewed launcher versions changed"
            )

    async def _require_route_authority(self, handle) -> None:
        if handle.route_guard is None or not await asyncio.wait_for(
            asyncio.to_thread(handle.route_guard), timeout=5
        ):
            raise WorkspaceError(
                "proxy_assignment_changed", "The current proxy assignment is unverified"
            )

    async def _probe(self, handle: CamoufoxHandle, route: CamoufoxProxyRoute):
        async with asyncio.timeout(5):
            await self._require_route_authority(handle)
            evidence = await route.probe.collect(
                handle.context, route.configuration, route.expectations
            )
            result = validate_proxy_preflight(route.configuration, route.expectations, evidence)
            # No authority snapshot from before a slow probe can widen routing.
            await self._require_route_authority(handle)
            if (
                not result.passed
                or handle.relay is None
                or not handle.relay.healthy
                or result.valid_until is None
                or result.valid_until <= datetime.now(timezone.utc)
            ):
                raise WorkspaceError("proxy_probe_failed", "The owned browser route is unverified")
            return result

    async def _monitor(self, handle, route, result):
        try:
            while not handle.close_requested:
                remaining = (result.valid_until - datetime.now(timezone.utc)).total_seconds()
                if remaining <= 0:
                    raise ValueError("Expired route evidence")
                # The next probe must finish before current evidence expires.
                await asyncio.sleep(min(10, remaining / 3))
                budget = (result.valid_until - datetime.now(timezone.utc)).total_seconds()
                result = await asyncio.wait_for(
                    self._probe(handle, route), timeout=max(0.001, budget)
                )
        except asyncio.CancelledError:
            return
        except Exception:
            handle.relay.fail_closed()

    async def _runtime_current(self, handle, runtime) -> bool:
        def unchanged() -> bool:
            return (
                handle.runtime_guard is not None
                and handle.runtime_guard()
                and (handle.identity_guard is None or handle.identity_guard())
                and RuntimeGate.is_unchanged(runtime)
                and handle.runtime_guard()
                and (handle.identity_guard is None or handle.identity_guard())
            )

        return await asyncio.wait_for(asyncio.to_thread(unchanged), timeout=5)

    def _require_final_authority(self, handle, runtime) -> None:
        """Non-awaiting fence immediately before spawn/release/readiness/report.

        Providers must expose bounded local snapshots here, not perform remote
        authority refresh. Async work is completed first; no later awaited guard
        can hide a change made by the previous one.
        """
        self.check(runtime, proxy=handle.route_guard is not None)
        if (
            handle.runtime_guard is None
            or not handle.runtime_guard()
            or (handle.identity_guard is not None and not handle.identity_guard())
            or (handle.route_guard is not None and not handle.route_guard())
            or not RuntimeGate.is_unchanged(runtime)
            or not handle.runtime_guard()
        ):
            raise WorkspaceError(
                "native_authority_changed",
                "Native runtime, profile identity or route authority changed",
            )

    async def _observe_identity(self, handle, runtime):
        if handle.identity is None or handle.identity_policy is None:
            raise WorkspaceError(
                "identity_probe_required", "Prepared identity observation is required"
            )
        if not await self._runtime_current(handle, runtime):
            raise WorkspaceError(
                "generated_identity_stale", "Identity authority changed before observation"
            )
        if handle.route_guard is not None:
            await self._require_route_authority(handle)
        challenge = identity_secrets.token_hex(16)
        started = datetime.now(timezone.utc)
        observation = await asyncio.wait_for(
            handle.identity_policy.probe.collect(handle.context, challenge, handle.identity),
            timeout=5,
        )
        if type(observation) is not CamoufoxIdentityObservation:
            raise WorkspaceError(
                "identity_probe_invalid", "A fixed native identity observation is required"
            )
        digest = observation.checked_digest(
            handle.identity_policy, handle.identity, challenge, started
        )
        if handle.route_guard is not None:
            await self._require_route_authority(handle)
        if not await self._runtime_current(handle, runtime):
            raise WorkspaceError(
                "generated_identity_stale", "Identity authority changed during observation"
            )
        self._require_final_authority(handle, runtime)
        # Check expiry again after every awaited authority check.
        observation.checked_digest(handle.identity_policy, handle.identity, challenge, started)
        if not handle.validating_identity:
            admission = handle.identity_policy.admission
            if admission is None or digest != admission.surfaces_sha256:
                raise WorkspaceError(
                    "identity_surface_mismatch", "Identity surfaces changed since native validation"
                )
        return digest, observation.observed_at

    async def _refresh_identity_observation(self, handle, runtime, observed_at):
        if handle.identity is None:
            return None
        if observed_at is None or datetime.now(timezone.utc) - observed_at > timedelta(seconds=10):
            _, observed_at = await self._observe_identity(handle, runtime)
        return observed_at

    @staticmethod
    def _require_fresh_identity_observation(handle, observed_at) -> None:
        if handle.identity is not None and (
            observed_at is None or datetime.now(timezone.utc) - observed_at > timedelta(seconds=10)
        ):
            raise WorkspaceError(
                "identity_probe_expired",
                "Fresh identity evidence is required before native admission",
            )

    async def _finish_identity_validation(self, handle, runtime):
        first, _ = await self._observe_identity(handle, runtime)
        second, observed_at = await self._observe_identity(handle, runtime)
        if first != second:
            raise WorkspaceError(
                "identity_unstable", "The generated identity is not repeatable in its owned context"
            )
        if handle.close_requested or handle.ownership_uncertain:
            return
        policy, artifact = handle.identity_policy, handle.identity
        lease = handle.launch_context.lease
        # Proxy quarantine is never released. Explicit local-direct diagnostics
        # retain ordinary egress. A report is published only after a
        # successful owned-context close, with the same lease/authority current.
        handle.close_requested = True
        if handle.relay is not None:
            await handle.relay.stop()
        if handle.context.is_closed():
            handle.ownership_uncertain = True
            handle._set_phase("unknown")
            return
        try:
            # Retain the exact close operation. wait_for on the raw coroutine
            # can exceed its deadline indefinitely when a driver suppresses
            # cancellation; shielding only the owned task bounds our wait.
            # Its eventual completion cannot publish an admission or resolve
            # sticky unknown ownership after this validation has timed out.
            handle.identity_close_task = asyncio.create_task(handle.context.close())
            handle.identity_close_task.add_done_callback(
                lambda task: None if task.cancelled() else task.exception()
            )
            await asyncio.wait_for(asyncio.shield(handle.identity_close_task), timeout=5)
        except Exception:
            handle.ownership_uncertain = True
            handle._set_phase("unknown")
            return
        if not handle.context.is_closed():
            handle.ownership_uncertain = True
            handle._set_phase("unknown")
            return
        if handle.ownership_uncertain or not await self._runtime_current(handle, runtime):
            handle._set_phase("stopped")
            return
        try:
            self._require_final_authority(handle, runtime)
        except Exception:
            handle._set_phase("stopped")
            return
        now = datetime.now(timezone.utc)
        if handle.identity_validation_cancelled or now - observed_at > timedelta(seconds=10):
            handle._set_phase("stopped")
            return
        handle.identity_admission = CamoufoxProfileIdentityAdmission(
            policy.binding.profile_id,
            policy.binding.sha256,
            artifact.artifact_sha256,
            artifact.config_sha256,
            policy.program.sha256,
            second,
            lease.token,
            identity_secrets.token_hex(16),
            observed_at,
            min(now + timedelta(days=7), policy.program.valid_until),
        )
        handle._set_phase("stopped")

    async def _launch_camoufox(self, handle, runtime, settings, route, home):
        try:
            if handle.close_requested:
                handle._set_phase("stopped")
                return
            self.check(runtime, proxy=route is not None)
            if not await self._runtime_current(handle, runtime):
                raise WorkspaceError("runtime_changed", "Camoufox changed before execution")
            if self._driver_lock is None:
                self._driver_lock = asyncio.Lock()
            async with self._driver_lock:
                if self._playwright is None:
                    if self.factory is None:
                        from playwright.async_api import async_playwright

                        factory = async_playwright
                    else:
                        factory = self.factory
                    self._playwright = await factory().start()
            prefs = {"network.proxy.type": 0}
            if handle.validating_identity and route is None:
                # Direct mode is explicitly accepted ordinary egress, NOT a
                # network sandbox. Suppress session restore for fixed diagnostics.
                prefs.update(
                    {key: value for key, value in ROUTE_PREFS.items() if key.startswith("browser.")}
                )
            if route is not None:
                transport = (
                    self.transport_factory(route.configuration)
                    if self.transport_factory is not None
                    else HTTPSConnectTransport(route.configuration, secrets=self.secrets)
                )
                handle.relay = ProxyRelay(
                    transport,
                    on_failure=handle._route_failure,
                    diagnostic_targets=route.diagnostic_targets,
                )
                port = await handle.relay.start()
                prefs = {**ROUTE_PREFS, "network.proxy.socks_port": port}
            if handle.identity is not None:
                validate_generated_config(
                    json.loads(handle.identity.config_json),
                    handle.identity.firefox_user_prefs,
                    handle.identity_policy.binding,
                )
                identity_prefs = handle.identity.firefox_user_prefs
                if set(identity_prefs) & set(prefs):
                    raise WorkspaceError(
                        "identity_preference_collision", "Identity and route preferences conflict"
                    )
                prefs = {**prefs, **identity_prefs}
            environment = {
                "HOME": str(home),
                "PATH": os.defpath,
                "LANG": "C.UTF-8",
                **_identity_environment(
                    handle.identity.config_json
                    if handle.identity is not None
                    else settings.config_json
                ),
            }
            for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY"):
                if name in os.environ:
                    environment[name] = os.environ[name]
            options = {
                "executable_path": str(runtime.executable),
                "user_data_dir": str(handle.launch_context.browser_data),
                "headless": False,
                "no_viewport": True,
                "accept_downloads": False,
                "ignore_https_errors": False,
                "timeout": 30000,
                "firefox_user_prefs": prefs,
                "env": environment,
                "locale": settings.locale,
                "timezone_id": settings.timezone_id,
            }
            if handle.close_requested:
                if handle.relay is not None:
                    await handle.relay.stop()
                handle._set_phase("stopped")
                return
            if self.launcher is None:
                from camoufox.async_api import AsyncNewBrowser

                launcher = AsyncNewBrowser
            else:
                launcher = self.launcher
            # Re-observe exact metadata and pinned bytes after driver/SDK setup,
            # immediately before the call that can spawn the selected runtime.
            self.check(runtime, proxy=route is not None)
            if route is not None:
                await self._require_route_authority(handle)
            # Authority lookups can await: do the final content/metadata check
            # after them, so they cannot hide a runtime replacement before spawn.
            if not await self._runtime_current(handle, runtime):
                raise WorkspaceError("runtime_changed", "Camoufox changed before execution")
            if handle.close_requested:
                if handle.relay is not None:
                    await handle.relay.stop()
                handle._set_phase("stopped")
                return
            self._require_final_authority(handle, runtime)
            # Nonempty from_options bypasses launch_options: no random identity,
            # lookup of an active release, addon/geo-IP download or proxy IP query.
            handle.spawn_attempted = True
            handle.context = await launcher(
                self._playwright, from_options=options, persistent_context=True
            )
            handle.context.on("close", handle._on_close)
            if handle.context.is_closed():
                # Catch a close that occurred before listener registration too.
                # No browser-close acknowledgement belongs to this handle yet.
                handle.ownership_uncertain = True
                handle._set_phase("unknown")
                if handle.relay is not None:
                    handle.relay.fail_closed()
                return
            if handle.close_requested or handle.ownership_uncertain:
                return
            if not await self._runtime_current(handle, runtime):
                handle.stop()
                return
            if handle.close_requested or handle.ownership_uncertain:
                return
            result = None
            if route is not None:
                result = await self._probe(handle, route)
                if handle.close_requested or handle.ownership_uncertain:
                    return
            if handle.validating_identity:
                await self._finish_identity_validation(handle, runtime)
                return
            identity_observed_at = None
            if handle.identity is not None:
                _, identity_observed_at = await self._observe_identity(handle, runtime)
                if handle.close_requested or handle.ownership_uncertain:
                    return
            # Create/focus the owned initial page while diagnostic quarantine
            # remains closed. Each await can change identity/lease/route authority.
            handle.page = (
                handle.context.pages[0] if handle.context.pages else await handle.context.new_page()
            )
            if handle.close_requested or handle.ownership_uncertain:
                return
            if not await self._runtime_current(handle, runtime):
                raise WorkspaceError(
                    "generated_identity_stale",
                    "Identity authority changed while preparing the owned page",
                )
            self._require_final_authority(handle, runtime)
            async with self.native_focus_lock():
                if (
                    handle.selected
                    and not handle.close_requested
                    and not handle.ownership_uncertain
                ):
                    await handle.page.bring_to_front()
            if handle.close_requested or handle.ownership_uncertain:
                return
            if not await self._runtime_current(handle, runtime):
                raise WorkspaceError(
                    "generated_identity_stale",
                    "Identity authority changed while focusing the owned page",
                )
            identity_observed_at = await self._refresh_identity_observation(
                handle, runtime, identity_observed_at
            )
            self._require_final_authority(handle, runtime)
            self._require_fresh_identity_observation(handle, identity_observed_at)
            if handle.close_requested or handle.ownership_uncertain:
                return
            if route is not None:
                if result.valid_until <= datetime.now(timezone.utc) or not handle.relay.healthy:
                    raise WorkspaceError(
                        "proxy_probe_failed", "Route evidence expired before identity admission"
                    )
                handle.relay.release_quarantine()
                handle.monitor_task = asyncio.create_task(self._monitor(handle, route, result))
            if handle.launch_context.initial_url == GMAIL_INBOX_URL:
                await handle.page.goto(
                    GMAIL_INBOX_URL, wait_until="domcontentloaded", timeout=15000
                )
                handle.gmail_page = handle.page
            if handle.close_requested or handle.ownership_uncertain:
                return
            if not await self._runtime_current(handle, runtime):
                raise WorkspaceError(
                    "generated_identity_stale", "Identity authority changed before readiness"
                )
            identity_observed_at = await self._refresh_identity_observation(
                handle, runtime, identity_observed_at
            )
            self._require_final_authority(handle, runtime)
            self._require_fresh_identity_observation(handle, identity_observed_at)
            if not handle.close_requested and not handle.ownership_uncertain:
                handle._set_phase("ready")
        except asyncio.CancelledError:
            # A cancelled coroutine is not acknowledgement that an owned native
            # child exited. Make the failure explicit and preserve its lease.
            if handle.spawn_attempted:
                handle.ownership_uncertain = True
                handle._set_phase("unknown")
            else:
                handle._set_phase("stopped")
            if handle.relay is not None:
                handle.relay.fail_closed()
        except Exception:
            if handle.relay is not None:
                await handle.relay.stop()
            if handle.context is not None and not handle.ownership_uncertain:
                handle.stop()  # Keep ownership while acknowledged close is pending.
            elif handle.spawn_attempted:
                handle.ownership_uncertain = True
                handle._set_phase("unknown")
            else:
                handle._set_phase("stopped")

    def launch(
        self,
        runtime,
        context,
        settings,
        route,
        *,
        home,
        route_guard=None,
        runtime_guard=None,
        identity=None,
        identity_policy=None,
        identity_guard=None,
        validating_identity=False,
        local_direct_validation=False,
    ):
        self.check(runtime, proxy=route is not None)
        if runtime_guard is None:
            raise WorkspaceError(
                "runtime_metadata_required", "A fresh Camoufox metadata guard is required"
            )
        if identity is not None or identity_policy is not None or validating_identity:
            if (
                type(identity) is not EngineIdentity
                or type(identity_policy) is not CamoufoxGeneratedIdentityPolicy
                or identity_guard is None
                or not identity_guard()
                or identity_policy.binding.profile_id != context.profile_id
            ):
                raise WorkspaceError(
                    "generated_identity_stale", "A current leased prepared identity is required"
                )
            identity_policy.program.check(
                runtime,
                identity_policy.binding,
                identity_policy.generator.provenance(identity_policy.binding),
            )
            validate_generated_config(
                json.loads(identity.config_json),
                identity.firefox_user_prefs,
                identity_policy.binding,
            )
            if identity.artifact_sha256 != identity_policy.artifact_sha256:
                raise WorkspaceError(
                    "generated_identity_stale", "Prepared artifact does not match native policy"
                )
            if validating_identity and (
                context.initial_url != "about:blank"
                or (
                    route is None
                    and not (
                        local_direct_validation is True
                        and identity_policy.binding.proxy_fingerprint is None
                        and settings.proxy_fingerprint is None
                    )
                )
            ):
                raise WorkspaceError(
                    "identity_validation_route_required",
                    "Identity validation requires an accepted diagnostic network policy and a blank initial page",
                )
            if not validating_identity:
                if identity_policy.admission is None:
                    raise WorkspaceError(
                        "profile_identity_unverified", "Native identity validation is required"
                    )
                identity_policy.admission.check(identity_policy, identity)
        self._ensure_loop()
        with self._lock:
            if any(
                existing.launch_context.profile_id == context.profile_id
                and (existing.phase != "stopped" or existing.ownership_uncertain)
                for existing in self._handles
            ):
                raise WorkspaceError(
                    "profile_already_owned", "This profile already has an active native owner"
                )
            handle = CamoufoxHandle(self, context)
            handle.route_guard = route_guard
            handle.runtime_guard = runtime_guard
            handle.identity, handle.identity_policy, handle.identity_guard = (
                identity,
                identity_policy,
                identity_guard,
            )
            handle.validating_identity = validating_identity
            self._handles.append(handle)
            handle.launch_future = asyncio.run_coroutine_threadsafe(
                self._launch_camoufox(handle, runtime, settings, route, home), self._loop
            )
            return handle


class CamoufoxAdapter:
    execution_kind = "installed"

    def __init__(
        self,
        *,
        profile_store: ProfileStore,
        executable: Path,
        observed_version: str | None = None,
        policy: RuntimePolicy,
        runtime_gate: RuntimeGate,
        supervisor: CamoufoxSupervisor,
        profile_policies: ProfilePolicies,
        proxy_routes: CamoufoxRoutes | None = None,
        metadata_observer: Callable[[Path], CamoufoxRuntimeMetadata] | None = None,
        generated_identities: CamoufoxGeneratedIdentities | None = None,
    ):
        if policy.engine_id != "camoufox":
            raise ValueError("Camoufox requires its own reviewed runtime policy")
        self.profile_store, self.executable = profile_store, Path(executable)
        self.observed_version, self.policy, self.gate = observed_version, policy, runtime_gate
        self.supervisor, self.profile_policies, self.proxy_routes = (
            supervisor,
            profile_policies,
            proxy_routes,
        )
        self.metadata_observer = metadata_observer
        self.generated_identities = generated_identities
        self._approved: dict[str, tuple] = {}
        self._validation_approved: dict[str, tuple] = {}

    def _observe_metadata(self) -> CamoufoxRuntimeMetadata:
        if self.metadata_observer is None:
            raise WorkspaceError(
                "runtime_metadata_required",
                "A trusted Camoufox distribution metadata observer is required",
            )
        try:
            metadata = self.metadata_observer(self.executable)
        except Exception:
            raise WorkspaceError(
                "runtime_metadata_unavailable", "Camoufox metadata could not be safely observed"
            ) from None
        if not isinstance(metadata, CamoufoxRuntimeMetadata):
            raise WorkspaceError(
                "runtime_metadata_invalid", "Camoufox metadata evidence is invalid"
            )
        if metadata.version != self.policy.version or (
            self.observed_version is not None and metadata.version != self.observed_version
        ):
            raise WorkspaceError(
                "runtime_version_changed",
                "Observed Camoufox version does not match the reviewed policy",
            )
        return metadata

    def _runtime_evidence(self):
        before = self._observe_metadata()
        runtime = self.gate.verify(
            self.executable, observed_version=before.version, policy=self.policy
        )
        after = self._observe_metadata()
        if before != after:
            raise WorkspaceError(
                "runtime_metadata_changed",
                "Camoufox metadata changed during signature verification",
            )
        return runtime, before

    def _runtime(self):
        return self._runtime_evidence()[0]

    def global_blockers(self) -> tuple[str, ...]:
        try:
            self.supervisor.check(self._runtime())
            return ()
        except WorkspaceError as exc:
            return (exc.message,)
        except Exception:
            return ("Camoufox runtime provenance could not be verified.",)

    def _route(self, profile, runtime, settings):
        network = profile.get("network_policy", "unconfigured")
        if profile.get("origin", "local") == "local" and network == "local_direct":
            if settings.proxy_fingerprint is not None:
                raise WorkspaceError(
                    "profile_policy_stale", "Remove the old proxy assignment explicitly"
                )
            return None
        if network != "verified_proxy" or self.proxy_routes is None:
            raise WorkspaceError(
                "proxy_required", "Configure the profile route or explicitly choose local direct"
            )
        self.supervisor.check(runtime, proxy=True)
        route = self.proxy_routes.for_profile(profile["id"])
        if (
            route.configuration.scheme != "https"
            or route.expectations.profile_id != profile["id"]
            or route.expectations.runtime_sha256 != runtime.sha256
            or route.configuration.fingerprint != settings.proxy_fingerprint
            or (route.configuration.credentials is not None and self.supervisor.secrets is None)
        ):
            raise WorkspaceError(
                "proxy_assignment_invalid", "The reviewed profile proxy assignment is invalid"
            )
        return route

    def blockers(self, profile: dict[str, Any]) -> tuple[str, ...]:
        return self._identity_blockers(profile, validation=False)

    def validation_blockers(self, profile: dict[str, Any]) -> tuple[str, ...]:
        """Explicit trusted native test entrypoint; never an automatic launch fallback."""
        return self._identity_blockers(profile, validation=True)

    def _identity_blockers(self, profile, *, validation):
        approvals = self._validation_approved if validation else self._approved
        approvals.pop(profile["id"], None)
        try:
            if profile["engine_id"] != "camoufox":
                raise WorkspaceError("engine_mismatch", "This adapter requires a Camoufox profile")
            runtime, metadata = self._runtime_evidence()
            self.supervisor.check(runtime)
            settings = self.profile_policies.for_profile(profile["id"])
            settings.check(profile)
            route = self._route(profile, runtime, settings)
            identity_policy = None
            if self.generated_identities is not None:
                identity_policy = self.generated_identities.for_profile(profile["id"])
                if type(identity_policy) is not CamoufoxGeneratedIdentityPolicy:
                    raise WorkspaceError(
                        "generated_identity_stale",
                        "A trusted generated identity policy is required",
                    )
                identity_policy.check(runtime, profile, settings, validation=validation)
            if validation and (
                identity_policy is None
                or (
                    route is None
                    and not (
                        profile.get("origin") == "local"
                        and profile.get("network_policy") == "local_direct"
                        and settings.proxy_fingerprint is None
                    )
                )
            ):
                raise WorkspaceError(
                    "identity_validation_route_required",
                    "Prepared identity validation requires an accepted route or explicit local-direct policy",
                )
            approvals[profile["id"]] = (
                runtime,
                dict(profile),
                settings,
                route,
                metadata,
                identity_policy,
            )
            return ()
        except WorkspaceError as exc:
            return (exc.message,)
        except Exception:
            return ("Camoufox profile/runtime checks could not be completed safely.",)

    def _bind_profile_identity(self, profile_id: str, settings: CamoufoxProfilePolicy) -> None:
        # Never adopt another browser's existing data directory. Persist a small
        # app-owned, non-secret identity marker outside website-controlled files.
        # A different locale/timezone/preset requires an explicit migration/reset,
        # which this adapter does not perform on the user's behalf.
        directory_fd, paths = self.profile_store._open_profile(profile_id)
        marker = ".camoufox-identity.json"
        expected = json.dumps(
            {
                "schema": 1,
                "engine_id": "camoufox",
                "profile_id": profile_id,
                "preset_id": settings.preset_id,
                "config_sha256": hashlib.sha256(settings.config_json.encode()).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            try:
                os.stat(ARTIFACT_NAME, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WorkspaceError(
                    "profile_identity_mode_mismatch",
                    "This profile requires its generated identity policy",
                )
            try:
                fd = os.open(marker, os.O_RDONLY | flags, dir_fd=directory_fd)
            except FileNotFoundError:
                data_fd = os.open(
                    "browser-data", os.O_RDONLY | os.O_DIRECTORY | flags, dir_fd=directory_fd
                )
                try:
                    _check_private(data_fd, directory=True)
                    if os.listdir(data_fd):
                        raise WorkspaceError(
                            "profile_not_fresh", "Camoufox requires a fresh app-owned profile"
                        )
                finally:
                    os.close(data_fd)
                fd = os.open(
                    marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o600, dir_fd=directory_fd
                )
                try:
                    _check_private(fd, directory=False)
                    remaining = memoryview(expected)
                    while remaining:
                        count = os.write(fd, remaining)
                        if count <= 0:
                            raise OSError("Identity marker write failed")
                        remaining = remaining[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory_fd)
            else:
                try:
                    _check_private(fd, directory=False)
                    if os.read(fd, 4097) != expected:
                        raise WorkspaceError(
                            "profile_identity_changed",
                            "Persistent Camoufox identity does not match reviewed settings",
                        )
                finally:
                    os.close(fd)
        finally:
            os.close(directory_fd)

    def start(self, context: LaunchContext):
        return self._start_identity(context, validation=False)

    def validate_identity(self, context: LaunchContext):
        """Run only fixed native identity diagnostics; return the owned handle.

        Success is handle.identity_admission after phase='stopped'. A missing
        result, unknown ownership, or close failure grants no normal-use access.
        The caller retains the same lease until shutdown is acknowledged.
        """
        if context.initial_url != "about:blank":
            raise WorkspaceError(
                "identity_validation_target_invalid", "Identity validation only permits about:blank"
            )
        return self._start_identity(context, validation=True)

    def _start_identity(self, context, *, validation):
        approvals = self._validation_approved if validation else self._approved
        approved = approvals.pop(context.profile_id, None)
        if approved is None:
            raise WorkspaceError(
                "launch_not_approved", "A fresh profile-bound launch check is required"
            )
        runtime, profile, settings, route, metadata, identity_policy = approved
        current = self.profile_policies.for_profile(context.profile_id)
        if current != settings:
            raise WorkspaceError("profile_policy_stale", "Camoufox settings changed before launch")
        if context.engine_id != "camoufox" or context.initial_url not in (
            "about:blank",
            GMAIL_INBOX_URL,
        ):
            raise WorkspaceError(
                "launch_context_mismatch", "Launch target or engine does not match"
            )
        paths = self.profile_store.prepare(context.profile_id)
        if (
            context.lease is None
            or not context.lease.active
            or context.lease.paths != paths
            or context.browser_data != paths.browser_data
        ):
            raise WorkspaceError(
                "profile_lease_required", "An active application-owned profile lease is required"
            )
        fd = os.open(paths.browser_data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _check_private(fd, directory=True)
        finally:
            os.close(fd)

        def runtime_guard() -> bool:
            return self._observe_metadata() == metadata

        if not runtime_guard() or not RuntimeGate.is_unchanged(runtime) or not runtime_guard():
            raise WorkspaceError("runtime_changed", "Camoufox changed before execution")
        fresh_route = self._route(profile, runtime, settings)
        if fresh_route != route:
            raise WorkspaceError(
                "proxy_assignment_changed", "Proxy assignment changed before launch"
            )
        artifact = None
        properties = None
        if identity_policy is None:
            self._bind_profile_identity(context.profile_id, settings)
        else:
            artifact, properties = self._load_generated_identity(
                context, runtime, profile, settings, identity_policy, validation=validation
            )

        def identity_guard() -> bool:
            try:
                if (
                    not context.lease.active
                    or self.profile_policies.for_profile(context.profile_id) != settings
                ):
                    return False
                if identity_policy is None:
                    self._bind_profile_identity(context.profile_id, settings)
                    return True
                if (
                    self.generated_identities is None
                    or self.generated_identities.for_profile(context.profile_id) != identity_policy
                ):
                    return False
                current, observed = self._load_generated_identity(
                    context, runtime, profile, settings, identity_policy, validation=validation
                )
                return current == artifact and observed == properties
            except Exception:
                return False

        def route_guard() -> bool:
            self.supervisor.check(runtime, proxy=True)
            return (
                self.profile_policies.for_profile(context.profile_id) == settings
                and self.proxy_routes is not None
                and self.proxy_routes.for_profile(context.profile_id) == route
            )

        return self.supervisor.launch(
            runtime,
            context,
            settings,
            route,
            home=self.profile_store.root.parent,
            route_guard=route_guard if route is not None else None,
            runtime_guard=runtime_guard,
            identity=artifact,
            identity_policy=identity_policy,
            identity_guard=identity_guard,
            validating_identity=validation,
            local_direct_validation=(
                validation
                and route is None
                and profile.get("origin") == "local"
                and profile.get("network_policy") == "local_direct"
            ),
        )

    def _load_generated_identity(
        self, context, runtime, profile, settings, identity_policy, *, validation
    ):
        identity_policy.check(runtime, profile, settings, validation=validation)
        directory_fd, _paths = self.profile_store._open_profile(context.profile_id)
        try:
            try:
                os.stat(".camoufox-identity.json", dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WorkspaceError(
                    "profile_identity_mode_mismatch",
                    "Legacy identity migration requires an explicit separate workflow",
                )
        finally:
            os.close(directory_fd)
        before = identity_policy.properties_observer(runtime.executable)
        if (
            type(before) is not CamoufoxIdentityProperties
            or before.source_sha256 != identity_policy.program.properties_sha256
        ):
            raise WorkspaceError(
                "identity_properties_changed", "Accepted engine properties changed"
            )
        artifact = EngineIdentityStore(self.profile_store).load_or_create(
            context.lease,
            identity_policy.binding,
            _ExistingIdentityGenerator(identity_policy.generator),
        )
        artifact.validate_engine_properties(
            before.content, identity_policy.program.properties_sha256
        )
        if artifact.artifact_sha256 != identity_policy.artifact_sha256:
            raise WorkspaceError(
                "generated_identity_stale", "Prepared artifact changed after native admission"
            )
        if not validation:
            identity_policy.admission.check(identity_policy, artifact)
        after = identity_policy.properties_observer(runtime.executable)
        if before != after:
            raise WorkspaceError(
                "identity_properties_changed", "Engine properties changed while loading identity"
            )
        return artifact, before

    def shutdown(self) -> None:
        self.supervisor.shutdown()
