"""Non-executing engine adapters with inspectable, secret-free launch plans.

There is deliberately no subprocess, download, shell, Playwright, or Camoufox
import here. Browser-specific routing/sandbox behavior must be independently
validated before an execution adapter can exist. Flags below are only a plan,
not proof of proxy isolation or protection from fingerprinting.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol

from .errors import EngineExecutionUnavailable
from .proxy import PreflightResult, ProxyConfiguration
from .runtime import RuntimeGate, VerifiedRuntime
from .storage import ProfileLease


@dataclass(frozen=True)
class LaunchPlan:
    engine_id: str
    profile_id: str
    executable: Path | None
    browser_data: Path
    argv: tuple[str, ...]
    blockers: tuple[str, ...]
    dry_run: Literal[True] = True
    can_launch: Literal[False] = False


class EngineAdapter(Protocol):
    engine_id: str

    def plan(
        self,
        lease: ProfileLease,
        *,
        runtime: VerifiedRuntime | None,
        proxy: ProxyConfiguration,
        preflight: PreflightResult | None = None,
        now: datetime | None = None,
    ) -> LaunchPlan: ...

    def launch(self, plan: LaunchPlan) -> None: ...


def _blockers(
    engine_id: str,
    lease: ProfileLease,
    runtime: VerifiedRuntime | None,
    proxy: ProxyConfiguration,
    preflight: PreflightResult | None,
    now: datetime,
) -> list[str]:
    blockers = ["Browser execution is disabled in this scaffold"]
    if not lease.active:
        blockers.append("An active profile lease is required")
    if runtime is None:
        blockers.append("A verified, pinned browser runtime is required")
    else:
        if runtime.engine_id != engine_id:
            blockers.append("The verified runtime belongs to a different engine")
        if runtime.verified_at.utcoffset() is None or not (
            timedelta(0) <= now - runtime.verified_at <= timedelta(minutes=5)
        ):
            blockers.append("Runtime verification is stale or future-dated")
        if not RuntimeGate.is_unchanged(runtime):
            blockers.append("The runtime changed after verification")
    if preflight is None or preflight.passed is not True or preflight.blockers:
        blockers.append("Browser-context proxy preflight has not passed")
    else:
        if (
            preflight.profile_id != lease.paths.profile_id
            or preflight.proxy_fingerprint != proxy.fingerprint
            or runtime is None
            or preflight.runtime_sha256 != runtime.sha256
        ):
            blockers.append("Proxy preflight does not match this launch context")
        if (
            preflight.valid_until is None
            or preflight.valid_until.utcoffset() is None
            or preflight.checked_at.utcoffset() is None
            or not preflight.checked_at <= now <= preflight.valid_until
        ):
            blockers.append("Proxy preflight evidence is no longer current")
    if proxy.credentials is not None:
        blockers.append("A vetted in-memory proxy authentication bridge is not configured")
    return blockers


class NormalBrowserAdapter:
    """Dry-run plan for a Chromium-family normal browser; no spoofing features."""

    engine_id = "chromium"

    def plan(
        self,
        lease: ProfileLease,
        *,
        runtime: VerifiedRuntime | None,
        proxy: ProxyConfiguration,
        preflight: PreflightResult | None = None,
        now: datetime | None = None,
    ) -> LaunchPlan:
        now = now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError("An aware timestamp is required")
        blockers = _blockers(self.engine_id, lease, runtime, proxy, preflight, now)
        argv: tuple[str, ...] = ()
        if runtime is not None and runtime.engine_id == self.engine_id:
            argv = (
                str(runtime.executable),
                f"--user-data-dir={lease.paths.browser_data}",
                f"--proxy-server={proxy.endpoint}",
                "about:blank",
            )
        return LaunchPlan(
            self.engine_id,
            lease.paths.profile_id,
            runtime.executable if runtime else None,
            lease.paths.browser_data,
            argv,
            tuple(blockers),
        )

    def launch(self, plan: LaunchPlan) -> None:
        raise EngineExecutionUnavailable("Browser execution is disabled; inspect the dry-run plan")


class CamoufoxAdapter:
    """Optional adapter contract only. No dependency install or implicit download.

    A future adapter needs a reviewed runtime pin, verified signed distribution,
    documented packaging and license review, and real leak tests first. Camoufox
    is not required by the local client and is not a privacy guarantee.
    """

    engine_id = "camoufox"

    def plan(
        self,
        lease: ProfileLease,
        *,
        runtime: VerifiedRuntime | None,
        proxy: ProxyConfiguration,
        preflight: PreflightResult | None = None,
        now: datetime | None = None,
    ) -> LaunchPlan:
        now = now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError("An aware timestamp is required")
        blockers = _blockers(self.engine_id, lease, runtime, proxy, preflight, now)
        blockers.append("The optional Camoufox adapter is not configured or verified")
        return LaunchPlan(
            self.engine_id,
            lease.paths.profile_id,
            runtime.executable if runtime else None,
            lease.paths.browser_data,
            (),
            tuple(blockers),
        )

    def launch(self, plan: LaunchPlan) -> None:
        raise EngineExecutionUnavailable("The optional Camoufox execution adapter is unavailable")
