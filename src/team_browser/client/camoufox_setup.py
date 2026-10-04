"""Ordinary local-app Camoufox preparation and supervised admission bridge.

HTTP actions select only these bounded operations. No request supplies proof,
paths, executable options, scripts, remote URLs or signing keys. Admissions are
kept in native memory and are issued only by the owned supervisor after close.
"""

from __future__ import annotations

import threading
import time
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from pydantic import Field

from .camoufox_deployment import AuthenticatedDeployment, DEFAULT_TRUST, ProfileSelection
from .camoufox_runtime import (
    CamoufoxAdapter,
    CamoufoxGeneratedIdentityPolicy,
    CamoufoxProfileIdentityAdmission,
    CamoufoxProfilePolicy,
    CamoufoxSupervisor,
    profile_policy_binding,
)
from .engine_identity import EngineIdentityStore, IdentityBinding, OfflineCamoufoxGenerator
from .identity_probe import FixedCamoufoxIdentityProbe
from .lifecycle import LaunchContext
from .models import InputModel
from .store import ACTIVE_STATES, WorkspaceError, WorkspaceStore


class SetupAction(InputModel):
    action: Literal["prepare", "validate", "cancel"]
    expected_revision: int = Field(ge=1)
    expected_setup_revision: int = Field(ge=1)


@dataclass
class _Entry:
    revision: int = 1
    state: str = "not_prepared"
    blockers: tuple[str, ...] = ()
    artifact: object | None = None
    runtime: object | None = None
    binding: IdentityBinding | None = None
    policy: CamoufoxGeneratedIdentityPolicy | None = None
    operation_id: str | None = None
    cancel: threading.Event | None = None
    lease: object | None = None
    handle: object | None = None
    thread: threading.Thread | None = None
    expected_revision: int | None = None
    generation: int | None = None
    native_reserved: bool = False


class _Settings:
    def __init__(self, setup):
        self.setup = setup

    def for_profile(self, profile_id):
        return self.setup._binding(profile_id)[0]


class _Identities:
    def __init__(self, setup):
        self.setup = setup

    def for_profile(self, profile_id):
        with self.setup.store.lock:
            self.setup.deployment.current()
            entry = self.setup._entry(profile_id)
            settings, binding = self.setup._binding(profile_id)
            if entry.binding != binding or entry.policy is None:
                raise WorkspaceError(
                    "identity_not_prepared",
                    "Prepare this exact profile identity first; changed identities require reviewed recovery.",
                )
            if entry.operation_id and (
                entry.cancel.is_set()
                or self.setup.store.get(profile_id)["revision"] != entry.expected_revision
            ):
                raise WorkspaceError(
                    "identity_setup_cancelled",
                    "The setup operation was cancelled or its profile changed.",
                )
            settings.check(self.setup.store.get(profile_id))
            return entry.policy


class CamoufoxSetup:
    """One bounded setup operation; exact persistent lease until known shutdown."""

    def __init__(
        self,
        store: WorkspaceStore,
        deployment=None,
        *,
        configured=False,
        blocker=None,
        generator=None,
        supervisor=None,
        probe=None,
    ):
        self.store, self.deployment = store, deployment
        self.configured = configured or deployment is not None
        self.blocker = (
            blocker
            or "Configure a reviewed Camoufox distribution and independently provisioned deployment trust before setup."
        )
        self.generator = generator if generator is not None else OfflineCamoufoxGenerator()
        self.probe = probe if probe is not None else FixedCamoufoxIdentityProbe()
        self._entries: dict[str, _Entry] = {}
        self._closed = False
        self.adapter = None
        self.coordinator = None
        if deployment is not None:
            self.adapter = CamoufoxAdapter(
                profile_store=store.profiles,
                executable=deployment.executable,
                policy=deployment.policy,
                runtime_gate=deployment,
                supervisor=supervisor
                if supervisor is not None
                else CamoufoxSupervisor(acceptance=deployment.acceptance()),
                profile_policies=_Settings(self),
                metadata_observer=deployment.metadata,
                generated_identities=_Identities(self),
            )

    def _entry(self, profile_id):
        return self._entries.setdefault(profile_id, _Entry())

    def _set(self, entry, state, blockers=()):
        blockers = tuple(blockers)
        if (entry.state, entry.blockers) != (state, blockers):
            entry.state, entry.blockers = state, blockers
            entry.revision += 1

    def _binding(self, profile_id):
        if self.deployment is None:
            raise WorkspaceError("camoufox_setup_unavailable", self.blocker)
        self.deployment.current()
        profile = self.store.get(profile_id)
        chosen = next(
            (
                item
                for item in self.deployment.configuration.profiles
                if item.profile_id == profile_id
            ),
            None,
        )
        template = self.deployment.record.profile_defaults
        if chosen is None and self.deployment.configuration.use_accepted_profile_defaults:
            chosen = ProfileSelection(
                profile_id=profile_id,
                profile_binding_sha256=profile_policy_binding(profile),
                **template.model_dump(),
            )
        if chosen is not None and any(
            getattr(chosen, key) != value for key, value in template.model_dump().items()
        ):
            raise WorkspaceError(
                "profile_template_unapproved",
                "The selected locale, timezone, preset or network policy is outside the authenticated release template.",
            )
        if chosen is None:
            raise WorkspaceError(
                "camoufox_profile_not_configured",
                "Ask the release administrator to bind this profile, accepted display, locale and timezone in the private setup configuration.",
            )
        if profile["origin"] != "local" or profile["network_policy"] != chosen.network_policy:
            raise WorkspaceError(
                "camoufox_network_policy_required",
                "This deployment permits explicitly chosen Local direct profiles only. Managed profiles still require an accepted verified-proxy integration.",
            )
        settings = CamoufoxProfilePolicy(
            chosen.profile_id,
            chosen.profile_binding_sha256,
            chosen.preset_id,
            chosen.locale,
            chosen.timezone_id,
        )
        settings.check(profile)
        if profile["engine_id"] != "camoufox":
            raise WorkspaceError(
                "engine_mismatch", "Choose the Camoufox preset for this profile before setup."
            )
        record = self.deployment.record
        binding = IdentityBinding(
            profile_id,
            profile_policy_binding(profile),
            chosen.preset_id,
            self.deployment.policy.version,
            self.deployment.policy.sha256,
            int(record.firefox_version.split(".")[0]),
            record.platform,
            "linux",
            self.deployment.display,
            chosen.locale,
            chosen.timezone_id,
        )
        return settings, binding

    def overview(self):
        usable = False
        blockers = [self.blocker]
        state = "needs_approval" if self.configured else "unavailable"
        if self.deployment is not None:
            try:
                self.deployment.current()
                self.deployment.program()
                if self.adapter.supervisor.acceptance is None:
                    raise WorkspaceError(
                        "native_qualification_required", "Native qualification is required."
                    )
                blockers = []
                usable = True
                state = "available" if usable else "needs_approval"
            except Exception:
                blockers = [
                    "A current authenticated release qualification and matching runtime are required."
                ]
        return {
            "supported": True,
            "configured": self.configured,
            "usable": usable,
            "state": state,
            "blockers": blockers,
            "next_step": "Select a Camoufox profile to prepare and validate its identity."
            if usable
            else blockers[0],
            "fresh_execution_checks_required": True,
        }

    def snapshot(self, profile_id):
        with self.store.lock:
            profile = self.store.get(profile_id)
            entry = self._entry(profile_id)
            acknowledged = False
            available = []
            if entry.operation_id:
                # Unknown native ownership is sticky. A cancel cannot free it.
                available = ["cancel"] if entry.state in {"preparing", "validating"} else []
            elif profile["state"] == "recovery_required" or entry.state == "recovery_required":
                self._set(
                    entry,
                    "recovery_required",
                    (
                        "Verify the previous native process has ended through trusted recovery before using this profile. No reset or lease override is available.",
                    ),
                )
            elif self.deployment is None:
                self._set(
                    entry, "needs_approval" if self.configured else "unavailable", (self.blocker,)
                )
            else:
                try:
                    settings, binding = self._binding(profile_id)
                    if entry.artifact is None:
                        self._set(
                            entry,
                            "not_prepared",
                            entry.blockers if entry.state == "not_prepared" else (),
                        )
                        available = ["prepare"]
                    elif entry.binding != binding:
                        self._set(
                            entry,
                            "recovery_required",
                            (
                                "The persistent identity no longer matches the accepted profile/display/runtime. Reviewed migration is required; it will not be regenerated.",
                            ),
                        )
                    else:
                        program = self.deployment.program()
                        if entry.policy is None:
                            entry.policy = CamoufoxGeneratedIdentityPolicy(
                                binding,
                                entry.artifact.artifact_sha256,
                                self.generator,
                                program,
                                self.deployment.properties,
                                self.probe,
                            )
                        if entry.policy.admission is not None:
                            entry.policy.admission.check(entry.policy, entry.artifact)
                            # Passive status does not hash a multi-GB distribution.
                            # It describes this unexpired admission, not a new
                            # execution authorization. Ordinary start re-verifies
                            # the entire distribution and current context.
                            if entry.policy.binding != binding or entry.policy.program != program:
                                raise WorkspaceError(
                                    "identity_program_changed",
                                    "The accepted identity program or profile binding changed.",
                                )
                            # Full generator-package and executable content checks
                            # belong to the next bounded execution operation, not
                            # status polling. The snapshot is explicitly dated.
                            settings.check(profile)
                            self.adapter.supervisor.check(entry.runtime)
                            self.deployment.metadata(entry.runtime.executable)
                            properties = self.deployment.properties(entry.runtime.executable)
                            if properties.source_sha256 != entry.policy.program.properties_sha256:
                                raise WorkspaceError(
                                    "identity_properties_changed",
                                    "Accepted engine properties changed.",
                                )
                            acknowledged = True
                            self._set(entry, "ready")
                        else:
                            self._set(
                                entry,
                                "prepared",
                                entry.blockers if entry.state == "prepared" else (),
                            )
                            available = ["validate"]
                except WorkspaceError as exc:
                    # Error messages are application-controlled constants only.
                    self._set(entry, "needs_approval", (exc.message,))
                    if entry.artifact is not None and entry.policy is not None:
                        entry.policy = replace(entry.policy, admission=None)
                        available = (
                            ["validate"] if exc.code == "profile_identity_unverified" else []
                        )
                except Exception:
                    self._set(
                        entry,
                        "needs_approval",
                        (
                            "The configured engine, accepted display or reviewed dependencies changed. Ask the release administrator to review setup.",
                        ),
                    )
            if profile["state"] in ACTIVE_STATES and not entry.operation_id:
                available = []
            return {
                "profile_id": profile_id,
                "profile_revision": profile["revision"],
                "revision": entry.revision,
                "state": entry.state,
                "operation_id": entry.operation_id,
                "blockers": list(entry.blockers),
                "next_step": entry.blockers[0]
                if entry.blockers
                else {
                    "not_prepared": "Prepare the immutable identity offline.",
                    "preparing": "Preparing offline. No browser is running for this step.",
                    "prepared": "Run the authorized fixed native diagnostic.",
                    "validating": "Waiting for fixed native observations and acknowledged shutdown.",
                    "ready": "Launch this admitted profile using the normal browser control.",
                }.get(entry.state, "Review setup with the release administrator."),
                "available_actions": available,
                "admission_acknowledged": acknowledged,
                "fresh_execution_checks_required": True,
                "runtime_observed_at": entry.runtime.verified_at.isoformat()
                if entry.runtime is not None
                else None,
                "launch_available": acknowledged and profile["state"] not in ACTIVE_STATES,
                "admission_expires_at": entry.policy.admission.valid_until.isoformat()
                if acknowledged
                else None,
                "network_scope": profile["network_policy"],
                "network_warning": "Local direct validation has ordinary network egress. A blank diagnostic is not an offline or network-isolated browser."
                if profile["network_policy"] == "local_direct"
                else "Managed and proxy-required profiles cannot fall back to direct networking.",
            }

    def active_native_count(self):
        # Caller and controller share the workspace lock. No coordinator callback
        # occurs here, so resource-accounting cannot recurse.
        with self.store.lock:
            return sum(entry.native_reserved for entry in self._entries.values())

    def require_idle(self, profile_id):
        with self.store.lock:
            entry = self._entries.get(profile_id)
            if entry is not None and (entry.operation_id or entry.state == "recovery_required"):
                raise WorkspaceError(
                    "camoufox_setup_busy",
                    "Use the Camoufox setup Cancel control and wait for acknowledged shutdown before changing this profile.",
                )

    def action(self, profile_id, *, action, expected_revision, expected_setup_revision):
        with self.store.lock:
            profile = self.store.get(profile_id)
            self.store.require_revision(profile, expected_revision)
            status = self.snapshot(profile_id)
            entry = self._entry(profile_id)
            if self._closed or entry.revision != expected_setup_revision:
                raise WorkspaceError(
                    "camoufox_setup_stale", "Refresh Camoufox setup before continuing."
                )
            if action not in status["available_actions"]:
                raise WorkspaceError(
                    "camoufox_setup_action_blocked",
                    "This setup action is unavailable; follow the current setup next step.",
                )
            if action == "cancel":
                entry.cancel.set()
                entry.revision += 1
                return self.snapshot(profile_id)
            if any(value.operation_id for value in self._entries.values()):
                raise WorkspaceError(
                    "camoufox_setup_busy", "Wait for the other bounded setup operation to finish."
                )
            if profile["state"] in ACTIVE_STATES | {"recovery_required"}:
                raise WorkspaceError(
                    "profile_in_use",
                    "Stop and verify the profile before preparing or validating it.",
                )
            if action == "validate":
                if self.coordinator is None:
                    raise WorkspaceError(
                        "resource_reservation_unknown",
                        "Native setup resource accounting is not configured.",
                    )
                resources = self.coordinator.resources()
                if resources["resident_profiles"] >= resources["effective_capacity"]:
                    raise WorkspaceError(
                        "budget_exceeded",
                        "Close a browser profile or raise its resource budget before native validation.",
                    )
            try:
                lease = self.store.profiles.acquire(profile_id)
            except Exception:
                raise WorkspaceError(
                    "profile_in_use", "This profile lease is unavailable; it may already be in use."
                ) from None
            entry.lease, entry.cancel = lease, threading.Event()
            entry.operation_id = secrets.token_hex(16)
            entry.handle = None
            if action == "validate":
                entry.native_reserved = True
                profile = self.store._change(
                    profile_id, state="starting", generation=profile["generation"] + 1, blockers=[]
                )
            entry.expected_revision, entry.generation = profile["revision"], profile["generation"]
            self._set(entry, "preparing" if action == "prepare" else "validating")
            entry.revision += 1
            entry.thread = threading.Thread(
                target=self._work,
                args=(profile_id, entry, action),
                daemon=True,
                name="camoufox-setup",
            )
            try:
                entry.thread.start()
            except Exception:
                # No worker ever ran and no native handle could be created.
                entry.native_reserved = False
                entry.operation_id = None
                entry.thread = None
                entry.lease.release()
                entry.lease = None
                if action == "validate":
                    self.store._change(profile_id, state="stopped", blockers=[])
                self._set(
                    entry,
                    "prepared" if entry.artifact is not None else "not_prepared",
                    ("The bounded setup worker could not start. Refresh and retry.",),
                )
                raise WorkspaceError(
                    "camoufox_setup_worker_unavailable",
                    "The bounded setup worker could not start. Refresh and retry.",
                ) from None
            return self.snapshot(profile_id)

    def _valid(self, profile_id, entry):
        return (
            not self._closed
            and not entry.cancel.is_set()
            and entry.lease.active
            and self._entries.get(profile_id) is entry
            and self.store.get(profile_id)["revision"] == entry.expected_revision
            and self.store.get(profile_id)["generation"] == entry.generation
        )

    def _work(self, profile_id, entry, action):
        recovery = False
        message = None
        admission = None
        try:
            with self.store.lock:
                _, binding = self._binding(profile_id)
                profile = self.store.get(profile_id)
            # Fresh approved runtime observation does not launch any executable.
            runtime = self.adapter._runtime()
            if action == "prepare":
                artifact = EngineIdentityStore(self.store.profiles).load_or_create(
                    entry.lease, binding, self.generator
                )
                properties = self.deployment.properties(runtime.executable)
                artifact.validate_engine_properties(
                    properties.content,
                    self.deployment.record.files[self.deployment.record.properties],
                )
                with self.store.lock:
                    if not self._valid(profile_id, entry):
                        raise WorkspaceError(
                            "setup_cancelled",
                            "Preparation was cancelled or its profile changed. Any created immutable identity is retained and can be checked again.",
                        )
                    entry.binding, entry.artifact, entry.runtime = binding, artifact, runtime
                    try:
                        program = self.deployment.program()
                    except WorkspaceError:
                        program = None
                    entry.policy = (
                        None
                        if program is None
                        else CamoufoxGeneratedIdentityPolicy(
                            binding,
                            artifact.artifact_sha256,
                            self.generator,
                            program,
                            self.deployment.properties,
                            self.probe,
                        )
                    )
            else:
                blockers = self.adapter.validation_blockers(profile)
                if blockers:
                    raise WorkspaceError("identity_validation_blocked", blockers[0])
                with self.store.lock:
                    if not self._valid(profile_id, entry):
                        raise WorkspaceError(
                            "setup_cancelled", "Validation was cancelled before native startup."
                        )
                    entry.handle = self.adapter.validate_identity(
                        LaunchContext(
                            profile_id,
                            "camoufox",
                            entry.lease.paths.browser_data,
                            entry.generation,
                            "about:blank",
                            entry.lease,
                            False,
                        )
                    )
                deadline = time.monotonic() + 90
                while True:
                    if entry.cancel.is_set() or self._closed or time.monotonic() >= deadline:
                        entry.cancel.set()
                        entry.handle.stop()
                    try:
                        observed = entry.handle.status()
                    except Exception:
                        recovery = True
                        break
                    if not observed.alive:
                        with self.store.lock:
                            candidate = entry.handle.identity_admission
                            if (
                                self._valid(profile_id, entry)
                                and type(candidate) is CamoufoxProfileIdentityAdmission
                            ):
                                candidate.check(entry.policy, entry.artifact)
                                if candidate.validation_lease_token != entry.lease.token:
                                    raise WorkspaceError(
                                        "validation_lease_changed",
                                        "Validation did not acknowledge this exact owned profile lease.",
                                    )
                                self.deployment.current()
                                admission = candidate
                        break
                    if time.monotonic() > deadline + 6:
                        recovery = True
                        break
                    time.sleep(0.05)
                if admission is None:
                    message = "Validation did not issue an admission. Review the native diagnostic or retry after acknowledged shutdown."
        except WorkspaceError as exc:
            message = exc.message
        except Exception:
            message = "Setup could not verify the runtime, accepted display, catalogue or dependencies. The existing identity is retained; ask the release administrator to review the exact configuration."
        finally:
            with self.store.lock:
                if entry.handle is not None:
                    try:
                        if entry.handle.status().alive:
                            entry.handle.stop()
                            recovery = entry.handle.status().alive
                    except Exception:
                        recovery = True
                if recovery:
                    entry.policy = replace(entry.policy, admission=None) if entry.policy else None
                    self.store._change(
                        profile_id,
                        state="recovery_required",
                        blockers=[
                            "Camoufox diagnostic process ownership is unconfirmed; its lease remains held."
                        ],
                    )
                    self._set(
                        entry,
                        "recovery_required",
                        (
                            "Native shutdown could not be verified. The profile lease remains held; trusted process recovery is required.",
                        ),
                    )
                else:
                    if admission is not None:
                        try:
                            if not self._valid(profile_id, entry):
                                raise WorkspaceError(
                                    "setup_cancelled",
                                    "Validation was superseded before admission publication.",
                                )
                            self.deployment.current()
                            admission.check(entry.policy, entry.artifact)
                        except Exception:
                            admission = None
                            message = "Validation authority changed before admission publication; no admission was retained."
                    if action == "validate":
                        self.store._change(profile_id, state="stopped", blockers=[])
                    entry.native_reserved = False
                    if admission is not None:
                        entry.policy = replace(entry.policy, admission=admission)
                        self._set(entry, "ready")
                    else:
                        self._set(
                            entry,
                            "prepared" if entry.artifact is not None else "not_prepared",
                            (message,) if message else (),
                        )
                    entry.lease.release()
                    entry.lease = None
                    entry.operation_id = None
                entry.revision += 1

    def shutdown(self):
        self._closed = True
        threads = []
        with self.store.lock:
            for entry in self._entries.values():
                if entry.cancel:
                    entry.cancel.set()
                if entry.handle:
                    entry.handle.stop()
                if entry.thread:
                    threads.append(entry.thread)
        deadline = time.monotonic() + 35
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)


def load_camoufox_setup(path: Path | None, store: WorkspaceStore, *, trust_path=DEFAULT_TRUST):
    if path is None:
        return CamoufoxSetup(store)
    try:
        deployment = AuthenticatedDeployment(Path(path), Path(trust_path))
        return CamoufoxSetup(store, deployment)
    except Exception:
        return CamoufoxSetup(
            store,
            configured=True,
            blocker="The private Camoufox setup, administrator trust anchor or signed distribution receipt is invalid or unavailable. Ask the release administrator to review those files and exact host approval; no engine will be downloaded or launched.",
        )
