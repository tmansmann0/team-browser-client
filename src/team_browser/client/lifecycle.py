"""Account-free profile selection and conservative local process supervision.

Native execution is admitted only through InstalledBrowserAdapter with trusted
operator configuration and fresh runtime, route, vault and supervision checks.
The default adapter remains unavailable. A caller-supplied boolean or web request
cannot unlock an executable. Synthetic adapters are visibly marked simulations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from team_browser.local.errors import LocalClientError
from team_browser.local.storage import ProfileLease

from .store import WorkspaceError, WorkspaceStore, now_iso
from .tabs import TAB_ID, LatestFocusPump, TabSnapshot


GMAIL_INBOX_URL = "https://mail.google.com/mail/u/0/#inbox"

NATIVE_BLOCKERS = (
    "A verified, pinned and signed installed browser runtime is not configured.",
    "Trusted installed-browser lifetime supervision is not configured.",
)


@dataclass(frozen=True)
class ProcessStatus:
    alive: bool
    ready: bool = False
    safe_to_stop: bool = False
    stop_pending: bool = False


@dataclass(frozen=True)
class LaunchContext:
    profile_id: str
    engine_id: str
    browser_data: Path
    generation: int
    initial_url: str = "about:blank"
    lease: ProfileLease | None = None
    selected: bool = True


class ProcessHandle(Protocol):
    """Trusted adapter methods must be bounded and never use shell strings.

    status() must reflect the whole owned browser process tree, not a short-lived
    launcher PID. stop() returns True only when that lifetime is confirmed ended.
    """

    def status(self) -> ProcessStatus: ...
    def focus(self) -> bool: ...
    def open_gmail(self) -> bool: ...
    def stop(self) -> bool: ...


class ProcessAdapter(Protocol):
    execution_kind: Literal["unavailable", "synthetic", "installed"]

    def blockers(self, profile: dict[str, Any]) -> tuple[str, ...]: ...
    def start(self, context: LaunchContext) -> ProcessHandle: ...


class UnavailableProcessAdapter:
    execution_kind = "unavailable"

    def blockers(self, profile: dict[str, Any]) -> tuple[str, ...]:
        blockers = list(NATIVE_BLOCKERS)
        if profile.get("network_policy", "unconfigured") == "unconfigured":
            blockers.append(
                "Choose local direct networking explicitly or configure a verified proxy."
            )
        elif (
            profile.get("network_policy") == "verified_proxy" or profile.get("origin") == "managed"
        ):
            blockers.append("Continuous proxy enforcement is not implemented.")
        return tuple(blockers)

    def start(self, context: LaunchContext) -> ProcessHandle:
        raise WorkspaceError(
            "engine_unavailable",
            "Native browser execution is unavailable",
            blockers=list(NATIVE_BLOCKERS),
        )


@dataclass
class RunningProfile:
    handle: ProcessHandle
    lease: ProfileLease
    generation: int
    pending_gmail: bool = False


class LifecycleCoordinator:
    def __init__(
        self, store: WorkspaceStore, adapter: ProcessAdapter | None = None, *, reserved_slots=None
    ):
        self.store = store
        self._reserved_slots = reserved_slots
        self.adapter = adapter if adapter is not None else UnavailableProcessAdapter()
        self._running: dict[str, RunningProfile] = {}
        self._closed = False
        self._request_epoch: dict[str, int] = {}
        self._selection_epoch = 0
        self._focus_pump = LatestFocusPump()

    @property
    def synthetic(self) -> bool:
        return self.adapter.execution_kind == "synthetic"

    @property
    def installed(self) -> bool:
        from .installed_browser import InstalledBrowserAdapter
        from .camoufox_runtime import CamoufoxAdapter

        return isinstance(self.adapter, (InstalledBrowserAdapter, CamoufoxAdapter))

    def capabilities(self) -> dict[str, Any]:
        blockers = self.adapter.global_blockers() if self.installed else NATIVE_BLOCKERS
        return {
            "available": self.synthetic or (self.installed and not blockers),
            "actual_process_available": self.installed and not blockers,
            "execution_kind": "synthetic"
            if self.synthetic
            else "installed"
            if self.installed
            else "unavailable",
            "blockers": [] if self.synthetic else list(blockers),
            "warning": "Synthetic process simulation only"
            if self.synthetic
            else (
                "Automation-controlled installed browser pilot; native runtime QA is still required."
                if self.installed
                else None
            ),
        }

    @staticmethod
    def capacity(settings: dict[str, Any]) -> int:
        return min(
            settings["max_warm_profiles"],
            settings["memory_budget_mb"] // settings["estimated_profile_mb"],
        )

    def _reserved(self) -> int:
        if self._reserved_slots is None:
            return 0
        try:
            value = self._reserved_slots()
        except Exception:
            raise WorkspaceError(
                "resource_reservation_unknown",
                "Native setup resource ownership is unverified; another launch is blocked.",
            ) from None
        if type(value) is not int or not 0 <= value <= 16:
            raise WorkspaceError(
                "resource_reservation_unknown",
                "Native setup resource ownership is unverified; another launch is blocked.",
            )
        return value

    def resources(self) -> dict[str, Any]:
        with self.store.lock:
            settings = self.store.metadata("settings")
            reserved = self._reserved()
            return {
                "resident_profiles": len(self._running) + reserved,
                "setup_reserved_profiles": reserved,
                "effective_capacity": self.capacity(settings),
                "estimated_resident_mb": (len(self._running) + reserved)
                * settings["estimated_profile_mb"],
                "memory_measurement": "estimate_only",
            }

    def refresh(self) -> None:
        with self.store.lock:
            for profile_id, running in list(self._running.items()):
                profile = self.store.get(profile_id)
                try:
                    status = running.handle.status()
                except Exception:
                    self.store._change(
                        profile_id,
                        state="recovery_required",
                        blockers=[
                            "The supervisor could not verify process state. Another launch is blocked."
                        ],
                    )
                    continue
                if not status.alive:
                    running.lease.release()
                    self._running.pop(profile_id)
                    self.store._change(
                        profile_id,
                        state="stopped" if profile["state"] == "stopping" else "error",
                        blockers=[]
                        if profile["state"] == "stopping"
                        else [
                            "The supervised process exited. It can be restarted after checking the cause."
                        ],
                    )
                elif status.ready and profile["state"] == "starting":
                    blockers = []
                    if running.pending_gmail:
                        running.pending_gmail = False
                        try:
                            opened = running.handle.open_gmail()
                        except Exception:
                            opened = False
                        if not opened:
                            blockers = ["Profile-bound Gmail navigation has not been confirmed."]
                    self.store._change(
                        profile_id,
                        state="running" if profile["selected"] else "warm",
                        blockers=blockers,
                    )

    def _select(self, profile_id: str) -> dict[str, Any]:
        profile = self.store.get(profile_id)
        old_id = self.store.selected()
        # Selection is manager navigation only. It must never raise a native
        # window, navigate a tab or start a browser, including on re-selection.
        # Even re-selecting the current profile is a newer explicit navigation
        # intent and must fence an older startup still in slow preflight.
        self._selection_epoch += 1
        self._focus_pump.submit(self._selection_epoch, None)
        if old_id == profile_id:
            return self.store.get(profile_id)
        self.store.db.execute("BEGIN IMMEDIATE")
        try:
            if old_id in self._running:
                old = self.store.get(old_id)
                if old["state"] == "running":
                    self.store._change(old_id, state="warm")
            self.store.set_metadata("selected_profile_id", profile_id)
            state = "running" if profile["state"] == "warm" else profile["state"]
            self.store._change(profile_id, state=state, last_selected_at=now_iso())
            self.store.db.execute("COMMIT")
        except BaseException:
            self.store.db.execute("ROLLBACK")
            raise
        for active_id, running in self._running.items():
            set_selected = getattr(running.handle, "set_selected", None)
            if set_selected is not None:
                set_selected(active_id == profile_id)
        return self.store.get(profile_id)

    def _focus(
        self, profile_id: str, *, mirror_source=None, settings_revision=None, tab_id=None
    ) -> None:
        running = self._running[profile_id]
        from .playwright_supervisor import PlaywrightHandle

        if isinstance(running.handle, PlaywrightHandle):
            self._queue_tab_focus(
                profile_id,
                running,
                tab_id=tab_id,
                mirror_source=mirror_source,
                settings_revision=settings_revision,
            )
            return
        try:
            focused = self._running[profile_id].handle.focus()
        except Exception:
            focused = False
        if not focused:
            raise WorkspaceError(
                "focus_unavailable",
                "The existing browser could not be focused",
                profile=self.store.get(profile_id),
            )

    def _tab_binding_valid(self, profile_id: str, running: RunningProfile) -> bool:
        """Called under the workspace lock, including from the native owner loop."""
        if self._closed or self._running.get(profile_id) is not running or not running.lease.active:
            return False
        profile = self.store.get(profile_id)
        launch = getattr(running.handle, "launch_context", None)
        return bool(
            profile["state"] in {"running", "warm"}
            and profile["generation"] == running.generation
            and launch is not None
            and launch.profile_id == profile_id
            and launch.generation == running.generation
            and launch.lease is running.lease
            and launch.browser_data == running.lease.paths.browser_data
        )

    def _queue_tab_focus(
        self, profile_id, running, *, tab_id=None, mirror_source=None, settings_revision=None
    ) -> None:
        epoch = self._selection_epoch

        def valid():
            with self.store.lock:
                return (
                    self._selection_epoch == epoch
                    and self.store.selected() == profile_id
                    and self._tab_binding_valid(profile_id, running)
                )

        def mirror_valid():
            with self.store.lock:
                if not valid():
                    return False
                settings = self.store.metadata("settings")
                return (
                    settings.get("mirror_same_origin", False) is True
                    and settings["revision"] == settings_revision
                )

        def source_valid():
            from .playwright_supervisor import PlaywrightHandle

            with self.store.lock:
                return (
                    mirror_source is not None
                    and isinstance(mirror_source.handle, PlaywrightHandle)
                    and mirror_valid()
                    and self._tab_binding_valid(
                        mirror_source.handle.launch_context.profile_id, mirror_source
                    )
                )

        def admit():
            with self.store.lock:
                return valid(), mirror_valid()

        def work():
            if not valid():
                return "superseded"
            origin = None
            if mirror_source is not None and source_valid():
                try:
                    snapshot = mirror_source.handle.tab_snapshot(source_valid)
                except Exception:
                    snapshot = TabSnapshot("unavailable")
                if snapshot.status == "ready" and snapshot.active_tab_id and source_valid():
                    origin = next(
                        (tab.origin for tab in snapshot.tabs if tab.id == snapshot.active_tab_id),
                        None,
                    )
            return running.handle.focus_tabs(
                valid, tab_id=tab_id, mirror_origin=origin, mirror_valid=mirror_valid, admit=admit
            )

        self._focus_pump.submit(epoch, work)

    def selected_tabs(self) -> dict[str, Any]:
        """Bounded read-only native snapshot; never holds metadata lock over IPC."""
        from .playwright_supervisor import PlaywrightHandle

        with self.store.lock:
            profile_id = self.store.selected()
            running = self._running.get(profile_id)
            generation = running.generation if running is not None else None
            epoch = self._selection_epoch
            if profile_id is None:
                snapshot = TabSnapshot("no_selection")
            elif running is None:
                snapshot = TabSnapshot("not_ready")
            elif not isinstance(running.handle, PlaywrightHandle):
                snapshot = TabSnapshot("unsupported")
            elif not self._tab_binding_valid(profile_id, running):
                snapshot = TabSnapshot("not_ready")
            else:
                snapshot = None

        def valid():
            with self.store.lock:
                return (
                    self._selection_epoch == epoch
                    and self.store.selected() == profile_id
                    and self._tab_binding_valid(profile_id, running)
                )

        if snapshot is None:
            try:
                snapshot = running.handle.tab_snapshot(valid)
            except Exception:
                snapshot = TabSnapshot("unavailable")
            if not valid():
                snapshot = TabSnapshot("superseded")
        return {
            "profile_id": profile_id,
            "generation": generation,
            **snapshot.as_dict(),
            "focus": self._focus_pump.snapshot(),
        }

    def focus_tab(
        self,
        profile_id: str,
        tab_id: str,
        *,
        generation: int,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        from .playwright_supervisor import PlaywrightHandle

        if not isinstance(tab_id, str) or not TAB_ID.fullmatch(tab_id):
            raise WorkspaceError("invalid_tab", "A current opaque tab ID is required", status=422)
        if type(generation) is not int or generation < 1:
            raise WorkspaceError(
                "invalid_generation", "A current generation is required", status=422
            )
        with self.store.lock:
            profile = self.store.get(profile_id)
            self.store.require_revision(profile, expected_revision)
            if self.store.selected() != profile_id:
                raise WorkspaceError(
                    "selection_changed", "Select this profile before selecting a tab"
                )
            running = self._running.get(profile_id)
            if running is None or running.generation != generation:
                raise WorkspaceError(
                    "stale_context", "The tab's browser context is no longer current"
                )
            if not isinstance(running.handle, PlaywrightHandle):
                raise WorkspaceError(
                    "tabs_unsupported", "This runtime cannot enumerate native tabs"
                )
            if not self._tab_binding_valid(profile_id, running):
                raise WorkspaceError("tabs_not_ready", "The owned browser context is not ready")
            self._selection_epoch += 1
            self._queue_tab_focus(profile_id, running, tab_id=tab_id)
            return {
                "profile_id": profile_id,
                "generation": generation,
                "tab_id": tab_id,
                "outcome": "queued",
                "focus": self._focus_pump.snapshot(),
            }

    def _stop(self, profile_id: str) -> str:
        profile = self.store.get(profile_id)
        running = self._running.get(profile_id)
        if running is None:
            if profile["state"] == "recovery_required":
                raise WorkspaceError(
                    "recovery_required",
                    "A previous process may still exist. "
                    "Trusted process recovery is required before restarting.",
                    profile=profile,
                    blockers=profile["blockers"],
                )
            if profile["state"] != "stopped":
                self.store._change(profile_id, state="stopped", blockers=[])
            return "already_stopped"
        self.store._change(profile_id, state="stopping")
        try:
            stopped = running.handle.stop()
            observed = running.handle.status()
            if not stopped and observed.stop_pending:
                return "stopping"
            stopped = stopped and not observed.alive
        except Exception:
            stopped = False
        if not stopped:
            profile = self.store._change(
                profile_id,
                state="recovery_required",
                blockers=[
                    "Process termination could not be verified; its profile lease remains held."
                ],
            )
            raise WorkspaceError(
                "stop_unconfirmed",
                "Process termination is unconfirmed",
                profile=profile,
                blockers=profile["blockers"],
            )
        running.lease.release()
        self._running.pop(profile_id)
        self.store._change(profile_id, state="stopped", blockers=[])
        return "stopped"

    def _trim(self, capacity: int, *, keep: str | None = None) -> None:
        needed = len(self._running) - capacity
        if needed <= 0:
            return
        candidates = []
        for profile_id, running in self._running.items():
            if profile_id == keep:
                continue
            try:
                safe = self.synthetic and running.handle.status().safe_to_stop
            except Exception:
                safe = False
            if safe:
                candidates.append(self.store.get(profile_id))
        if len(candidates) < needed:
            raise WorkspaceError(
                "budget_exceeded",
                "Close a profile or raise the resource limit. "
                "Open profiles with unknown unsaved work cannot be closed automatically.",
            )
        candidates.sort(
            key=lambda item: (
                item["state"] != "warm",
                item["last_selected_at"] or "",
                item["created_at"],
                item["id"],
            )
        )
        for victim in candidates[:needed]:
            self._stop(victim["id"])

    def _start(
        self,
        profile_id: str,
        intent: str | None = None,
        checked_blockers: tuple[str, ...] | None = None,
        select_on_start: bool = True,
    ) -> str:
        profile = self.store.get(profile_id)
        if profile["state"] == "recovery_required":
            raise WorkspaceError(
                "recovery_required",
                "Previous process ownership must be verified first",
                blockers=profile["blockers"],
                profile=profile,
            )
        if profile_id in self._running:
            settings = self.store.metadata("settings")
            old_id = self.store.selected()
            mirror_source = (
                self._running.get(old_id)
                if old_id != profile_id and settings.get("mirror_same_origin", False) is True
                else None
            )
            self._select(profile_id)
            if profile["state"] in {"running", "warm"}:
                self._focus(
                    profile_id, mirror_source=mirror_source, settings_revision=settings["revision"]
                )
            if intent == "gmail" and profile["state"] == "starting":
                self._running[profile_id].pending_gmail = True
            if intent == "gmail" and profile["state"] != "starting":
                try:
                    opened = self._running[profile_id].handle.open_gmail()
                except Exception:
                    opened = False
                if not opened:
                    raise WorkspaceError(
                        "gmail_open_failed",
                        "The profile-bound Gmail target could not be opened",
                        profile=self.store.get(profile_id),
                    )
            return "already_starting" if profile["state"] == "starting" else "focused_existing"
        if checked_blockers is None:
            try:
                blockers = tuple(self.adapter.blockers(profile))
            except Exception:
                blockers = ("The trusted launch gate could not be checked.",)
        else:
            blockers = checked_blockers
        if profile["engine_id"] == "electron_chromium":
            blockers = (*blockers, "Built-in Chromium launches only inside the desktop app.")
        if profile.get("proxy_config") is not None:
            blockers = (
                *blockers,
                "Saved proxy details are not active. A trusted adapter must verify this exact configuration before launch.",
            )
        # The installed boundary is a concrete programmatically configured adapter,
        # never a request-level trust flag or a generic claim of native capability.
        if not self.synthetic and not self.installed:
            blockers = tuple(dict.fromkeys((*blockers, *NATIVE_BLOCKERS)))
        if blockers:
            profile = self.store._change(profile_id, state="blocked", blockers=list(blockers))
            raise WorkspaceError(
                "engine_unavailable",
                "Browser launch is blocked by safety gates",
                blockers=list(blockers),
                profile=profile,
            )
        capacity = self.capacity(self.store.metadata("settings")) - self._reserved()
        if capacity < 1:
            raise WorkspaceError("budget_exceeded", "Memory budget does not fit one profile")
        try:
            lease = self.store.profiles.acquire(profile_id)
        except LocalClientError:
            raise WorkspaceError(
                "profile_in_use",
                "The profile storage could not be safely acquired. "
                "It may already be open in another process.",
                profile=profile,
            ) from None
        generation = profile["generation"] + 1
        try:
            self._trim(capacity - 1)
            self.store._change(profile_id, state="starting", generation=generation, blockers=[])
            if select_on_start:
                self._select(profile_id)
        except BaseException:
            lease.release()
            raise
        try:
            handle = self.adapter.start(
                LaunchContext(
                    profile_id,
                    profile["engine_id"],
                    lease.paths.browser_data,
                    generation,
                    GMAIL_INBOX_URL if intent == "gmail" else "about:blank",
                    lease,
                    select_on_start and self.store.selected() == profile_id,
                )
            )
        except Exception:
            # Adapter.start must either return ownership of every spawned process,
            # or fail before creating one. Unknown post-spawn ownership must be
            # represented by a handle whose status is unverified, not an exception.
            lease.release()
            profile = self.store._change(
                profile_id,
                state="error",
                blockers=["The configured process adapter failed during startup."],
            )
            raise WorkspaceError(
                "start_failed", "Profile process startup failed", profile=profile
            ) from None
        self._running[profile_id] = RunningProfile(handle, lease, generation)
        self.refresh()
        current = self.store.get(profile_id)
        if current["state"] in {"error", "recovery_required"}:
            raise WorkspaceError(
                "start_failed",
                "The process did not reach a verified startup state",
                profile=current,
                blockers=current["blockers"],
            )
        return "started" if current["state"] == "running" else "starting"

    def action(
        self,
        profile_id: str,
        action: str,
        *,
        expected_revision: int | None = None,
        idempotency_key: str | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        # Signature checks and optional route probes may be slow. Snapshot under
        # the lock, verify outside it, then fence against every metadata revision.
        # Selection/cancel and other profile actions remain responsive meanwhile.
        checked_blockers = None
        checked_revision = None
        checked_epoch = None
        selection_epoch = self._selection_epoch
        if action == "start":
            with self.store.lock:
                snapshot = self.store.get(profile_id)
                needs_check = profile_id not in self._running
                prior = (
                    self.store.db.execute(
                        "SELECT 1 FROM operations WHERE key=?", (idempotency_key,)
                    ).fetchone()
                    if idempotency_key
                    else None
                )
                self.store.require_revision(snapshot, expected_revision if not prior else None)
                if needs_check and not prior:
                    checked_epoch = self._request_epoch.get(profile_id, 0) + 1
                    self._request_epoch[profile_id] = checked_epoch
                    selection_epoch = self._selection_epoch
            if needs_check and not prior:
                try:
                    checked_blockers = tuple(self.adapter.blockers(snapshot))
                except Exception:
                    checked_blockers = ("The trusted launch gate could not be checked.",)
                checked_revision = snapshot["revision"]
        with self.store.lock:
            if self._closed:
                raise WorkspaceError("workspace_closed", "The supervisor has stopped", status=503)
            self.refresh()
            profile = self.store.get(profile_id)
            if intent is not None and (
                intent != "gmail" or action != "start" or expected_revision is None
            ):
                raise WorkspaceError(
                    "invalid_intent",
                    "Gmail open requires a fixed intent and expected revision",
                    status=422,
                )
            operation_action = action + (":" + intent if intent else "")
            if idempotency_key:
                prior = self.store.db.execute(
                    "SELECT * FROM operations WHERE key=?", (idempotency_key,)
                ).fetchone()
                if prior:
                    if prior["profile_id"] != profile_id or prior["action"] != operation_action:
                        raise WorkspaceError(
                            "idempotency_conflict", "This operation key was already used"
                        )
                    # Return current reality, never a persisted successful launch snapshot.
                    return {
                        "profile": profile,
                        "selected_profile_id": self.store.selected(),
                        "outcome": "replayed",
                        "original_outcome": prior["outcome"],
                        "replayed": True,
                        "blockers": profile["blockers"],
                    }
            if action in {"stop", "cancel"}:
                self._request_epoch[profile_id] = self._request_epoch.get(profile_id, 0) + 1
            if checked_epoch is not None and self._request_epoch.get(profile_id) != checked_epoch:
                raise WorkspaceError(
                    "operation_superseded", "The pending start was cancelled or replaced"
                )
            self.store.require_revision(profile, expected_revision)
            if checked_revision is not None and profile_id not in self._running:
                self.store.require_revision(profile, checked_revision)
            if action not in {"select", "start", "stop", "cancel"}:
                raise WorkspaceError("invalid_action", "Unknown profile action", status=422)
            if idempotency_key:
                self.store.db.execute(
                    "INSERT INTO operations VALUES (?,?,?,?,?)",
                    (idempotency_key, profile_id, operation_action, "pending", now_iso()),
                )
            try:
                if action == "select":
                    self._select(profile_id)
                    outcome = "selected"
                elif action == "start":
                    outcome = self._start(
                        profile_id,
                        intent,
                        checked_blockers,
                        selection_epoch == self._selection_epoch,
                    )
                else:
                    outcome = self._stop(profile_id)
                    if action == "cancel" and outcome == "stopped":
                        outcome = "cancelled"
            except WorkspaceError as exc:
                if idempotency_key:
                    self.store.db.execute(
                        "UPDATE operations SET outcome=? WHERE key=?", (exc.code, idempotency_key)
                    )
                raise
            if idempotency_key:
                self.store.db.execute(
                    "UPDATE operations SET outcome=? WHERE key=?", (outcome, idempotency_key)
                )
            profile = self.store.get(profile_id)
            return {
                "profile": profile,
                "selected_profile_id": self.store.selected(),
                "outcome": outcome,
                "replayed": False,
                "blockers": profile["blockers"],
            }

    def update_settings(self, expected_revision: int, **changes: Any) -> dict[str, Any]:
        with self.store.lock:
            self.refresh()
            settings = self.store.metadata("settings")
            self.store.require_revision(settings, expected_revision)
            if not set(changes).issubset(
                {
                    "max_warm_profiles",
                    "memory_budget_mb",
                    "estimated_profile_mb",
                    "profile_navigation",
                    "tab_navigation",
                    "mirror_same_origin",
                }
            ):
                raise ValueError("Unknown settings")
            if "profile_navigation" in changes and changes["profile_navigation"] not in {
                "sidebar",
                "grid",
            }:
                raise ValueError("Invalid profile navigation")
            if "tab_navigation" in changes and changes["tab_navigation"] not in {"top", "side"}:
                raise ValueError("Invalid tab navigation")
            if "mirror_same_origin" in changes and type(changes["mirror_same_origin"]) is not bool:
                raise ValueError("Mirror setting must be a boolean")
            updated = {**settings, **changes, "revision": settings["revision"] + 1}
            capacity = self.capacity(updated)
            if capacity < 1:
                raise WorkspaceError(
                    "invalid_budget", "The memory budget must fit at least one profile", status=422
                )
            if set(changes) & {"max_warm_profiles", "memory_budget_mb", "estimated_profile_mb"}:
                reserved = self._reserved()
                if capacity < reserved:
                    raise WorkspaceError(
                        "budget_exceeded",
                        "Wait for acknowledged diagnostic shutdown before lowering the resource budget.",
                    )
                self._trim(capacity - reserved, keep=self.store.selected())
            self.store.set_metadata("settings", updated)
            return {**updated, **self.resources()}

    def shutdown(self) -> None:
        with self.store.lock:
            if self._closed:
                return
            self._closed = True
            self._focus_pump.close()
            for profile_id in list(self._running):
                try:
                    self._stop(profile_id)
                except WorkspaceError:
                    # Retain the lease until process exit. Do not fabricate shutdown.
                    pass
        shutdown = getattr(self.adapter, "shutdown", None)
        if shutdown is not None:
            shutdown()
            self.refresh()
