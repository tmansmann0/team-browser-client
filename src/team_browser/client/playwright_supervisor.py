"""Optional official Playwright pipe supervisor for an installed signed browser.

No bundled browser download, remote-debugging TCP listener, cookie API, arbitrary
navigation, exposed CDP endpoint, or browser-security flag bypass is provided.
Async Playwright objects stay on one dedicated event loop across FastAPI worker
threads. Missing dependencies and uncertain lifetime remain fail-closed.

Official ownership contract:
https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-persistent-context
Real macOS execution, process-crash behavior and window focus require native QA.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import threading
from concurrent.futures import TimeoutError
from pathlib import Path
from typing import Any

from team_browser.local.runtime import RuntimeGate, VerifiedRuntime

from .lifecycle import GMAIL_INBOX_URL, LaunchContext, ProcessStatus
from .store import WorkspaceError
from .tabs import OwnedTabs, TabSnapshot


class PlaywrightHandle:
    def __init__(self, owner: PlaywrightSupervisor, context: LaunchContext):
        self.owner, self.launch_context = owner, context
        self.selected = context.selected
        self.context: Any = None
        self.page: Any = None
        self.phase = "starting"
        self.close_requested = False
        self.ownership_uncertain = False
        self.launch_future: Any = None
        self.stop_future: Any = None
        # Private diagnostic only. The ordinary API never exposes exception
        # text, which can contain browser output. A bounded synthetic acceptance
        # harness may inspect it without changing conservative lifetime state.
        self._startup_exception: Exception | None = None
        self._state_lock = threading.Lock()
        self.tabs = OwnedTabs(self)

    def _set_phase(self, phase: str) -> None:
        with self._state_lock:
            # Unknown ownership is sticky: a late launch/focus completion cannot
            # turn a disconnected native child into a ready or stopped profile.
            self.phase = "unknown" if self.ownership_uncertain else phase

    def _on_close(self, *_: object) -> None:
        self.tabs.invalidate()
        # An unsolicited driver/context disconnect is not proof every owned OS
        # process exited. Keep the lease until explicit close is acknowledged.
        if not self.close_requested:
            self.ownership_uncertain = True
            self._set_phase("unknown")

    def set_selected(self, selected: bool) -> None:
        self.selected = selected

    def status(self) -> ProcessStatus:
        with self._state_lock:
            phase = self.phase
        if phase == "unknown" or self.ownership_uncertain:
            raise WorkspaceError(
                "process_state_unknown", "The browser connection ended without verified shutdown"
            )
        return ProcessStatus(
            phase != "stopped",
            phase == "ready",
            safe_to_stop=False,
            stop_pending=phase == "stopping",
        )

    async def _focus(self) -> bool:
        return await self.tabs.focus(lambda: True) == "focused"

    def focus(self) -> bool:
        return self.owner.call(self._focus(), timeout=1.0)

    def tab_snapshot(self, valid) -> TabSnapshot:
        return self.owner.call(self.tabs.snapshot(valid), timeout=2.5)

    def focus_tabs(
        self, valid, *, tab_id=None, mirror_origin=None, mirror_valid=lambda: True, admit=None
    ) -> str:
        # Only the background latest-intent pump waits for native acknowledgement.
        # A timeout must not let a newer command race an unacknowledged old focus.
        self.owner._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(
            self.tabs.focus(
                valid,
                tab_id=tab_id,
                mirror_origin=mirror_origin,
                mirror_valid=mirror_valid,
                admit=admit,
            ),
            self.owner._loop,
        )
        return future.result()

    async def _gmail(self) -> bool:
        if self.ownership_uncertain or self.phase != "ready":
            return False
        if not hasattr(self, "_gmail_lock"):
            self._gmail_lock = asyncio.Lock()
        async with self._gmail_lock:
            # Cache a Gmail page only after fixed-target navigation succeeds.
            # Failed/pending attempts reuse their own candidate on explicit retry;
            # an existing blank page must never masquerade as opened Gmail.
            if getattr(self, "gmail_page", None) is None or self.gmail_page.is_closed():
                candidate = getattr(self, "_gmail_candidate", None)
                if candidate is None or candidate.is_closed():
                    candidate = await self.context.new_page()
                    self._gmail_candidate = candidate
                await candidate.goto(GMAIL_INBOX_URL, wait_until="domcontentloaded", timeout=15000)
                self.gmail_page = candidate
                self._gmail_candidate = None
            self.page = self.gmail_page
            async with self.owner.native_focus_lock():
                if self.selected and not self.ownership_uncertain and not self.close_requested:
                    await self.page.bring_to_front()
            return True

    def open_gmail(self) -> bool:
        return self.owner.call(self._gmail(), timeout=1.0)

    async def _stop(self) -> bool:
        if self.ownership_uncertain:
            self._set_phase("unknown")
            return False
        if self.phase == "stopped":
            return True
        if self.launch_future is not None and not self.launch_future.done():
            try:
                await asyncio.wrap_future(self.launch_future)
            except Exception:
                pass
        if self.phase == "stopped":
            return True
        if self.context is None:
            # A launch transport error cannot prove that no native child exists.
            return False
        if self.ownership_uncertain or self.context.is_closed():
            self.ownership_uncertain = True
            self._set_phase("unknown")
            return False
        self.close_requested = True
        try:
            await self.context.close()
        except Exception:
            self.ownership_uncertain = True
            self._set_phase("unknown")
            return False
        self._set_phase("stopped")
        return True

    def stop(self) -> bool:
        if self.ownership_uncertain:
            return False
        if self.phase == "stopped":
            return True
        if self.stop_future is None or (self.stop_future.done() and not self.stop_future.result()):
            self.close_requested = True
            self._set_phase("stopping")
            self.stop_future = asyncio.run_coroutine_threadsafe(self._stop(), self.owner._loop)
        if not self.stop_future.done():
            return False
        return bool(self.stop_future.result())


class PlaywrightSupervisor:
    """Built-in persistent-context ownership, no platform-specific focus script."""

    def __init__(self, *, factory=None, operation_timeout: float = 20.0):
        self.factory = factory
        self.operation_timeout = operation_timeout
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._playwright: Any = None
        self._driver_lock: asyncio.Lock | None = None
        self._native_focus_lock: asyncio.Lock | None = None
        self._handles: list[PlaywrightHandle] = []

    def native_focus_lock(self) -> asyncio.Lock:
        # Access only on the owner loop. Include startup and fixed Gmail focus
        # in the same acknowledgement ordering as manager tab/profile selection.
        if self._native_focus_lock is None:
            self._native_focus_lock = asyncio.Lock()
        return self._native_focus_lock

    def check(self, runtime: VerifiedRuntime) -> None:
        if self.factory is None and importlib.util.find_spec("playwright") is None:
            raise WorkspaceError(
                "supervisor_unavailable",
                "Install the optional official Playwright dependency; no browser download is needed",
            )

    def _ensure_loop(self) -> None:
        with self._lock:
            if self._loop is not None:
                return
            ready = threading.Event()

            def run():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                ready.set()
                loop.run_forever()
                loop.close()

            self._thread = threading.Thread(target=run, name="tbm-browser-owner", daemon=True)
            self._thread.start()
            if not ready.wait(3):
                raise WorkspaceError(
                    "supervisor_unavailable", "The local process owner did not start"
                )

    def call(self, coroutine, *, timeout: float | None = None):
        self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout if timeout is not None else self.operation_timeout)
        except TimeoutError:
            # Do not cancel a close or abandon a pending ownership operation.
            raise WorkspaceError(
                "process_state_unknown", "The native operation has not acknowledged completion"
            ) from None

    async def _launch(
        self, handle: PlaywrightHandle, runtime: VerifiedRuntime, argv: tuple[str, ...], home: Path
    ) -> None:
        try:
            if handle.close_requested:
                handle._set_phase("stopped")
                return
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
            if not await asyncio.to_thread(RuntimeGate.is_unchanged, runtime):
                raise WorkspaceError(
                    "runtime_changed", "Installed browser changed before execution"
                )
            route_flags = [
                flag
                for flag in argv
                if flag == "--no-proxy-server" or flag.startswith("--proxy-server=")
            ]
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
            context = await self._playwright.chromium.launch_persistent_context(
                str(handle.launch_context.browser_data),
                executable_path=str(runtime.executable),
                headless=False,
                chromium_sandbox=True,
                timeout=30000,
                # Own the entire tiny argument list. Playwright's default test
                # switches disable security updates, phishing checks, native
                # keychains and selected isolation features. None are inherited.
                # The fixed pipe and profile switches replace only IPC plumbing.
                args=[
                    f"--user-data-dir={handle.launch_context.browser_data}",
                    "--remote-debugging-pipe",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-mode",
                    *route_flags,
                    "about:blank",
                ],
                ignore_default_args=True,
                env=environment,
                accept_downloads=False,
                no_viewport=True,
            )
            handle.context = context
            context.on("close", handle._on_close)
            if context.is_closed():
                # The close event might have occurred before listener registration.
                handle.ownership_uncertain = True
                handle._set_phase("unknown")
                return
            if handle.close_requested or handle.ownership_uncertain:
                return
            unchanged = await asyncio.to_thread(RuntimeGate.is_unchanged, runtime)
            if handle.close_requested or handle.ownership_uncertain:
                return
            if not unchanged:
                handle.close_requested = True
                await context.close()
                handle._set_phase("stopped")
                return
            handle.page = context.pages[0] if context.pages else await context.new_page()
            if handle.close_requested or handle.ownership_uncertain:
                return
            if handle.launch_context.initial_url == GMAIL_INBOX_URL:
                await handle.page.goto(
                    GMAIL_INBOX_URL, wait_until="domcontentloaded", timeout=15000
                )
                handle.gmail_page = handle.page
            if handle.close_requested or handle.ownership_uncertain:
                return
            async with self.native_focus_lock():
                if (
                    handle.selected
                    and not handle.close_requested
                    and not handle.ownership_uncertain
                ):
                    await handle.page.bring_to_front()
            if not handle.close_requested and not handle.ownership_uncertain:
                handle._set_phase("ready")
        except Exception as exc:
            # Preserve lease/ownership even if the transport failed after spawning.
            handle._startup_exception = exc
            handle.ownership_uncertain = True
            handle._set_phase("unknown")

    def launch(
        self, runtime: VerifiedRuntime, context: LaunchContext, argv: tuple[str, ...], *, home: Path
    ) -> PlaywrightHandle:
        self.check(runtime)
        self._ensure_loop()
        handle = PlaywrightHandle(self, context)
        self._handles.append(handle)
        handle.launch_future = asyncio.run_coroutine_threadsafe(
            self._launch(handle, runtime, argv, home), self._loop
        )
        return handle

    def shutdown(self) -> None:
        # Graceful app shutdown may await explicit close acknowledgements, while
        # ordinary API stop/cancel remains nonblocking and reports stopping.
        if self._loop is None:
            return
        for handle in self._handles:
            if handle.stop_future is not None:
                try:
                    handle.stop_future.result(timeout=self.operation_timeout)
                except Exception:
                    pass
        # Never destroy the owner of an uncertain still-live browser.
        if any(handle.phase != "stopped" for handle in self._handles):
            return
        if self._playwright is not None:
            self.call(self._playwright.stop())
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=3)
