"""Bounded, process-local native tab metadata and latest-intent focus scheduling.

Only a handle's owned persistent context supplies pages. No URL is a control
input, and no cookie, storage, page text, favicon or account identity is read.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import secrets
import threading
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

MAX_TABS = 128
MAX_TITLE = 160
MAX_URL = 8192
SNAPSHOT_TIMEOUT = 2.0
TAB_ID = re.compile(r"tab_[a-f0-9]{32}\Z", re.ASCII)
_URL_IN_TITLE = re.compile(r"(?:https?|ftp|file)://[^\s<>]+", re.IGNORECASE)


def web_origin(value: object) -> str | None:
    """Canonical exact HTTPS origin, including non-default effective ports.

    Reject credentials and ambiguous host spellings rather than guessing an
    origin. Paths, query strings and fragments are never returned or stored.
    """
    if not isinstance(value, str) or len(value) > MAX_URL:
        return None
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 443
        if not host or not 1 <= port <= 65535 or "%" in host:
            return None
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        else:
            # Browser page.url is already URL-serialized (ASCII/punycode).
            # Python's built-in IDNA2003 differs from browser UTS46 for names
            # such as ß, so reject uncanonicalized Unicode rather than merge it
            # with a distinct ASCII origin.
            host = host.encode("ascii").decode("ascii").lower()
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host):
                return None
            if any(not label or len(label) > 63 for label in host.rstrip(".").split(".")):
                return None
            if any(label.startswith("-") or label.endswith("-") for label in host.split(".")):
                return None
        return "https://" + host + (f":{port}" if port != 443 else "")
    except (ValueError, UnicodeError):
        return None


def safe_title(value: object) -> str:
    if not isinstance(value, str):
        return "Untitled tab"
    # Inspect bounded input, remove controls/bidi formatting, collapse whitespace,
    # and redact URL-shaped titles so sensitive URL components cannot leak here.
    value = value[:2048]
    value = "".join(
        " " if c.isspace() else c
        for c in value
        if c.isspace() or not unicodedata.category(c).startswith("C")
    )
    value = _URL_IN_TITLE.sub(lambda m: web_origin(m.group()) or "[URL]", value)
    return " ".join(value.split())[:MAX_TITLE] or "Untitled tab"


@dataclass(frozen=True)
class Tab:
    id: str
    title: str
    origin: str | None
    active: bool = False


@dataclass(frozen=True)
class TabSnapshot:
    status: str
    tabs: tuple[Tab, ...] = ()
    active_tab_id: str | None = None
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "tabs": [asdict(tab) for tab in self.tabs],
            "active_tab_id": self.active_tab_id,
            "truncated": self.truncated,
            "active_evidence": "dom_visibility_hint" if self.active_tab_id else "unknown",
        }


class OwnedTabs:
    """Registry lives on the native owner loop; IDs never survive invalidation."""

    def __init__(self, handle: Any):
        self.handle = handle
        self.pid = os.getpid()
        self.launch_context = handle.launch_context
        self.lease_token = getattr(handle.launch_context.lease, "token", None)
        self.context: Any = None
        self.pages: dict[str, Any] = {}
        self._reading = False

    def invalidate(self) -> None:
        self.pages.clear()
        self.context = None

    def _owned(self) -> bool:
        h, launch = self.handle, self.handle.launch_context
        lease = launch.lease
        try:
            if (
                h.phase == "ready"
                and h.context is not None
                and h.context.is_closed()
                and not h.close_requested
            ):
                h._on_close()
            owned = (
                self.pid == os.getpid()
                and launch is self.launch_context
                and lease is self.launch_context.lease
                and lease.token == self.lease_token
                and not h.ownership_uncertain
                and not h.close_requested
                and h.phase == "ready"
                and h.context is not None
                and not h.context.is_closed()
                and lease is not None
                and lease.active
                and lease.paths.profile_id == launch.profile_id
                and lease.paths.browser_data == launch.browser_data
            )
        except Exception:
            owned = False
        if not owned:
            self.invalidate()
            return False
        if self.context is not None and self.context is not h.context:
            # A new persistent context requires a new supervised handle and
            # generation. Rebinding an existing handle is not ownership proof.
            h._on_close()
            self.invalidate()
            return False
        if self.context is None:
            self.context = h.context
        return True

    async def owned(self, valid: Callable[[], bool]) -> bool:
        # Workspace validation may briefly take the metadata lock. Never block
        # the native event loop on it: legacy fixed-intent IPC shares this loop.
        return self._owned() and await asyncio.to_thread(valid) and self._owned()

    async def current_pages(self, valid: Callable[[], bool]) -> tuple[list[Any], bool] | None:
        if not await self.owned(valid):
            return None
        pages = self.context.pages
        # Playwright's public pages property returns a finite current list. Do not
        # scan arbitrary many entries or keep page references beyond this bound.
        truncated = len(pages) > MAX_TABS
        pages = [p for p in pages[:MAX_TABS] if not p.is_closed()]
        self.pages = {
            key: page for key, page in self.pages.items() if any(page is p for p in pages)
        }
        for page in pages:
            if not any(page is prior for prior in self.pages.values()):
                self.pages["tab_" + secrets.token_hex(16)] = page
        return pages, truncated

    async def snapshot(self, valid: Callable[[], bool]) -> TabSnapshot:
        if self._reading:
            return TabSnapshot("busy")
        self._reading = True
        try:
            return await asyncio.wait_for(self._snapshot(valid), SNAPSHOT_TIMEOUT)
        except Exception:
            return TabSnapshot("not_ready" if not self._owned() else "unavailable")
        finally:
            self._reading = False

    async def _snapshot(self, valid: Callable[[], bool]) -> TabSnapshot:
        current = await self.current_pages(valid)
        if current is None:
            return TabSnapshot("not_ready")
        pages, truncated = current
        context = self.context
        tokens = dict(self.pages)
        semaphore = asyncio.Semaphore(8)

        async def metadata(key: str, page: Any):
            async with semaphore:
                if not await self.owned(valid) or self.context is not context or page.is_closed():
                    raise ValueError("Stale tab")
                title = await page.title()
                if not await self.owned(valid) or self.context is not context or page.is_closed():
                    raise ValueError("Stale tab")
                # Fixed visibility-state metadata only. No page text, identity,
                # URL evaluation, injected listener or persistent script is read.
                visible = await page.evaluate("document.visibilityState === 'visible'")
                if not await self.owned(valid) or self.context is not context or page.is_closed():
                    raise ValueError("Stale tab")
                return Tab(key, safe_title(title), web_origin(page.url)), visible is True

        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(metadata(key, page)) for key, page in tokens.items()]
        observed = [task.result() for task in tasks]
        current = await self.current_pages(valid)
        if current is None or self.context is not context:
            return TabSnapshot("not_ready")
        if current[1] != truncated:
            return TabSnapshot("changed")
        if len(current[0]) != len(pages) or any(not any(p is q for q in current[0]) for p in pages):
            return TabSnapshot("changed")
        # Multiple native windows can each have a visible tab. Never guess which
        # window is active; only one visible tab in a complete snapshot is known.
        visible_ids = [tab.id for tab, visible in observed if visible]
        active = visible_ids[0] if len(visible_ids) == 1 and not truncated else None
        tabs = tuple(Tab(t.id, t.title, t.origin, t.id == active) for t, _ in observed)
        return TabSnapshot("limited" if truncated else "ready", tabs, active, truncated)

    async def focus(
        self,
        valid: Callable[[], bool],
        *,
        tab_id: str | None = None,
        mirror_origin: str | None = None,
        mirror_valid: Callable[[], bool] = lambda: True,
        admit=None,
    ) -> str:
        async with self.handle.owner.native_focus_lock():
            return await self._focus(
                valid,
                tab_id=tab_id,
                mirror_origin=mirror_origin,
                mirror_valid=mirror_valid,
                admit=admit,
            )

    async def _focus(
        self, valid, *, tab_id=None, mirror_origin=None, mirror_valid=lambda: True, admit=None
    ) -> str:
        current = await self.current_pages(valid)
        if current is None:
            return "not_ready"
        pages, truncated = current
        context = self.context
        # The coordinator captures selection and settings together under its
        # lock, on a worker thread. No awaited operation separates that admission
        # result from choosing and sending the native command on this loop.
        admitted, mirror_allowed = await asyncio.to_thread(
            admit if admit is not None else lambda: (valid(), mirror_valid())
        )
        if not admitted or not self._owned() or self.context is not context:
            return "not_ready"
        mirror_allowed = mirror_origin is not None and mirror_allowed
        pages_now = self.context.pages
        truncated = truncated or len(pages_now) > MAX_TABS
        pages = [p for p in pages_now[:MAX_TABS] if not p.is_closed()]
        if tab_id is not None:
            page = self.pages.get(tab_id)
            if page is None or not any(page is p for p in pages):
                return "stale_tab"
        else:
            page = self.handle.page
            if not any(page is p for p in pages):
                page = pages[0] if pages else None
            if mirror_allowed and not truncated:
                matches = [p for p in pages if web_origin(p.url) == mirror_origin]
                if len(matches) == 1:
                    page = matches[0]
        if page is None:
            return "empty"
        # No timeout/cancellation is treated as native acknowledgement. The pump
        # cannot undo an already-admitted command, and waits before newer focus.
        await page.bring_to_front()
        if not await self.owned(valid) or self.context is not context or page.is_closed():
            return "superseded"
        if not any(page is p for p in self.context.pages[:MAX_TABS]):
            return "stale_tab"
        self.handle.page = page
        return "focused"


class LatestFocusPump:
    """At most one executing work item and one replacement pending intent.

    A stalled native call can delay convergence but cannot block API callers or
    grow the queue. Never report queued work as completed native focus.
    """

    def __init__(self):
        self._condition = threading.Condition()
        self._pending: tuple[int, Callable[[], str]] | None = None
        self._thread: threading.Thread | None = None
        self._closed = False
        self._epoch = 0
        self._status = "idle"

    def submit(self, epoch: int, work: Callable[[], str] | None) -> None:
        with self._condition:
            if self._closed or epoch < self._epoch:
                return
            self._epoch = epoch
            self._status = "queued" if work is not None else "idle"
            self._pending = (epoch, work) if work is not None else None
            if work is not None and self._thread is None:
                self._thread = threading.Thread(target=self._run, name="tbm-tab-focus", daemon=True)
                self._thread.start()
            self._condition.notify_all()

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            return {"intent": self._epoch, "status": self._status}

    def _run(self) -> None:
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._closed or self._pending is not None)
                if self._closed:
                    return
                epoch, work = self._pending
                self._pending = None
                self._status = "pending"
            try:
                status = work()
            except Exception:
                status = "unavailable"
            with self._condition:
                if self._epoch == epoch and not self._closed:
                    self._status = status

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._pending = None
            self._status = "closed"
            self._condition.notify_all()
