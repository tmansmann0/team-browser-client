"""Owned desktop sidecar. Never opens a browser or installs a dependency.

The packaged Electron main process supplies a per-launch capability on its stdin
pipe. It is not an account credential, persistent secret, URL or CLI argument.
Every HTTP request needs it in addition to the local API's Host/Origin/CSRF gates.
EOF on the parent pipe requests graceful shutdown, including if the shell dies.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
from typing import BinaryIO
from contextlib import asynccontextmanager

import uvicorn
from pydantic import Field

from team_browser.client.app import create_local_app
from team_browser.client_cli import mount_workspace
from team_browser.client.models import InputModel
from team_browser.client.store import ACTIVE_STATES, WorkspaceError

TOKEN_HEADER = b"x-tbm-desktop-token"
MAX_CONTROL_BYTES = 512


def read_capability(stream: BinaryIO) -> tuple[str, str]:
    line = stream.readline(MAX_CONTROL_BYTES + 1)
    if len(line) > MAX_CONTROL_BYTES or not line.endswith(b"\n"):
        raise ValueError("Invalid desktop bootstrap")
    try:
        message = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid desktop bootstrap") from None
    if (
        type(message) is not dict
        or set(message) != {"protocol", "token", "owner_token"}
        or type(message["protocol"]) is not int
        or message["protocol"] != 1
        or type(message["token"]) is not str
        or re.fullmatch(r"[a-f0-9]{64}", message["token"]) is None
        or type(message["owner_token"]) is not str
        or re.fullmatch(r"[a-f0-9]{64}", message["owner_token"]) is None
        or message["token"] == message["owner_token"]
    ):
        raise ValueError("Invalid desktop bootstrap")
    return message["token"], message["owner_token"]


class DesktopCapabilityGate:
    """Pure ASGI gate also protects static assets/config before any workspace read."""

    def __init__(self, app, token: str, owner_token: str):
        if type(token) is not str or re.fullmatch(r"[a-f0-9]{64}", token) is None:
            raise ValueError("Invalid desktop capability")
        self.app = app
        self._token = token.encode("ascii")
        if (
            type(owner_token) is not str
            or re.fullmatch(r"[a-f0-9]{64}", owner_token) is None
            or token == owner_token
        ):
            raise ValueError("Invalid desktop owner capability")
        self._owner_token = owner_token.encode("ascii")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        values = [v for k, v in scope.get("headers", []) if k.lower() == TOKEN_HEADER]
        expected = (
            self._owner_token if scope.get("path", "").startswith("/desktop/") else self._token
        )
        if len(values) != 1 or not hmac.compare_digest(values[0], expected):
            body = b'{"detail":{"code":"desktop_session_required"}}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        # The application never receives the secret and cannot reflect it in errors.
        scope = {
            **scope,
            "headers": [(k, v) for k, v in scope["headers"] if k.lower() != TOKEN_HEADER],
        }
        await self.app(scope, receive, send)


class ClaimProfile(InputModel):
    expected_revision: int = Field(ge=1)


class DesktopProfileLeases:
    """Metadata/OS leases for the exact Electron main, never browser renderer actions."""

    def __init__(self, store):
        self.store = store
        self.leases = {}

    def claim(self, profile_id: str, expected_revision: int):
        with self.store.lock:
            profile = self.store.get(profile_id)
            self.store.require_revision(profile, expected_revision)
            if profile_id in self.leases:
                return profile
            if profile["origin"] != "local" or profile["engine_id"] != "electron_chromium":
                raise WorkspaceError(
                    "desktop_engine_required",
                    "Only local built-in Chromium profiles can open inside the app",
                )
            if profile["state"] in ACTIVE_STATES | {"recovery_required"}:
                raise WorkspaceError(
                    "profile_in_use", "This profile needs a confirmed stop or recovery"
                )
            if profile["network_policy"] not in {"local_direct", "verified_proxy"}:
                raise WorkspaceError(
                    "network_unconfigured", "Choose direct networking or a local proxy first"
                )
            settings = self.store.metadata("settings")
            # Embedded views use the explicit user limit, not a fabricated
            # per-profile RAM estimate from the legacy process adapter.
            capacity = settings["max_warm_profiles"]
            if len(self.leases) >= capacity:
                raise WorkspaceError(
                    "budget_exceeded", "Close a profile or raise the resource limit"
                )
            lease = self.store.profiles.acquire(profile_id)
            try:
                profile = self.store._change(profile_id, state="running", blockers=[])
                self.leases[profile_id] = lease
                return profile
            except BaseException:
                lease.release()
                raise

    def release(self, profile_id: str):
        with self.store.lock:
            if profile_id not in self.leases:
                # Acknowledgement can be lost after a successful release. Only
                # an already stopped record is safe to acknowledge idempotently;
                # active/recovery records must never be normalized by a retry.
                profile = self.store.get(profile_id)
                if profile["state"] == "stopped":
                    return profile
                raise WorkspaceError(
                    "desktop_lease_missing", "No owned embedded profile can be released"
                )
            profile = self.store._change(profile_id, state="stopped", blockers=[])
            self.leases.pop(profile_id).release()
            return profile

    def abandon(self):
        with self.store.lock:
            for profile_id, lease in self.leases.items():
                self.store._change(
                    profile_id,
                    state="recovery_required",
                    blockers=["The desktop browser ended without acknowledging profile shutdown."],
                )
                lease.release()
            self.leases.clear()


def mount_desktop_ownership(app):
    registry = DesktopProfileLeases(app.state.workspace)
    app.state.desktop_leases = registry

    @app.post("/desktop/v1/profiles/{profile_id}/claim")
    def claim(profile_id: str, body: ClaimProfile):
        return registry.claim(profile_id, body.expected_revision)

    @app.post("/desktop/v1/profiles/{profile_id}/release")
    def release(profile_id: str):
        return registry.release(profile_id)

    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with original(application):
            try:
                yield
            finally:
                registry.abandon()

    app.router.lifespan_context = lifespan
    return app


def watch_owner(stream: BinaryIO, stop: threading.Event) -> None:
    # Exactly one final command is supported. EOF and malformed input both fail closed.
    # The command carries no paths, browser arguments, credentials, or arbitrary actions.
    stream.readline(MAX_CONTROL_BYTES + 1)
    stop.set()


async def serve_owned(workspace: Path, token: str, owner_token: str, control: BinaryIO):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        listener.setblocking(False)
        port = listener.getsockname()[1]
        app = mount_desktop_ownership(
            mount_workspace(create_local_app(workspace, port=port), desktop=True)
        )
        server = uvicorn.Server(
            uvicorn.Config(
                DesktopCapabilityGate(app, token, owner_token),
                host="127.0.0.1",
                port=port,
                proxy_headers=False,
                access_log=False,
                log_level="warning",
                lifespan="on",
                ws="none",
            )
        )
        stop = threading.Event()
        threading.Thread(target=watch_owner, args=(control, stop), daemon=True).start()
        task = asyncio.create_task(server.serve(sockets=[listener]))
        announced = False
        try:
            while not task.done():
                if stop.is_set():
                    server.should_exit = True
                if server.started and not announced and not stop.is_set():
                    # stdout is a bounded protocol channel, not a log stream.
                    print(
                        json.dumps(
                            {
                                "kind": "tbm-desktop-ready",
                                "protocol": 1,
                                "port": port,
                                "pid": os.getpid(),
                            }
                        ),
                        flush=True,
                    )
                    announced = True
                await asyncio.sleep(0.05)
            await task
        finally:
            server.should_exit = True
            if not task.done():
                await task


def main():
    parser = argparse.ArgumentParser(prog="tbm-desktop-sidecar")
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args()
    if not args.workspace.is_absolute():
        parser.error("An absolute workspace is required")
    # No Camoufox/managed option: frozen builds do not have a compatible isolated
    # CPython helper. Those paths require a separate reviewed packaging design.
    try:
        token, owner_token = read_capability(sys.stdin.buffer)
        asyncio.run(serve_owned(args.workspace, token, owner_token, sys.stdin.buffer))
    except (ValueError, OSError):
        print("Desktop workspace could not start.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
