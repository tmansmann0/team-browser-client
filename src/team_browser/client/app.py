"""Strict same-origin loopback API for an account-free durable workspace.

Serve with the bundled loopback runner or bind 127.0.0.1 yourself. Never expose
this API through a network reverse proxy. CSRF tokens live only in process
memory, are regenerated on restart and are not accounts or enrollment tokens.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse

from .lifecycle import GMAIL_INBOX_URL, LifecycleCoordinator, ProcessAdapter
from .camoufox_setup import SetupAction
from .models import (
    ManagedConnectionPut,
    ManagedNativeAction,
    ProfileAction,
    ProfileCreate,
    ProfilePatch,
    SettingsPatch,
    TabFocus,
)
from .store import PRESETS, WorkspaceError, WorkspaceStore


def create_local_app(
    workspace_root: Path,
    *,
    port: int = 8765,
    process_adapter: ProcessAdapter | None = None,
    runtime_config: Path | None = None,
    managed_host=None,
    camoufox_config: Path | None = None,
    camoufox_trust: Path | None = None,
) -> FastAPI:
    from .managed_host import NativeManagedHost, unconfigured_snapshot

    if managed_host is not None and type(managed_host) is not NativeManagedHost:
        raise TypeError("An exact trusted native managed host is required")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("A valid loopback port is required")
    if sum(value is not None for value in (runtime_config, process_adapter, camoufox_config)) > 1:
        raise ValueError("Choose either trusted runtime configuration or an injected test adapter")
    store = WorkspaceStore(workspace_root)
    try:
        if runtime_config is not None:
            from .installed_browser import load_installed_adapter

            process_adapter = load_installed_adapter(runtime_config, store.profiles)
        from .camoufox_setup import load_camoufox_setup

        setup = load_camoufox_setup(
            camoufox_config,
            store,
            **({"trust_path": camoufox_trust} if camoufox_trust is not None else {}),
        )
        if setup.adapter is not None:
            process_adapter = setup.adapter
        coordinator = LifecycleCoordinator(
            store, process_adapter, reserved_slots=setup.active_native_count
        )
        setup.coordinator = coordinator
    except BaseException:
        store.close()
        raise
    csrf_token = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if port == 80:
        allowed_hosts.update({"127.0.0.1", "localhost", "[::1]"})
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            if managed_host is not None:
                managed_host.shutdown()
            setup_stopped = setup.shutdown()
            coordinator.shutdown()
            if setup_stopped:
                store.close()

    app = FastAPI(
        title="Local browser workspace",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.workspace = store
    app.state.coordinator = coordinator
    app.state.camoufox_setup = setup

    @app.middleware("http")
    async def protect_loopback(request: Request, call_next):
        # TestClient must use client=('127.0.0.1', port), never a production
        # 'testserver' allowlist entry. Uvicorn runner disables proxy headers.
        try:
            loopback = (
                request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
            )
        except ValueError:
            loopback = False
        host = request.headers.get("host", "").lower()
        origin = request.headers.get("origin")
        if not loopback or host not in allowed_hosts or len(request.headers.getlist("host")) != 1:
            return JSONResponse(
                {
                    "detail": {
                        "code": "loopback_only",
                        "message": "This workspace accepts direct loopback requests only",
                    }
                },
                status_code=403,
            )
        if (
            len(request.headers.getlist("origin")) > 1
            or (origin is not None and origin not in allowed_origins)
            or (origin is not None and origin != "http://" + host)
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            return JSONResponse(
                {
                    "detail": {
                        "code": "origin_rejected",
                        "message": "Only this local workspace origin is permitted",
                    }
                },
                status_code=403,
            )
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            token = request.headers.get("x-local-csrf", "")
            if not hmac.compare_digest(token.encode("utf-8"), csrf_token.encode("ascii")):
                return JSONResponse(
                    {
                        "detail": {
                            "code": "csrf_rejected",
                            "message": "Refresh this local workspace before making changes",
                        }
                    },
                    status_code=403,
                )
            if request.method in {"POST", "PUT", "PATCH"} and (
                request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                return JSONResponse(
                    {
                        "detail": {
                            "code": "json_required",
                            "message": "Workspace changes require JSON",
                        }
                    },
                    status_code=415,
                )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(WorkspaceError)
    async def workspace_error(request: Request, exc: WorkspaceError):
        return JSONResponse({"detail": exc.as_detail()}, status_code=exc.status)

    @app.get("/local/config")
    def config() -> dict[str, Any]:
        launch = coordinator.capabilities()
        return {
            "mode": "local",
            "desktop_shell": bool(getattr(app.state, "desktop_shell", False)),
            "persistent": True,
            "account_required": False,
            "api_base": "/local/v1",
            "csrf_token": csrf_token,
            "selected_profile_id": store.selected(),
            "launch": launch,
            "camoufox_setup": {
                "supported": True,
                "configured": setup.configured,
                "status_path": "/local/v1/camoufox-setup",
                "profile_path_template": "/local/v1/profiles/{profile_id}/camoufox-setup",
            },
            "settings": {**store.metadata("settings"), **coordinator.resources()},
            "managed": store.metadata("managed_connection"),
            "managed_native": {
                "supported": True,
                "configured": managed_host is not None,
                "status_path": "/local/v1/managed-native",
                "actions_path": "/local/v1/managed-native/actions",
            },
            "inbox": {
                "native_open_available": bool(launch["actual_process_available"]),
                "gmail_target": GMAIL_INBOX_URL,
                "unread_threads": None,
                "summary_source": "unavailable",
                "identity_status": "unverified",
                "blockers": []
                if launch["actual_process_available"]
                else ["Verified profile-bound browser execution is unavailable."],
            },
        }

    @app.get("/healthz")
    def health() -> dict[str, Any]:
        return {"ok": True, "mode": "local", "account_required": False}

    @app.get("/local/v1/profiles")
    def profiles() -> list[dict[str, Any]]:
        coordinator.refresh()
        return store.list_profiles()

    @app.post("/local/v1/profiles", status_code=201)
    def create_profile(body: ProfileCreate) -> dict[str, Any]:
        return store.create(**body.model_dump())

    @app.get("/local/v1/profiles/{profile_id}")
    def get_profile(profile_id: str) -> dict[str, Any]:
        coordinator.refresh()
        return store.get(profile_id)

    @app.patch("/local/v1/profiles/{profile_id}")
    def update_profile(profile_id: str, body: ProfilePatch) -> dict[str, Any]:
        with store.lock:
            setup.require_idle(profile_id)
            return store.update(profile_id, **body.model_dump(exclude_unset=True))

    @app.delete("/local/v1/profiles/{profile_id}", status_code=204)
    def delete_profile(profile_id: str, expected_revision: int = Query(ge=1)) -> Response:
        with store.lock:
            setup.require_idle(profile_id)
            store.delete(profile_id, expected_revision)
        return Response(status_code=204)

    @app.post("/local/v1/profiles/{profile_id}/actions")
    def profile_action(profile_id: str, body: ProfileAction) -> dict[str, Any]:
        if getattr(app.state, "desktop_shell", False) and body.action != "select":
            raise WorkspaceError(
                "desktop_controls_required", "Use the integrated browser controls for this profile"
            )
        setup.require_idle(profile_id)
        return coordinator.action(profile_id, **body.model_dump())

    @app.get("/local/v1/camoufox-setup")
    def camoufox_setup_status():
        return setup.overview()

    @app.get("/local/v1/profiles/{profile_id}/camoufox-setup")
    def camoufox_profile_setup(profile_id: str):
        return setup.snapshot(profile_id)

    @app.post("/local/v1/profiles/{profile_id}/camoufox-setup/actions", status_code=202)
    def camoufox_setup_action(profile_id: str, body: SetupAction):
        return setup.action(profile_id, **body.model_dump())

    @app.get("/local/v1/tabs")
    def selected_tabs() -> dict[str, Any]:
        return coordinator.selected_tabs()

    @app.post("/local/v1/profiles/{profile_id}/tab-focus", status_code=202)
    def focus_tab(profile_id: str, body: TabFocus) -> dict[str, Any]:
        return coordinator.focus_tab(profile_id, **body.model_dump())

    @app.get("/local/v1/presets")
    def presets() -> list[dict[str, str]]:
        return [dict(preset) for preset in PRESETS]

    @app.get("/local/v1/settings")
    def settings() -> dict[str, Any]:
        coordinator.refresh()
        return {**store.metadata("settings"), **coordinator.resources()}

    @app.patch("/local/v1/settings")
    def update_settings(body: SettingsPatch) -> dict[str, Any]:
        return coordinator.update_settings(**body.model_dump(exclude_unset=True))

    @app.get("/local/v1/managed-connection")
    def managed_connection() -> dict[str, Any]:
        return store.metadata("managed_connection")

    @app.get("/local/v1/managed-native")
    def native_managed_status() -> dict[str, Any]:
        # These snapshots contain only reviewed presentation fields. No URL,
        # authorization request, vault reference or token bridge is exposed.
        return (
            managed_host.snapshot() if managed_host is not None else unconfigured_snapshot()
        ).public()

    @app.post("/local/v1/managed-native/actions")
    def native_managed_action(body: ManagedNativeAction):
        if managed_host is None:
            return JSONResponse(
                {
                    "detail": {
                        "code": "managed_unconfigured",
                        "message": "Managed sign-in has not been configured for this installation.",
                    }
                },
                status_code=503,
            )
        # Input selects only a fixed argument-free operation. Configuration,
        # provider destinations and credentials remain native-owned.
        return getattr(managed_host, body.action)().public()

    @app.put("/local/v1/managed-connection")
    def set_managed_connection(body: ManagedConnectionPut) -> dict[str, Any]:
        with store.lock:
            connection = store.metadata("managed_connection")
            store.require_revision(connection, body.expected_revision)
            connection = {
                "revision": connection["revision"] + 1,
                "server_url": body.server_url,
                "status": "not_enrolled",
                "authenticated": False,
            }
            store.set_metadata("managed_connection", connection)
            return connection

    return app


def run_local(workspace_root: Path, *, port: int = 8765) -> None:
    """Only supported runner; no external bind or forwarded client addresses."""
    import uvicorn

    app = create_local_app(workspace_root, port=port)
    uvicorn.run(app, host="127.0.0.1", port=port, proxy_headers=False)
