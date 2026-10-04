"""Durable local metadata; no credentials, cookies, account or browser content.

The workspace has one owning process. Its kernel lock guards crash recovery,
which never trusts stored PIDs or kills processes. SQLite paths are application
chosen inside a private, symlink-free root. This protects separate OS users;
it cannot protect against a hostile process already running as this OS user.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from team_browser.local.storage import (
    ProfileStore,
    _check_private,
    _open_private_root,
    fcntl,
    validate_identifier,
)

from .models import ProfileCreate, ProfilePatch


class WorkspaceError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 409, **details: Any):
        super().__init__(message)
        self.code, self.message, self.status, self.details = code, message, status, details

    def as_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.details}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


PRESETS = (
    {"id": "desktop", "name": "Built-in Chromium", "engine_id": "electron_chromium"},
    {"id": "standard", "name": "Standard browser", "engine_id": "chromium"},
    {"id": "isolated", "name": "Camoufox browser", "engine_id": "camoufox"},
)

LAYOUT_DEFAULTS = {
    "profile_navigation": "sidebar",
    "tab_navigation": "top",
    "mirror_same_origin": False,
}
ACTIVE_STATES = {"starting", "running", "warm", "stopping"}


class WorkspaceStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.lock = threading.RLock()
        self._owner_fd: int | None = None
        self._db: sqlite3.Connection | None = None
        root_fd = _open_private_root(self.root)
        try:
            if fcntl is None:
                raise WorkspaceError(
                    "platform_unsupported", "Local locking requires POSIX", status=503
                )
            fd = os.open(
                ".workspace.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
            try:
                _check_private(fd, directory=False)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BaseException:
                os.close(fd)
                raise
            self._owner_fd = fd
            # Refuse unsafe existing database/sidecars before sqlite opens any.
            for filename in (
                "workspace.sqlite3",
                "workspace.sqlite3-journal",
                "workspace.sqlite3-wal",
                "workspace.sqlite3-shm",
            ):
                if filename != "workspace.sqlite3":
                    try:
                        os.stat(filename, dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if filename == "workspace.sqlite3":
                    flags |= os.O_CREAT
                file_fd = os.open(filename, flags, 0o600, dir_fd=root_fd)
                try:
                    _check_private(file_fd, directory=False)
                finally:
                    os.close(file_fd)
            self._db = sqlite3.connect(
                self.root / "workspace.sqlite3", check_same_thread=False, isolation_level=None
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=3000")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._initialize()
            self.profiles = ProfileStore(self.root / "profiles")
        except BaseException:
            self.close()
            raise
        finally:
            os.close(root_fd)

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            raise WorkspaceError("workspace_closed", "This workspace is closed", status=503)
        return self._db

    def _initialize(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3):
            raise WorkspaceError(
                "schema_unsupported", "Unsupported local metadata version", status=503
            )
        self.db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, preset_id TEXT NOT NULL,
                engine_id TEXT NOT NULL, favorite INTEGER NOT NULL DEFAULT 0,
                revision INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL DEFAULT 'stopped',
                last_selected_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                blockers TEXT NOT NULL DEFAULT '[]', generation INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operations (
                key TEXT PRIMARY KEY, profile_id TEXT NOT NULL, action TEXT NOT NULL,
                outcome TEXT NOT NULL, created_at TEXT NOT NULL
            );
            COMMIT;
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(profiles)")}
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if "network_policy" not in columns:
                self.db.execute(
                    "ALTER TABLE profiles ADD COLUMN network_policy TEXT NOT NULL DEFAULT 'unconfigured'"
                )
            if "origin" not in columns:
                self.db.execute(
                    "ALTER TABLE profiles ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'"
                )
            # Purely local display labels and untrusted proxy metadata. Defaults
            # preserve old profiles' network and runtime admission behavior.
            for name, default in (
                ("icon_preset", "browser"),
                ("custom_icon_data_url", ""),
                ("assignment_label", ""),
                ("proxy_config", "null"),
            ):
                if name not in columns:
                    self.db.execute(
                        f"ALTER TABLE profiles ADD COLUMN {name} TEXT NOT NULL DEFAULT '{default}'"
                    )
            self.db.execute("PRAGMA user_version=3")
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        defaults = {
            "selected_profile_id": None,
            "settings": {
                "revision": 1,
                "max_warm_profiles": 3,
                "memory_budget_mb": 2048,
                "estimated_profile_mb": 512,
                **LAYOUT_DEFAULTS,
            },
            "managed_connection": {
                "revision": 1,
                "server_url": None,
                "status": "not_enrolled",
                "authenticated": False,
            },
        }
        for key, value in defaults.items():
            self.db.execute(
                "INSERT OR IGNORE INTO metadata VALUES (?, ?)", (key, json.dumps(value))
            )
        # A detached browser may still exist. Never silently relabel it stopped.
        self.db.execute(
            "UPDATE profiles SET state='recovery_required', revision=revision+1, "
            "updated_at=?, blockers=? WHERE state IN ('starting','running','warm','stopping')",
            (
                now_iso(),
                json.dumps(
                    [
                        "The previous supervisor ended unexpectedly. "
                        "Process lifetime must be verified before another launch."
                    ]
                ),
            ),
        )
        self.db.execute("UPDATE operations SET outcome='interrupted' WHERE outcome='pending'")

    def close(self) -> None:
        with self.lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._owner_fd is not None:
                os.close(self._owner_fd)
                self._owner_fd = None

    def metadata(self, key: str) -> Any:
        with self.lock:
            value = json.loads(
                self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0]
            )
            # Older stores inherit explicit local presentation defaults without
            # rewriting their revision or enabling opt-in mirroring.
            return {**LAYOUT_DEFAULTS, **value} if key == "settings" else value

    def set_metadata(self, key: str, value: Any) -> None:
        with self.lock:
            self.db.execute("UPDATE metadata SET value=? WHERE key=?", (json.dumps(value), key))

    def selected(self) -> str | None:
        return self.metadata("selected_profile_id")

    def _profile(self, row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["favorite"] = bool(value["favorite"])
        value["selected"] = value["id"] == self.selected()
        value["blockers"] = json.loads(value["blockers"])
        value["proxy_config"] = json.loads(value["proxy_config"])
        return value

    def get(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            try:
                validate_identifier(profile_id)
            except ValueError:
                raise WorkspaceError("not_found", "Profile not found", status=404) from None
            row = self.db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if row is None:
                raise WorkspaceError("not_found", "Profile not found", status=404)
            return self._profile(row)

    def list_profiles(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM profiles ORDER BY created_at ASC, id ASC"
            ).fetchall()
            return [self._profile(row) for row in rows]

    @staticmethod
    def preset(preset_id: str) -> dict[str, str]:
        for preset in PRESETS:
            if preset["id"] == preset_id:
                return dict(preset)
        raise WorkspaceError("preset_not_found", "Preset not found", status=422)

    @staticmethod
    def require_revision(profile: dict[str, Any], revision: int | None) -> None:
        if revision is not None and profile["revision"] != revision:
            raise WorkspaceError(
                "revision_conflict",
                "This item changed. Refresh and try again.",
                current_revision=profile["revision"],
            )

    def create(
        self,
        name: str,
        preset_id: str = "standard",
        favorite: bool = False,
        network_policy: str = "unconfigured",
        icon_preset: str = "browser",
        custom_icon_data_url: str = "",
        assignment_label: str = "",
        proxy_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            preset = self.preset(preset_id)
            if network_policy not in {"unconfigured", "local_direct", "verified_proxy"}:
                raise WorkspaceError(
                    "invalid_network_policy", "Unsupported network policy", status=422
                )
            try:
                metadata = ProfileCreate(
                    name=name,
                    preset_id=preset_id,
                    favorite=favorite,
                    network_policy=network_policy,
                    icon_preset=icon_preset,
                    custom_icon_data_url=custom_icon_data_url,
                    assignment_label=assignment_label,
                    proxy_config=proxy_config,
                ).model_dump()
            except ValidationError:
                raise WorkspaceError(
                    "invalid_profile_configuration", "Invalid profile configuration", status=422
                ) from None
            profile_id, timestamp = "local_" + uuid.uuid4().hex, now_iso()
            self.profiles.prepare(profile_id)
            self.db.execute(
                "INSERT INTO profiles(id,name,preset_id,engine_id,favorite,created_at,updated_at,"
                "network_policy,icon_preset,custom_icon_data_url,assignment_label,proxy_config) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    profile_id,
                    metadata["name"],
                    preset_id,
                    preset["engine_id"],
                    int(favorite),
                    timestamp,
                    timestamp,
                    network_policy,
                    metadata["icon_preset"],
                    metadata["custom_icon_data_url"],
                    metadata["assignment_label"],
                    json.dumps(metadata["proxy_config"]),
                ),
            )
            return self.get(profile_id)

    def update(self, profile_id: str, expected_revision: int, **changes: Any) -> dict[str, Any]:
        with self.lock:
            profile = self.get(profile_id)
            self.require_revision(profile, expected_revision)
            if not set(changes).issubset(ProfileCreate.model_fields):
                raise ValueError("Unsupported profile fields")
            if "network_policy" in changes:
                if changes["network_policy"] not in {
                    "unconfigured",
                    "local_direct",
                    "verified_proxy",
                }:
                    raise WorkspaceError(
                        "invalid_network_policy", "Unsupported network policy", status=422
                    )
                if profile["origin"] == "managed" and changes["network_policy"] != "verified_proxy":
                    raise WorkspaceError(
                        "proxy_required", "Managed profiles require a verified proxy"
                    )
            if {"preset_id", "network_policy", "proxy_config"} & changes.keys():
                if profile["state"] in ACTIVE_STATES | {"recovery_required"}:
                    raise WorkspaceError(
                        "profile_in_use",
                        "Stop and verify the profile before changing engines or network configuration",
                    )
            try:
                changes = ProfilePatch(expected_revision=expected_revision, **changes).model_dump(
                    exclude_unset=True, exclude={"expected_revision"}
                )
                candidate = {key: profile[key] for key in ProfileCreate.model_fields}
                candidate.update(changes)
                normalized = ProfileCreate(**candidate).model_dump()
                changes = {key: normalized[key] for key in changes}
            except ValidationError:
                raise WorkspaceError(
                    "invalid_profile_configuration", "Invalid profile configuration", status=422
                ) from None
            if "preset_id" in changes:
                changes["engine_id"] = self.preset(changes["preset_id"])["engine_id"]
            return self._change(profile_id, **changes)

    def _change(self, profile_id: str, **changes: Any) -> dict[str, Any]:
        # Only internal code reaches this helper. No arbitrary SQL columns from API.
        allowed = {
            "name",
            "preset_id",
            "engine_id",
            "favorite",
            "state",
            "last_selected_at",
            "blockers",
            "generation",
            "network_policy",
            "icon_preset",
            "custom_icon_data_url",
            "assignment_label",
            "proxy_config",
        }
        if not changes or not set(changes).issubset(allowed):
            raise ValueError("Unsupported lifecycle fields")
        with self.lock:
            self.get(profile_id)
            if "blockers" in changes:
                changes["blockers"] = json.dumps(changes["blockers"])
            if "proxy_config" in changes:
                changes["proxy_config"] = json.dumps(changes["proxy_config"])
            columns = ", ".join(key + "=?" for key in changes)
            self.db.execute(
                f"UPDATE profiles SET {columns}, revision=revision+1, updated_at=? WHERE id=?",
                (*changes.values(), now_iso(), profile_id),
            )
            return self.get(profile_id)

    def delete(self, profile_id: str, expected_revision: int) -> None:
        with self.lock:
            profile = self.get(profile_id)
            self.require_revision(profile, expected_revision)
            if profile["state"] in ACTIVE_STATES | {"recovery_required"}:
                raise WorkspaceError(
                    "profile_in_use", "Stop and verify the profile before removing it"
                )
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
                if self.selected() == profile_id:
                    self.set_metadata("selected_profile_id", None)
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            # Deliberately retain browser data. This route removes metadata only.
            # Data wiping requires its own approved, recoverable workflow.
