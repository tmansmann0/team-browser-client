"""Local-only profile metadata, durable order and fail-closed configuration tests."""

import base64
import json
import sqlite3
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from team_browser.client import (
    LifecycleCoordinator,
    WorkspaceError,
    WorkspaceStore,
    create_local_app,
)
from team_browser.client.models import MAX_ICON_BYTES, ProfileCreate, ProxyConfig


def data_url(mime, raw):
    return f"data:image/{mime};base64," + base64.b64encode(raw).decode()


def png(width=1, height=1, extra=b""):
    def chunk(kind, data):
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + (chunk(b"tEXt", extra) if extra else b"")
        + chunk(b"IDAT", zlib.compress(b"\0\xff\xff\xff"))
        + chunk(b"IEND", b"")
    )


PNG_URL = data_url("png", png())
# Static 1x1 white raster fixtures generated with ImageMagick, no external data.
JPEG_URL = "data:image/jpeg;base64," + (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkK"
    "DA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAA"
    "AAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AVN//2Q=="
)
WEBP_URL = "data:image/webp;base64,UklGRiQAAABXRUJQVlA4IBgAAAAwAQCdASoBAAEAAgA0JaQAA3AA/vuUAAA="
PROXY = {"protocol": "https", "hostname": "proxy.example", "port": 443, "label": "Work route"}


class ProfileConfigurationModelTests(unittest.TestCase):
    def test_named_icons_and_bounded_rasters(self):
        for icon in ("browser", "facebook", "google_ads", "youtube"):
            with self.subTest(icon=icon):
                self.assertEqual(ProfileCreate(name="Local", icon_preset=icon).icon_preset, icon)
        for icon in (PNG_URL, JPEG_URL, WEBP_URL):
            with self.subTest(mime=icon.split(";")[0]):
                profile = ProfileCreate(
                    name="Local", icon_preset="custom", custom_icon_data_url=icon
                )
                self.assertEqual(profile.custom_icon_data_url, icon)

    def test_remote_active_mislabeled_corrupt_and_oversized_icons_rejected(self):
        invalid = (
            "https://images.example/icon.png",
            "file:///tmp/icon.png",
            data_url("svg+xml", b"<svg onload='alert(1)'/>"),
            data_url("png", b"<svg onload='alert(1)'/>"),
            data_url("jpeg", png()),
            data_url("png", png()[:-1]),
            data_url("png", png() + b"<script>"),
            data_url("png", png(1025, 1)),
            data_url("png", png(1, 1025)),
            data_url("png", png(0, 1)),
            data_url("png", png(extra=b"x" * MAX_ICON_BYTES)),
            "data:image/png;base64,AA===",
            "data:image/png;base64,",
            PNG_URL.replace(";base64,", ";charset=utf-8;base64,"),
        )
        for value in invalid:
            with self.subTest(prefix=value[:60]), self.assertRaises(ValidationError):
                ProfileCreate(name="Local", icon_preset="custom", custom_icon_data_url=value)

    def test_custom_icon_metadata_must_be_coherent(self):
        for fields in (
            {"icon_preset": "custom"},
            {"icon_preset": "facebook", "custom_icon_data_url": PNG_URL},
            {"icon_preset": "safari"},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                ProfileCreate(name="Local", **fields)

    def test_jpeg_webp_headers_and_dimensions_are_bounded(self):
        jpeg = bytearray(base64.b64decode(JPEG_URL.split(",")[1]))
        marker = jpeg.index(b"\xff\xc0")
        jpeg[marker + 5 : marker + 7] = struct.pack(">H", 1025)
        webp = bytearray(base64.b64decode(WEBP_URL.split(",")[1]))
        webp[26:28] = struct.pack("<H", 1025)
        extended_without_image = b"VP8X" + struct.pack("<I", 10) + b"\0" * 10
        riff = b"RIFF" + struct.pack("<I", len(extended_without_image) + 4) + b"WEBP"
        for value in (
            data_url("jpeg", jpeg),
            data_url("webp", webp),
            data_url("webp", riff + extended_without_image),
            data_url("webp", base64.b64decode(WEBP_URL.split(",")[1]) + b"trailing"),
        ):
            with self.subTest(prefix=value[:50]), self.assertRaises(ValidationError):
                ProfileCreate(name="Local", icon_preset="custom", custom_icon_data_url=value)

    def test_truncated_raster_headers_never_raise_unhandled_exceptions(self):
        for value in (PNG_URL, JPEG_URL, WEBP_URL):
            header, content = value.split(",")
            raw = base64.b64decode(content)
            for end in range(len(raw)):
                truncated = header + "," + base64.b64encode(raw[:end]).decode()
                with self.subTest(header=header, end=end), self.assertRaises(ValidationError):
                    ProfileCreate(
                        name="Local", icon_preset="custom", custom_icon_data_url=truncated
                    )

    def test_proxy_metadata_has_no_credentials_or_urls(self):
        for hostname in (
            "https://proxy.example",
            "user:secret@proxy.example",
            "proxy.example:443",
            "proxy.example/path",
            "proxy.example?token=secret",
            "proxy.example#fragment",
            "proxy .example",
            "proxy\n.example",
            "fe80::1%eth0",
            "-proxy.example",
            "proxy.example..",
            "a" * 64 + ".example",
        ):
            with self.subTest(hostname=hostname), self.assertRaises(ValidationError):
                ProxyConfig(**{**PROXY, "hostname": hostname})
        for extra in ("username", "password", "token", "credentials", "verified", "active"):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                ProxyConfig(**PROXY, **{extra: "not-accepted"})
        for port in (0, 65536, True, "443"):
            with self.subTest(port=port), self.assertRaises(ValidationError):
                ProxyConfig(**{**PROXY, "port": port})

    def test_proxy_metadata_protocol_hosts_and_normalization(self):
        for protocol in ("http", "https", "socks5"):
            self.assertEqual(ProxyConfig(**{**PROXY, "protocol": protocol}).protocol, protocol)
        for host in ("127.0.0.1", "2001:db8::1", "localhost"):
            self.assertEqual(ProxyConfig(**{**PROXY, "hostname": host}).hostname, host)
        self.assertEqual(
            ProxyConfig(**{**PROXY, "hostname": "PROXY.Example"}).hostname, "proxy.example"
        )
        with self.assertRaises(ValidationError):
            ProxyConfig(**{**PROXY, "protocol": "ftp"})

    def test_no_arbitrary_browser_identity_or_permission_fields(self):
        for fields in (
            {"user_agent": "Chrome on Firefox"},
            {"engine_id": "safari"},
            {"identity_request": {"locale": "en-US"}},
            {"assignee_id": "admin"},
            {"team_access": True},
            {"origin": "managed"},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                ProfileCreate(name="Local", **fields)

    def test_labels_cannot_contain_control_characters(self):
        for label in ("one\ntwo", "one\rtwo", "one\ttwo", "one\x7ftwo", "x" * 121):
            with self.subTest(label=label), self.assertRaises(ValidationError):
                ProfileCreate(name="Local", assignment_label=label)


class ProfileConfigurationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        self.store = WorkspaceStore(self.root)
        self.addCleanup(self.store.close)

    def test_defaults_do_not_enable_networking_or_team_access(self):
        p = self.store.create("Default")
        self.assertEqual(p["icon_preset"], "browser")
        self.assertEqual(p["custom_icon_data_url"], "")
        self.assertEqual(p["assignment_label"], "")
        self.assertIsNone(p["proxy_config"])
        self.assertEqual(p["network_policy"], "unconfigured")
        self.assertEqual(p["origin"], "local")

    def test_desktop_engine_is_explicit_and_distinct_from_legacy_adapters(self):
        p = self.store.create("Built-in", preset_id="desktop")
        self.assertEqual(p["engine_id"], "electron_chromium")
        self.assertEqual(self.store.preset("desktop")["name"], "Built-in Chromium")
        legacy = self.store.create("Legacy")
        self.assertEqual(legacy["engine_id"], "chromium")
        changed = self.store.update(legacy["id"], legacy["revision"], preset_id="desktop")
        self.assertEqual(changed["engine_id"], "electron_chromium")
        for unsupported in ("safari", "firefox", "chrome_on_firefox"):
            with self.subTest(preset=unsupported), self.assertRaises(WorkspaceError):
                self.store.create("Invalid", preset_id=unsupported)

    def test_all_metadata_survives_restart_and_update_is_revision_bound(self):
        p = self.store.create(
            "Local",
            preset_id="isolated",
            icon_preset="custom",
            custom_icon_data_url=PNG_URL,
            assignment_label="Design team",
            network_policy="verified_proxy",
            proxy_config=PROXY,
        )
        self.assertEqual(p["engine_id"], "camoufox")
        self.store.close()
        self.store = WorkspaceStore(self.root)
        self.addCleanup(self.store.close)
        restored = self.store.get(p["id"])
        self.assertEqual(restored, p)
        updated = self.store.update(p["id"], p["revision"], assignment_label="Campaigns")
        self.assertEqual(updated["assignment_label"], "Campaigns")
        self.assertEqual(updated["origin"], "local")
        with self.assertRaises(WorkspaceError) as caught:
            self.store.update(p["id"], p["revision"], assignment_label="Old change")
        self.assertEqual(caught.exception.code, "revision_conflict")

    def test_selection_favorite_rename_and_restart_never_reorder_profiles(self):
        profiles = [self.store.create(name) for name in ("One", "Two", "Three")]
        expected = [p["id"] for p in profiles]
        coordinator = LifecycleCoordinator(self.store)
        self.addCleanup(coordinator.shutdown)
        for p in reversed(profiles):
            coordinator.action(p["id"], "select")
            self.assertEqual([p["id"] for p in self.store.list_profiles()], expected)
        for p in reversed(profiles):
            current = self.store.get(p["id"])
            self.store.update(p["id"], current["revision"], favorite=True, name="Renamed")
            self.assertEqual([p["id"] for p in self.store.list_profiles()], expected)
        coordinator.shutdown()
        self.store.close()
        self.store = WorkspaceStore(self.root)
        self.addCleanup(self.store.close)
        self.assertEqual([p["id"] for p in self.store.list_profiles()], expected)

    def test_equal_creation_times_have_stable_id_tiebreaker(self):
        with patch("team_browser.client.store.now_iso", return_value="2026-10-04T16:00:00+00:00"):
            profiles = [self.store.create(str(index)) for index in range(4)]
        self.assertEqual(
            [p["id"] for p in self.store.list_profiles()], sorted(p["id"] for p in profiles)
        )

    def test_proxy_requires_explicit_policy_and_clearing_before_direct(self):
        for policy in ("local_direct", "unconfigured"):
            with self.subTest(policy=policy), self.assertRaises(WorkspaceError):
                self.store.create("Invalid", network_policy=policy, proxy_config=PROXY)
        p = self.store.create("Route", network_policy="verified_proxy", proxy_config=PROXY)
        with self.assertRaises(WorkspaceError):
            self.store.update(p["id"], p["revision"], network_policy="local_direct")
        self.assertEqual(self.store.get(p["id"]), p)
        p = self.store.update(
            p["id"], p["revision"], network_policy="local_direct", proxy_config=None
        )
        self.assertIsNone(p["proxy_config"])
        self.assertEqual(p["network_policy"], "local_direct")

    def test_proxy_and_engine_edits_blocked_during_process_or_unknown_recovery(self):
        for state in ("starting", "running", "warm", "stopping", "recovery_required"):
            p = self.store.create("Busy", network_policy="verified_proxy", proxy_config=PROXY)
            p = self.store._change(p["id"], state=state)
            for changes in (
                {"proxy_config": {**PROXY, "port": 8443}},
                {"proxy_config": None},
                {"preset_id": "isolated"},
                {"network_policy": "local_direct", "proxy_config": None},
            ):
                with (
                    self.subTest(state=state, changes=changes),
                    self.assertRaises(WorkspaceError) as caught,
                ):
                    self.store.update(p["id"], p["revision"], **changes)
                self.assertEqual(caught.exception.code, "profile_in_use")
            # Pure display metadata does not grant access or mutate runtime state.
            updated = self.store.update(p["id"], p["revision"], assignment_label="Local label")
            self.assertEqual(updated["state"], state)

    def test_custom_icon_update_and_removal_are_atomic(self):
        p = self.store.create("Custom", icon_preset="custom", custom_icon_data_url=PNG_URL)
        with self.assertRaises(WorkspaceError):
            self.store.update(p["id"], p["revision"], icon_preset="youtube")
        self.assertEqual(self.store.get(p["id"]), p)
        updated = self.store.update(
            p["id"], p["revision"], icon_preset="youtube", custom_icon_data_url=""
        )
        self.assertEqual(updated["icon_preset"], "youtube")
        self.assertEqual(updated["custom_icon_data_url"], "")

    def test_store_callers_cannot_bypass_configuration_validation(self):
        p = self.store.create("Local")
        for changes in (
            {"assignment_label": "bad\nlabel"},
            {"custom_icon_data_url": "https://images.example/x.png", "icon_preset": "custom"},
            {"proxy_config": {**PROXY, "password": "not-accepted"}},
            {"icon_preset": "invalid"},
            {"favorite": "true"},
        ):
            with self.subTest(changes=changes), self.assertRaises(WorkspaceError):
                self.store.update(p["id"], p["revision"], **changes)
            self.assertEqual(self.store.get(p["id"]), p)


class ProfileConfigurationMigrationTests(unittest.TestCase):
    def test_legacy_versions_migrate_without_granting_network_or_changing_revisions(self):
        for version in (0, 1, 2):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "workspace"
                root.mkdir(mode=0o700)
                database = root / "workspace.sqlite3"
                with sqlite3.connect(database) as db:
                    db.executescript("""
                        CREATE TABLE profiles (
                            id TEXT PRIMARY KEY, name TEXT NOT NULL, preset_id TEXT NOT NULL,
                            engine_id TEXT NOT NULL, favorite INTEGER NOT NULL DEFAULT 0,
                            revision INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL DEFAULT 'stopped',
                            last_selected_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                            blockers TEXT NOT NULL DEFAULT '[]', generation INTEGER NOT NULL DEFAULT 0
                        );
                        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    """)
                    if version == 2:
                        db.execute(
                            "ALTER TABLE profiles ADD COLUMN network_policy TEXT NOT NULL DEFAULT 'unconfigured'"
                        )
                        db.execute(
                            "ALTER TABLE profiles ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'"
                        )
                    db.execute(
                        "INSERT INTO profiles(id,name,preset_id,engine_id,favorite,revision,created_at,updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (
                            "local_legacy",
                            "Legacy",
                            "standard",
                            "chromium",
                            1,
                            7,
                            "2026-01-01",
                            "2026-01-02",
                        ),
                    )
                    db.execute(
                        "INSERT INTO metadata VALUES (?,?)",
                        ("selected_profile_id", json.dumps("local_legacy")),
                    )
                    if version == 2:
                        db.execute("UPDATE profiles SET network_policy='local_direct'")
                    db.execute(f"PRAGMA user_version={version}")
                database.chmod(0o600)
                store = WorkspaceStore(root)
                try:
                    p = store.get("local_legacy")
                    self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 3)
                    self.assertEqual(p["revision"], 7)
                    self.assertTrue(p["selected"])
                    self.assertTrue(p["favorite"])
                    self.assertEqual(
                        p["network_policy"], "local_direct" if version == 2 else "unconfigured"
                    )
                    self.assertEqual(p["origin"], "local")
                    self.assertEqual(p["assignment_label"], "")
                    self.assertEqual(p["icon_preset"], "browser")
                    self.assertEqual(p["custom_icon_data_url"], "")
                    self.assertIsNone(p["proxy_config"])
                finally:
                    store.close()


class NoLaunchAdapter:
    execution_kind = "synthetic"

    def __init__(self):
        self.starts = 0

    def blockers(self, profile):
        return ()

    def start(self, context):
        self.starts += 1
        raise AssertionError("Configuration metadata must never authorize launch")


class ProfileConfigurationAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.adapter = NoLaunchAdapter()
        self.app = create_local_app(
            Path(self.temp.name) / "workspace", process_adapter=self.adapter
        )
        self.client = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
        )
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.headers = {"X-Local-CSRF": self.client.get("/local/config").json()["csrf_token"]}

    def test_proxy_save_is_metadata_only_and_start_remains_blocked(self):
        with patch("socket.create_connection", side_effect=AssertionError("No network allowed")):
            response = self.client.post(
                "/local/v1/profiles",
                headers=self.headers,
                json={"name": "Proxy", "network_policy": "verified_proxy", "proxy_config": PROXY},
            )
        self.assertEqual(response.status_code, 201, response.text)
        p = response.json()
        self.assertEqual(p["proxy_config"], PROXY)
        self.assertEqual(p["state"], "stopped")
        self.assertEqual(p["origin"], "local")
        result = self.client.post(
            f"/local/v1/profiles/{p['id']}/actions",
            headers=self.headers,
            json={"action": "start", "expected_revision": p["revision"]},
        )
        self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(result.json()["detail"]["code"], "engine_unavailable")
        self.assertTrue(any("not active" in b for b in result.json()["detail"]["blockers"]))
        self.assertEqual(self.adapter.starts, 0)

    def test_desktop_profile_is_not_launched_through_python_native_adapter(self):
        p = self.client.post(
            "/local/v1/profiles",
            headers=self.headers,
            json={"name": "Desktop", "preset_id": "desktop", "network_policy": "local_direct"},
        ).json()
        self.assertEqual(p["engine_id"], "electron_chromium")
        result = self.client.post(
            f"/local/v1/profiles/{p['id']}/actions",
            headers=self.headers,
            json={"action": "start", "expected_revision": p["revision"]},
        )
        self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(result.json()["detail"]["code"], "engine_unavailable")
        self.assertTrue(any("desktop app" in b for b in result.json()["detail"]["blockers"]))
        self.assertEqual(self.adapter.starts, 0)

    def test_proxy_null_clears_metadata_without_relaxing_policy_implicitly(self):
        p = self.client.post(
            "/local/v1/profiles",
            headers=self.headers,
            json={"name": "Proxy", "network_policy": "verified_proxy", "proxy_config": PROXY},
        ).json()
        cleared = self.client.patch(
            f"/local/v1/profiles/{p['id']}",
            headers=self.headers,
            json={"expected_revision": p["revision"], "proxy_config": None},
        )
        self.assertEqual(cleared.status_code, 200, cleared.text)
        self.assertIsNone(cleared.json()["proxy_config"])
        self.assertEqual(cleared.json()["network_policy"], "verified_proxy")

    def test_api_rejects_proxy_secrets_and_direct_config_mismatch(self):
        for fields in (
            {"proxy_config": PROXY, "network_policy": "local_direct"},
            {"proxy_config": PROXY},
            {
                "proxy_config": {**PROXY, "password": "not-accepted"},
                "network_policy": "verified_proxy",
            },
            {"assignment_label": None},
            {"icon_preset": "custom", "custom_icon_data_url": "https://images.example/x.png"},
            {"user_agent": "fake"},
        ):
            with self.subTest(fields=fields):
                response = self.client.post(
                    "/local/v1/profiles", headers=self.headers, json={"name": "Invalid", **fields}
                )
                self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.client.get("/local/v1/profiles").json(), [])
