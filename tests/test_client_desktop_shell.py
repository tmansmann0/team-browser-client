"""Desktop transport and route contracts only; no Electron/native browser launch."""

import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from fastapi.testclient import TestClient

from team_browser.client.app import create_local_app
from team_browser.client_cli import mount_workspace
from team_browser.desktop_sidecar import (
    DesktopCapabilityGate,
    read_capability,
    watch_owner,
    mount_desktop_ownership,
)

TOKEN = "a" * 64
OWNER_TOKEN = "b" * 64


class DesktopBootstrapTests(unittest.TestCase):
    def test_reads_only_fixed_bounded_private_pipe_protocol(self):
        raw = (
            json.dumps({"protocol": 1, "token": TOKEN, "owner_token": OWNER_TOKEN}).encode()
            + b"\nstop\n"
        )
        stream = io.BytesIO(raw)
        self.assertEqual(read_capability(stream), (TOKEN, OWNER_TOKEN))
        self.assertEqual(stream.read(), b"stop\n")

    def test_rejects_malformed_missing_extra_and_unbounded_input(self):
        values = [
            b"",
            b"{",
            b"a" * 513,
            b"{}\n",
            b"[]\n",
            json.dumps({"protocol": True, "token": TOKEN}).encode() + b"\n",
            json.dumps({"protocol": 1, "token": TOKEN, "path": "/tmp"}).encode() + b"\n",
            json.dumps({"protocol": 1, "token": "x" * 64}).encode() + b"\n",
            json.dumps({"protocol": 1, "token": TOKEN, "owner_token": OWNER_TOKEN}).encode(),
        ]
        for raw in values:
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                read_capability(io.BytesIO(raw))

    def test_owner_eof_stop_and_invalid_command_all_request_shutdown(self):
        for data in [b"", b"stop\n", b"arbitrary action\n", b"x" * 600]:
            stop = threading.Event()
            watch_owner(io.BytesIO(data), stop)
            self.assertTrue(stop.is_set())


class DesktopGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS exposes its temporary directory through the system /var symlink.
        # Canonicalize only this owned test fixture; production rejects symlinks.
        self.root = Path(self.temp.name).resolve(strict=True)
        self.app = mount_desktop_ownership(
            mount_workspace(create_local_app(self.root / "workspace"), desktop=True)
        )
        self.client = self.enterContext(
            TestClient(
                DesktopCapabilityGate(self.app, TOKEN, OWNER_TOKEN),
                base_url="http://127.0.0.1:8765",
                client=("127.0.0.1", 15001),
            )
        )
        self.headers = {"X-TBM-Desktop-Token": TOKEN}

    def test_static_config_health_and_root_require_desktop_session(self):
        for path in ["/", "/app/", "/preview/", "/local/config", "/healthz"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 403)
                response = self.client.get(path, headers=self.headers)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(TOKEN, response.text)
        self.assertEqual(self.client.get("/", headers=self.headers).url.path, "/app/")
        self.assertTrue(
            self.client.get("/local/config", headers=self.headers).json()["desktop_shell"]
        )

    def test_capability_does_not_replace_host_origin_or_csrf_checks(self):
        self.assertEqual(
            self.client.get("/healthz", headers={**self.headers, "Host": "evil.test"}).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(
                "/healthz", headers={**self.headers, "Origin": "https://evil.test"}
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/local/v1/profiles", headers=self.headers, json={"name": "Fixture"}
            ).status_code,
            403,
        )
        config = self.client.get("/local/config", headers=self.headers).json()
        response = self.client.post(
            "/local/v1/profiles",
            headers={**self.headers, "X-Local-CSRF": config["csrf_token"]},
            json={"name": "Fixture"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertFalse(config["launch"]["actual_process_available"])

    def test_duplicate_or_wrong_capability_is_rejected(self):
        for headers in [
            {"X-TBM-Desktop-Token": "b" * 64},
            [("x-tbm-desktop-token", TOKEN), ("x-tbm-desktop-token", TOKEN)],
        ]:
            self.assertEqual(self.client.get("/healthz", headers=headers).status_code, 403)

    def test_no_secret_is_forwarded_to_application(self):

        observed = []

        async def app(scope, receive, send):
            if scope["type"] == "http":
                observed.extend(scope["headers"])
                await send({"type": "http.response.start", "status": 204, "headers": []})
                await send({"type": "http.response.body", "body": b""})

        client = TestClient(DesktopCapabilityGate(app, TOKEN, OWNER_TOKEN))
        client.get("/", headers=self.headers)
        self.assertFalse(any(k == b"x-tbm-desktop-token" for k, _ in observed))

    def create_desktop(self):
        profile = self.app.state.workspace.create(
            "Integrated fixture", preset_id="desktop", network_policy="local_direct"
        )
        csrf = self.client.get("/local/config", headers=self.headers).json()["csrf_token"]
        owner = {"X-TBM-Desktop-Token": OWNER_TOKEN, "X-Local-CSRF": csrf}
        return profile, owner

    def test_main_owner_claim_blocks_metadata_route_changes_and_release_restores_editing(self):
        profile, owner = self.create_desktop()
        path = f"/desktop/v1/profiles/{profile['id']}"
        body = {"expected_revision": profile["revision"]}
        denied = self.client.post(
            path + "/claim", headers={**owner, "X-TBM-Desktop-Token": TOKEN}, json=body
        )
        self.assertEqual(denied.status_code, 403)
        response = self.client.post(path + "/claim", headers=owner, json=body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "running")
        from team_browser.client.store import WorkspaceError

        with self.assertRaises(WorkspaceError):
            self.app.state.workspace.update(
                profile["id"], response.json()["revision"], network_policy="unconfigured"
            )
        self.assertEqual(
            self.client.post(path + "/release", headers=owner, json={}).json()["state"], "stopped"
        )
        self.assertFalse(self.app.state.desktop_leases.leases)
        self.assertEqual(
            self.client.post(path + "/release", headers=owner, json={}).json()["state"], "stopped"
        )

    def test_non_embeddable_and_unconfigured_profiles_cannot_be_claimed(self):
        profile, owner = self.create_desktop()
        for preset, network in [
            ("standard", "local_direct"),
            ("isolated", "local_direct"),
            ("desktop", "unconfigured"),
        ]:
            item = self.app.state.workspace.create(
                "Blocked", preset_id=preset, network_policy=network
            )
            result = self.client.post(
                f"/desktop/v1/profiles/{item['id']}/claim",
                headers=owner,
                json={"expected_revision": item["revision"]},
            )
            self.assertEqual(result.status_code, 409)

    def test_abandoned_claim_remains_recovery_required_not_stopped(self):
        profile, _owner = self.create_desktop()
        registry = self.app.state.desktop_leases
        registry.claim(profile["id"], profile["revision"])
        registry.abandon()
        self.assertEqual(self.app.state.workspace.get(profile["id"])["state"], "recovery_required")

    def test_normal_lifecycle_api_cannot_fake_stopped_embedded_profile(self):
        profile, owner = self.create_desktop()
        claimed = self.app.state.desktop_leases.claim(profile["id"], profile["revision"])
        result = self.client.post(
            f"/local/v1/profiles/{profile['id']}/actions",
            headers={**owner, "X-TBM-Desktop-Token": TOKEN},
            json={"action": "stop", "expected_revision": claimed["revision"]},
        )
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.app.state.workspace.get(profile["id"])["state"], "running")
        self.app.state.desktop_leases.release(profile["id"])

    def test_embedded_capacity_uses_explicit_limit_not_legacy_ram_estimate(self):
        store = self.app.state.workspace
        settings = store.metadata("settings")
        store.set_metadata("settings", {**settings, "max_warm_profiles": 5})
        registry = self.app.state.desktop_leases
        for index in range(5):
            profile = store.create(
                f"Embedded {index}", preset_id="desktop", network_policy="local_direct"
            )
            registry.claim(profile["id"], profile["revision"])
        self.assertEqual(len(registry.leases), 5)
        profile = store.create("Sixth", preset_id="desktop", network_policy="local_direct")
        from team_browser.client.store import WorkspaceError

        with self.assertRaises(WorkspaceError) as caught:
            registry.claim(profile["id"], profile["revision"])
        self.assertEqual(caught.exception.code, "budget_exceeded")
        for profile_id in list(registry.leases):
            registry.release(profile_id)

    def test_plain_cli_mount_does_not_claim_desktop(self):
        app = mount_workspace(create_local_app(self.root / "other"))
        with TestClient(
            app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 12000)
        ) as client:
            self.assertFalse(client.get("/local/config").json()["desktop_shell"])
            self.assertEqual(client.get("/").url.path, "/preview/")
            self.assertEqual(client.get("/app/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
