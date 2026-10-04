"""Fixed loopback bridge contracts with no native/provider activity."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from team_browser.client.app import create_local_app
from team_browser.client.auth_flow import entra_native_configuration
from team_browser.client.managed_host import NativeManagedHost, unconfigured_snapshot
from team_browser.client.managed_session import TrustedBackendConfiguration
from team_browser.local.macos_keychain import KeychainConfiguration


class ManagedBridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "workspace"

    def client(self, host=None):
        app = create_local_app(self.root, managed_host=host)
        client = self.enterContext(
            TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 43111))
        )
        self.headers = {
            "Origin": "http://127.0.0.1:8765",
            "X-Local-CSRF": client.get("/local/config").json()["csrf_token"],
        }
        return client

    def host(self):
        oidc = entra_native_configuration(
            tenant_id="11111111-1111-4111-8111-111111111111",
            desktop_client_id="33333333-3333-4333-8333-333333333333",
            api_client_id="22222222-2222-4222-8222-222222222222",
        )
        return NativeManagedHost(
            oidc,
            TrustedBackendConfiguration("https://api.example.test", oidc),
            KeychainConfiguration("ABCDEFGHIJ", "test.example.TeamBrowser", "managed-signin"),
        )

    def test_default_snapshot_is_unconfigured_and_secret_free(self):
        client = self.client()
        response = client.get("/local/v1/managed-native")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["configured"])
        self.assertFalse(data["managed_access_available"])
        self.assertEqual(data["profiles"], [])
        self.assertEqual(data["presets"], [])
        self.assertEqual(response.headers["cache-control"], "no-store")
        for key in ("access_token", "id_token", "session_id", "authorization_url", "backend_url"):
            self.assertNotIn(key, data)

    def test_unconfigured_action_cannot_activate_a_fake_adapter(self):
        client = self.client()
        response = client.post(
            "/local/v1/managed-native/actions", headers=self.headers, json={"action": "sign_in"}
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"]["code"], "managed_unconfigured")

    def test_only_exact_trusted_host_is_accepted(self):
        with self.assertRaises(TypeError):
            create_local_app(self.root, managed_host=object())

    def test_routes_require_loopback_origin_and_csrf(self):
        client = self.client()
        for headers in (
            {},
            {**self.headers, "Origin": "https://other.example.test"},
            {**self.headers, "Host": "other.example.test"},
        ):
            with self.subTest(headers=tuple(headers)):
                self.assertEqual(
                    client.post(
                        "/local/v1/managed-native/actions",
                        headers=headers,
                        json={"action": "prepare"},
                    ).status_code,
                    403,
                )

    def test_action_has_no_configuration_or_token_input(self):
        client = self.client()
        bodies = [
            {"action": "get_token"},
            {"action": "prepare", "server_url": "https://other.example.test"},
            {"action": "sign_in", "scopes": ["mail.read"]},
            {"action": "sign_out", "session_id": "SYNTHETIC"},
        ]
        for body in bodies:
            with self.subTest(body=tuple(body)):
                self.assertEqual(
                    client.post(
                        "/local/v1/managed-native/actions", headers=self.headers, json=body
                    ).status_code,
                    422,
                )

    def test_fixed_dispatch_passes_no_arguments_and_no_native_io(self):
        host = self.host()
        with (
            patch.object(host, "prepare", return_value=unconfigured_snapshot()) as prepare,
            patch.object(host, "shutdown", return_value=unconfigured_snapshot()),
        ):
            client = self.client(host)
            response = client.post(
                "/local/v1/managed-native/actions", headers=self.headers, json={"action": "prepare"}
            )
            self.assertEqual(response.status_code, 200)
            prepare.assert_called_once_with()

    def test_ui_config_contains_only_fixed_bridge_paths(self):
        client = self.client()
        data = client.get("/local/config").json()["managed_native"]
        self.assertEqual(
            data,
            {
                "supported": True,
                "configured": False,
                "status_path": "/local/v1/managed-native",
                "actions_path": "/local/v1/managed-native/actions",
            },
        )
