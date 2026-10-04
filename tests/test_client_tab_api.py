"""Fixed loopback tab contracts; no native browser is executed."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from team_browser.client import create_local_app, WorkspaceStore


class TabAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        self.app = create_local_app(self.root)
        self.client = TestClient(
            self.app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50100)
        )
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.headers = {"X-Local-CSRF": self.client.get("/local/config").json()["csrf_token"]}
        self.body = {"tab_id": "tab_" + "a" * 32, "generation": 1, "expected_revision": 1}

    def test_tab_read_has_no_fabricated_profiles(self):
        response = self.client.get("/local/v1/tabs")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "no_selection")
        self.assertEqual(response.json()["tabs"], [])
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_focus_requires_loopback_origin_csrf(self):
        path = "/local/v1/profiles/local_a/tab-focus"
        self.assertEqual(self.client.post(path, json=self.body).status_code, 403)
        self.assertEqual(
            self.client.post(
                path,
                json=self.body,
                headers={**self.headers, "Origin": "https://outside.example.test"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                path, json=self.body, headers={**self.headers, "Host": "outside.example.test"}
            ).status_code,
            403,
        )

    def test_focus_exact_model_and_no_script_url_inputs(self):
        invalid = [
            {**self.body, "url": "https://example.test"},
            {**self.body, "javascript": "alert(1)"},
            {**self.body, "generation": True},
            {**self.body, "generation": "1"},
            {**self.body, "expected_revision": None},
            {**self.body, "tab_id": "https://example.test"},
            {**self.body, "tab_id": self.body["tab_id"] + "\n"},
        ]
        with patch.object(self.app.state.coordinator, "focus_tab") as focus:
            for body in invalid:
                with self.subTest(body=body):
                    self.assertEqual(
                        self.client.post(
                            "/local/v1/profiles/local_a/tab-focus", json=body, headers=self.headers
                        ).status_code,
                        422,
                    )
            focus.assert_not_called()

    def test_focus_only_passes_fixed_typed_binding_and_reports_queued(self):
        result = {"profile_id": "local_a", **self.body, "outcome": "queued"}
        with patch.object(self.app.state.coordinator, "focus_tab", return_value=result) as focus:
            response = self.client.post(
                "/local/v1/profiles/local_a/tab-focus", json=self.body, headers=self.headers
            )
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["outcome"], "queued")
            focus.assert_called_once_with("local_a", **self.body)

    def test_defaults_and_durable_layout_only_settings(self):
        settings = self.client.get("/local/v1/settings").json()
        self.assertEqual(
            (
                settings["profile_navigation"],
                settings["tab_navigation"],
                settings["mirror_same_origin"],
            ),
            ("sidebar", "top", False),
        )
        response = self.client.patch(
            "/local/v1/settings",
            headers=self.headers,
            json={
                "expected_revision": settings["revision"],
                "profile_navigation": "grid",
                "tab_navigation": "side",
                "mirror_same_origin": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.app.state.workspace.close()
        store = WorkspaceStore(self.root)
        self.addCleanup(store.close)
        saved = store.metadata("settings")
        self.assertEqual(
            (saved["profile_navigation"], saved["tab_navigation"], saved["mirror_same_origin"]),
            ("grid", "side", True),
        )

    def test_layout_rejects_null_and_unrecognized_values(self):
        for values in (
            {"mirror_same_origin": "true"},
            {"mirror_same_origin": 1},
            {"mirror_same_origin": None},
            {"tab_navigation": "iframe"},
            {"profile_navigation": "remote"},
        ):
            self.assertEqual(
                self.client.patch(
                    "/local/v1/settings",
                    headers=self.headers,
                    json={"expected_revision": 1, **values},
                ).status_code,
                422,
            )
