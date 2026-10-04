"""Local client API/security tests. No account, browser or network credentials."""

import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from team_browser.client import WorkspaceStore, create_local_app
from team_browser.local import UnsafePathError


def crash_workspace(root: str) -> None:
    store = WorkspaceStore(Path(root))
    profile = store.create("Crash fixture")
    store._change(profile["id"], state="running")
    os._exit(0)


class WorkspaceAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "workspace"
        self.app = create_local_app(self.root)
        self.client = self.make_client(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.csrf = self.client.get("/local/config").json()["csrf_token"]

    @staticmethod
    def make_client(app, *, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)):
        return TestClient(app, base_url=base_url, client=client)

    def call(self, method, path, **kwargs):
        headers = {"X-Local-CSRF": self.csrf, **kwargs.pop("headers", {})}
        return self.client.request(method, path, headers=headers, **kwargs)

    def profile(self, name="My local profile"):
        response = self.call("POST", "/local/v1/profiles", json={"name": name})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_no_manager_account_required_and_no_seeded_people(self):
        config = self.client.get("/local/config").json()
        self.assertEqual(config["mode"], "local")
        self.assertFalse(config["account_required"])
        self.assertTrue(config["persistent"])
        self.assertEqual(self.client.get("/local/v1/profiles").json(), [])
        self.assertFalse(config["launch"]["available"])
        self.assertFalse(config["launch"]["actual_process_available"])
        self.assertFalse(config["inbox"]["native_open_available"])
        self.assertEqual(config["managed"]["status"], "not_enrolled")

    def test_crud_revision_selection_and_restart_durability(self):
        p = self.profile()
        path = "/local/v1/profiles/" + p["id"]
        selected = self.call("POST", path + "/actions", json={"action": "select"})
        self.assertTrue(selected.json()["profile"]["selected"])
        p = selected.json()["profile"]
        self.assertIsNotNone(p["last_selected_at"])
        edited = self.call(
            "PATCH",
            path,
            json={"expected_revision": p["revision"], "name": "Renamed", "favorite": True},
        )
        self.assertEqual(edited.status_code, 200, edited.text)
        self.assertTrue(edited.json()["favorite"])
        stale = self.call("PATCH", path, json={"expected_revision": p["revision"], "name": "Stale"})
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "revision_conflict")
        self.app.state.workspace.close()
        reopened = WorkspaceStore(self.root)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get(p["id"])["name"], "Renamed")
        self.assertTrue(reopened.get(p["id"])["selected"])
        self.assertTrue(reopened.get(p["id"])["favorite"])

    def test_remove_retains_data_and_clears_selection(self):
        p = self.profile()
        path = "/local/v1/profiles/" + p["id"]
        p = self.call("POST", path + "/actions", json={"action": "select"}).json()["profile"]
        data = self.root / "profiles" / p["id"] / "browser-data"
        self.assertTrue(data.is_dir())
        stale = self.call("DELETE", path + "?expected_revision=1")
        self.assertEqual(stale.status_code, 409)
        removed = self.call("DELETE", path + f"?expected_revision={p['revision']}")
        self.assertEqual(removed.status_code, 204, removed.text)
        self.assertEqual(self.client.get(path).status_code, 404)
        self.assertIsNone(self.client.get("/local/config").json()["selected_profile_id"])
        self.assertTrue(data.is_dir())

    def test_launch_is_fail_closed_and_selection_still_works(self):
        p = self.profile()
        path = "/local/v1/profiles/" + p["id"] + "/actions"
        response = self.call(
            "POST", path, json={"action": "start", "expected_revision": p["revision"]}
        )
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["detail"]["code"], "engine_unavailable")
        blocked = response.json()["detail"]["profile"]
        self.assertEqual(blocked["state"], "blocked")
        self.assertGreaterEqual(len(blocked["blockers"]), 2)
        selected = self.call("POST", path, json={"action": "select"})
        self.assertEqual(selected.status_code, 200)
        self.assertTrue(selected.json()["profile"]["selected"])
        self.assertEqual(selected.json()["profile"]["state"], "blocked")

    def test_gmail_intent_is_revision_bound_fixed_and_native_blocked(self):
        p = self.profile()
        path = "/local/v1/profiles/" + p["id"] + "/actions"
        for body in (
            {"action": "start", "intent": "gmail"},
            {"action": "start", "intent": "https://evil.example", "expected_revision": 1},
            {
                "action": "start",
                "intent": "gmail",
                "expected_revision": 1,
                "url": "https://evil.example",
            },
            {"action": "select", "intent": "gmail", "expected_revision": 1},
        ):
            with self.subTest(body=body):
                self.assertEqual(self.call("POST", path, json=body).status_code, 422)
        blocked = self.call(
            "POST", path, json={"action": "start", "intent": "gmail", "expected_revision": 1}
        )
        self.assertEqual(blocked.status_code, 409)
        self.assertEqual(blocked.json()["detail"]["code"], "engine_unavailable")
        stale = self.call(
            "POST", path, json={"action": "start", "intent": "gmail", "expected_revision": 1}
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "revision_conflict")
        inbox = self.client.get("/local/config").json()["inbox"]
        self.assertIsNone(inbox["unread_threads"])
        self.assertEqual(inbox["identity_status"], "unverified")
        self.assertEqual(inbox["gmail_target"], "https://mail.google.com/mail/u/0/#inbox")

    def test_non_ascii_csrf_is_rejected_without_server_error(self):
        response = self.client.post(
            "/local/v1/profiles", json={"name": "No token"}, headers={b"X-Local-CSRF": b"\xff\xfe"}
        )
        self.assertEqual(response.status_code, 403)

    def test_metadata_never_authenticates_or_contacts_company(self):
        with patch("socket.create_connection", side_effect=AssertionError("Network not allowed")):
            response = self.call(
                "PUT",
                "/local/v1/managed-connection",
                json={"expected_revision": 1, "server_url": "https://company.example"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "not_enrolled")
        self.assertFalse(response.json()["authenticated"])
        for data in (
            {"server_url": "https://user:password@company.example"},
            {"server_url": "http://company.example"},
            {"server_url": "https://company.example/?secret=test"},
            {"server_url": "https://company.example/path"},
            {"server_url": "https://company.example", "shared_key": "not-a-secret"},
            {"server_url": "https://company.example", "authenticated": True},
        ):
            with self.subTest(data=data):
                self.assertEqual(
                    self.call(
                        "PUT", "/local/v1/managed-connection", json={"expected_revision": 2, **data}
                    ).status_code,
                    422,
                )

    def test_budget_strict_validation_and_conflicts(self):
        settings = self.client.get("/local/v1/settings").json()
        self.assertEqual(settings["effective_capacity"], 3)
        result = self.call(
            "PATCH",
            "/local/v1/settings",
            json={
                "expected_revision": settings["revision"],
                "max_warm_profiles": 2,
                "memory_budget_mb": 1024,
            },
        )
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["effective_capacity"], 2)
        self.assertEqual(result.json()["memory_measurement"], "estimate_only")
        self.assertEqual(
            self.call(
                "PATCH", "/local/v1/settings", json={"expected_revision": 1, "max_warm_profiles": 1}
            ).status_code,
            409,
        )
        for changes in (
            {"max_warm_profiles": 0},
            {"max_warm_profiles": "3"},
            {"max_warm_profiles": True},
            {"estimated_profile_mb": None},
            {"memory_budget_mb": 256, "estimated_profile_mb": 512},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    self.call(
                        "PATCH", "/local/v1/settings", json={"expected_revision": 2, **changes}
                    ).status_code,
                    422,
                )

    def test_no_paths_commands_secrets_or_cookie_fields_accepted(self):
        for extra in (
            "id",
            "browser_data",
            "executable",
            "argv",
            "password",
            "proxy_password",
            "cookies",
            "engine_id",
            "account_email",
            "launch_allowed",
        ):
            with self.subTest(extra=extra):
                response = self.call(
                    "POST",
                    "/local/v1/profiles",
                    json={"name": "Safety fixture", extra: "forbidden"},
                )
                self.assertEqual(response.status_code, 422)
        for name in (" ", "x\nscript", "x" * 121):
            self.assertEqual(
                self.call("POST", "/local/v1/profiles", json={"name": name}).status_code, 422
            )
        self.assertEqual(
            self.call(
                "POST", "/local/v1/profiles", json={"name": "Valid", "preset_id": "../escape"}
            ).status_code,
            422,
        )

    def test_csrf_host_origin_and_client_address_guards(self):
        self.assertEqual(
            self.client.post("/local/v1/profiles", json={"name": "No token"}).status_code, 403
        )
        for headers in (
            {"Host": "evil.example:8765"},
            {"Host": "localhost:9999"},
            {"Origin": "https://evil.example"},
            {"Origin": "null"},
            {"Origin": "http://localhost:8765"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.get("/local/config", headers=headers).status_code, 403)
        self.assertEqual(
            self.client.get(
                "/local/config", headers={"Origin": "http://127.0.0.1:8765"}
            ).status_code,
            200,
        )
        remote = self.make_client(self.app, client=("192.0.2.1", 33333))
        self.assertEqual(remote.get("/local/config").status_code, 403)
        remote_with_forwarded = remote.get(
            "/local/config", headers={"X-Forwarded-For": "127.0.0.1"}
        )
        self.assertEqual(remote_with_forwarded.status_code, 403)
        response = self.client.get("/local/config")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", response.headers)
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    def test_csrf_regenerated_on_restart_not_written_to_disk(self):
        self.profile()
        self.assertNotIn(self.csrf.encode(), (self.root / "workspace.sqlite3").read_bytes())
        self.app.state.workspace.close()
        restarted = create_local_app(self.root)
        self.addCleanup(restarted.state.workspace.close)
        token = self.make_client(restarted).get("/local/config").json()["csrf_token"]
        self.assertNotEqual(token, self.csrf)
        rejected = self.make_client(restarted).post(
            "/local/v1/profiles", headers={"X-Local-CSRF": self.csrf}, json={"name": "Old page"}
        )
        self.assertEqual(rejected.status_code, 403)

    def test_conflicting_concurrent_edits_only_one_wins(self):
        p = self.profile()
        store = self.app.state.workspace

        def edit(name):
            try:
                return store.update(p["id"], 1, name=name)["name"]
            except Exception as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(edit, ("A", "B")))
        self.assertEqual(outcomes.count("revision_conflict"), 1)
        self.assertEqual(store.get(p["id"])["revision"], 2)


class WorkspaceDiskSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "workspace"

    def test_all_owned_directories_and_metadata_are_private(self):
        store = WorkspaceStore(self.root)
        self.addCleanup(store.close)
        p = store.create("Private fixture")
        for path in (
            self.root,
            self.root / "profiles",
            self.root / "profiles" / p["id"],
            self.root / "profiles" / p["id"] / "browser-data",
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for filename in ("workspace.sqlite3", ".workspace.lock"):
            self.assertEqual(stat.S_IMODE((self.root / filename).stat().st_mode), 0o600)

    def test_exclusive_workspace_lock(self):
        first = WorkspaceStore(self.root)
        self.addCleanup(first.close)
        with self.assertRaises(BlockingIOError):
            WorkspaceStore(self.root)
        first.close()
        second = WorkspaceStore(self.root)
        second.close()

    def test_unsafe_root_symlink_and_database_links_refused(self):
        self.root.mkdir(mode=0o700)
        target = self.root.parent / "outside"
        target.write_text("unchanged")
        target.chmod(0o600)
        database = self.root / "workspace.sqlite3"
        database.symlink_to(target)
        with self.assertRaises((UnsafePathError, OSError)):
            WorkspaceStore(self.root)
        self.assertEqual(target.read_text(), "unchanged")
        database.unlink()
        os.link(target, database)
        with self.assertRaises(UnsafePathError):
            WorkspaceStore(self.root)
        self.assertEqual(target.read_text(), "unchanged")

    def test_database_sidecar_link_refused(self):
        self.root.mkdir(mode=0o700)
        target = self.root.parent / "outside"
        target.write_text("unchanged")
        (self.root / "workspace.sqlite3-journal").symlink_to(target)
        with self.assertRaises((UnsafePathError, OSError)):
            WorkspaceStore(self.root)
        self.assertEqual(target.read_text(), "unchanged")

    def test_crash_recovery_never_claims_unknown_browser_stopped(self):
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=crash_workspace, args=(str(self.root),))
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("Crash fixture hung")
        self.assertEqual(process.exitcode, 0)
        store = WorkspaceStore(self.root)
        self.addCleanup(store.close)
        p = store.list_profiles()[0]
        self.assertEqual(p["state"], "recovery_required")
        self.assertIn("previous supervisor", p["blockers"][0])
        contents = json.dumps(p)
        self.assertNotIn('"pid"', contents)
