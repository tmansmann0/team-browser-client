"""Public Camoufox setup UI contract; no browser or native acceptance is run."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(shutil.which("node"), "Node required for setup source/DOM tests")
class FrontendCamoufoxSetupTests(unittest.TestCase):
    def test_camoufox_setup_source_dom_scenarios(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["node", "tests/frontend_camoufox_setup.cjs"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_actual_unconfigured_local_bridge_matches_ui_contract(self):
        from fastapi.testclient import TestClient

        from team_browser import client_cli

        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch(
                    "sys.argv", ["tbm-client", "--workspace", str(Path(directory) / "workspace")]
                ),
                patch.object(client_cli.uvicorn, "run") as serve,
            ):
                client_cli.main()
            app = serve.call_args.args[0]
            with TestClient(
                app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)
            ) as client:
                config = client.get("/local/config").json()
                profile_response = client.post(
                    "/local/v1/profiles",
                    headers={"X-Local-CSRF": config["csrf_token"]},
                    json={"name": "Setup contract fixture", "preset_id": "isolated"},
                )
                self.assertEqual(profile_response.status_code, 201)
                profile = profile_response.json()
                overview = client.get("/local/v1/camoufox-setup").json()
                snapshot = client.get(f"/local/v1/profiles/{profile['id']}/camoufox-setup").json()
                page = client.get("/")
                self.assertEqual(page.status_code, 200)
                self.assertIn("./camoufox_setup.js", page.text)
                asset = client.get("/preview/camoufox_setup.js")
                self.assertEqual(asset.status_code, 200)
                self.assertIn("TeamCamoufoxSetup", asset.text)
                self.assertIn("script-src 'self'", asset.headers["content-security-policy"])
                self.assertFalse(overview["configured"])
                self.assertFalse(snapshot["admission_acknowledged"])
                self.assertFalse(snapshot["launch_available"])
                self.assertEqual(profile["network_policy"], "unconfigured")
                script = """
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const window = {};
vm.runInNewContext(fs.readFileSync('src/team_browser/static/camoufox_setup.js', 'utf8'),
  {window});
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const overview = window.TeamCamoufoxSetup.runtimeSnapshot(data.overview);
const setup = window.TeamCamoufoxSetup.profileSnapshot(data.snapshot, data.profile);
assert.equal(overview.configured, false);
assert.equal(setup.state, 'unavailable');
assert.equal(setup.launch_available, false);
console.log('PASS: actual unconfigured bridge matches UI contract; no native execution.');
"""
                result = subprocess.run(
                    ["node", "-e", script],
                    cwd=root,
                    input=json.dumps(
                        {"overview": overview, "snapshot": snapshot, "profile": profile}
                    ),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS", result.stdout)
