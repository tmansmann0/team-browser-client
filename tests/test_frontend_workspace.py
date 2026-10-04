"""Public local workspace UI contract scenarios; this is not rendered-browser QA."""

from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node required for source-level workspace scenarios")
class FrontendWorkspaceTests(unittest.TestCase):
    def test_local_workspace_scenarios(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["node", "tests/frontend_workspace.cjs"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_native_tab_ui_scenarios(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["node", "tests/frontend_tabs.cjs"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)
