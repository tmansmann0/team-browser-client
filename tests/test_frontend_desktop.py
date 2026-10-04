"""Desktop frontend source contracts; no native runtime or rendered-browser QA."""

from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node required for desktop frontend source contracts")
class FrontendDesktopTests(unittest.TestCase):
    def test_desktop_frontend_regressions(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["node", "tests/frontend_desktop_regressions.cjs"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)
