"""Source guards for rendered CI; these do not establish browser acceptance."""

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RenderedBrowserContractTests(unittest.TestCase):
    def test_browser_launch_is_explicit_sandboxed_system_chrome_without_fallback(self):
        tree = ast.parse((ROOT / "e2e/test_local_browser.py").read_text())
        launches = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "launch"
        ]
        self.assertEqual(len(launches), 1)
        launch = launches[0]
        self.assertEqual(ast.unparse(launch.func), "cls.playwright.chromium.launch")
        self.assertEqual(launch.args, [])
        self.assertEqual(
            {keyword.arg: ast.literal_eval(keyword.value) for keyword in launch.keywords},
            {"headless": True, "channel": "chrome", "chromium_sandbox": True},
        )
        setup = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "setUpClass"
        )
        # A failed launch must propagate, not be caught and converted to a skip
        # or a retry using a weaker runtime.
        self.assertTrue(any(
            isinstance(node, ast.Assign) and node.value is launch for node in setup.body
        ))

    def test_workflow_uses_existing_runner_browser_and_preserves_video_dependency(self):
        workflow = (ROOT / ".github/workflows/browser.yml").read_text()
        runner_lines = [line.strip() for line in workflow.splitlines() if "runs-on:" in line]
        self.assertEqual(runner_lines, ["runs-on: ubuntu-24.04"])
        self.assertIn("- run: google-chrome --version", workflow)
        self.assertIn("- run: python -m playwright install ffmpeg", workflow)
        self.assertIn("playwright==1.62.0", workflow)
        self.assertIn("TBM_RUN_BROWSER_TESTS: '1'", workflow)
        self.assertIn("path: artifacts/browser", workflow)
        for forbidden in (
            "--no-sandbox", "--disable-setuid-sandbox", "sysctl", "sudo",
            "apparmor_parser", "chmod", "continue-on-error", "--with-deps chromium",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_rendered_suite_remains_opt_in_and_records_video(self):
        source = (ROOT / "e2e/test_local_browser.py").read_text()
        self.assertIn('os.getenv("TBM_RUN_BROWSER_TESTS") == "1"', source)
        self.assertIn('record_video_dir=str(self.artifacts / "raw-video")', source)
        self.assertNotIn("--no-sandbox", source)
        self.assertNotIn("--disable-setuid-sandbox", source)


if __name__ == "__main__":
    unittest.main()
