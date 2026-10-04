"""Pure smoke-runner contract tests. The real browser check is an opt-in CLI."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from team_browser.local.smoke import (
    CHROMIUM,
    SYNTHETIC_PAGE,
    UNSHARE,
    SmokeBlocked,
    _browser_command,
    _check_system_tool,
    _environment,
    _namespace_command,
    run_smoke,
)


class LocalSmokeTests(unittest.TestCase):
    def test_command_is_offline_and_retains_sandbox(self) -> None:
        root = Path("/tmp/synthetic-test-root")
        command = _browser_command(root)
        self.assertEqual(
            command[:7],
            [
                str(UNSHARE),
                "--user",
                "--map-current-user",
                "--net",
                "--",
                str(CHROMIUM),
                "--headless=new",
            ],
        )
        self.assertEqual(command[-1], "file:///tmp/synthetic-test-root/synthetic.html")
        self.assertIn("--user-data-dir=/tmp/synthetic-test-root/profile", command)
        for flag in (
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-web-security",
            "--ignore-certificate-errors",
            "--remote-debugging-port",
        ):
            self.assertFalse(any(arg == flag or arg.startswith(flag + "=") for arg in command))

    def test_namespace_is_always_present(self) -> None:
        self.assertIn("--net", _namespace_command())
        self.assertIn("--user", _namespace_command())

    def test_environment_does_not_inherit_tokens_home_or_proxy_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.dict(
                "os.environ",
                {
                    "HOME": "/sensitive-home",
                    "API_TOKEN": "synthetic-token",
                    "HTTP_PROXY": "http://outside.invalid",
                },
            ):
                env = _environment(root)
            self.assertEqual(env["HOME"], str(root / "home"))
            self.assertNotIn("API_TOKEN", env)
            self.assertNotIn("HTTP_PROXY", env)
            self.assertNotIn("DISPLAY", env)
            self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", env)
            self.assertEqual((root / "runtime").stat().st_mode & 0o777, 0o700)

    def test_generated_page_has_no_external_resources(self) -> None:
        self.assertIn("default-src 'none'", SYNTHETIC_PAGE)
        self.assertIn("connect-src 'none'", SYNTHETIC_PAGE)
        self.assertNotIn("http://", SYNTHETIC_PAGE)
        self.assertNotIn("https://", SYNTHETIC_PAGE)
        self.assertIn("localStorage.setItem", SYNTHETIC_PAGE)

    def test_arbitrary_executable_is_rejected(self) -> None:
        with self.assertRaises(SmokeBlocked):
            _check_system_tool(Path("/tmp/untrusted-browser"))

    def test_root_execution_is_rejected(self) -> None:
        with patch("os.getuid", return_value=0), self.assertRaises(SmokeBlocked):
            run_smoke()

    def test_non_linux_is_rejected(self) -> None:
        with patch("sys.platform", "darwin"), self.assertRaises(SmokeBlocked):
            run_smoke()

    def test_synthetic_success_requires_two_distinct_persistent_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "not-an-executable.txt"
            fixture.write_bytes(b"synthetic hash fixture, never executed")
            with (
                patch("team_browser.local.smoke.CHROMIUM", fixture),
                patch("team_browser.local.smoke._check_system_tool"),
                patch("team_browser.local.smoke._run") as runner,
            ):
                runner.side_effect = [
                    "Chromium synthetic-test-version",
                    '<p id="result">TBM_SMOKE_VISIT_1</p>',
                    '<p id="result">TBM_SMOKE_VISIT_2</p>',
                ]
                result = run_smoke()
                self.assertTrue(result.passed)
                self.assertTrue(result.temporary_data_removed)
                self.assertFalse(result.production_launch_enabled)
                self.assertFalse(result.chromium_sandbox_disabled)
                self.assertEqual(runner.call_count, 3)
                self.assertEqual(runner.call_args_list[1].args[0], runner.call_args_list[2].args[0])
                self.assertFalse(runner.call_args.args[2].exists())

    def test_real_child_failure_is_reported_and_temporary_data_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "not-an-executable.txt"
            fixture.write_bytes(b"synthetic hash fixture, never executed")
            with (
                patch("team_browser.local.smoke.CHROMIUM", fixture),
                patch("team_browser.local.smoke._check_system_tool"),
                patch("team_browser.local.smoke._run") as runner,
            ):
                runner.side_effect = [
                    "Chromium synthetic-test-version",
                    SmokeBlocked("synthetic socket denial"),
                ]
                with self.assertRaisesRegex(SmokeBlocked, "synthetic socket denial"):
                    run_smoke()
                self.assertFalse(runner.call_args.args[2].exists())

    def test_second_first_visit_does_not_pass_persistence_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "not-an-executable.txt"
            fixture.write_bytes(b"synthetic hash fixture, never executed")
            with (
                patch("team_browser.local.smoke.CHROMIUM", fixture),
                patch("team_browser.local.smoke._check_system_tool"),
                patch("team_browser.local.smoke._run") as runner,
            ):
                runner.side_effect = [
                    "Chromium synthetic-test-version",
                    '<p id="result">TBM_SMOKE_VISIT_1</p>',
                    '<p id="result">TBM_SMOKE_VISIT_1</p>',
                ]
                with self.assertRaisesRegex(SmokeBlocked, "did not retain"):
                    run_smoke()
