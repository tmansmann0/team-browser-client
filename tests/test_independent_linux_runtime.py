"""Independent Debian inventory checks against disposable synthetic databases.

These tests invoke only the existing system dpkg/dpkg-query inspection commands.
They do not install packages, execute a browser, inspect browser profiles, or
produce successful production runtime approval. All package files are inert
fixture bytes under a temporary root. The injected runner can redirect only
the implementation's fixed inspection arguments to that temporary root.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from team_browser.client import linux_runtime as linux
from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimePolicy


VERSIONS = {f"{name}:amd64": "1.0-1" for name in sorted(linux.PACKAGE_NAMES)}
PAYLOADS = {
    "chromium": ("usr/lib/chromium/chromium",),
    "chromium-common": ("usr/lib/chromium/libEGL.so", "usr/lib/chromium/resources.pak"),
    "chromium-sandbox": ("usr/lib/chromium/chrome-sandbox",),
}
TOOLS_AVAILABLE = sys.platform == "linux" and all(
    path.is_file() and os.access(path, os.X_OK) for path in (linux.DPKG, linux.QUERY)
)


@unittest.skipUnless(TOOLS_AVAILABLE, "Existing Linux dpkg inspection tools are required")
class IndependentDpkgCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tbm-dpkg-independent-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "var/lib/dpkg"
        self.info = self.database / "info"
        self.info.mkdir(parents=True)
        records = []
        for package, names in PAYLOADS.items():
            records.append(
                f"Package: {package}\n"
                "Status: install ok installed\n"
                "Priority: optional\n"
                "Section: misc\n"
                "Installed-Size: 1\n"
                "Maintainer: Test Fixture <fixture@example.invalid>\n"
                "Architecture: amd64\n"
                "Version: 1.0-1\n"
                "Description: inert synthetic inventory; never executable\n\n"
            )
            checksums = []
            for name in names:
                payload = self.root / name
                payload.parent.mkdir(parents=True, exist_ok=True)
                payload.write_bytes(b"\x7fELFinert test data: " + name.encode())
                checksum = hashlib.md5(payload.read_bytes(), usedforsecurity=False).hexdigest()
                checksums.append(f"{checksum}  {name}\n")
            self.control(package, "md5sums").write_text("".join(checksums))
            self.control(package, "list").write_text(
                "/.\n/usr\n/usr/lib\n/usr/lib/chromium\n" + "".join(f"/{name}\n" for name in names)
            )
        (self.database / "status").write_text("".join(records))
        self.commands = []

    def control(self, package, name):
        return self.info / f"{package}.{name}"

    def command(self, tool, *args):
        self.assertIn(tool, (linux.DPKG, linux.QUERY))
        return subprocess.run(
            [str(tool), f"--root={self.root}", f"--admindir={self.database}", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=10,
            check=False,
            shell=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
        )

    def fixture_runner(self, command, **kwargs):
        """Map only fixed package verification to the fixture, never execute payloads."""
        self.assertEqual(
            command[:3],
            [str(linux.DPKG), "--root=/", f"--admindir={linux.DATABASE}"],
        )
        arguments = command[3:]
        self.assertIn(arguments, (["--verify", name] for name in VERSIONS))
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["cwd"], "/")
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.commands.append(tuple(command))
        return self.command(linux.DPKG, *arguments)

    def assert_clean(self, result):
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_clean_inspection_only_fixture(self):
        for package in VERSIONS:
            with self.subTest(package=package):
                self.assert_clean(self.command(linux.DPKG, "--verify", package))

    def test_changed_payload_can_report_success_exit_with_failure_output(self):
        payload = self.root / PAYLOADS["chromium-common"][0]
        payload.write_bytes(b"modified inert fixture")
        result = self.command(linux.DPKG, "--verify", "chromium-common:amd64")
        self.assertEqual(result.returncode, 0)
        self.assertIn("5", result.stdout.split()[0])
        self.assertIn("/usr/lib/chromium/libEGL.so", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_deleted_payload_can_report_success_exit_with_failure_output(self):
        (self.root / PAYLOADS["chromium-sandbox"][0]).unlink()
        result = self.command(linux.DPKG, "--verify", "chromium-sandbox:amd64")
        self.assertEqual(result.returncode, 0)
        self.assertIn("missing", result.stdout)
        self.assertIn("/usr/lib/chromium/chrome-sandbox", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_missing_checksums_can_report_empty_success(self):
        self.control("chromium-common", "md5sums").unlink()
        (self.root / PAYLOADS["chromium-common"][0]).write_bytes(b"modified inert fixture")
        self.assert_clean(self.command(linux.DPKG, "--verify", "chromium-common:amd64"))
        query = self.command(linux.QUERY, "--control-show", "chromium-common:amd64", "md5sums")
        self.assertNotEqual(query.returncode, 0)

    def test_empty_file_list_skips_even_present_checksum_entries(self):
        self.control("chromium-common", "list").write_text("")
        (self.root / PAYLOADS["chromium-common"][0]).write_bytes(b"modified inert fixture")
        checksums = self.command(linux.QUERY, "--control-show", "chromium-common:amd64", "md5sums")
        self.assertEqual(len(linux._manifest(checksums.stdout)), 2)
        self.assert_clean(self.command(linux.DPKG, "--verify", "chromium-common:amd64"))

    def test_incomplete_file_list_skips_unlisted_changed_payload(self):
        self.control("chromium-common", "list").write_text("/usr/lib/chromium/resources.pak\n")
        (self.root / PAYLOADS["chromium-common"][0]).write_bytes(b"modified inert fixture")
        self.assert_clean(self.command(linux.DPKG, "--verify", "chromium-common:amd64"))
        listing = self.command(linux.QUERY, "--listfiles", "chromium-common:amd64")
        self.assertEqual(listing.stdout.splitlines(), ["/usr/lib/chromium/resources.pak"])

    def test_production_query_format_is_understood_by_real_dpkg_query(self):
        # Extract the actual argument rather than repeating a supposedly correct
        # copy. Doubled dpkg escape sequences previously passed fake-runner tests.
        tree = ast.parse(textwrap.dedent(inspect.getsource(linux.LinuxPackageRuntimeGate.observe)))
        formats = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("--showformat=")
        ]
        self.assertEqual(len(formats), 1)
        result = self.command(linux.QUERY, "--show", formats[0], "chromium:amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            result.stdout.splitlines(), ["chromium", "amd64", "1.0-1", "installed", "ok"]
        )

    def test_control_file_apis_and_exact_ownership(self):
        for package in PAYLOADS:
            with self.subTest(package=package):
                located = self.command(linux.QUERY, "--control-path", package + ":amd64", "md5sums")
                self.assertEqual(located.returncode, 0, located.stderr)
                self.assertEqual(located.stdout, str(self.control(package, "md5sums")) + "\n")
                sums = self.command(linux.QUERY, "--control-show", package + ":amd64", "md5sums")
                self.assertEqual(set(linux._manifest(sums.stdout)), set(PAYLOADS[package]))
        owner = self.command(linux.QUERY, "--search", "/usr/lib/chromium/chromium")
        self.assertEqual(owner.stdout, "chromium: /usr/lib/chromium/chromium\n")

    def test_internal_file_list_is_not_a_control_path(self):
        # The .list exists, but it is not part of the package control archive.
        # A production observer must derive its validated metadata sibling path
        # rather than assume --control-path can return this internal inventory.
        for package in PAYLOADS:
            with self.subTest(package=package):
                self.assertTrue(self.control(package, "list").is_file())
                result = self.command(linux.QUERY, "--control-path", package + ":amd64", "list")
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def observation_runner(self, command, **kwargs):
        """Real query parsing, with only fixed logical paths translated to fixtures."""
        self.assertEqual(
            command[:3],
            [str(linux.QUERY), "--root=/", f"--admindir={linux.DATABASE}"],
        )
        args = command[3:]
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        if args[0] == "--show":
            self.assertEqual(len(args), 3)
            self.assertTrue(args[1].startswith("--showformat="))
            self.assertIn(args[2], VERSIONS)
        elif args[0] in {"--control-path", "--control-show"}:
            self.assertEqual(len(args), 3)
            self.assertIn(args[1], VERSIONS)
            self.assertIn(args[2], {"md5sums", "list"})
        elif args[0] == "--listfiles":
            self.assertEqual(len(args), 2)
            self.assertIn(args[1], VERSIONS)
        else:
            self.assertEqual(args, ["--search", str(linux.CHROMIUM)])
        result = self.command(linux.QUERY, *args)
        # A test-only namespace translation preserves the real tool's data and
        # parsing semantics while avoiding any use of the machine's package DB.
        if args[0] == "--control-path" and result.stdout:
            actual = Path(result.stdout.rstrip("\n"))
            relative = actual.relative_to(self.root)
            result.stdout = str(Path("/") / relative) + "\n"
        return result

    def observe_fixture(self):
        """Read metadata only; no successful runtime gate or process launch."""
        checked = []
        gate = linux.LinuxPackageRuntimeGate(
            VERSIONS,
            runner=self.observation_runner,
            path_checker=lambda path, **_kwargs: checked.append(Path(path)),
        )
        real_open, real_access = os.open, os.access

        def fixture_open(path, *args, **kwargs):
            if Path(path) == linux.CHROMIUM:
                return real_open(self.root / PAYLOADS["chromium"][0], *args, **kwargs)
            return real_open(path, *args, **kwargs)

        def fixture_access(path, mode, **kwargs):
            if Path(path) == linux.CHROMIUM:
                return True
            return real_access(path, mode, **kwargs)

        with (
            patch.object(linux.os, "open", side_effect=fixture_open),
            patch.object(linux.os, "access", side_effect=fixture_access),
            patch.object(linux.os, "geteuid", return_value=1000),
        ):
            metadata = gate.observe(linux.CHROMIUM)
        return metadata, checked

    def test_observer_parses_real_query_results_and_checks_payload_paths(self):
        metadata, checked = self.observe_fixture()
        self.assertEqual(metadata.version, "1.0-1")
        self.assertEqual(len(metadata.package_inventory), 3)
        for package, names in PAYLOADS.items():
            self.assertIn(linux.DATABASE / "info" / f"{package}.list", checked)
            for name in names:
                self.assertIn(Path("/") / name, checked)

    def test_observer_rejects_real_empty_or_incomplete_file_inventory(self):
        for listing in ("", "/usr/lib/chromium/resources.pak\n"):
            with self.subTest(listing=listing):
                self.control("chromium-common", "list").write_text(listing)
                with self.assertRaises(RuntimeVerificationError):
                    self.observe_fixture()

    def test_modified_support_package_is_rejected_by_gate_even_with_exit_zero(self):
        (self.root / PAYLOADS["chromium-common"][0]).write_bytes(b"modified inert fixture")
        self.assert_fixture_gate_rejects()

    def test_missing_support_payload_is_rejected_by_gate_even_with_exit_zero(self):
        (self.root / PAYLOADS["chromium-common"][0]).unlink()
        self.assert_fixture_gate_rejects()

    def assert_fixture_gate_rejects(self):
        # Only a rejection path is exercised. Observation and main-file hashing
        # are synthetic; these inert files must never receive runtime approval.
        gate = linux.LinuxPackageRuntimeGate(
            VERSIONS,
            runner=self.fixture_runner,
            path_checker=lambda *_args, **_kwargs: None,
        )
        metadata = linux.LinuxPackageMetadata("1.0-1", "chromium", ())
        digest = hashlib.sha256(b"independent rejection-only fixture").hexdigest()
        policy = RuntimePolicy("chromium", "1.0-1", digest, linux.PROVENANCE, False)
        with (
            patch.object(gate, "observe", return_value=metadata),
            patch.object(linux, "_hash_regular_file", return_value=(digest, (1, 2, 3, 4))),
            self.assertRaisesRegex(RuntimeVerificationError, "modified or missing"),
        ):
            gate.verify(linux.CHROMIUM, observed_version="1.0-1", policy=policy)
        self.assertTrue(self.commands)


class IndependentLinuxManifestTests(unittest.TestCase):
    def test_regular_canonical_manifest(self):
        self.assertEqual(
            linux._manifest("a" * 32 + "  usr/lib/chromium/chromium\n"),
            {"usr/lib/chromium/chromium": "a" * 32},
        )

    def test_manifest_rejects_malformed_ambiguous_and_traversing_entries(self):
        invalid = [
            "",
            "\n",
            "a" * 31 + "  usr/lib/chromium/chromium\n",
            "G" * 32 + "  usr/lib/chromium/chromium\n",
            "a" * 32 + " usr/lib/chromium/chromium\n",
        ]
        names = [
            "/usr/lib/chromium/chromium",
            "../usr/lib/chromium/chromium",
            "usr/../lib/chromium/chromium",
            "usr/./lib/chromium/chromium",
            "usr//lib/chromium/chromium",
            "usr/lib/chromium/chromium/",
            "usr/lib/chromium/chro\x00mium",
            "usr/lib/chromium/chro\tmium",
        ]
        invalid.extend("a" * 32 + "  " + name + "\n" for name in names)
        row = "a" * 32 + "  usr/lib/chromium/chromium\n"
        invalid.append(row + row)
        for raw in invalid:
            with self.subTest(raw=repr(raw)), self.assertRaises(RuntimeVerificationError):
                linux._manifest(raw)

    def test_package_pins_cannot_mix_architectures_or_use_query_patterns(self):
        invalid = [
            {"chromium:amd64": "1.0-1"},
            {**VERSIONS, "chromium-common:arm64": "1.0-1"},
            {
                "chromium:amd64": "1.0-1",
                "chromium-common:arm64": "1.0-1",
                "chromium-sandbox:amd64": "1.0-1",
            },
            {
                "chromium*:amd64": "1.0-1",
                "chromium-common:amd64": "1.0-1",
                "chromium-sandbox:amd64": "1.0-1",
            },
            {**VERSIONS, "chromium:amd64": "1.0-1\n"},
        ]
        for versions in invalid:
            with self.subTest(versions=versions), self.assertRaises(ValueError):
                linux.LinuxPackageRuntimeGate(versions)


@unittest.skipUnless(sys.platform == "linux", "Linux selector-backed runner")
class IndependentBoundedRunnerTests(unittest.TestCase):
    def run_python(self, source, timeout=2):
        # Existing Python executes only inline inert output/sleep fixtures.
        return linux._bounded_run(
            [sys.executable, "-c", source],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
            shell=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
        )

    def test_drains_stdout_and_stderr_without_merging_evidence(self):
        result = self.run_python("import os; os.write(1, b'out'); os.write(2, b'err')")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "out", "err"))

    def test_limit_counts_aggregate_bytes_from_both_streams(self):
        with (
            patch.object(linux, "_MAX_OUTPUT", 100),
            self.assertRaisesRegex(RuntimeVerificationError, "output exceeds"),
        ):
            self.run_python("import os; os.write(1, b'x' * 60); os.write(2, b'y' * 60)")

    def test_invalid_utf8_is_not_silently_replaced(self):
        with self.assertRaises(UnicodeError):
            self.run_python("import os; os.write(1, b'\\xff')")

    def test_stalled_child_has_a_real_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_python("import time; time.sleep(10)", timeout=0.05)


if __name__ == "__main__":
    unittest.main()
