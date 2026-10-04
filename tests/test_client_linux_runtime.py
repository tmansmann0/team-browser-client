"""Synthetic Linux provenance contracts, never a real browser acceptance claim."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.client import WorkspaceStore, WorkspaceError
from team_browser.client.installed_browser import load_installed_adapter
from team_browser.client.linux_runtime import (
    DATABASE,
    PROVENANCE,
    LinuxPackageRuntimeGate,
    _manifest,
    _system_path,
)
from team_browser.client.playwright_supervisor import PlaywrightSupervisor
from team_browser.local.errors import RuntimeVerificationError
from team_browser.local.runtime import RuntimePolicy


MODULE = "team_browser.client.linux_runtime"
VERSION = "154.0.8037.57-1~deb13u1"
PACKAGES = {
    f"{name}:amd64": VERSION for name in ("chromium", "chromium-common", "chromium-sandbox")
}


class LinuxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "synthetic-chromium"
        self.binary.write_bytes(b"\x7fELFsynthetic fixture: never execute")
        self.binary.chmod(0o700)
        self.calls = []
        self.overrides = {}
        self.policy = RuntimePolicy(
            "chromium",
            VERSION,
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            PROVENANCE,
            False,
        )
        self.gate = LinuxPackageRuntimeGate(
            PACKAGES, runner=self.run_query, path_checker=lambda *a, **k: None
        )
        for target, value in (("CHROMIUM", self.binary), ("sys.platform", "linux")):
            patcher = patch(f"{MODULE}.{target}", value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch(f"{MODULE}.os.geteuid", return_value=1000)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_query(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if "--show" in command:
            package = command[-1]
            name, arch = package.split(":")
            output = f"{name}\n{arch}\n{VERSION}\ninstalled\nok\n"
            key = "summary"
        elif "--control-path" in command:
            package = command[-2]
            output = f"{DATABASE}/info/{package}.{command[-1]}\n"
            key = "control_path"
        elif "--control-show" in command:
            package = command[-2]
            path = (
                str(self.binary).lstrip("/")
                if package.startswith("chromium:")
                else f"usr/lib/chromium/{package.split(':')[0]}-fixture"
            )
            output = f"{'a' * 32}  {path}\n"
            key = "manifest"
        elif "--listfiles" in command:
            package = command[-1]
            path = (
                str(self.binary)
                if package.startswith("chromium:")
                else f"/usr/lib/chromium/{package.split(':')[0]}-fixture"
            )
            output = f"/.\n{path}\n"
            key = "listfiles"
        elif "--search" in command:
            output = f"chromium: {self.binary}\n"
            key = "owner"
        elif "--verify" in command:
            output = ""
            key = "verify"
        else:
            self.fail(f"Unexpected command: {command}")
        override = self.overrides.get(key, output)
        if callable(override):
            override = override(command, output)
        if isinstance(override, BaseException):
            raise override
        if isinstance(override, SimpleNamespace):
            return override
        return SimpleNamespace(returncode=0, stdout=override, stderr="")

    def verify(self):
        return self.gate.verify(self.binary, observed_version=VERSION, policy=self.policy)

    def test_valid_package_contract_returns_explicit_provenance_not_signature(self):
        runtime = self.verify()
        self.assertEqual(runtime.signer_identity, PROVENANCE)
        self.assertEqual(runtime.sha256, self.policy.sha256)
        self.assertEqual(runtime.version, VERSION)
        verifies = [command[-1] for command, _ in self.calls if "--verify" in command]
        self.assertEqual(verifies, sorted(PACKAGES))

    def test_commands_anchor_system_database_and_do_not_inherit_environment(self):
        with patch.dict(
            os.environ,
            {"DPKG_ROOT": "/evil", "LD_PRELOAD": "evil", "HOME": "/evil", "PAGER": "evil"},
        ):
            self.verify()
        for command, kwargs in self.calls:
            self.assertIn("--root=/", command)
            self.assertIn("--admindir=/var/lib/dpkg", command)
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["cwd"], "/")
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_changed_missing_and_diagnostic_files_block_even_with_exit_zero(self):
        for text in (
            "??5?????? /usr/lib/chromium/chromium\n",
            "missing /usr/lib/chromium/snapshot.bin\n",
            "\n",
        ):
            with self.subTest(text=text):
                self.overrides["verify"] = text
                with self.assertRaisesRegex(RuntimeVerificationError, "modified or missing"):
                    self.verify()

    def test_failed_exit_stderr_timeout_and_oversized_output_block(self):
        for result in (
            SimpleNamespace(returncode=1, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr="warning"),
            subprocess.TimeoutExpired("synthetic", 20),
            "x" * (4 * 1024 * 1024 + 1),
        ):
            with self.subTest(result=type(result).__name__):
                self.overrides["summary"] = result
                with self.assertRaises(RuntimeVerificationError):
                    self.verify()

    def test_wrong_package_arch_version_or_state_blocks(self):
        for field, replacement in (
            (0, "other"),
            (1, "arm64"),
            (2, "different"),
            (3, "unpacked"),
            (4, "reinstreq"),
        ):

            def corrupt(command, output):
                lines = output.splitlines()
                lines[field] = replacement
                return "\n".join(lines) + "\n"

            with self.subTest(field=field):
                self.overrides["summary"] = corrupt
                with self.assertRaisesRegex(RuntimeVerificationError, "identity/version"):
                    self.verify()

    def test_wrong_diverted_and_multiple_owners_block(self):
        for owner in (
            f"other: {self.binary}\n",
            f"diversion by another from: {self.binary}\n",
            f"chromium: {self.binary}\nother: {self.binary}\n",
        ):
            self.overrides["owner"] = owner
            with self.assertRaisesRegex(RuntimeVerificationError, "ambiguous or diverted"):
                self.verify()

    def test_missing_selected_checksum_blocks(self):
        self.overrides["manifest"] = f"{'b' * 32}  usr/share/doc/fixture\n"
        self.overrides["listfiles"] = "/.\n/usr/share/doc/fixture\n"
        with self.assertRaisesRegex(RuntimeVerificationError, "executable has no"):
            self.verify()

    def test_checksum_metadata_paths_are_exact_and_bounded(self):
        for path in (
            "/tmp/evil.md5sums\n",
            "/var/lib/dpkg/info/../evil.md5sums\n",
            "/var/lib/dpkg/info/chromium:amd64.md5sums\n\n",
        ):
            self.overrides["control_path"] = path
            with self.assertRaisesRegex(RuntimeVerificationError, "location is unexpected"):
                self.verify()

    def test_malformed_duplicate_and_traversing_checksums_block(self):
        valid = f"{'a' * 32}  usr/lib/chromium/chromium\n"
        for raw in (
            "",
            "bad\n",
            valid + valid,
            f"{'a' * 32}  ../escape\n",
            f"{'a' * 32}  /absolute\n",
            f"{'a' * 32}  usr//double\n",
            f"{'A' * 32}  usr/uppercase\n",
            f"{'a' * 32}  usr/./dot\n",
        ):
            with self.subTest(raw=raw[:50]):
                with self.assertRaises(RuntimeVerificationError):
                    _manifest(raw)

    def test_file_inventory_must_cover_every_verified_payload(self):
        for listing in ("", "/.\n", "/.\n/etc/../escape\n", "/.\n/.\n"):
            self.overrides["listfiles"] = listing
            with self.assertRaises(RuntimeVerificationError):
                self.verify()

    def test_every_support_payload_requires_protected_paths(self):
        checked = []

        def reject_support(path, **kwargs):
            checked.append(path)
            if str(path).endswith("chromium-common-fixture"):
                raise RuntimeVerificationError("Synthetic writable support payload")

        self.gate.path_checker = reject_support
        with self.assertRaisesRegex(RuntimeVerificationError, "writable support"):
            self.verify()
        self.assertIn(Path("/usr/lib/chromium/chromium-common-fixture"), checked)

    def test_reviewed_hash_change_blocks_before_package_verification(self):
        self.binary.write_bytes(b"\x7fELFdifferent synthetic fixture")
        with self.assertRaisesRegex(RuntimeVerificationError, "SHA-256"):
            self.verify()
        self.assertFalse(any("--verify" in command for command, _ in self.calls))

    def test_package_manifest_change_during_verification_blocks(self):
        def mutate(command, output):
            self.overrides["manifest"] = lambda c, out: out.replace("a" * 32, "b" * 32)
            return output

        self.overrides["verify"] = mutate
        with self.assertRaisesRegex(RuntimeVerificationError, "metadata changed"):
            self.verify()

    def test_executable_change_during_verification_blocks(self):
        def mutate(command, output):
            self.binary.write_bytes(b"\x7fELFchanged after approval")
            return output

        self.overrides["verify"] = mutate
        with self.assertRaisesRegex(RuntimeVerificationError, "executable changed"):
            self.verify()

    def test_wrong_platform_root_wrapper_and_arbitrary_path_block(self):
        with patch(f"{MODULE}.sys.platform", "darwin"):
            with self.assertRaisesRegex(RuntimeVerificationError, "non-root Linux"):
                self.verify()
        with patch(f"{MODULE}.os.geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeVerificationError, "non-root Linux"):
                self.verify()
        self.binary.write_bytes(b"#!/bin/sh\necho not a browser")
        with self.assertRaisesRegex(RuntimeVerificationError, "ELF"):
            self.verify()
        with self.assertRaisesRegex(RuntimeVerificationError, "installed Chromium path"):
            self.gate.observe(Path("/tmp/other-browser"))

    def test_package_policy_requires_exact_full_same_architecture_inventory(self):
        for packages in (
            {},
            {"chromium:amd64": VERSION},
            {**PACKAGES, "extra:amd64": VERSION},
            {
                "chromium:*": VERSION,
                "chromium-common:amd64": VERSION,
                "chromium-sandbox:amd64": VERSION,
            },
            {
                "chromium:amd64": VERSION,
                "chromium-common:arm64": VERSION,
                "chromium-sandbox:amd64": VERSION,
            },
        ):
            with self.subTest(packages=packages):
                with self.assertRaises(ValueError):
                    LinuxPackageRuntimeGate(packages)

    def test_macos_signature_policy_cannot_be_satisfied_by_linux_package_evidence(self):
        policy = RuntimePolicy("chromium", VERSION, self.policy.sha256, "APPLE:fixture", True)
        with self.assertRaisesRegex(RuntimeVerificationError, "vendor-signature"):
            self.gate.verify(self.binary, observed_version=VERSION, policy=policy)

    def test_real_unsafe_file_symlink_and_permissions_are_rejected(self):
        with self.assertRaisesRegex(RuntimeVerificationError, "root-owned"):
            _system_path(self.binary)
        link = self.root / "link"
        link.symlink_to(self.binary)
        with self.assertRaisesRegex(RuntimeVerificationError, "symlinked"):
            _system_path(link)
        self.binary.chmod(0o777)
        with self.assertRaisesRegex(RuntimeVerificationError, "publicly writable"):
            _system_path(self.binary)

    def test_linux_loader_uses_distinct_gate_and_preserves_pipe_supervisor(self):
        store = WorkspaceStore(self.root / "workspace")
        self.addCleanup(store.close)
        config = {
            "provenance": "debian-package",
            "executable": str(self.binary),
            "version": VERSION,
            "sha256": self.policy.sha256,
            "package_versions": PACKAGES,
        }
        path = self.root / "policy.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        adapter = load_installed_adapter(path, store.profiles)
        self.assertIsInstance(adapter.gate, LinuxPackageRuntimeGate)
        self.assertIsInstance(adapter.supervisor, PlaywrightSupervisor)
        self.assertIsNone(adapter.observed_version)
        self.assertIsNone(adapter.vault)
        self.assertEqual(adapter.metadata_observer, adapter.gate.observe)
        self.assertTrue(
            adapter.global_blockers()
        )  # Synthetic executable never becomes launch authority.
        for field in (
            "trusted",
            "argv",
            "signer_identity",
            "require_notarization",
            "supervision_accepted",
        ):
            path.write_text(json.dumps({**config, field: True}))
            with self.assertRaises(WorkspaceError):
                load_installed_adapter(path, store.profiles)


if __name__ == "__main__":
    unittest.main()
