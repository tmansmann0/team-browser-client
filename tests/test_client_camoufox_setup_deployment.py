"""Synthetic signatures and inert files only: no keys installed, no browser run."""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from team_browser.client import camoufox_deployment as deployment
from team_browser.client.camoufox_setup import load_camoufox_setup
from team_browser.client.store import WorkspaceStore


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.native = self.root / "inert-distribution"
        self.native.mkdir()
        (self.native / "camoufox-bin").write_bytes(b"fixture only; never execute")
        (self.native / "camoufox-bin").chmod(0o700)
        (self.native / "application.ini").write_text(
            "[App]\nVersion=152.0.4\nBuildID=20260901000000\n"
        )
        (self.native / "properties.json").write_text("[]")
        # Ephemeral test key only. Nothing writes its private material to disk.
        self.key = Ed25519PrivateKey.generate()
        self.anchor = {
            "schema_version": 1,
            "authority_id": "synthetic-reviewer",
            "host_id": "synthetic-host-0001",
            "platform": "linux",
            "public_key_hex": self.key.public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex(),
        }
        self.now = datetime.now(timezone.utc)
        self.payload = {
            "schema_version": 1,
            "authority_id": self.anchor["authority_id"],
            "host_id": self.anchor["host_id"],
            "platform": "linux",
            "issued_at": (self.now - timedelta(minutes=1)).isoformat(),
            "valid_until": (self.now + timedelta(hours=1)).isoformat(),
            "source_url": "https://github.com/daijro/camoufox/releases/download/v152.0.4-beta.30/camoufox-152.0.4-beta.30-lin.x86_64.zip",
            "archive_sha256": "a" * 64,
            "root": str(self.native),
            "engine_version": "152.0.4+beta.30.20260901000000",
            "firefox_version": "152.0.4",
            "gecko_build_id": "20260901000000",
            "camoufox_release": "beta.30",
            "executable": "camoufox-bin",
            "metadata": "application.ini",
            "properties": "properties.json",
            "files": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.native.iterdir()
            },
            "display": {
                "width": 1920,
                "height": 1080,
                "avail_width": 1920,
                "avail_height": 1053,
                "color_depth": 24,
                "device_pixel_ratio": 1.0,
            },
            "profile_defaults": {
                "preset_id": "isolated",
                "locale": "en-US",
                "timezone_id": "America/New_York",
                "network_policy": "local_direct",
            },
            "native_qualification": None,
        }
        self.trust = self.root / "trust.json"
        self.receipt = self.root / "receipt.json"
        self.config = self.root / "setup.json"
        self.trust.write_text(canonical(self.anchor))
        self.trust.chmod(0o600)
        self.config.write_text(
            canonical(
                {
                    "schema_version": 1,
                    "receipt_file": str(self.receipt),
                    "use_accepted_profile_defaults": True,
                }
            )
        )
        self.config.chmod(0o600)
        self.write_receipt()
        original = deployment._read

        def synthetic_read(path, **kwargs):
            # Synthetic files cannot become admin trust. Positive tests disable
            # only OS ownership checks; real Ed25519 parsing/verification stays.
            kwargs["protected"] = False
            return original(path, **kwargs)

        self.mock_read = patch.object(deployment, "_read", side_effect=synthetic_read)

    def tearDown(self):
        self.temp.cleanup()

    def write_receipt(self):
        text = canonical(self.payload)
        self.receipt.write_text(
            canonical({"payload": text, "signature_hex": self.key.sign(text.encode("ascii")).hex()})
        )
        self.receipt.chmod(0o600)

    def load(self):
        return deployment.AuthenticatedDeployment(self.config, self.trust)

    def test_actual_user_owned_trust_is_rejected(self):
        with self.assertRaises(Exception):
            self.load()

    def test_authenticated_selection_is_not_native_acceptance(self):
        with self.mock_read:
            selected = self.load()
            self.assertIsNone(selected.acceptance())
            with self.assertRaisesRegex(Exception, "qualification"):
                selected.program()
            metadata = selected.metadata(selected.executable)
            self.assertEqual(metadata.version, self.payload["engine_version"])
            self.assertEqual(selected.properties(selected.executable).content, b"[]")
        # Declarative deployment verification still rejects unprotected native
        # resources rather than turning a receipt into a publisher signature.
        with self.mock_read:
            with self.assertRaises(Exception):
                selected.verify(
                    selected.executable,
                    observed_version=selected.policy.version,
                    policy=selected.policy,
                )

    def test_unsigned_claim_and_changed_signature_are_rejected(self):
        envelope = json.loads(self.receipt.read_text())
        envelope["signature_hex"] = "0" * 128
        self.receipt.write_text(canonical(envelope))
        with self.mock_read, self.assertRaises(Exception):
            self.load()

    def test_key_from_receipt_cannot_become_trust(self):
        envelope = json.loads(self.receipt.read_text())
        envelope["public_key_hex"] = self.anchor["public_key_hex"]
        self.receipt.write_text(canonical(envelope))
        with self.mock_read, self.assertRaises(Exception):
            self.load()

    def test_config_receipt_and_anchor_changes_revoke(self):
        for path in (self.config, self.receipt, self.trust):
            with self.subTest(path=path.name), self.mock_read:
                selected = self.load()
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                with self.assertRaises(Exception):
                    selected.current()
                path.write_bytes(before)

    def test_foreign_host_expiry_distribution_and_unknown_fields_fail(self):
        cases = [
            ("host_id", "foreign-host-0001"),
            ("valid_until", (self.now - timedelta(hours=1)).isoformat()),
            (
                "source_url",
                "https://github.com/camoufox/camoufox/releases/download/tag/camoufox.zip",
            ),
            ("engine_version", "0.5.6"),
            ("success", True),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                saved = dict(self.payload)
                self.payload[field] = value
                self.write_receipt()
                with self.mock_read, self.assertRaises(Exception):
                    self.load()
                self.payload = saved
                self.write_receipt()

    def test_metadata_change_and_symlink_are_not_fresh_evidence(self):
        with self.mock_read:
            selected = self.load()
            path = self.native / "application.ini"
            before = path.read_bytes()
            path.write_bytes(before.replace(b"152.0.4", b"156.0.1"))
            with self.assertRaises(Exception):
                selected.metadata(selected.executable)
            path.unlink()
            path.symlink_to(self.native / "properties.json")
            with self.assertRaises(Exception):
                selected.metadata(selected.executable)

    def test_malformed_nested_json_becomes_safe_app_blocker(self):
        self.config.write_text("[" * 3000 + "0" + "]" * 3000)
        with self._store() as store:
            setup = load_camoufox_setup(self.config, store, trust_path=self.trust)
            self.assertIsNone(setup.adapter)
            self.assertEqual(setup.overview()["state"], "needs_approval")
            self.assertNotIn(str(self.root), json.dumps(setup.overview()))

    def _store(self):
        from contextlib import contextmanager

        @contextmanager
        def opened():
            store = WorkspaceStore(self.root / "workspace")
            try:
                yield store
            finally:
                store.close()

        return opened()

    def test_private_config_and_receipt_permissions_are_enforced(self):
        self.config.chmod(0o644)
        with self.mock_read, self.assertRaises(Exception):
            self.load()

    def test_no_download_or_runtime_execution_from_loader(self):
        with (
            self.mock_read,
            patch("subprocess.Popen", side_effect=AssertionError("No process allowed")),
            patch("socket.socket", side_effect=AssertionError("No network allowed")),
        ):
            self.load()
