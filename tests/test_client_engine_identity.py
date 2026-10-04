"""Synthetic artifact contracts; opt-in official-wheel generation, no browser."""

import copy
import hashlib
import importlib.metadata
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from team_browser.client import engine_identity as identity
from team_browser.client.engine_identity import (
    ARTIFACT_NAME,
    AcceptedDisplay,
    EngineIdentityError,
    EngineIdentityStore,
    GeneratorProvenance,
    IdentityBinding,
    OfflineCamoufoxGenerator,
    validate_identity,
)
from team_browser.local.storage import ProfileStore


def binding(profile="synthetic-profile"):
    return IdentityBinding(
        profile,
        "a" * 64,
        "isolated",
        "synthetic-150",
        "b" * 64,
        150,
        "linux",
        "linux",
        AcceptedDisplay(2560, 1440, 2560, 1400, 24, 1),
        "en-US",
        "America/New_York",
    )


def synthetic_config(b):
    config = {
        "navigator.userAgent": f"Mozilla/5.0 (X11; Linux x86_64; rv:{b.firefox_major}.0) Gecko/20100101 Firefox/{b.firefox_major}.0",
        "navigator.platform": "Linux x86_64",
        "navigator.oscpu": "Linux x86_64",
        "navigator.appVersion": "5.0 (X11)",
        "navigator.hardwareConcurrency": 8,
        "navigator.maxTouchPoints": 0,
        "screen.width": b.display.width,
        "screen.height": b.display.height,
        "screen.availWidth": b.display.avail_width,
        "screen.availHeight": b.display.avail_height,
        "screen.colorDepth": 24,
        "screen.pixelDepth": 24,
        "fonts:spacing_seed": 4294967295,
        "audio:seed": 12345,
        "canvas:seed": 67890,
        "timezone": b.timezone_id,
        "locale:language": b.locale.split("-")[0],
        "locale:region": b.locale.split("-")[1],
        "navigator.language": b.locale,
        "navigator.languages": [b.locale],
        "headers.Accept-Language": b.locale,
        "webGl:vendor": "Synthetic vendor",
        "webGl:renderer": "Synthetic renderer",
        "fonts": ["Synthetic A", "Synthetic B", "Synthetic C", "Synthetic D"],
        "voices:blockIfNotDefined": True,
        "voices": [
            {
                "name": "Synthetic",
                "lang": b.locale,
                "voiceUri": "urn:synthetic",
                "isDefault": True,
                "isLocalService": True,
            }
        ],
    }
    for prefix in ("webGl", "webGl2"):
        config[f"{prefix}:parameters"] = {"3379": 8192, "37137": 18446744073709552000}
        config[f"{prefix}:contextAttributes"] = {
            **{
                key: True
                for key in (
                    "alpha",
                    "antialias",
                    "depth",
                    "failIfMajorPerformanceCaveat",
                    "premultipliedAlpha",
                    "preserveDrawingBuffer",
                    "stencil",
                )
            },
            "powerPreference": "default",
        }
        config[f"{prefix}:shaderPrecisionFormats"] = {
            f"{shader},{precision}": {"rangeMin": 127, "rangeMax": 127, "precision": 23}
            for shader in (35632, 35633)
            for precision in range(36336, 36342)
        }
        config[f"{prefix}:supportedExtensions"] = ["SYNTHETIC_extension"]
    return config


PREFS = {"webgl.enable-webgl2": True, "webgl.force-enabled": True}
PROVENANCE = GeneratorProvenance(
    "synthetic-generator", "c" * 64, "d" * 64, "synthetic-catalogue", "e" * 64
)


class SyntheticGenerator:
    def __init__(self):
        self.calls = 0
        self.current_provenance = PROVENANCE
        self.after_generate = lambda: None

    def provenance(self, b):
        return self.current_provenance

    def generate(self, b):
        self.calls += 1
        self.after_generate()
        config = synthetic_config(b)
        config["audio:seed"] += self.calls
        return config, dict(PREFS), "f" * 64


class EngineIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.profiles = ProfileStore(self.root / "profiles")
        self.store = EngineIdentityStore(self.profiles)
        self.binding = binding()
        self.lease = self.profiles.acquire(self.binding.profile_id)
        self.generator = SyntheticGenerator()
        self.artifact = self.lease.paths.directory / ARTIFACT_NAME

    def tearDown(self):
        self.lease.release()
        self.temp.cleanup()

    def create(self, **kwargs):
        return self.store.load_or_create(
            kwargs.get("lease", self.lease),
            kwargs.get("binding", self.binding),
            kwargs.get("generator", self.generator),
        )

    def assert_reason(self, reason, action):
        with self.assertRaises(EngineIdentityError) as raised:
            action()
        self.assertEqual(raised.exception.reason, reason)

    def rewrite(self, payload, *, rehash=True):
        if rehash:
            payload["config_sha256"] = identity._digest(payload["config"])
            payload["payload_sha256"] = identity._digest(
                {k: v for k, v in payload.items() if k != "payload_sha256"}
            )
        self.artifact.write_text(identity._canonical(payload))

    def test_generate_once_and_reload_exact_bytes_across_new_store_and_lease(self):
        first = self.create()
        before = self.artifact.read_bytes()
        self.lease.release()
        self.lease = self.profiles.acquire(self.binding.profile_id)
        self.store = EngineIdentityStore(ProfileStore(self.profiles.root))
        second = self.create()
        self.assertEqual(self.generator.calls, 1)
        self.assertEqual(first, second)
        self.assertEqual(before, self.artifact.read_bytes())
        self.assertEqual(
            first.config_sha256, hashlib.sha256(first.config_json.encode()).hexdigest()
        )
        self.assertEqual(first.artifact_sha256, hashlib.sha256(before).hexdigest())
        self.assertEqual(self.artifact.stat().st_mode & 0o777, 0o600)

    def test_persisted_preferences_cannot_mutate_identity(self):
        result = self.create()
        prefs = result.firefox_user_prefs
        prefs["security.enterprise_roots.enabled"] = True
        self.assertEqual(result.firefox_user_prefs, PREFS)

    def test_website_data_after_creation_does_not_regenerate(self):
        first = self.create()
        (self.lease.paths.browser_data / "synthetic-session").write_text("synthetic")
        self.assertEqual(first, self.create())
        self.assertEqual(self.generator.calls, 1)

    def test_different_profiles_have_separate_generation_and_binding(self):
        first = self.create()
        with self.profiles.acquire("second") as lease:
            second = self.create(lease=lease, binding=binding("second"))
        self.assertNotEqual(first.artifact_sha256, second.artifact_sha256)
        self.assertNotEqual(first.config_sha256, second.config_sha256)
        self.assertEqual(self.generator.calls, 2)

    def test_all_material_binding_changes_require_migration(self):
        self.create()
        before = self.artifact.read_bytes()
        changes = [
            {"profile_binding_sha256": "0" * 64},
            {"preset_id": "different"},
            {"engine_version": "new-version"},
            {"engine_sha256": "0" * 64},
            {"firefox_major": 151},
            {"locale": "en-GB"},
            {"timezone_id": "Europe/London"},
            {"proxy_fingerprint": "0" * 64},
            {"display": replace(self.binding.display, avail_height=1390)},
            {"platform": "darwin", "target_os": "macos"},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assert_reason(
                    "identity_migration_required",
                    lambda: self.create(binding=replace(self.binding, **change)),
                )
        self.assertEqual(self.generator.calls, 1)
        self.assertEqual(before, self.artifact.read_bytes())

    def test_generator_and_catalogue_upgrades_never_regenerate(self):
        self.create()
        for field, value in [
            ("generator_version", "new"),
            ("implementation_sha256", "0" * 64),
            ("packages_sha256", "0" * 64),
            ("catalogue_name", "new"),
            ("catalogue_sha256", "0" * 64),
        ]:
            self.generator.current_provenance = replace(PROVENANCE, **{field: value})
            self.assert_reason("identity_migration_required", self.create)
        self.assertEqual(self.generator.calls, 1)

    def test_v2_artifact_is_not_reinterpreted_under_v3_conversion_rules(self):
        self.generator.current_provenance = replace(
            PROVENANCE, generator_version="tbm-camoufox-preset-v2"
        )
        self.create()
        before = self.artifact.read_bytes()
        self.generator.current_provenance = replace(
            self.generator.current_provenance, generator_version=identity.GENERATOR_VERSION
        )
        self.assertEqual(identity.GENERATOR_VERSION, "tbm-camoufox-preset-v3")
        self.assert_reason("identity_migration_required", self.create)
        self.assertEqual(self.generator.calls, 1)
        self.assertEqual(self.artifact.read_bytes(), before)

    def test_no_lease_released_lease_and_wrong_lease_rejected(self):
        self.assert_reason("profile_lease_required", lambda: self.create(lease=None))
        with self.profiles.acquire("other") as lease:
            self.assert_reason("profile_lease_required", lambda: self.create(lease=lease))
        self.lease.release()
        self.assert_reason("profile_lease_required", self.create)
        self.assertEqual(self.generator.calls, 0)

    def test_replaced_lock_inode_is_not_authority(self):
        lock = self.lease.paths.directory / ".lease.lock"
        lock.rename(lock.with_name("old-lock"))
        lock.write_text("synthetic")
        lock.chmod(0o600)
        self.assert_reason("profile_lease_changed", self.create)
        self.assertFalse(self.artifact.exists())

    def test_lease_released_during_generation_creates_nothing(self):
        self.generator.after_generate = self.lease.release
        self.assert_reason("profile_lease_required", self.create)
        self.assertFalse(self.artifact.exists())

    def test_generator_changed_mid_generation_creates_nothing(self):
        self.generator.after_generate = lambda: setattr(
            self.generator, "current_provenance", replace(PROVENANCE, generator_version="changed")
        )
        self.assert_reason("generator_changed", self.create)
        self.assertFalse(self.artifact.exists())

    def test_existing_data_and_legacy_marker_refuse_adoption(self):
        legacy = self.lease.paths.directory / ".camoufox-identity.json"
        legacy.write_text("synthetic old marker")
        self.assert_reason("identity_migration_required", self.create)
        legacy.unlink()
        (self.lease.paths.browser_data / "cookies.sqlite").write_text("synthetic")
        self.assert_reason("profile_not_fresh", self.create)
        self.assertEqual(self.generator.calls, 0)

    def test_symlink_and_hardlink_artifact_rejected(self):
        target = self.root / "outside"
        target.write_text("synthetic")
        target.chmod(0o600)
        self.artifact.symlink_to(target)
        self.assert_reason("identity_storage_unavailable", self.create)
        self.artifact.unlink()
        os.link(target, self.artifact)
        self.assert_reason("identity_storage_unavailable", self.create)
        self.assertEqual(target.read_text(), "synthetic")
        self.assertEqual(self.generator.calls, 0)

    def test_fifo_artifact_is_nonblocking_and_rejected(self):
        os.mkfifo(self.artifact, 0o600)
        self.assert_reason("identity_storage_unavailable", self.create)

    def test_unsafe_permissions_and_oversized_artifact_rejected(self):
        self.create()
        self.artifact.chmod(0o644)
        self.assert_reason("identity_storage_unavailable", self.create)
        self.artifact.chmod(0o600)
        self.artifact.write_bytes(b"x" * (identity.MAX_ARTIFACT_BYTES + 1))
        self.assert_reason("invalid_artifact", self.create)
        self.assertEqual(self.generator.calls, 1)

    def test_torn_duplicate_noncanonical_and_nan_artifacts_never_repaired(self):
        original = self.create().artifact_json
        for raw in (
            b"",
            b"{",
            b'{"schema":1,"schema":1}',
            b'{"schema":NaN}',
            original.encode() + b"\n",
        ):
            with self.subTest(raw=raw[:20]):
                self.artifact.write_bytes(raw)
                self.assert_reason("invalid_artifact", self.create)
                self.assertEqual(self.artifact.read_bytes(), raw)
        self.assertEqual(self.generator.calls, 1)

    def test_changed_schema_requires_migration(self):
        data = json.loads(self.create().artifact_json)
        data["schema"] = 2
        self.rewrite(data)
        self.assert_reason("identity_migration_required", self.create)

    def test_payload_or_config_tampering_rejected(self):
        data = json.loads(self.create().artifact_json)
        data["config"]["audio:seed"] += 1
        self.rewrite(data, rehash=False)
        self.assert_reason("invalid_artifact", self.create)

    def test_rehashed_but_disallowed_launch_fields_rejected(self):
        data = json.loads(self.create().artifact_json)
        data["config"]["addons"] = ["/synthetic/extension"]
        self.rewrite(data)
        self.assert_reason("invalid_identity_config", self.create)

    def test_unsupported_keys_missing_surfaces_and_bad_types_rejected(self):
        b = self.binding
        mutations = [
            lambda c: c.update({"audio:seed": 0}),
            lambda c: c.update({"audio:seed": True}),
            lambda c: c.update({"navigator.hardwareConcurrency": 0}),
            lambda c: c.update({"navigator.hardwareConcurrency": 500}),
            lambda c: c.pop("voices"),
            lambda c: c.update({"voices": []}),
            lambda c: c.update({"fonts": ["same"] * 4}),
            lambda c: c.update({"fonts": [["nested"]] * 4}),
            lambda c: c.update({"voices:blockIfNotDefined": 1}),
            lambda c: c.update({"screen.width": float("nan")}),
            lambda c: c.update({"webrtc:ipv4": "192.0.2.5"}),
            lambda c: c.update({"humanize": True}),
        ]
        for mutate in mutations:
            config = synthetic_config(b)
            mutate(config)
            with self.subTest(config=list(config)):
                self.assert_reason(
                    "invalid_identity_config", lambda: validate_identity(config, dict(PREFS), b)
                )

    def test_locale_platform_display_and_voice_mismatch_rejected(self):
        for key, value in [
            ("navigator.platform", "Win32"),
            ("navigator.oscpu", "Win64"),
            ("screen.width", 1920),
            ("timezone", "Europe/London"),
            ("navigator.languages", ["en-GB"]),
        ]:
            config = synthetic_config(self.binding)
            config[key] = value
            self.assert_reason(
                "incoherent_identity", lambda: validate_identity(config, dict(PREFS), self.binding)
            )
        config = synthetic_config(self.binding)
        config["voices"][0]["lang"] = "de-DE"
        self.assert_reason(
            "unsupported_locale_voices",
            lambda: validate_identity(config, dict(PREFS), self.binding),
        )

    def test_only_identity_webgl_preferences_allowed(self):
        for prefs in ({}, {**PREFS, "network.proxy.type": 0}, {**PREFS, "webgl.enable-webgl2": 1}):
            self.assert_reason(
                "invalid_identity_preferences",
                lambda: validate_identity(synthetic_config(self.binding), prefs, self.binding),
            )

    def test_engine_property_catalogue_unknown_missing_and_wrong_types_fail(self):
        result = self.create()
        types = {
            str: "str",
            int: "uint",
            float: "double",
            bool: "bool",
            list: "array",
            dict: "dict",
        }
        rows = [
            {"property": key, "type": types[type(value)]}
            for key, value in json.loads(result.config_json).items()
        ]

        def check(values):
            raw = json.dumps(values).encode()
            result.validate_engine_properties(raw, hashlib.sha256(raw).hexdigest())

        check(rows)
        self.assert_reason("engine_property_unsupported", lambda: check(rows[:-1]))
        wrong = copy.deepcopy(rows)
        wrong[0]["type"] = "unrecognized"
        self.assert_reason("engine_property_unsupported", lambda: check(wrong))
        self.assert_reason("invalid_engine_properties", lambda: check(rows + [rows[0]]))
        self.assert_reason(
            "engine_properties_changed", lambda: result.validate_engine_properties(b"[]", "0" * 64)
        )

    def test_writing_failure_is_retained_as_blocker_not_regenerated(self):
        real_write = os.write
        count = 0

        def partial(fd, raw):
            nonlocal count
            count += 1
            if count == 1:
                return real_write(fd, bytes(raw[:20]))
            raise OSError("synthetic failure")

        with patch.object(identity.os, "write", side_effect=partial):
            self.assert_reason("identity_storage_unavailable", self.create)
        self.assertTrue(self.artifact.exists())
        self.assertEqual(self.artifact.stat().st_size, 20)
        self.assert_reason("invalid_artifact", self.create)
        self.assertEqual(self.generator.calls, 1)

    def test_parent_directory_replacement_during_generation_rejected(self):
        old = self.lease.paths.directory

        def replace_directory():
            old.rename(old.with_name("moved"))
            self.profiles.prepare(self.binding.profile_id)

        self.generator.after_generate = replace_directory
        self.assert_reason("profile_directory_changed", self.create)
        self.assertFalse(self.artifact.exists())
        self.assertFalse((old.with_name("moved") / ARTIFACT_NAME).exists())

    def test_profile_fill_during_generation_blocks_publication(self):
        self.generator.after_generate = lambda: (
            self.lease.paths.browser_data / "foreign-data"
        ).write_text("synthetic")
        self.assert_reason("profile_not_fresh", self.create)
        self.assertFalse(self.artifact.exists())


class IdentityInputTests(unittest.TestCase):
    def test_cross_os_target_and_unbounded_display_refused(self):
        for kwargs in (
            {"target_os": "macos"},
            {"firefox_major": True},
            {"engine_sha256": "bad"},
            {"locale": "en"},
            {"proxy_fingerprint": "http://proxy.invalid"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                replace(binding(), **kwargs)
        for kwargs in (
            {"width": 0},
            {"avail_width": 5000},
            {"device_pixel_ratio": float("inf")},
            {"device_pixel_ratio": True},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                replace(binding().display, **kwargs)

    def test_audit_guard_denies_network_process_writes_and_sqlite_rw(self):
        for event, args in [
            ("socket.__new__", ()),
            ("socket.getaddrinfo", ()),
            ("subprocess.Popen", ()),
            ("os.system", ()),
            ("os.posix_spawn", ()),
            ("os.mkdir", ()),
            ("open", ("synthetic", "w", 0)),
            ("open", ("synthetic", None, os.O_RDWR)),
            ("sqlite3.connect", ("synthetic.db",)),
        ]:
            with self.subTest(event=event), self.assertRaises(EngineIdentityError):
                identity._offline_guard(event, args)
        identity._offline_guard("open", ("synthetic", "r", os.O_RDONLY))
        identity._offline_guard("sqlite3.connect", ("file:/synthetic?mode=ro&immutable=1",))

    def test_unavailable_dependencies_fail_without_import_or_download(self):
        with patch.object(
            identity.importlib.metadata,
            "distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            with self.assertRaises(EngineIdentityError) as raised:
                OfflineCamoufoxGenerator().provenance(binding())
        self.assertEqual(raised.exception.reason, "generator_unavailable")


@unittest.skipUnless(
    os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1",
    "optional pinned official-wheel offline generation; no native engine",
)
class OfficialWheelOfflineTests(unittest.TestCase):
    def test_real_generator_and_private_artifact_survive_restart_without_generation(self):
        generator = OfflineCamoufoxGenerator()
        with tempfile.TemporaryDirectory() as root:
            profiles = ProfileStore(Path(root).resolve() / "profiles")
            store = EngineIdentityStore(profiles)
            b = binding()
            with profiles.acquire(b.profile_id) as lease:
                first = store.load_or_create(lease, b, generator)
            with profiles.acquire(b.profile_id) as lease:
                with patch.object(
                    generator, "generate", side_effect=AssertionError("must not regenerate")
                ):
                    second = store.load_or_create(lease, b, generator)
            self.assertEqual(first, second)
            config = json.loads(first.config_json)
            self.assertEqual(set(config), identity._ALLOWED_KEYS)
            self.assertGreater(len(config["fonts"]), 8)
            self.assertEqual(len(config["voices"]), 131)
            self.assertGreater(len(config["webGl:parameters"]), 100)
            self.assertEqual(config["screen.width"], 2560)
            self.assertNotIn("mediaDevices:micros", config)
            self.assertNotIn("window.history.length", config)

    def test_no_catalogue_match_does_not_guess_or_change_display(self):
        b = replace(binding(), display=AcceptedDisplay(1777, 999, 1777, 969, 24, 1))
        with self.assertRaises(EngineIdentityError) as raised:
            OfflineCamoufoxGenerator().generate(b)
        self.assertEqual(raised.exception.reason, "catalogue_match_unavailable")

    def test_independent_new_profiles_receive_distinct_seed_tuple(self):
        generator = OfflineCamoufoxGenerator()
        first, _, _ = generator.generate(binding())
        second, _, _ = generator.generate(binding("second"))

        def seeds(c):
            return tuple(c[k] for k in ("audio:seed", "canvas:seed", "fonts:spacing_seed"))

        self.assertNotEqual(seeds(first), seeds(second))

    def test_import_and_generation_reject_new_side_effects(self):
        # Real helper installs an irreversible audit hook before all Camoufox
        # imports. Successful generation is evidence that this path attempts no
        # socket/process/Python-write operation, not a native-engine test.
        import importlib.metadata

        self.assertEqual(importlib.metadata.version("camoufox"), "0.5.6")
        self.assertEqual(importlib.metadata.version("browserforge"), "1.2.4")
        result = OfflineCamoufoxGenerator().generate(binding())
        validate_identity(result[0], result[1], binding())


if __name__ == "__main__":
    unittest.main()
