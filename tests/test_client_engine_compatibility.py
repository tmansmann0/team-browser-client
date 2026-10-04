"""Bounded configuration conversion; opt-in actual offline wheels, never a browser."""

import copy
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from team_browser.client import engine_identity as identity
from team_browser.client.engine_identity import (
    AcceptedDisplay,
    EngineIdentityError,
    EngineIdentityStore,
    OfflineCamoufoxGenerator,
)
from team_browser.local.storage import ProfileStore

from test_client_engine_identity import binding, synthetic_config


def preset(major=150):
    return {
        "navigator": {
            "userAgent": (
                f"Mozilla/5.0 (X11; Linux x86_64; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
            ),
            "platform": "Linux x86_64",
            "hardwareConcurrency": 8,
            "maxTouchPoints": 0,
        },
        "screen": {
            "width": 2560,
            "height": 1440,
            "availWidth": 2560,
            "availHeight": 1440,
            "colorDepth": 24,
            "devicePixelRatio": 1,
        },
        "webgl": {"unmaskedVendor": "Synthetic vendor", "unmaskedRenderer": "Synthetic renderer"},
    }


class ConfigurationCompatibilityTests(unittest.TestCase):
    def test_versioned_forward_conversion_range_and_legacy_exact_match(self):
        for target in range(149, 157):
            for source in range(148, 157):
                with self.subTest(source=source, target=target):
                    expected = source if 149 <= source <= min(target, 152) else None
                    self.assertEqual(
                        identity._preset_source_major(
                            preset(source), replace(binding(), firefox_major=target)
                        ),
                        expected,
                    )
        self.assertEqual(
            identity._preset_source_major(preset(148), replace(binding(), firefox_major=148)),
            148,
        )
        self.assertIsNone(
            identity._preset_source_major(preset(147), replace(binding(), firefox_major=148))
        )

    def test_future_major_fails_before_dependencies_or_helper_process(self):
        for major in (157, 200, 999):
            with (
                self.subTest(major=major),
                patch.object(identity, "_package_manifest") as package,
                patch.object(identity.subprocess, "run") as process,
                self.assertRaises(EngineIdentityError) as raised,
            ):
                OfflineCamoufoxGenerator().generate(replace(binding(), firefox_major=major))
            self.assertEqual(raised.exception.reason, "unsupported_engine_conversion")
            package.assert_not_called()
            process.assert_not_called()

    def test_bound_major_must_be_a_bounded_integer(self):
        for major in (True, 156.0, "156", -1, 99, 1000):
            with self.subTest(major=major), self.assertRaises(ValueError):
                replace(binding(), firefox_major=major)

    def test_observed_available_geometry_does_not_mutate_source_preset(self):
        p = preset(152)
        before = copy.deepcopy(p)
        for width, height in ((2560, 1440), (2560, 1413), (2510, 1400)):
            b = replace(
                binding(),
                firefox_major=156,
                display=AcceptedDisplay(2560, 1440, width, height, 24, 1),
            )
            self.assertEqual(identity._preset_source_major(p, b), 152)
        self.assertEqual(p, before)

    def test_untrusted_or_invalid_geometry_is_not_a_compatibility_escape(self):
        for changes in (
            {"width": True},
            {"height": "1440"},
            {"avail_width": 2561},
            {"avail_height": 1441},
            {"avail_width": 0},
            {"avail_height": -1},
            {"avail_height": True},
            {"color_depth": True},
            {"device_pixel_ratio": 0},
            {"device_pixel_ratio": float("nan")},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(binding().display, **changes)
        with self.assertRaises(ValueError):
            replace(binding(), display={"width": 2560})
        for key, value in (
            ("width", 2559),
            ("height", 1439),
            ("colorDepth", 30),
            ("devicePixelRatio", 2),
            ("devicePixelRatio", None),
            ("availHeight", 1441),
            ("availWidth", True),
        ):
            with self.subTest(key=key, value=value):
                p = preset()
                p["screen"][key] = value
                self.assertIsNone(identity._preset_source_major(p, binding()))

    def test_source_ua_and_navigator_must_be_coherent_before_normalizing(self):
        for key, value in (
            ("userAgent", preset()["navigator"]["userAgent"].replace("rv:150", "rv:149")),
            ("userAgent", preset()["navigator"]["userAgent"] + " AtContent/1.0"),
            ("userAgent", preset()["navigator"]["userAgent"].replace("X11; Linux x86_64", "Win64")),
            ("userAgent", preset()["navigator"]["userAgent"].replace("150.0", "0150.0")),
            ("userAgent", None),
            ("platform", "Win32"),
            ("oscpu", "Intel Mac OS X 10.15"),
            ("appVersion", "5.0 (Windows)"),
            ("hardwareConcurrency", True),
            ("maxTouchPoints", 21),
        ):
            with self.subTest(key=key, value=value):
                p = preset()
                p["navigator"][key] = value
                self.assertIsNone(identity._preset_source_major(p, binding()))
        for target_os, platform in (("macos", "darwin"), ("windows", "win32")):
            b = replace(binding(), platform=platform, target_os=target_os)
            self.assertIsNone(identity._preset_source_major(preset(), b))

    def test_graphics_requires_complete_matching_capability_sets(self):
        config = synthetic_config(binding())
        graphics = {k: v for k, v in config.items() if k.startswith(("webGl:", "webGl2:"))}
        graphics["webGl2Enabled"] = True
        for prefix in ("webGl", "webGl2"):
            graphics[f"{prefix}:parameters"].update(
                {"37445": "Synthetic vendor", "37446": "Synthetic renderer"}
            )
        self.assertTrue(identity._catalogue_graphics_supported(graphics, preset()["webgl"]))
        for key in graphics:
            bad = copy.deepcopy(graphics)
            del bad[key]
            self.assertFalse(identity._catalogue_graphics_supported(bad, preset()["webgl"]))
        for key, value in (
            ("webGl2Enabled", False),
            ("webGl:renderer", "Different GPU"),
            ("webGl2:parameters", {"37445": "Wrong vendor", "37446": "Wrong GPU"}),
            ("webGl2:contextAttributes", {}),
            ("webGl:supportedExtensions", []),
        ):
            bad = copy.deepcopy(graphics)
            bad[key] = value
            self.assertFalse(identity._catalogue_graphics_supported(bad, preset()["webgl"]))


@unittest.skipUnless(
    os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1",
    "optional pinned official-wheel offline conversion; no native engine",
)
class OfficialWheelCompatibilityTests(unittest.TestCase):
    def test_152_and_156_use_original_152_preset_and_persist_observed_geometry(self):
        _, _, root = identity._package_manifest("camoufox")
        presets = json.loads((root / "fingerprint-presets-v150.json").read_text())["presets"][
            "linux"
        ]
        source = next(p for p in presets if p["navigator"]["userAgent"].endswith("Firefox/152.0"))
        source_digest = identity._digest(source)
        for major, available in ((152, (2560, 1440)), (156, (2560, 1440)), (156, (2510, 1400))):
            b = replace(
                binding(),
                firefox_major=major,
                engine_version=f"candidate-{major}",
                display=AcceptedDisplay(2560, 1440, *available, 24, 1),
            )
            with self.subTest(major=major, available=available), tempfile.TemporaryDirectory() as d:
                profiles = ProfileStore(Path(d).resolve() / "profiles")
                store, generator = EngineIdentityStore(profiles), OfflineCamoufoxGenerator()
                with profiles.acquire(b.profile_id) as lease:
                    first = store.load_or_create(lease, b, generator)
                    raw = (lease.paths.directory / identity.ARTIFACT_NAME).read_bytes()
                payload = json.loads(first.artifact_json)
                self.assertEqual(payload["selected_preset_sha256"], source_digest)
                self.assertEqual(
                    payload["generator"]["generator_version"], identity.GENERATOR_VERSION
                )
                config = json.loads(first.config_json)
                self.assertIn(f"rv:{major}.0", config["navigator.userAgent"])
                self.assertTrue(config["navigator.userAgent"].endswith(f"Firefox/{major}.0"))
                self.assertEqual(config["screen.availWidth"], available[0])
                self.assertEqual(config["screen.availHeight"], available[1])
                self.assertEqual(config["webGl:renderer"], source["webgl"]["unmaskedRenderer"])
                self.assertEqual(set(config), identity._ALLOWED_KEYS)
                with profiles.acquire(b.profile_id) as lease:
                    with patch.object(
                        generator, "generate", side_effect=AssertionError("no reseed")
                    ):
                        self.assertEqual(first, store.load_or_create(lease, b, generator))
                        changed = replace(b, display=replace(b.display, avail_height=1399))
                        with self.assertRaises(EngineIdentityError) as raised:
                            store.load_or_create(lease, changed, generator)
                        self.assertEqual(raised.exception.reason, "identity_migration_required")
                    self.assertEqual(
                        (lease.paths.directory / identity.ARTIFACT_NAME).read_bytes(), raw
                    )
        self.assertEqual(identity._digest(source), source_digest)

    def test_1920_by_1080_retains_independently_accepted_panel_height(self):
        b = replace(
            binding(),
            firefox_major=152,
            engine_version="candidate-152",
            display=AcceptedDisplay(1920, 1080, 1920, 1053, 24, 1),
        )
        config, prefs, _ = OfflineCamoufoxGenerator().generate(b)
        identity.validate_identity(config, prefs, b)
        self.assertEqual(config["screen.availHeight"], 1053)

    def test_unsupported_dimensions_and_dpr_never_get_nearest_match(self):
        for display in (
            AcceptedDisplay(1777, 999, 1777, 969, 24, 1),
            AcceptedDisplay(2560, 1440, 2560, 1400, 24, 1.1),
            AcceptedDisplay(2560, 1440, 2560, 1400, 30, 1),
        ):
            with self.subTest(display=display), self.assertRaises(EngineIdentityError) as raised:
                OfflineCamoufoxGenerator().generate(
                    replace(binding(), firefox_major=156, display=display)
                )
            self.assertEqual(raised.exception.reason, "catalogue_match_unavailable")


if __name__ == "__main__":
    unittest.main()
