"""Independent v3 conversion and persistence checks; no native engine execution."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from team_browser.client import engine_identity as identity
from team_browser.local.storage import ProfileStore
from test_client_engine_identity import binding


def source_preset():
    return {
        "navigator": {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
            "platform": "Linux x86_64",
            "hardwareConcurrency": 16,
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
    }


class IndependentConversionBounds(unittest.TestCase):
    def test_future_conversion_is_rejected_before_observing_packages(self):
        candidate = replace(binding(), firefox_major=157)
        with patch.object(identity, "_package_manifest") as observe:
            with self.assertRaises(identity.EngineIdentityError) as raised:
                identity.OfflineCamoufoxGenerator().provenance(candidate)
        self.assertEqual(raised.exception.reason, "unsupported_engine_conversion")
        observe.assert_not_called()

    def test_observed_available_geometry_is_not_a_physical_screen_escape(self):
        candidate = replace(
            binding(),
            firefox_major=156,
            display=identity.AcceptedDisplay(2560, 1440, 2500, 1391, 24, 1),
        )
        source = source_preset()
        original = copy.deepcopy(source)
        self.assertEqual(identity._preset_source_major(source, candidate), 152)
        self.assertEqual(source, original)
        for change in ({"width": 2559}, {"color_depth": 30}, {"device_pixel_ratio": 1.25}):
            with self.subTest(change=change):
                changed = replace(candidate, display=replace(candidate.display, **change))
                self.assertIsNone(identity._preset_source_major(source, changed))

    def test_conversion_never_sanitizes_an_incoherent_or_future_source(self):
        candidate = replace(binding(), firefox_major=156)
        for old, new in (
            ("rv:152.0", "rv:151.0"),
            ("152.0", "157.0"),
            ("Linux x86_64", "Windows NT 10.0; Win64; x64"),
        ):
            with self.subTest(old=old, new=new):
                source = source_preset()
                source["navigator"]["userAgent"] = source["navigator"]["userAgent"].replace(
                    old, new
                )
                self.assertIsNone(identity._preset_source_major(source, candidate))
        self.assertIsNone(
            identity._preset_source_major(source_preset(), replace(candidate, firefox_major=150))
        )


@unittest.skipUnless(
    os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1",
    "exact-wheel offline conversion only; no browser",
)
class IndependentRealOfflineConversion(unittest.TestCase):
    def test_current_and_newer_engine_configuration_reuse_is_exact(self):
        for major in (152, 156):
            with self.subTest(major=major), tempfile.TemporaryDirectory() as temporary:
                profiles = ProfileStore(Path(temporary).resolve() / "profiles")
                store = identity.EngineIdentityStore(profiles)
                generator = identity.OfflineCamoufoxGenerator()
                candidate = replace(
                    binding(),
                    engine_version=f"review-candidate-{major}",
                    firefox_major=major,
                    display=identity.AcceptedDisplay(2560, 1440, 2560, 1440, 24, 1),
                )
                with profiles.acquire(candidate.profile_id) as lease:
                    first = store.load_or_create(lease, candidate, generator)
                    original = (lease.paths.directory / identity.ARTIFACT_NAME).read_bytes()
                    self.assertEqual(json.loads(first.config_json)["screen.availHeight"], 1440)
                    navigator = json.loads(first.config_json)
                    self.assertIn(f"rv:{major}.0", navigator["navigator.userAgent"])
                    self.assertTrue(navigator["navigator.userAgent"].endswith(f"Firefox/{major}.0"))
                    self.assertEqual(navigator["navigator.appVersion"], "5.0 (X11)")
                with profiles.acquire(candidate.profile_id) as lease:
                    with patch.object(generator, "generate", side_effect=AssertionError("reseed")):
                        again = store.load_or_create(lease, candidate, generator)
                        self.assertEqual(again.artifact_json, first.artifact_json)
                        changed = replace(candidate, engine_version="different-reviewed-build")
                        with self.assertRaises(identity.EngineIdentityError) as raised:
                            store.load_or_create(lease, changed, generator)
                    self.assertEqual(raised.exception.reason, "identity_migration_required")
                    self.assertEqual(
                        (lease.paths.directory / identity.ARTIFACT_NAME).read_bytes(), original
                    )

    def test_observed_panel_geometry_does_not_rewrite_an_existing_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            profiles = ProfileStore(Path(temporary).resolve() / "profiles")
            store = identity.EngineIdentityStore(profiles)
            generator = identity.OfflineCamoufoxGenerator()
            candidate = replace(
                binding(),
                firefox_major=156,
                engine_version="review-candidate-156",
                display=identity.AcceptedDisplay(1920, 1080, 1920, 1053, 24, 1),
            )
            with profiles.acquire(candidate.profile_id) as lease:
                first = store.load_or_create(lease, candidate, generator)
                self.assertEqual(json.loads(first.config_json)["screen.availHeight"], 1053)
                raw = (lease.paths.directory / identity.ARTIFACT_NAME).read_bytes()
                with patch.object(generator, "generate", side_effect=AssertionError("reseed")):
                    changed = replace(
                        candidate, display=replace(candidate.display, avail_height=1080)
                    )
                    with self.assertRaises(identity.EngineIdentityError) as raised:
                        store.load_or_create(lease, changed, generator)
                self.assertEqual(raised.exception.reason, "identity_migration_required")
                self.assertEqual((lease.paths.directory / identity.ARTIFACT_NAME).read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
