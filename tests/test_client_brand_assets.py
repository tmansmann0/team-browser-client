"""Bundled original identity assets; no graphics service or browser required."""

from pathlib import Path
import struct
import tomllib
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "src/team_browser/static/brand"


class BrandAssetTests(unittest.TestCase):
    def test_svg_assets_have_no_executable_or_external_content(self):
        for path in BRAND.glob("*.svg"):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotIn("<!DOCTYPE", text)
                self.assertNotIn("<!ENTITY", text)
                root = ET.fromstring(text)
                self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
                self.assertIn("viewBox", root.attrib)
                for node in root.iter():
                    self.assertNotIn(
                        node.tag.split("}")[-1],
                        {"script", "foreignObject", "image", "use", "a", "style"},
                    )
                    for name, value in node.attrib.items():
                        self.assertFalse(name.lower().startswith("on"))
                        self.assertNotIn("href", name.lower())
                        self.assertNotIn("url(", value.lower())

    def test_png_dimensions_and_native_icon_sources(self):
        for path in BRAND.rglob("*.png"):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                self.assertEqual(raw[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(raw[12:16], b"IHDR")
                width, height = struct.unpack(">II", raw[16:24])
                self.assertEqual(width, height)
                self.assertLessEqual(width, 1024)
                self.assertGreaterEqual(width, 16)
        self.assertEqual(len(list((BRAND / "TeamBrowser.iconset").glob("*.png"))), 10)
        raw = (BRAND / "TeamBrowser.icns").read_bytes()
        self.assertEqual(raw[:4], b"icns")
        self.assertEqual(struct.unpack(">I", raw[4:8])[0], len(raw))

    def test_app_references_packaged_relative_identity_assets(self):
        page = (ROOT / "src/team_browser/static/index.html").read_text()
        for name in ("logo-reverse.svg", "favicon.svg", "mark.svg"):
            self.assertIn(f"./brand/{name}", page)
            self.assertTrue((BRAND / name).is_file())
        self.assertIn('aria-label="TeamBrowser home"', page)
        self.assertNotIn('class="brand-mark"', page)
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        patterns = data["tool"]["setuptools"]["package-data"]["team_browser"]
        self.assertIn("static/brand/*", patterns)
        self.assertIn("static/brand/TeamBrowser.iconset/*", patterns)

    def test_no_font_binary_or_unrelated_private_artifacts(self):
        suffixes = {".svg", ".png", ".ico", ".icns", ".css", ".txt"}
        for path in BRAND.rglob("*"):
            if path.is_file():
                self.assertIn(path.suffix, suffixes)
                self.assertFalse(path.is_symlink())
