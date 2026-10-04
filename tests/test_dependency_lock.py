"""Source-only checks for the public offline verification dependency boundary."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-client-verification-linux-py312.lock"


class VerificationLockTests(unittest.TestCase):
    def setUp(self):
        self.text = LOCK.read_text()
        self.entries = {}
        logical = self.text.replace("\\\n", " ")
        for line in logical.splitlines():
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(
                r"([a-z0-9][a-z0-9_-]*)==([a-zA-Z0-9.]+)\s+"
                r"((?:--hash=sha256:[a-f0-9]{64}\s*)+)",
                line,
            )
            self.assertIsNotNone(match, f"Not an exact hashed registry pin: {line[:80]}")
            name, version, _ = match.groups()
            self.assertNotIn(name, self.entries)
            self.entries[name] = version

    def test_toolchain_scope_is_explicit(self):
        self.assertIn("CPython 3.12, Linux x86_64", self.text)
        self.assertIn("not a browser engine or production release approval", self.text)
        self.assertGreater(len(self.entries), 40)

    def test_reviewed_engine_packages_are_exact(self):
        for name, expected in {
            "camoufox": "0.5.6",
            "playwright": "1.62.0",
            "browserforge": "1.2.4",
            "apify-fingerprint-datapoints": "0.15.0",
            "httpx": "0.28.1",
            "ruff": "0.16.10",
        }.items():
            self.assertEqual(self.entries.get(name), expected)

    def test_no_private_database_packages_or_sources(self):
        self.assertTrue({"sqlalchemy", "psycopg", "psycopg-binary"}.isdisjoint(self.entries))
        for prohibited in ("file:", "https:", "http:", "git+", "--index", "--find-links", " @ "):
            self.assertNotIn(prohibited, self.text)


if __name__ == "__main__":
    unittest.main()
