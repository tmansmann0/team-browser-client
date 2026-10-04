"""Independent offline identity review: no browser, accounts, or engine installation."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import importlib._bootstrap_external
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import venv
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.client import engine_identity as ei
from team_browser.local.storage import ProfileStore


def accepted_binding():
    return ei.IdentityBinding(
        "independent-profile",
        "1" * 64,
        "isolated",
        "reviewed-150-build",
        "2" * 64,
        150,
        "linux",
        "linux",
        ei.AcceptedDisplay(2560, 1440, 2560, 1400, 24, 1),
        "en-US",
        "America/New_York",
        "3" * 64,
    )


def supported_config(binding):
    result = {
        "navigator.userAgent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ),
        "navigator.platform": "Linux x86_64",
        "navigator.oscpu": "Linux x86_64",
        "navigator.appVersion": "5.0 (X11)",
        "navigator.hardwareConcurrency": 8,
        "navigator.maxTouchPoints": 0,
        "screen.width": binding.display.width,
        "screen.height": binding.display.height,
        "screen.availWidth": binding.display.avail_width,
        "screen.availHeight": binding.display.avail_height,
        "screen.colorDepth": binding.display.color_depth,
        "screen.pixelDepth": binding.display.color_depth,
        "fonts:spacing_seed": 2**32 - 1,
        "audio:seed": 42,
        "canvas:seed": 84,
        "timezone": binding.timezone_id,
        "locale:language": "en",
        "locale:region": "US",
        "navigator.language": binding.locale,
        "navigator.languages": [binding.locale],
        "headers.Accept-Language": binding.locale,
        "webGl:vendor": "Independent test vendor",
        "webGl:renderer": "Independent test renderer",
        "fonts": ["Independent A", "Independent B", "Independent C", "Independent D"],
        "voices:blockIfNotDefined": True,
        "voices": [
            {
                "lang": "en-US",
                "name": "Independent synthetic voice",
                "voiceUri": "urn:synthetic:independent",
                "isDefault": True,
                "isLocalService": True,
            }
        ],
    }
    for prefix in ("webGl", "webGl2"):
        result[f"{prefix}:parameters"] = {"3379": 8192, "37137": 18446744073709552000}
        result[f"{prefix}:contextAttributes"] = {
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
        result[f"{prefix}:shaderPrecisionFormats"] = {
            f"{shader},{precision}": {"rangeMin": 127, "rangeMax": 127, "precision": 23}
            for shader in (35632, 35633)
            for precision in range(36336, 36342)
        }
        result[f"{prefix}:supportedExtensions"] = ["SYNTHETIC_extension"]
    return result


PREFERENCES = {"webgl.enable-webgl2": True, "webgl.force-enabled": True}
PROVENANCE = ei.GeneratorProvenance(
    "independent-review", "4" * 64, "5" * 64, "independent-synthetic", "6" * 64
)


class FixtureGenerator:
    def __init__(self):
        self.calls = 0
        self.hook = lambda: None
        self.lock = threading.Lock()

    def provenance(self, binding):
        return PROVENANCE

    def generate(self, binding):
        with self.lock:
            self.calls += 1
            call = self.calls
        self.hook()
        config = supported_config(binding)
        config["audio:seed"] += call
        return config, dict(PREFERENCES), "7" * 64


class IndependentStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.profiles = ProfileStore(Path(self.temp.name) / "profiles")
        self.store = ei.EngineIdentityStore(self.profiles)
        self.binding = accepted_binding()
        self.lease = self.profiles.acquire(self.binding.profile_id)
        self.generator = FixtureGenerator()
        self.path = self.lease.paths.directory / ei.ARTIFACT_NAME

    def tearDown(self):
        self.lease.release()
        self.temp.cleanup()

    def create(self):
        return self.store.load_or_create(self.lease, self.binding, self.generator)

    def test_real_interpreter_restart_reuses_complete_exact_artifact(self):
        first = self.create()
        before = self.path.read_bytes()
        self.lease.release()
        script = (
            "import sys;sys.path[:0]="
            + repr([str(Path(ei.__file__).resolve().parents[2]), str(Path(__file__).parent)])
            + ";from test_independent_engine_identity import *;"
            "p=ProfileStore(Path(sys.argv[1]));g=FixtureGenerator();"
            "g.generate=lambda _:(_ for _ in ()).throw(AssertionError('regeneration'));"
            "lease=p.acquire(accepted_binding().profile_id);"
            "value=ei.EngineIdentityStore(p).load_or_create(lease,accepted_binding(),g);"
            "print(value.artifact_sha256);lease.release()"
        )
        child = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script, str(self.profiles.root)],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(child.stdout.strip(), first.artifact_sha256)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.generator.calls, 1)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX-only supported storage")
    def test_fork_inherited_lease_cannot_create_and_does_not_release_parent(self):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                self.create()
                result = b"unexpected-success"
            except ei.EngineIdentityError as error:
                result = error.reason.encode()
            except BaseException:
                result = b"unexpected-error"
            self.lease.release()
            os.write(write_fd, result)
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 1024)
        os.close(read_fd)
        os.waitpid(pid, 0)
        self.assertEqual(result, b"profile_lease_required")
        self.assertTrue(self.lease.active)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.generator.calls, 0)
        self.create()

    def test_competing_calls_never_return_two_different_identities(self):
        barrier = threading.Barrier(2, timeout=5)
        self.generator.hook = barrier.wait
        results, errors = [], []

        def run():
            try:
                results.append(self.create())
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ei.EngineIdentityError)
        self.assertEqual(self.path.read_text(), results[0].artifact_json)
        self.generator.hook = lambda: None
        self.assertEqual(self.create(), results[0])
        self.assertEqual(self.generator.calls, 2)

    def test_missing_artifact_with_existing_browser_data_never_generates(self):
        (self.lease.paths.browser_data / "synthetic-session").write_bytes(b"synthetic")
        with self.assertRaisesRegex(ei.EngineIdentityError, "profile_not_fresh"):
            self.create()
        self.assertEqual(self.generator.calls, 0)
        self.assertFalse(self.path.exists())

    def test_directory_fsync_failure_keeps_same_complete_identity_on_retry(self):
        original = os.fsync
        count = 0

        def fail_second(fd):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("synthetic directory fsync failure")
            return original(fd)

        with patch.object(ei.os, "fsync", side_effect=fail_second):
            with self.assertRaises(ei.EngineIdentityError):
                self.create()
        before = self.path.read_bytes()
        second = self.create()
        self.assertEqual(before.decode(), second.artifact_json)
        self.assertEqual(self.generator.calls, 1)

    def test_dpr_change_never_reuses_or_regenerates(self):
        self.create()
        before = self.path.read_bytes()
        changed = replace(self.binding, display=replace(self.binding.display, device_pixel_ratio=2))
        with self.assertRaisesRegex(ei.EngineIdentityError, "identity_migration_required"):
            self.store.load_or_create(self.lease, changed, self.generator)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.generator.calls, 1)

    def test_legacy_symlink_is_migration_blocker_even_when_target_is_missing(self):
        (self.lease.paths.directory / ".camoufox-identity.json").symlink_to("missing")
        with self.assertRaisesRegex(ei.EngineIdentityError, "identity_migration_required"):
            self.create()
        self.assertEqual(self.generator.calls, 0)

    def test_separate_profile_lease_cannot_be_acquired_during_generation(self):
        from team_browser.local.errors import ProfileInUseError

        def competing_acquire():
            with self.assertRaises(ProfileInUseError):
                ProfileStore(self.profiles.root).acquire(self.binding.profile_id)

        self.generator.hook = competing_acquire
        self.create()

    def test_returned_nested_values_are_copies(self):
        first = self.create()
        config = json.loads(first.config_json)
        config["voices"][0]["name"] = "changed"
        config["webGl:parameters"]["3379"] = 1
        prefs = first.firefox_user_prefs
        prefs["webgl.force-enabled"] = False
        self.assertEqual(first, self.create())
        self.assertNotEqual(config, json.loads(first.config_json))
        self.assertEqual(first.firefox_user_prefs, PREFERENCES)


class IndependentSchemaTests(unittest.TestCase):
    def check_bad_config(self, key, value):
        b = accepted_binding()
        config = supported_config(b)
        config[key] = value
        with self.assertRaises(ei.EngineIdentityError):
            ei.validate_identity(config, PREFERENCES, b)

    def test_app_version_must_match_ua_os(self):
        self.check_bad_config("navigator.appVersion", "5.0 (Windows)")

    def test_webgl_nested_shapes_and_primitive_types_are_validated(self):
        for key, value in (
            ("webGl:contextAttributes", {"alpha": "yes"}),
            ("webGl:shaderPrecisionFormats", {"bogus": True}),
            ("webGl:shaderPrecisionFormats", {"35633,36336": {"precision": "23"}}),
            ("webGl:parameters", {"3379": {"unrelated": "tree"}}),
        ):
            with self.subTest(key=key, value=value):
                self.check_bad_config(key, value)

    def test_all_scalar_integer_fields_reject_bool_and_float(self):
        for key in ei._INTEGER_KEYS:
            for value in (True, 1.0):
                with self.subTest(key=key, value=value):
                    self.check_bad_config(key, value)

    def test_unknown_config_and_preferences_never_pass(self):
        b = accepted_binding()
        for key in ("humanize", "addons", "webrtc:ipv4", "geolocation:latitude", "proxy"):
            config = supported_config(b)
            config[key] = "synthetic"
            with self.subTest(key=key), self.assertRaises(ei.EngineIdentityError):
                ei.validate_identity(config, PREFERENCES, b)
        for key in (
            "network.proxy.type",
            "privacy.resistFingerprinting",
            "security.enterprise_roots.enabled",
        ):
            with self.subTest(key=key), self.assertRaises(ei.EngineIdentityError):
                ei.validate_identity(supported_config(b), {**PREFERENCES, key: True}, b)

    def test_json_tree_depth_and_byte_bounds(self):
        self.check_bad_config("webGl:parameters", {"a": [[[[[[[[1]]]]]]]]})
        b = accepted_binding()
        c = supported_config(b)
        c["webGl:parameters"] = {str(i): "x" * 2048 for i in range(100)}
        with self.assertRaises(ei.EngineIdentityError):
            ei.validate_identity(c, PREFERENCES, b)

    def test_voice_booleans_duplicates_and_missing_default_rejected(self):
        b = accepted_binding()
        for change in ({"isLocalService": 1}, {"isDefault": 1}, {"isDefault": False}):
            voices = supported_config(b)["voices"]
            voices[0].update(change)
            self.check_bad_config("voices", voices)
        self.check_bad_config("voices", supported_config(b)["voices"] * 2)

    def test_properties_signed_seed_bool_alias_and_missing_fields_fail(self):
        c = supported_config(accepted_binding())
        value = ei.EngineIdentity(ei._canonical({"config": c}))
        kinds = {str: "str", int: "uint", bool: "bool", list: "array", dict: "dict"}
        rows = [{"property": k, "type": kinds[type(v)]} for k, v in c.items()]

        def validate(rows):
            raw = json.dumps(rows).encode()
            value.validate_engine_properties(raw, hashlib.sha256(raw).hexdigest())

        validate(rows)
        for key, kind in (("fonts:spacing_seed", "int"), ("voices:blockIfNotDefined", "uint")):
            changed = copy.deepcopy(rows)
            next(row for row in changed if row["property"] == key)["type"] = kind
            with self.subTest(key=key), self.assertRaises(ei.EngineIdentityError):
                validate(changed)
        with self.assertRaises(ei.EngineIdentityError):
            validate(rows[:-1])


class IndependentHelperTests(unittest.TestCase):
    def test_spawn_environment_input_and_timeout_are_bounded(self):
        b = accepted_binding()
        response = {
            "config": supported_config(b),
            "firefox_user_prefs": PREFERENCES,
            "selected_preset_sha256": "7" * 64,
        }
        seen = {}

        def fake_run(command, **kwargs):
            seen.update(kwargs)
            seen["command"] = command
            kwargs["stdout"].write(ei._canonical(response).encode())
            return SimpleNamespace(returncode=0)

        with (
            patch.object(ei.OfflineCamoufoxGenerator, "provenance", return_value=PROVENANCE),
            patch.object(ei.subprocess, "run", side_effect=fake_run),
            patch.object(ei, "_dependency_roots", return_value=(Path(tempfile.gettempdir()),)),
            patch.dict(os.environ, {"HTTPS_PROXY": "synthetic-secret", "CAMOU_CONFIG_1": "bad"}),
        ):
            result = ei.OfflineCamoufoxGenerator().generate(b)
        self.assertEqual(result[0], response["config"])
        self.assertLessEqual(len(seen["input"]), 16384)
        self.assertEqual(seen["timeout"], 30)
        self.assertNotIn("HTTPS_PROXY", seen["env"])
        self.assertNotIn("CAMOU_CONFIG_1", seen["env"])
        self.assertNotIn("synthetic-secret", repr(seen))
        self.assertIn("-I", seen["command"])
        self.assertIn("-B", seen["command"])
        self.assertIn("-S", seen["command"])
        self.assertEqual(seen["stderr"], subprocess.DEVNULL)

    def test_helper_timeout_reports_fixed_diagnostic(self):
        with (
            patch.object(ei.OfflineCamoufoxGenerator, "provenance", return_value=PROVENANCE),
            patch.object(ei.subprocess, "run", side_effect=subprocess.TimeoutExpired("secret", 30)),
        ):
            with self.assertRaisesRegex(
                ei.EngineIdentityError, "offline_generator_failed"
            ) as error:
                ei.OfflineCamoufoxGenerator().generate(accepted_binding())
        self.assertNotIn("secret", str(error.exception))

    def test_oversized_malformed_and_untrusted_helper_output_fails_closed(self):
        for raw in (
            b"x" * (ei.MAX_ARTIFACT_BYTES + 1),
            b"[]",
            b'{"error":"secret-location"}',
            b'{"error":"one","error":"two"}',
            b'{"error":NaN}',
        ):

            def fake_run(command, **kwargs):
                kwargs["stdout"].write(raw)
                return SimpleNamespace(returncode=0)

            with (
                self.subTest(raw=raw[:40]),
                patch.object(ei.OfflineCamoufoxGenerator, "provenance", return_value=PROVENANCE),
                patch.object(ei, "_dependency_roots", return_value=(Path(tempfile.gettempdir()),)),
                patch.object(ei.subprocess, "run", side_effect=fake_run),
            ):
                with self.assertRaises(ei.EngineIdentityError) as error:
                    ei.OfflineCamoufoxGenerator().generate(accepted_binding())
            self.assertNotIn("secret-location", str(error.exception))

    def test_real_bootstrap_ignores_pth_sitecustomize_and_poisoned_bytecode(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            environment = root / "venv"
            venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
            executable = environment / "bin" / "python"
            site = (
                environment
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            package = site / "independent_bootstrap_fixture"
            package.mkdir()
            source = package / "__init__.py"
            source.write_text("ORIGIN = 'verified-source'\n")
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir()
            cache.write_bytes(
                importlib._bootstrap_external._code_to_timestamp_pyc(
                    compile("ORIGIN = 'poisoned-cache'", str(source), "exec"),
                    int(source.stat().st_mtime),
                    source.stat().st_size,
                )
            )
            (site / "independent-fixture.pth").write_text(
                "import builtins; builtins.INDEPENDENT_PTH_RAN = True\n"
            )
            (site / "sitecustomize.py").write_text(
                "import builtins; builtins.INDEPENDENT_SITE_RAN = True\n"
            )
            probe = root / "probe.py"
            probe.write_text(
                "import json, builtins, sys, resource; import independent_bootstrap_fixture as f; "
                "print(json.dumps({'origin':f.ORIGIN, 'pth':getattr(builtins, 'INDEPENDENT_PTH_RAN', False), "
                "'site':getattr(builtins, 'INDEPENDENT_SITE_RAN', False), 'no_site':sys.flags.no_site, "
                "'cpu':resource.getrlimit(resource.RLIMIT_CPU), 'file':resource.getrlimit(resource.RLIMIT_FSIZE)}))"
            )
            # The fixture really is exploitable by the former -I -B invocation:
            # timestamp/size cache checks accept this safe synthetic cached code.
            control = subprocess.run(
                [str(executable), "-I", "-B", str(probe)],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            prior = json.loads(control.stdout)
            self.assertEqual(prior["origin"], "poisoned-cache")
            self.assertTrue(prior["pth"])
            self.assertTrue(prior["site"])
            with patch.object(ei.sys, "executable", str(executable)):
                command = ei._worker_command(probe, (site,))
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            final = json.loads(result.stdout)
            self.assertEqual(final["origin"], "verified-source")
            self.assertFalse(final["pth"])
            self.assertFalse(final["site"])
            self.assertEqual(final["no_site"], 1)
            self.assertEqual(final["cpu"], [20, 20])
            self.assertEqual(final["file"], [1048576, 1048576])

    def test_bootstrap_has_guard_before_dependency_import_and_refuses_sourceless_cache(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / "must-not-be-created"
            module = root / "independent_guard_fixture.py"
            module.write_text(f"open({str(target)!r}, 'w').write('must not happen')\n")
            (root / "independent_sourceless.pyc").write_bytes(
                importlib._bootstrap_external._code_to_timestamp_pyc(
                    compile("MARKER = True", "synthetic-cache", "exec"), 0, 0
                )
            )
            probe = root / "probe.py"
            probe.write_text("""
try:
    import independent_guard_fixture
except RuntimeError:
    pass
else:
    raise AssertionError('unguarded dependency import')
try:
    import independent_sourceless
except ModuleNotFoundError:
    pass
else:
    raise AssertionError('sourceless bytecode import')
print('guarded-source-only')
""")
            result = subprocess.run(
                ei._worker_command(probe, (root,)),
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            self.assertEqual(result.stdout.strip(), "guarded-source-only")
            self.assertFalse(target.exists())

    def test_source_manifest_changes_when_record_is_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "synthetic_package" / "__init__.py"
            source.parent.mkdir()
            source.write_text("MARKER = 'first'\n")
            fake = SimpleNamespace(
                files=[Path("synthetic_package/__init__.py")],
                version="1.0",
                locate_file=lambda member: root / member,
            )
            with patch.object(ei.importlib.metadata, "distribution", return_value=fake):
                first = ei._package_manifest("synthetic_package")
                source.write_text("MARKER = 'other'\n")
                second = ei._package_manifest("synthetic_package")
            self.assertNotEqual(first[1], second[1])

    def test_reviewed_package_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "synthetic_package" / "__init__.py"
            source.parent.mkdir()
            target = root / "original.py"
            target.write_text("MARKER = 'first'\n")
            source.symlink_to(target)
            fake = SimpleNamespace(
                files=[Path("synthetic_package/__init__.py")],
                version="1.0",
                locate_file=lambda member: root / member,
            )
            with patch.object(ei.importlib.metadata, "distribution", return_value=fake):
                with self.assertRaisesRegex(ei.EngineIdentityError, "generator_package_changed"):
                    ei._package_manifest("synthetic_package")

    def test_actual_audit_hook_blocks_python_socket_process_and_write(self):
        source_root = str(Path(ei.__file__).resolve().parents[2])
        script = """
import sys, socket, subprocess, os, sqlite3
sys.path.insert(0, sys.argv[1])
from team_browser.client.engine_identity import _offline_guard, EngineIdentityError
sys.addaudithook(_offline_guard)
actions = [lambda: socket.socket(), lambda: socket.getaddrinfo('invalid.invalid', 1),
           lambda: subprocess.Popen([sys.executable, '-c', 'pass']),
           lambda: open(sys.argv[2], 'w'), lambda: sqlite3.connect(sys.argv[2])]
for action in actions:
    try:
        action()
    except EngineIdentityError:
        continue
    raise AssertionError('guard allowed operation')
print('all-denied')
"""
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "must-not-exist"
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", script, source_root, str(target)],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(result.stdout.strip(), "all-denied")
            self.assertFalse(target.exists())


@unittest.skipUnless(os.environ.get("TBM_TEST_OFFLINE_IDENTITY") == "1", "official-wheel opt-in")
class IndependentOfficialWheelTests(unittest.TestCase):
    def test_official_generated_artifact_is_exact_after_process_restart(self):
        with tempfile.TemporaryDirectory() as root:
            profiles = ProfileStore(Path(root) / "profiles")
            binding = accepted_binding()
            with profiles.acquire(binding.profile_id) as lease:
                first = ei.EngineIdentityStore(profiles).load_or_create(
                    lease, binding, ei.OfflineCamoufoxGenerator()
                )
                artifact_path = lease.paths.directory / ei.ARTIFACT_NAME
                before = artifact_path.read_bytes()
            script = (
                "import sys;sys.path[:0]="
                + repr([str(Path(ei.__file__).resolve().parents[2]), str(Path(__file__).parent)])
                + ";from test_independent_engine_identity import *;"
                "p=ProfileStore(Path(sys.argv[1]));g=ei.OfflineCamoufoxGenerator();"
                "g.generate=lambda _:(_ for _ in ()).throw(AssertionError('regeneration'));"
                "lease=p.acquire(accepted_binding().profile_id);"
                "value=ei.EngineIdentityStore(p).load_or_create(lease,accepted_binding(),g);"
                "print(json.dumps({'artifact':value.artifact_sha256,'config':value.config_sha256,"
                "'preferences':value.firefox_user_prefs}));lease.release()"
            )
            child = subprocess.run(
                [sys.executable, "-I", "-B", "-c", script, str(profiles.root)],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            final = json.loads(child.stdout)
            self.assertEqual(
                final,
                {
                    "artifact": first.artifact_sha256,
                    "config": first.config_sha256,
                    "preferences": first.firefox_user_prefs,
                },
            )
            self.assertEqual(before, artifact_path.read_bytes())

    def test_actual_linux_macos_windows_bound_catalogue_generation(self):
        generator = ei.OfflineCamoufoxGenerator()
        cases = (
            ("linux", "linux", ei.AcceptedDisplay(1600, 900, 1575, 880, 24, 1)),
            ("darwin", "macos", ei.AcceptedDisplay(2240, 1260, 2240, 1230, 30, 2)),
            ("win32", "windows", ei.AcceptedDisplay(1920, 1080, 1920, 1032, 24, 1)),
        )
        for platform, target_os, display in cases:
            with self.subTest(target_os=target_os):
                binding = replace(
                    accepted_binding(), platform=platform, target_os=target_os, display=display
                )
                config, preferences, selected = generator.generate(binding)
                ei.validate_identity(config, preferences, binding)
                self.assertEqual(set(config), ei._ALLOWED_KEYS)
                self.assertEqual(len(selected), 64)
                self.assertEqual(config["screen.width"], display.width)
                self.assertEqual(config["screen.colorDepth"], display.color_depth)


if __name__ == "__main__":
    unittest.main()
