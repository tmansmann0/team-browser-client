"""Synthetic fixed-collector contracts. No Playwright/browser is installed/run."""

import asyncio
import copy
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.client import identity_probe as probe
from team_browser.client.camoufox_runtime import (
    IDENTITY_PROBE_SCHEMA,
    IDENTITY_SIGNAL_NAMES,
    expected_identity_core,
    identity_voices_sha256,
)
from team_browser.client.engine_identity import AcceptedDisplay, EngineIdentity
from team_browser.client.store import WorkspaceError


CHALLENGE = "a" * 32
DISPLAY = AcceptedDisplay(1920, 1080, 1920, 1040, 24, 1)
CORE = {
    "navigator.userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
    "navigator.platform": "Linux x86_64",
    "navigator.oscpu": "Linux x86_64",
    "navigator.appVersion": "5.0 (X11)",
    "navigator.hardwareConcurrency": 8,
    "navigator.maxTouchPoints": 0,
    "navigator.language": "en-US",
    "navigator.languages": ["en-US"],
    "screen.width": 1920,
    "screen.height": 1080,
    "screen.availWidth": 1920,
    "screen.availHeight": 1040,
    "screen.colorDepth": 24,
    "screen.pixelDepth": 24,
    "timezone": "America/New_York",
    "devicePixelRatio": 1,
}
VOICES = [
    {
        "name": "Synthetic one",
        "lang": "en-US",
        "voiceUri": "urn:synthetic:one",
        "isDefault": True,
        "isLocalService": True,
    },
    {
        "name": "Synthetic two",
        "lang": "en-US",
        "voiceUri": "urn:synthetic:two",
        "isDefault": False,
        "isLocalService": True,
    },
]
GPU = {
    "vendor": "Synthetic vendor",
    "renderer": "Synthetic renderer",
    "parameters": {"3379": 8192, "3386": [8192, 8192], "34921": 16, "34930": 16},
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def artifact():
    # Models an already validated artifact supplied by the trusted runtime.
    # This test does not claim to revalidate the offline generator/store here.
    config = {k: copy.deepcopy(v) for k, v in CORE.items() if k != "devicePixelRatio"}
    config["voices"] = copy.deepcopy(VOICES)
    config["canvas:seed"] = 1987654321
    config["audio:seed"] = 1987654322
    config["fonts:spacing_seed"] = 1987654323
    for prefix in ("webGl", "webGl2"):
        config[f"{prefix}:parameters"] = copy.deepcopy(GPU["parameters"])
    config["webGl:vendor"], config["webGl:renderer"] = GPU["vendor"], GPU["renderer"]
    return EngineIdentity(
        canonical(
            {
                "config": config,
                "binding": {
                    "display": {
                        "width": 1920,
                        "height": 1080,
                        "avail_width": 1920,
                        "avail_height": 1040,
                        "color_depth": 24,
                        "device_pixel_ratio": 1.0,
                    }
                },
            }
        )
    )


def payload():
    return {
        "schema": IDENTITY_PROBE_SCHEMA,
        "challenge": CHALLENGE,
        "core": copy.deepcopy(CORE),
        "canvas": [i % 256 for i in range(2048)],
        "voices": copy.deepcopy(VOICES),
        "webgl": copy.deepcopy(GPU),
        "webgl2": copy.deepcopy(GPU),
    }


class Events:
    def __init__(self):
        self.listeners = {}

    def on(self, event, callback):
        self.listeners.setdefault(event, []).append(callback)

    def remove_listener(self, event, callback):
        self.listeners[event].remove(callback)

    def emit(self, event, *args):
        for callback in list(self.listeners.get(event, [])):
            callback(*args)


class ForeignPage:
    """Any interaction, other than an object-identity comparison, is a failure."""

    def __getattr__(self, name):
        raise AssertionError(f"Foreign page was accessed: {name}")


class FakePage(Events):
    def __init__(self, context):
        super().__init__()
        self.context = context
        self.url = "about:blank"
        self.main_frame = SimpleNamespace(page=self, url="about:blank")
        self.frames = [self.main_frame]
        self.closed = False
        self.close_calls = []
        self.evaluate_calls = []
        self.output = canonical(payload())
        self.after_evaluate = lambda: None
        self.on_close = lambda: None
        self.evaluate_error = self.close_error = None
        self.evaluate_started = asyncio.Event()
        self.close_started = asyncio.Event()
        self.evaluate_wait = self.close_wait = None
        self.close_ack = True

    async def evaluate(self, script, arg):
        self.evaluate_calls.append((script, arg))
        self.evaluate_started.set()
        if self.evaluate_wait is not None:
            await self.evaluate_wait.wait()
        if self.evaluate_error is not None:
            raise self.evaluate_error
        self.after_evaluate()
        return self.output

    async def close(self, **kwargs):
        self.close_calls.append(kwargs)
        self.close_started.set()
        if self.close_wait is not None:
            await self.close_wait.wait()
        if self.close_error:
            raise self.close_error
        self.on_close()
        if self.close_ack:
            self.closed = True
            if self in self.context.pages:
                self.context.pages.remove(self)
            self.emit("close")

    def is_closed(self):
        return self.closed


class FakeContext(Events):
    def __init__(self):
        super().__init__()
        self.original = ForeignPage()
        self.pages = [self.original]
        self.page = FakePage(self)
        self.new_page_calls = 0
        self.new_page_wait = None
        self.new_page_error = None
        self.on_new_page = lambda: None
        self.new_page_started = asyncio.Event()

    async def new_page(self):
        self.new_page_calls += 1
        self.new_page_started.set()
        if self.new_page_wait is not None:
            await self.new_page_wait.wait()
        if self.new_page_error:
            raise self.new_page_error
        self.pages.append(self.page)
        self.on_new_page()
        return self.page


class FixedIdentityProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = FakeContext()
        self.collector = probe.FixedCamoufoxIdentityProbe()
        self.artifact = artifact()

    async def collect(self, **kwargs):
        return await self.collector.collect(
            kwargs.get("context", self.context),
            kwargs.get("challenge", CHALLENGE),
            kwargs.get("artifact", self.artifact),
        )

    async def rejected(self, code, **kwargs):
        with self.assertRaises(WorkspaceError) as caught:
            await self.collect(**kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("SENSITIVE", str(caught.exception))

    def set_payload(self, data):
        self.context.page.output = canonical(data)

    def assert_clean(self):
        self.assertEqual(self.context.pages, [self.context.original])
        self.assertTrue(self.context.page.is_closed())
        self.assertEqual(self.context.page.close_calls, [{"run_before_unload": False}])
        self.assertFalse(any(self.context.listeners.values()))
        self.assertFalse(any(self.context.page.listeners.values()))

    async def test_success_uses_one_fixed_call_and_acknowledged_owned_cleanup(self):
        before = datetime.now(timezone.utc)
        observed = await self.collect()
        self.assertEqual(self.context.new_page_calls, 1)
        self.assertEqual(
            self.context.page.evaluate_calls, [(probe.FIXED_IDENTITY_SCRIPT, CHALLENGE)]
        )
        self.assertEqual(observed.probe_id, probe.PROBE_ID)
        self.assertEqual(observed.challenge, CHALLENGE)
        self.assertEqual(observed.artifact_sha256, self.artifact.artifact_sha256)
        self.assertGreaterEqual(observed.observed_at, before)
        self.assertEqual(
            observed.core_json, canonical(expected_identity_core(self.artifact, DISPLAY))
        )
        self.assertEqual(tuple(k for k, _ in observed.signals), IDENTITY_SIGNAL_NAMES)
        digests = dict(observed.signals)
        self.assertEqual(digests["canvas"], hashlib.sha256(bytes(payload()["canvas"])).hexdigest())
        self.assertEqual(digests["voices"], identity_voices_sha256(VOICES))
        self.assertEqual(digests["webgl"], hashlib.sha256(canonical(GPU).encode()).hexdigest())
        policy = SimpleNamespace(
            program=SimpleNamespace(probe_id=probe.PROBE_ID),
            binding=SimpleNamespace(display=DISPLAY),
        )
        self.assertEqual(len(observed.checked_digest(policy, self.artifact, CHALLENGE, before)), 64)
        self.assert_clean()

    async def test_script_is_version_bound_fixed_and_excludes_network_or_accounts(self):
        await self.collect()
        script, arg = self.context.page.evaluate_calls[0]
        self.assertTrue(probe.PROBE_ID.endswith(hashlib.sha256(script.encode()).hexdigest()))
        self.assertEqual(arg, CHALLENGE)
        for forbidden in (
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "cookie",
            "localStorage",
            "sessionStorage",
            "querySelector",
            "Worker(",
            "AudioContext",
            "1987654321",
        ):
            self.assertNotIn(forbidden, script)
        for fixed in ("getImageData(0, 0, 32, 16)", "getVoices()", 'gpu("webgl2")'):
            self.assertIn(fixed, script)

    async def test_voice_order_is_normalized_but_fields_and_multiplicity_are_not_erased(self):
        first = await self.collect()
        self.context = FakeContext()
        data = payload()
        data["voices"].reverse()
        self.set_payload(data)
        second = await self.collect()
        self.assertEqual(first.core_json, second.core_json)
        self.assertEqual(first.signals, second.signals)
        for mutation in ("name", "lang", "voiceUri", "isDefault", "isLocalService", "duplicate"):
            with self.subTest(mutation=mutation):
                self.context = FakeContext()
                data = payload()
                if mutation == "duplicate":
                    data["voices"].append(copy.deepcopy(data["voices"][0]))
                elif type(data["voices"][0][mutation]) is bool:
                    data["voices"][0][mutation] = not data["voices"][0][mutation]
                else:
                    data["voices"][0][mutation] += " changed"
                self.set_payload(data)
                await self.rejected("identity_surface_mismatch")
                self.assert_clean()

    async def test_valid_but_wrong_core_gpu_and_dpr_fail_against_artifact(self):
        mutations = [
            ("core", "navigator.userAgent", "Another UA"),
            ("core", "navigator.platform", "Win32"),
            ("core", "timezone", "Europe/London"),
            ("core", "devicePixelRatio", 2),
            ("core", "navigator.languages", ["en-GB"]),
            ("webgl", "vendor", "Wrong vendor"),
            ("webgl2", "renderer", "Wrong renderer"),
            ("webgl", "parameters", {**GPU["parameters"], "3379": 4096}),
            ("webgl2", "parameters", {**GPU["parameters"], "3386": [4096, 8192]}),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                self.context = FakeContext()
                data = payload()
                data[section][key] = value
                self.set_payload(data)
                await self.rejected("identity_surface_mismatch")
                self.assert_clean()

    async def test_canvas_is_actual_observation_and_changes_continuity_digest(self):
        first = await self.collect()
        self.context = FakeContext()
        data = payload()
        data["canvas"][0] = 12
        self.set_payload(data)
        second = await self.collect()
        self.assertEqual(first.core_json, second.core_json)
        self.assertNotEqual(dict(first.signals)["canvas"], dict(second.signals)["canvas"])

    async def test_bad_challenge_and_artifact_never_create_page(self):
        for challenge in (None, True, "", "A" * 32, "a" * 64, "https://example.test"):
            with self.subTest(challenge=challenge):
                await self.rejected("identity_probe_invalid", challenge=challenge)
        for value in (None, {}, SimpleNamespace(artifact_json=self.artifact.artifact_json)):
            await self.rejected("identity_probe_invalid", artifact=value)
        for raw in ("{}", "{" * 10000, "x" * (probe.MAX_ARTIFACT_BYTES + 1)):
            await self.rejected("identity_probe_artifact_invalid", artifact=EngineIdentity(raw))
        self.assertEqual(self.context.new_page_calls, 0)

    async def test_response_schema_challenge_and_scalar_types_are_strict(self):
        mutations = [
            lambda d: d.update(schema="future-schema"),
            lambda d: d.update(challenge="b" * 32),
            lambda d: d.update(extra="unexpected"),
            lambda d: d.pop("voices"),
            lambda d: d.update(core=[]),
            lambda d: d["core"].update(extra="unexpected"),
            lambda d: d["core"].update({"navigator.hardwareConcurrency": True}),
            lambda d: d["core"].update({"navigator.maxTouchPoints": 0.0}),
            lambda d: d["core"].update({"devicePixelRatio": True}),
            lambda d: d["core"].update({"devicePixelRatio": 0}),
            lambda d: d["core"].update({"navigator.languages": "en-US"}),
            lambda d: d["core"].update({"navigator.languages": ["en-US"] * 17}),
            lambda d: d["core"].update({"timezone": "a" * 81}),
            lambda d: d["core"].update({"navigator.userAgent": "x\nSENSITIVE"}),
            lambda d: d["core"].update({"navigator.userAgent": "x" * 513}),
            lambda d: d.update(canvas=[0] * 2047),
            lambda d: d.update(canvas=[0] * 2049),
            lambda d: d["canvas"].__setitem__(0, True),
            lambda d: d["canvas"].__setitem__(0, 256),
            lambda d: d.update(voices=[]),
            lambda d: d.update(voices=[VOICES[0]] * 513),
            lambda d: d["voices"][0].update(voiceURI="SENSITIVE"),
            lambda d: d["voices"][0].update(isDefault=1),
            lambda d: d["voices"][0].update(name="x" * 513),
            lambda d: d.update(webgl=None),
            lambda d: d["webgl2"].update(renderer=""),
            lambda d: d["webgl"]["parameters"].update({"3379": True}),
            lambda d: d["webgl"]["parameters"].update({"3386": [8192]}),
            lambda d: d["webgl"]["parameters"].update({"3386": [8192, False]}),
            lambda d: d["webgl"]["parameters"].update({"1": 100}),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.context = FakeContext()
                data = payload()
                mutate(data)
                self.set_payload(data)
                await self.rejected("identity_probe_invalid")
                self.assert_clean()

    async def test_raw_response_is_bounded_json_without_duplicate_keys_or_nonfinite_values(self):
        good = canonical(payload())
        values = [
            None,
            {},
            [],
            b"{}",
            "",
            "{",
            "[]",
            "null",
            "true",
            "x" * (probe.MAX_RESPONSE_BYTES + 1),
            '"' + "é" * (probe.MAX_RESPONSE_BYTES // 2) + '"',
            '{"schema":"duplicate",' + good[1:],
            good.replace('"devicePixelRatio":1', '"devicePixelRatio":NaN'),
            good.replace('"devicePixelRatio":1', '"devicePixelRatio":Infinity'),
            good.replace('"devicePixelRatio":1', '"devicePixelRatio":1e400'),
            "[" * 10000 + "0" + "]" * 10000,
        ]
        for i, value in enumerate(values):
            with self.subTest(case=i):
                self.context = FakeContext()
                self.context.page.output = value
                await self.rejected("identity_probe_invalid")
                self.assert_clean()

    async def test_nonblank_and_frames_never_evaluated(self):
        for target in ("url", "frame_url", "frames"):
            with self.subTest(target=target):
                self.context = FakeContext()
                if target == "url":
                    self.context.page.url = "about:blank#not-exact"
                elif target == "frame_url":
                    self.context.page.main_frame.url = "https://SENSITIVE.example/"
                else:
                    self.context.page.frames.append(object())
                await self.rejected("identity_probe_context_changed")
                self.assertEqual(self.context.page.evaluate_calls, [])
                self.assert_clean()

    async def test_same_url_navigation_and_frame_replacement_are_rejected(self):
        for event in ("framenavigated", "frameattached", "framedetached", "replace_frame"):
            with self.subTest(event=event):
                self.context = FakeContext()
                page = self.context.page
                if event == "replace_frame":

                    def mutate():
                        page.main_frame = SimpleNamespace(page=page, url="about:blank")
                        page.frames = [page.main_frame]
                else:

                    def mutate():
                        page.emit(event, page.main_frame)

                page.after_evaluate = mutate
                await self.rejected("identity_probe_context_changed")
                self.assert_clean()

    async def test_context_closure_during_evaluation_or_cleanup_prevents_evidence(self):
        for phase in ("evaluate", "close"):
            with self.subTest(phase=phase):
                self.context = FakeContext()

                def callback():
                    self.context.emit("close")

                if phase == "evaluate":
                    self.context.page.after_evaluate = callback
                else:
                    self.context.page.on_close = callback
                await self.rejected("identity_probe_context_changed")
                self.assert_clean()

    async def test_foreign_context_page_never_evaluated_or_closed(self):
        self.context.page.context = FakeContext()
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.evaluate_calls, [])
        self.assertEqual(self.context.page.close_calls, [])

    async def test_preexisting_page_returned_by_driver_never_touched_or_closed(self):
        self.context.pages.append(self.context.page)
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.evaluate_calls, [])
        self.assertEqual(self.context.page.close_calls, [])

    async def test_context_change_after_evaluation_is_not_closed_as_owned(self):
        self.context.page.after_evaluate = lambda: setattr(
            self.context.page, "context", FakeContext()
        )
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.close_calls, [])

    async def test_context_change_during_close_cannot_emit_evidence(self):
        foreign = FakeContext()
        self.context.page.on_close = lambda: setattr(self.context.page, "context", foreign)
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.close_calls, [{"run_before_unload": False}])
        self.assertEqual(foreign.page.close_calls, [])

    async def test_page_removed_without_closed_ack_fails_without_closing_other_tabs(self):
        self.context.page.after_evaluate = lambda: self.context.pages.remove(self.context.page)
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.close_calls, [])
        self.assertEqual(self.context.pages, [self.context.original])

    async def test_page_closed_during_evaluation_is_failure_without_double_close(self):
        def externally_closed():
            self.context.page.closed = True
            self.context.pages.remove(self.context.page)
            self.context.page.emit("close")

        self.context.page.after_evaluate = externally_closed
        await self.rejected("identity_probe_context_changed")
        self.assertEqual(self.context.page.close_calls, [])

    async def test_driver_error_redacts_details_and_still_closes_owned_page(self):
        self.context.page.evaluate_error = RuntimeError(
            "SENSITIVE account URL, cookie, native path"
        )
        await self.rejected("identity_probe_failed")
        self.assert_clean()

    async def test_upstream_workspace_error_does_not_bypass_error_redaction(self):
        self.context.page.evaluate_error = WorkspaceError("SENSITIVE", "SENSITIVE details")
        await self.rejected("identity_probe_failed")
        self.assert_clean()

    async def test_listener_cleanup_failure_does_not_skip_remaining_listeners(self):
        original = self.context.page.remove_listener

        def remove(event, callback):
            original(event, callback)
            if event == "close":
                raise RuntimeError("SENSITIVE failure")

        self.context.page.remove_listener = remove
        await self.rejected("identity_probe_cleanup_unverified")
        self.assert_clean()

    async def test_evaluation_timeout_closes_page(self):
        self.context.page.evaluate_wait = asyncio.Event()
        with patch.object(probe, "EVALUATE_TIMEOUT", 0.005):
            await self.rejected("identity_probe_failed")
        self.assert_clean()

    async def test_cancellation_resistant_evaluation_cannot_overrun_cleanup_budget(self):
        release = asyncio.Event()
        started = asyncio.Event()

        async def resistant(script, challenge):
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    pass
            return canonical(payload())

        self.context.page.evaluate = resistant
        try:
            with (
                patch.object(probe, "EVALUATE_TIMEOUT", 0.005),
                patch.object(probe, "CLEANUP_TIMEOUT", 0.01),
            ):
                await asyncio.wait_for(self.rejected("identity_probe_cleanup_unverified"), 0.5)
        finally:
            release.set()
        self.assertTrue(started.is_set())
        self.assert_clean()

    async def test_creation_error_is_unverified_cleanup(self):
        self.context.new_page_error = RuntimeError("SENSITIVE driver details")
        await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.close_calls, [])

    async def test_late_creation_after_timeout_is_closed_exactly(self):
        release = self.context.new_page_wait = asyncio.Event()
        asyncio.get_running_loop().call_later(0.02, release.set)
        with patch.object(probe, "CREATE_TIMEOUT", 0.005):
            await self.rejected("identity_probe_failed")
        self.assertEqual(self.context.page.evaluate_calls, [])
        self.assert_clean()

    async def test_unresolved_creation_is_bounded_and_reports_uncertain_cleanup(self):
        self.context.new_page_wait = asyncio.Event()
        with (
            patch.object(probe, "CREATE_TIMEOUT", 0.005),
            patch.object(probe, "CLEANUP_TIMEOUT", 0.01),
        ):
            await self.rejected("identity_probe_cleanup_unverified")
        self.assertEqual(self.context.page.close_calls, [])
        self.assertEqual(self.context.pages, [self.context.original])

    async def test_close_errors_and_missing_ack_do_not_emit_evidence(self):
        for failure in ("error", "unacknowledged", "timeout"):
            with self.subTest(failure=failure):
                self.context = FakeContext()
                if failure == "error":
                    self.context.page.close_error = RuntimeError("SENSITIVE close details")
                elif failure == "unacknowledged":
                    self.context.page.close_ack = False
                else:
                    self.context.page.close_wait = asyncio.Event()
                with patch.object(probe, "CLEANUP_TIMEOUT", 0.01):
                    await self.rejected("identity_probe_cleanup_unverified")
                self.assertEqual(self.context.page.close_calls, [{"run_before_unload": False}])

    async def test_cancel_during_evaluation_waits_for_cleanup_then_propagates(self):
        self.context.page.evaluate_wait = asyncio.Event()
        task = asyncio.create_task(self.collect())
        await self.context.page.evaluate_started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assert_clean()

    async def test_cancel_during_creation_closes_late_owned_page(self):
        release = self.context.new_page_wait = asyncio.Event()
        task = asyncio.create_task(self.collect())
        await self.context.new_page_started.wait()
        task.cancel()
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.context.page.evaluate_calls, [])
        self.assert_clean()

    async def test_repeated_cancel_during_cleanup_still_requires_acknowledgment(self):
        release = self.context.page.close_wait = asyncio.Event()
        task = asyncio.create_task(self.collect())
        await self.context.page.close_started.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assert_clean()

    async def test_expiry_after_cleanup_is_rejected(self):
        with patch.object(probe, "MAX_ELAPSED", -1):
            await self.rejected("identity_probe_expired")
        self.assert_clean()

    async def test_runtime_rejects_old_observation(self):
        from dataclasses import replace

        observed = await self.collect()
        now = datetime.now(timezone.utc)
        stale = replace(observed, observed_at=now - timedelta(seconds=11))
        policy = SimpleNamespace(
            program=SimpleNamespace(probe_id=probe.PROBE_ID),
            binding=SimpleNamespace(display=DISPLAY),
        )
        with self.assertRaises(WorkspaceError) as raised:
            stale.checked_digest(policy, self.artifact, CHALLENGE, now - timedelta(seconds=20))
        self.assertEqual(raised.exception.code, "identity_probe_invalid")


if __name__ == "__main__":
    unittest.main()
