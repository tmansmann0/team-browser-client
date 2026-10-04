"""Fixed, bounded observations from one disposable, exactly owned blank page.

This module does not install or launch a browser, grant native acceptance, or
read account pages. Real Camoufox/platform compatibility remains unverified.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any

from .camoufox_runtime import (
    IDENTITY_PROBE_SCHEMA,
    IDENTITY_SIGNAL_NAMES,
    IDENTITY_WEBGL_PARAMETERS,
    CamoufoxIdentityObservation,
    expected_identity_core,
    identity_voices_sha256,
)
from .engine_identity import MAX_ARTIFACT_BYTES, AcceptedDisplay, EngineIdentity
from .store import WorkspaceError


# Only this literal script is evaluated. Its sole input is a fresh challenge;
# no artifact/configuration, URL, shader, font, or caller-provided code enters JS.
FIXED_IDENTITY_SCRIPT = r"""async (challenge) => {
  "use strict";
  const fail = () => { throw new Error("identity-probe-invalid"); };
  const text = (v, max = 512) => {
    if (typeof v !== "string" || !v.length || v.length > max ||
        /[\u0000-\u001f\u007f]/u.test(v)) fail();
    return v;
  };
  const integer = (v, min, max) => {
    if (!Number.isSafeInteger(v) || v < min || v > max) fail();
    return v;
  };
  const bool = (v) => { if (typeof v !== "boolean") fail(); return v; };
  const blank = () => {
    if (window !== window.top || location.href !== "about:blank" ||
        document.URL !== "about:blank" || window.frames.length !== 0) fail();
  };
  if (typeof challenge !== "string" || !/^[a-f0-9]{32}$/.test(challenge)) fail();
  blank();
  const originalDocument = document;
  const started = performance.now();
  const core = {
    "navigator.userAgent": text(navigator.userAgent),
    "navigator.platform": text(navigator.platform),
    "navigator.oscpu": text(navigator.oscpu),
    "navigator.appVersion": text(navigator.appVersion),
    "navigator.hardwareConcurrency": integer(navigator.hardwareConcurrency, 1, 256),
    "navigator.maxTouchPoints": integer(navigator.maxTouchPoints, 0, 20),
    "navigator.language": text(navigator.language, 80),
    "screen.width": integer(screen.width, 320, 16384),
    "screen.height": integer(screen.height, 240, 16384),
    "screen.availWidth": integer(screen.availWidth, 1, 16384),
    "screen.availHeight": integer(screen.availHeight, 1, 16384),
    "screen.colorDepth": integer(screen.colorDepth, 1, 64),
    "screen.pixelDepth": integer(screen.pixelDepth, 1, 64),
    "timezone": text(Intl.DateTimeFormat().resolvedOptions().timeZone, 80),
    "devicePixelRatio": window.devicePixelRatio
  };
  if (!Number.isFinite(core.devicePixelRatio) || core.devicePixelRatio < 0.5 ||
      core.devicePixelRatio > 4) fail();
  const languages = navigator.languages;
  if (!Array.isArray(languages) || !languages.length || languages.length > 16) fail();
  core["navigator.languages"] = languages.map((v) => text(v, 80));

  // One fixed 32 x 16 RGBA fixture; no external image, text, or DOM content.
  const canvas = document.createElement("canvas");
  canvas.width = 32; canvas.height = 16;
  const ctx = canvas.getContext("2d", {willReadFrequently: true});
  if (!ctx) fail();
  const gradient = ctx.createLinearGradient(0, 0, 32, 16);
  gradient.addColorStop(0, "#1b3355"); gradient.addColorStop(1, "#e6a149");
  ctx.fillStyle = gradient; ctx.fillRect(0, 0, 32, 16);
  ctx.globalCompositeOperation = "multiply";
  ctx.fillStyle = "rgba(83,197,122,0.63)";
  ctx.beginPath(); ctx.arc(15.5, 8.5, 6.25, 0, Math.PI * 2); ctx.fill();
  const pixels = Array.from(ctx.getImageData(0, 0, 32, 16).data);
  if (pixels.length !== 2048) fail();

  const gpu = (kind) => {
    const c = document.createElement("canvas"); c.width = 1; c.height = 1;
    const gl = c.getContext(kind);
    if (!gl || gl.isContextLost() || !gl.getExtension("WEBGL_debug_renderer_info")) fail();
    const parameters = {
      "3379": integer(gl.getParameter(3379), 1, 2147483647),
      "34921": integer(gl.getParameter(34921), 1, 2147483647),
      "34930": integer(gl.getParameter(34930), 1, 2147483647)
    };
    const viewport = gl.getParameter(3386);
    if (!viewport || viewport.length !== 2) fail();
    parameters["3386"] = [integer(viewport[0], 1, 2147483647),
                          integer(viewport[1], 1, 2147483647)];
    const result = {vendor: text(gl.getParameter(37445)),
                    renderer: text(gl.getParameter(37446)), parameters};
    if (gl.isContextLost()) fail();
    return result;
  };
  const webgl = gpu("webgl"), webgl2 = gpu("webgl2");

  // At most 11 enumerations and 10 short timers, including an initial read.
  // Never synthesize speech or install a persistent event handler.
  const synth = window.speechSynthesis;
  if (!synth || typeof synth.getVoices !== "function") fail();
  let available;
  for (let attempt = 0; attempt <= 10; attempt++) {
    available = synth.getVoices();
    if (!Array.isArray(available) || available.length > 512) fail();
    if (available.length) break;
    if (attempt === 10) fail();
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  const voices = available.map((v) => ({
    name: text(v.name), lang: text(v.lang), voiceUri: text(v.voiceURI),
    isDefault: bool(v.default), isLocalService: bool(v.localService)
  }));
  blank();
  if (document !== originalDocument || performance.now() - started > 1500) fail();
  const result = JSON.stringify({schema: "camoufox-stable-surfaces-v1", challenge,
                                core, canvas: pixels, voices, webgl, webgl2});
  if (result.length > 262144) fail();
  return result;
}"""

PROBE_ID = "tbm-fixed-identity-v1-" + hashlib.sha256(FIXED_IDENTITY_SCRIPT.encode()).hexdigest()
MAX_RESPONSE_BYTES = 262144
CREATE_TIMEOUT = 1.0
EVALUATE_TIMEOUT = 2.0
CLEANUP_TIMEOUT = 1.0
MAX_ELAPSED = 4.5
_CORE_TEXT_KEYS = (
    "navigator.userAgent",
    "navigator.platform",
    "navigator.oscpu",
    "navigator.appVersion",
    "navigator.language",
    "timezone",
)
_CORE_INT_BOUNDS = {
    "navigator.hardwareConcurrency": (1, 256),
    "navigator.maxTouchPoints": (0, 20),
    "screen.width": (320, 16384),
    "screen.height": (240, 16384),
    "screen.availWidth": (1, 16384),
    "screen.availHeight": (1, 16384),
    "screen.colorDepth": (1, 64),
    "screen.pixelDepth": (1, 64),
}
_CORE_KEYS = (
    set(_CORE_TEXT_KEYS)
    | set(_CORE_INT_BOUNDS)
    | {
        "navigator.languages",
        "devicePixelRatio",
    }
)


class _ProbeFailure(WorkspaceError):
    """Only internally created diagnostics may cross the driver boundary."""


def _error(code: str = "identity_probe_invalid") -> _ProbeFailure:
    return _ProbeFailure(code, "The fixed owned-context identity observation was not verified")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _text(value: Any, maximum: int = 512) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(ord(c) >= 32 and ord(c) != 127 for c in value)
    )


def _integer(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _error()
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise _error()


def _load(raw: Any, maximum: int) -> Any:
    if type(raw) is not str or not 0 < len(raw) <= maximum:
        raise _error()
    try:
        if len(raw.encode()) > maximum:
            raise _error()
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _error() from None


def _observed(raw: Any, challenge: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Validate browser-controlled data before constructing any evidence."""
    result = _load(raw, MAX_RESPONSE_BYTES)
    if (
        type(result) is not dict
        or set(result) != {"schema", "challenge", "core", "canvas", "voices", "webgl", "webgl2"}
        or result["schema"] != IDENTITY_PROBE_SCHEMA
        or result["challenge"] != challenge
    ):
        raise _error()
    core = result["core"]
    if type(core) is not dict or set(core) != _CORE_KEYS:
        raise _error()
    for key in _CORE_TEXT_KEYS:
        if not _text(core[key], 80 if key in ("navigator.language", "timezone") else 512):
            raise _error()
    for key, limits in _CORE_INT_BOUNDS.items():
        if not _integer(core[key], *limits):
            raise _error()
    languages, dpr = core["navigator.languages"], core["devicePixelRatio"]
    if (
        type(languages) is not list
        or not 1 <= len(languages) <= 16
        or not all(_text(v, 80) for v in languages)
        or type(dpr) not in (int, float)
        or not math.isfinite(dpr)
        or not 0.5 <= dpr <= 4
    ):
        raise _error()
    core["devicePixelRatio"] = float(dpr)
    pixels = result["canvas"]
    if (
        type(pixels) is not list
        or len(pixels) != 2048
        or not all(_integer(v, 0, 255) for v in pixels)
    ):
        raise _error()
    voices = result["voices"]
    if type(voices) is not list or not 1 <= len(voices) <= 512:
        raise _error()
    for voice in voices:
        if (
            type(voice) is not dict
            or set(voice) != {"name", "lang", "voiceUri", "isDefault", "isLocalService"}
            or not all(_text(voice[key]) for key in ("name", "lang", "voiceUri"))
            or type(voice["isDefault"]) is not bool
            or type(voice["isLocalService"]) is not bool
        ):
            raise _error()
    voices_digest = identity_voices_sha256(voices)
    core["voices.sha256"] = voices_digest
    digests = {"canvas": hashlib.sha256(bytes(pixels)).hexdigest(), "voices": voices_digest}
    for signal, prefix in (("webgl", "webGl"), ("webgl2", "webGl2")):
        gpu = result[signal]
        if (
            type(gpu) is not dict
            or set(gpu) != {"vendor", "renderer", "parameters"}
            or not _text(gpu["vendor"])
            or not _text(gpu["renderer"])
            or type(gpu["parameters"]) is not dict
            or set(gpu["parameters"]) != {str(n) for n in IDENTITY_WEBGL_PARAMETERS}
        ):
            raise _error()
        core[f"{prefix}:vendor"], core[f"{prefix}:renderer"] = gpu["vendor"], gpu["renderer"]
        for enum in IDENTITY_WEBGL_PARAMETERS:
            value = gpu["parameters"][str(enum)]
            if enum == 3386:
                if (
                    type(value) is not list
                    or len(value) != 2
                    or not all(_integer(n, 1, 2**31 - 1) for n in value)
                ):
                    raise _error()
            elif not _integer(value, 1, 2**31 - 1):
                raise _error()
            core[f"{prefix}:parameter:{enum}"] = value
        digests[signal] = _sha(gpu)
    canonical = _canonical(core)
    if len(canonical) > 8192:
        raise _error()
    return canonical, tuple((name, digests[name]) for name in IDENTITY_SIGNAL_NAMES)


def _consume(task: asyncio.Task) -> None:
    if not task.cancelled():
        task.exception()


async def _settle_cleanup(task: asyncio.Task, deadline: float) -> bool:
    """Allow bounded cleanup to finish even if the caller cancels repeatedly."""
    interrupted = False
    while not task.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            task.cancel()
            task.add_done_callback(_consume)
            raise _error("identity_probe_cleanup_unverified")
        try:
            await asyncio.wait_for(asyncio.shield(task), remaining)
        except asyncio.CancelledError:
            interrupted = True
        except TimeoutError:
            task.cancel()
            task.add_done_callback(_consume)
            raise _error("identity_probe_cleanup_unverified") from None
        except Exception:
            raise _error("identity_probe_cleanup_unverified") from None
    if task.cancelled():
        raise _error("identity_probe_cleanup_unverified")
    try:
        task.result()
    except Exception:
        raise _error("identity_probe_cleanup_unverified") from None
    return interrupted


class FixedCamoufoxIdentityProbe:
    """Callable Playwright collector; its mere presence does not admit an engine.

    The caller owns the context and must dispose/quarantine it after any probe
    error or uncertain creation/cleanup. Only this probe's exact new page may
    be closed here. The driver and context are trusted native objects, not web
    JSON, and context creation must prohibit unreviewed init scripts/extensions.
    """

    probe_id = PROBE_ID

    async def collect(
        self, context: Any, challenge: str, artifact: EngineIdentity
    ) -> CamoufoxIdentityObservation:
        if (
            type(challenge) is not str
            or not re.fullmatch(r"[a-f0-9]{32}", challenge)
            or type(artifact) is not EngineIdentity
        ):
            raise _error()
        try:
            document = _load(artifact.artifact_json, MAX_ARTIFACT_BYTES)
            display = AcceptedDisplay(**document["binding"]["display"])
            expected = _canonical(expected_identity_core(artifact, display))
            artifact_sha256 = artifact.artifact_sha256
        except Exception:
            raise _error("identity_probe_artifact_invalid") from None
        loop = asyncio.get_running_loop()
        started = loop.time()
        page = creation = evaluation = None
        before = ()
        listeners: list[tuple[Any, str, Any]] = []
        changed = False
        context_closed = False
        closing = False

        def context_close(*_: Any) -> None:
            nonlocal context_closed
            context_closed = True

        def changed_page(*_: Any) -> None:
            nonlocal changed
            changed = True

        def page_close(*_: Any) -> None:
            if not closing:
                changed_page()

        def listen(target: Any, event: str, callback: Any) -> None:
            target.on(event, callback)
            listeners.append((target, event, callback))

        def new_owned(candidate: Any) -> bool:
            return (
                candidate.context is context
                and all(candidate is not old for old in before)
                and any(candidate is current for current in context.pages)
            )

        def stable(frame: Any) -> None:
            if (
                context_closed
                or changed
                or page.context is not context
                or page.is_closed()
                or not any(page is current for current in context.pages)
                or page.url != "about:blank"
                or page.main_frame is not frame
                or frame.page is not page
                or frame.url != "about:blank"
                or len(page.frames) != 1
                or page.frames[0] is not frame
            ):
                raise _error("identity_probe_context_changed")

        async def cleanup() -> None:
            nonlocal page, closing
            # Creation can finish after a cancellation/timeout. Close it only if
            # the exact returned object proves new ownership; never guess from
            # differences in context.pages or touch a concurrent user tab.
            if creation is not None and page is None:
                page = await asyncio.shield(creation)
            if page is not None:
                if not new_owned(page):
                    # A closed owned page has already acknowledged closure.
                    if not (
                        page.context is context
                        and all(page is not old for old in before)
                        and page.is_closed()
                    ):
                        raise _error("identity_probe_cleanup_unverified")
                elif not page.is_closed():
                    closing = True
                    await page.close(run_before_unload=False)
                if page.context is not context or not page.is_closed():
                    raise _error("identity_probe_cleanup_unverified")
            if evaluation is not None:
                if not evaluation.done():
                    evaluation.cancel()
                try:
                    await asyncio.shield(evaluation)
                except asyncio.CancelledError:
                    if not evaluation.cancelled():
                        raise
                except Exception:
                    # Evaluation failure is never evidence, but a terminated
                    # failed RPC does not make acknowledged page closure fail.
                    pass

        try:
            listen(context, "close", context_close)
            before = tuple(context.pages)
            if len(before) > 512:
                raise _error()
            creation = asyncio.create_task(context.new_page())
            page = await asyncio.wait_for(asyncio.shield(creation), CREATE_TIMEOUT)
            if not new_owned(page):
                raise _error("identity_probe_context_changed")
            listen(page, "framenavigated", changed_page)
            listen(page, "frameattached", changed_page)
            listen(page, "framedetached", changed_page)
            listen(page, "close", page_close)
            frame = page.main_frame
            stable(frame)
            evaluation = asyncio.create_task(page.evaluate(FIXED_IDENTITY_SCRIPT, challenge))
            # Shield prevents wait_for from waiting indefinitely for a driver
            # coroutine that does not acknowledge cancellation. The separate
            # cleanup budget closes the page and settles this exact RPC.
            raw = await asyncio.wait_for(asyncio.shield(evaluation), EVALUATE_TIMEOUT)
            stable(frame)
            core_json, signals = _observed(raw, challenge)
            if core_json != expected:
                raise _error("identity_surface_mismatch")
            observed_at = datetime.now(timezone.utc)
            stable(frame)
        except asyncio.CancelledError:
            raise
        except _ProbeFailure:
            raise
        except Exception:
            raise _error("identity_probe_failed") from None
        finally:
            cleanup_task = asyncio.create_task(cleanup())
            try:
                interrupted = await _settle_cleanup(cleanup_task, loop.time() + CLEANUP_TIMEOUT)
            finally:
                if creation is not None and not creation.done():
                    creation.cancel()
                    creation.add_done_callback(_consume)
                if evaluation is not None and not evaluation.done():
                    evaluation.cancel()
                    evaluation.add_done_callback(_consume)
                listener_error = False
                for target, event, callback in reversed(listeners):
                    try:
                        target.remove_listener(event, callback)
                    except Exception:
                        listener_error = True
                if listener_error:
                    raise _error("identity_probe_cleanup_unverified") from None
            if interrupted:
                raise asyncio.CancelledError
        try:
            if context_closed or changed or page.context is not context or not page.is_closed():
                raise _error("identity_probe_context_changed")
        except _ProbeFailure:
            raise
        except Exception:
            raise _error("identity_probe_context_changed") from None
        if loop.time() - started > MAX_ELAPSED:
            raise _error("identity_probe_expired")
        return CamoufoxIdentityObservation(
            self.probe_id, challenge, artifact_sha256, observed_at, core_json, signals
        )
