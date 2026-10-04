# Bounded Camoufox identity observations

## Status

`src/team_browser/client/identity_probe.py` supplies the concrete callable
`FixedCamoufoxIdentityProbe` for the generated-identity runtime protocol. It
collects browser-returned observations and compares them with the immutable
artifact. It does not install, start, authorize, or certify a browser.

The collector has been exercised with synthetic Playwright-shaped objects only.
**No native browser, driver process, account, proxy, network diagnostic, or
Camoufox installation was run for this collector. Actual native compatibility
and fingerprint continuity remain unverified.** Its existence must not enable
the separately gated engine or be presented as production/anti-detect parity.

The artifact/generator contract and wider remaining native acceptance criteria
are in [engine-identity.md](engine-identity.md). Runtime wiring remains responsible
for exact admitted engine/properties/generator/display provenance, current
profile lease, immutable artifact, route authority, quarantine, two independent
validation observations, acknowledged validation-context shutdown, and an
ordinary-launch recheck before opening general traffic.

## Invocation and authority

The trusted native runtime supplies:

- The exact owned Playwright browser context, not a serialized handle or page
  selected from a user URL.
- A fresh 32-character lowercase hexadecimal challenge.
- The already validated `EngineIdentity` artifact, retained byte-for-byte.

`FixedCamoufoxIdentityProbe.collect(context, challenge, artifact)` is async and
returns `CamoufoxIdentityObservation`. The collector's fixed `PROBE_ID` includes
the SHA-256 of its literal JavaScript fixture. The reviewed program acceptance
must name that ID; changing the fixture changes this binding. As with the rest
of the native program, Python implementation changes also require review.

The observation contains the probe ID, challenge, artifact SHA-256, UTC
observation time, canonical measured core JSON and four ordered digest pairs:
`canvas`, `voices`, `webgl`, `webgl2`. The schema is
`camoufox-stable-surfaces-v1`. The runtime independently checks the expected
core, freshness, challenge, artifact, program and current native authority.

The challenge binds a response to a fresh invocation. It is not a remote
attestation or proof against a malicious native driver, injected init script,
extension, compromised interpreter, or same-user process. Context construction
and exact native acceptance must exclude unreviewed overrides. No caller URL,
script, shader, configuration value or artifact is passed to JavaScript. The
script receives only the challenge, so a matching configuration cannot be
manufactured by echoing expected fields into the browser result.

## Owned-page lifecycle

1. Observe context closure and record only the identities of existing pages.
2. Call `context.new_page()` once. The exact returned page must belong to that
   same context, be present in its page inventory and not be a preexisting page.
3. Require exact `about:blank` for the page and its single main frame; reject
   fragments, other URLs, replaced frames, attached/detached frames, navigation
   events and unexpected page/context closure.
4. Evaluate the single fixed fixture once. Page/frame/context invariants are
   checked before and after evaluation and again after response validation.
   The script also checks exact blank location, document identity and no child
   frames before/after its bounded asynchronous voice wait.
5. In `finally`, close only the exact new owned diagnostic page using
   `close(run_before_unload=False)` and require `page.is_closed()` acknowledgment.
   Exact context ownership is rechecked after that await and before success.
   No preexisting, foreign or concurrently created page is selected for cleanup.
   No context/browser close, URL navigation or inventory-difference guessing is
   performed by the collector.
6. Remove this collector's event listeners, require the evaluation RPC to have
   terminated, and only then publish a successful observation. Expected closure
   of the diagnostic page is distinct from unexpected context/page changes.

Cancellation is propagated after bounded cleanup, including repeated
cancellation during page close. A late result from page creation can still be
closed when its exact returned object establishes new ownership. If creation
never returns an object, ownership changes, a close is unacknowledged, the RPC
does not terminate or cleanup otherwise fails, the collector emits no evidence
and raises `identity_probe_cleanup_unverified`.

The caller must quarantine/dispose the owned context on any failed observation
and preserve lease/ownership protections when shutdown is uncertain. The
collector cannot safely find and close an unknown late-created page by guessing
from the context inventory. It never compensates by closing unrelated tabs.

## Measured v1 surfaces

All returned browser data is treated as untrusted and type/size checked in
Python, even where the JavaScript fixture already checked it.

- Navigator: `userAgent`, `platform`, `oscpu`, `appVersion`,
  `hardwareConcurrency`, `maxTouchPoints`, `language`, `languages`.
- Screen: width/height, available width/height, color depth and pixel depth.
- `Intl.DateTimeFormat().resolvedOptions().timeZone` and native
  `window.devicePixelRatio`. DPR is represented as a Python float; it is not
  overridden.
- Canvas: one fixed 32-by-16 2D gradient/compositing/arc operation. It uses no
  text, external image, account DOM or caller-supplied input. Exactly 2,048 raw
  RGBA bytes return to Python and are hashed with SHA-256. The persisted canvas
  seed is never substituted for measured output. Canvas is a repeatability
  signal; this probe does not derive an independently known pixel result from
  the seed.
- Voices: `speechSynthesis.getVoices()` with bounded availability polling and
  no audio playback. `voiceURI`, `default`, and `localService` are normalized to
  the artifact's `voiceUri`, `isDefault`, and `isLocalService`, retaining `name`
  and `lang`. Full voice objects are sorted by canonical JSON before hashing;
  order variation is ignored, while fields and duplicate multiplicity remain.
  The measured voice digest must match the artifact's expected voice digest.
- WebGL and WebGL2: separate 1-by-1 canvases, fixed context kinds, the
  `WEBGL_debug_renderer_info` extension and unmasked vendor/renderer enums
  37445/37446. The fixed capability subset is MAX_TEXTURE_SIZE (3379),
  MAX_VIEWPORT_DIMS (3386, exactly two integers), MAX_VERTEX_ATTRIBS (34921),
  MAX_TEXTURE_IMAGE_UNITS (34930). Missing contexts/extensions, context loss,
  malformed values and unavailable capabilities fail closed. There is no shader
  execution or arbitrary parameter input.

Python hashes each canonical measured GPU object
`{vendor, renderer, parameters}`. It adds the measured vendor/renderer and each
parameter to the core. The final core is compared exactly with the runtime's
`expected_identity_core(artifact, display)`, including measured voice digest and
both GPU capability groups. `identity_voices_sha256` is shared with the runtime
to avoid inconsistent ordering rules. Matching two observations alone cannot
admit a consistently wrong voice list, GPU or navigator identity.

## Bounds and error handling

- One page-creation call, one evaluate call and at most one owned-page close.
- Page creation: 1 second; evaluation: 2 seconds; cleanup: 1 second shared across
  late creation, page close and RPC termination. Successful evidence also has a
  4.5-second total monotonic freshness limit. Runtime freshness remains separate.
- JavaScript voice availability: at most 11 enumerations and ten 50-ms timers.
  The script also rejects elapsed execution over 1.5 seconds. Background timer
  throttling or slow hardware can therefore fail closed and need real acceptance
  review rather than silently widening the budget.
- Response JSON: at most 262,144 UTF-8 bytes, with duplicate keys, unknown fields,
  excessive nesting, NaN/infinity and wrong primitive types rejected. The script
  independently bounds its returned string length. Core canonical JSON is at
  most 8,192 characters.
- Voice lists: 1–512 complete objects; each text field 1–512 characters, boolean
  flags strictly boolean. Navigator languages: 1–16 strings of at most 80
  characters. Fixed bounded integer, string and vector constraints apply to
  screen, navigator and GPU fields. Boolean-as-integer substitutions fail.
- Fixed diagnostics only. Native/script exceptions, account URLs, filesystem
  paths and other upstream details are not forwarded as error messages. No raw
  pixels/voice lists or configuration are logged or persisted by the collector.

Timeouts bound the async control flow; they are not an OS sandbox against a
malicious native extension, synchronous driver stall or compromised event loop.
Unacknowledged RPC termination is a failure, never successful cleanup evidence.

## Explicit remaining acceptance limits

The four v1 signals do not measure seeded audio output, font-list/spacing output,
worker contexts, offscreen canvas, full WebGL parameter/extension/precision
surfaces, codecs/media devices, WebGPU, TLS/network-stack behavior or every
fingerprint surface. Audio, font and worker measurements remain explicit release
acceptance requirements where those features are promised. There are no dummy
digests pretending those surfaces were observed.

The tests do not establish that the accepted engine honors its native seeds,
voice properties or GPU configuration, that real voice enumeration is ready
within the budget, or that a real display/DPR/catalogue combination matches.
Real acceptance still needs exact-build/platform observations through restart,
warm reuse, crash recovery, sleep/wake, quarantine and route failure scenarios.
No remote diagnostics, GeoIP, network requests, permissions, credentials,
cookies, browser history, account page content or OS security changes are part
of this probe.

## Synthetic verification

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_identity_probe.py -v
.venv/bin/ruff check src/team_browser/client/identity_probe.py tests/test_client_identity_probe.py
.venv/bin/ruff format --check src/team_browser/client/identity_probe.py tests/test_client_identity_probe.py
```

The collector's 31 synthetic tests include exact fixed invocation, raw-pixel
hashing, canonical voice normalization, artifact-bound GPU/voice/core mismatch,
schema and oversized response rejection, blank-page/frame/context changes,
foreign/preexisting-page protection, timeout/late creation, repeated
cancellation, cancellation-resistant evaluation, expiry, error redaction and
acknowledged-cleanup failures. Runtime integration tests are separate and must
also be run against the final combined source tree.

API references: [Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext),
[Playwright Page](https://playwright.dev/python/docs/api/class-page), and
[SpeechSynthesis.getVoices](https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis/getVoices).
