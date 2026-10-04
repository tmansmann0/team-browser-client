# Stable per-profile Camoufox identity

## Status and limits

`client/engine_identity.py` implements a callable offline generator and a private,
lease-bound identity artifact. `client/camoufox_runtime.py` now has a separate
callable generated-identity path, supervised diagnostic validation and exact
per-profile admission. The six-key locale/timezone mode remains explicitly
separate. The ordinary app/CLI now includes the explicitly configured setup
bridge described in [camoufox-setup.md](camoufox-setup.md). It remains
unconfigured by default: no silent legacy migration or automatic native
acceptance occurs. Installing these modules does not enable Camoufox or certify
any real browser.

The generator has run successfully using official, exact-version PyPI wheels in
a separate disposable Python environment. It generated synthetic identities
without a browser, live proxy, account, credential, cookie, engine download,
add-on download, GeoIP request, hardware query or OS security change. The full
generator/persistence and independent regression suites passed in that exact-wheel
environment. The generated-runtime and independent regression suites include
an actual offline-generated configuration passed through fake native contexts.
The existing legacy Camoufox tests also pass. Tests requiring optional wheels
are explicitly skipped in environments without those dependencies. These results establish
Python generation, persistence and fake-driver behavior, **not real-engine behavior, production readiness,
anti-detect parity or prevention of account restrictions**.

This work addresses a P0 prerequisite for authorized ad-account workflows.
Routing, supported ad dashboards, media upload/download, permitted handoff,
update/recovery and real native fingerprint continuity still need their own
acceptance. A browser identity does not confer website authority or override a
platform's account rules.

## Exact generation input

A trusted native caller supplies `IdentityBinding`, never browser/API JSON:

- Profile ID, preset ID and the existing stable profile-policy digest.
- Exact admitted engine version/build and executable SHA-256, plus its verified
  Firefox major. No parsing of a loosely related SDK version or active download.
- Admitted native platform and matching target OS. Arbitrary cross-OS targets
  are rejected at binding construction. The native integration must separately
  establish that the admitted platform is the actual target computer.
- `AcceptedDisplay`: CSS-pixel width/height, available width/height, color depth
  and native device-pixel ratio, explicitly observed/accepted for that computer.
- Explicit language-region locale, IANA timezone and exact assigned proxy
  fingerprint, or `None` for an independently authorized local-direct policy.

### Versioned configuration conversion

Generator `tbm-camoufox-preset-v3` implements one explicit, bounded conversion
policy. This is **offline configuration conversion, not native compatibility or
engine admission**. The exact admitted executable/build/hash, engine properties,
native program, probe and per-profile validation requirements remain separate.

- For the pinned modern catalogue, eligible source Firefox majors are 149–152
  and target majors are 149–156. Both the source `rv:` and `Firefox/` tokens must
  agree, use the supported desktop UA structure and match the native OS. No
  source newer than the target is eligible. A target above 156 fails with
  `unsupported_engine_conversion`; expanding the range requires source review
  and a new generator version. The original catalogue path below 149 retains
  exact source-major matching.
- The inspected Camoufox 0.5.6 `fingerprints.py:from_preset(preset, ff_version)`
  expressly replaces both version tokens with the supplied engine major. This
  adapter invokes that upstream conversion once, with the independently
  verified `IdentityBinding.firefox_major`. It does not infer a major from the
  package version or rewrite an existing artifact for a browser update.
- Width, height, color depth and device-pixel ratio must still exactly match a
  coherent same-OS source preset. Missing source DPR and unfamiliar dimensions,
  depth or scaling fail closed. There is no nearest-screen selection, guessed
  scaling, synthesized display or implicit cross-OS emulation.
- Available width and height come from the independently observed/accepted
  `AcceptedDisplay`, bounded within its exact screen. They can differ from the
  source preset and can equal the full display, such as an independently
  accepted auto-hidden panel configuration. The upstream `fix_screen_no_taskbar`
  heuristic guesses a 27-pixel Linux panel and is deliberately not called: a
  heuristic cannot override an observed native fact. No arbitrary UI/API JSON
  can grant display acceptance.
- Source navigator values must be coherent before conversion. The same-OS GPU
  vendor/renderer must have complete, valid WebGL and WebGL2 capability groups
  in the pinned database, with both groups' vendor/renderer parameters agreeing
  and WebGL2 enabled. Sparse/mismatched records are excluded before selecting a
  preset. The newest eligible source-major cohort is used, with one selection
  and one seed generation; there is no retry-based reseeding.

The original, unmodified selected preset digest, whole catalogue digest,
versioned generator source digest, exact accepted display/engine binding and
final config are persisted together. They identify which source and conversion
produced the artifact. A changed display, available geometry, engine build,
major, generator or dependency still blocks reuse and requires an explicit
reviewed migration. No reset/migration API ships here; never regenerate an
existing identity to fit a new display or security update.

Actual offline generation with the hash-locked official packages has verified
these Linux examples (all color depth 24, DPR 1):

| Target Firefox major | Exact CSS display | Accepted available geometry |
| --- | --- | --- |
| 152, 156 | 2560 × 1440 | 2560 × 1440 |
| 156 | 2560 × 1440 | 2560 × 1400; 2510 × 1400 |
| 152 | 1920 × 1080 | 1920 × 1053 |

The 2560 × 1440 cases use the original sole Linux 152 preset and its matching AMD
capabilities; target 156 correctly emits `rv:156.0` and `Firefox/156.0` despite no
156 preset existing. The stored source digest remains the original 152 preset.
The available-screen values survive persistence/reload byte-for-byte. These
results do not qualify those displays, GPUs, OSes or engine builds for native
use. Real Linux native execution remains blocked in the current environment;
no native retry, browser launch/download or OS-protection change is part of this
verification.

## Offline source review and provenance

Reviewed release sources, rather than mutable `main` branches:

| Distribution | Version | Official wheel SHA-256 |
| --- | --- | --- |
| camoufox | 0.5.6 | `b906836cd952376a466f0e55445f139b8a65adfb9f18ab55cb2cd0c727b11561` |
| browserforge | 1.2.4 | `fb1c14e62ac09de221dcfc73074200269f697596c642cb200ceaab1127a17542` |
| apify_fingerprint_datapoints | 0.15.0 | `fc9299b3136880f47b468897cd00ac622ad2c2a93e9cc9f972d10dbf5ed2b3aa` |

[Camoufox release metadata](https://pypi.org/pypi/camoufox/0.5.6/json),
[BrowserForge release metadata](https://pypi.org/pypi/browserforge/1.2.4/json),
[packaged model release metadata](https://pypi.org/pypi/apify-fingerprint-datapoints/0.15.0/json).
The official [BrowserForge integration](https://camoufox.com/python/browserforge/)
and [usage documentation](https://camoufox.com/python/usage/) provide context;
this implementation follows the inspected pinned wheels when they differ.

`camoufox.fingerprints` constructs a global BrowserForge generator at import.
BrowserForge 1.2.4 loads its model data through local-path getters in
`apify_fingerprint_datapoints`; its old download helpers are deprecated no-ops.
The reviewed datapoints wheel bundles the network/data files. This removes the
older dataset-fetch hazard for these exact versions. Other versions are not
accepted merely because their dependency range permits installation.

Before importing Camoufox, the adapter checks exact package versions and SHA-256
manifests of all installed package members from those three reviewed wheels.
The provenance record also binds this application's generator source bytes,
generator version, selected catalogue name/digest, and a digest of installed
transitive dependency versions and wheel `RECORD` metadata. Playwright is pinned
to 1.62.0. A missing or changed reviewed dependency fails without installing or
fetching anything.

The core manifests hash actual installed bytes; the remaining transitive
provenance is installed metadata, not a fresh hash of every transitive binary.
These digests are change detection/content provenance, not publisher signatures,
proof of a trusted interpreter or complete supply-chain certification. A release
still needs a reviewed, hashed complete dependency lock for its target platform.
The optional package versions are pinned in `pyproject.toml`; a complete hashed
Linux verification toolchain is now supplied in `requirements-client-verification-linux-py312.lock`
and documented in `dependency-locks.md`. It reproduces the source/package tests,
not a signed desktop release. Other platforms and release packaging still need
their own reviewed dependency set and native acceptance.

All functions/data remain imported from their respective packages. No upstream
source or catalogue has been vendored into this repository. Distribution of
those dependencies must retain their exact upstream licenses/notices; source
review is not a new redistribution license.

## Helper process and supported identity surfaces

`OfflineCamoufoxGenerator.generate()` uses the running trusted Python interpreter
with `-I -S -B` for one bounded helper. The bootstrap supplies only explicitly
observed dependency roots, bypasses cached bytecode with source-only loaders and
refuses `.pyc`/sourceless imports; it does not process `.pth` or `sitecustomize`.
A positive-control poisoned-cache/startup-hook regression test verifies this
boundary. The trusted interpreter, standard library and permitted native
extensions remain assumptions. It has a 30-second parent
wall timeout, a 20-second CPU limit, bounded input/output and fixed diagnostics.
It receives only synthetic/configuration input, not browser session data or
proxy credentials. Its environment excludes proxy settings, package paths,
provider tokens and ambient browser options.

Before adding dependency roots or importing application/dependency modules, the
bootstrap applies resource limits and a Python audit hook that refuses socket/DNS
operations, process creation, shell execution and audited Python writes. Package
imports and catalogue reads remain allowed. The reviewed WebGL helper's SQLite
connection is narrowly adapted to the one verified bundled database opened with
`mode=ro&immutable=1`; the original function performs its own OS/vendor/renderer
selection. No other database path or read-write connection is accepted.

This hook is defense in depth for reviewed code, **not an OS sandbox against
malicious native extensions**. It cannot prove that arbitrary native code cannot
use syscalls. No browser/driver/node executable was run in these tests; ordinary
installed Python extension modules from the official wheels were imported.

The app calls `from_preset` once and uses the reviewed pure helpers; all final
supported values are persisted. Its initial voice sampling is replaced once with
the locale-bound voice helper before persistence:

- Navigator UA, platform, OS CPU, appVersion, hardware concurrency and touch
  points from a coherent same-OS preset, with the explicit bounded engine-major
  conversion above. The architecture correction helper is applied; inconsistent
  output fails validation.
- Exact preset screen dimensions and color/pixel depth, plus independently
  accepted available dimensions. Upstream window dimension/position consistency
  helpers are called, but not its guessed-taskbar helper. Final values must
  exactly match the trusted display binding. No live display discovery is called.
- A sampled OS-appropriate bundled font subset and nonzero font-spacing seed.
- Nonzero audio and canvas seeds, generated once and reused byte-for-byte.
- Complete voice objects generated by the reviewed OS/locale helper, with one
  language-matching default. `voices:blockIfNotDefined=true` prevents a missing
  host-list fallback for engines that honor that property. Empty/malformed
  lists or an unavailable matching voice language fail closed.
- Matching WebGL and WebGL2 vendor/renderer, context attributes, supported
  extensions, parameters and shader-precision data from the bundled database.
  The exact two identity-only Firefox preferences are also persisted:
  `webgl.enable-webgl2` and `webgl.force-enabled`. The first supported path
  requires both complete WebGL capability groups; sparse catalogue variants
  cannot become partial identities.
- Explicit locale/languages/Accept-Language and timezone from trusted route
  policy, independent of ambient machine locale or third-party IP lookup.

The resulting configuration has a strict 34-key allowlist, nested JSON bounds,
locale/OS/appVersion/display checks, exact primitive types for scalar surfaces,
strict context-attribute fields, 12 typed shader-precision records and bounded
numeric-enum WebGL parameter values. Unknown
fields, launch arguments, arbitrary Firefox preferences, add-ons, scripts,
WebRTC IPs, geolocation coordinates and network/proxy settings are rejected.
The seeds are variation inputs, not keys or a cryptographic uniqueness promise.

### Deliberately omitted surfaces

This is a complete persisted **supported configuration**, not all of
`launch_options` or every possible browser fingerprint:

- No fake media-device counts. The SDK's fixed mic/camera default is deliberately
  omitted instead of asserting hardware that was never accepted.
- No device-pixel-ratio override. The reviewed conversion omits it. The accepted
  native DPR is bound and must be checked in real browser observations.
- Window size/position/inner dimensions and history remain native, resizable and
  navigation-dependent. They are not fabricated as immutable profile properties.
- No codec, plugin, battery, WebGPU, TLS/network-stack, input-device, graphics
  driver, installed application or every-DOM-surface stabilization claim.
- No automation concealment, humanization, main-world injection, COOP disabling,
  extension handling, automatic fonts installation or runtime fontconfig writes.
- No GeoIP, GPS/geolocation, WebRTC-address override or proxy allocation. Existing
  route enforcement and acceptance remain independent requirements.

Native acceptance must verify the implications of these omissions on the exact
supported engine/platform/workflow. A missing required surface is a release gate,
not permission to fill it with an arbitrary value.

## Durable immutable artifact

`EngineIdentityStore(ProfileStore).load_or_create(lease, binding, generator)`
requires the exact active current-process `ProfileLease`, its matching private
profile paths and the same on-disk lock inode. It rechecks the live lease and
profile-directory inode after generation and immediately before returning.

The artifact is `.camoufox-engine-identity.json`, alongside `browser-data`, never
inside website-controlled files. Schema v1 contains the exact binding, generator
provenance/digest, selected preset digest, complete config, fixed identity
preferences, config digest and a canonical-payload digest. The returned
`EngineIdentity` keeps canonical immutable text; preferences are returned as
copies. Artifact structure remains schema v1; the v3 generator version and source
digest explicitly distinguish the new conversion rules. V2 artifacts fail with
`identity_migration_required` and remain unchanged, with no silent reinterpretation
or regeneration.

Creation is allowed only if the artifact is absent, browser-data is empty and no
legacy `.camoufox-identity.json` exists. Existing profiles/legacy six-key markers
are never adopted automatically. The final name is created with `O_EXCL`, mode
0600, descriptor-relative no-follow operations, complete writes, file `fsync`
and directory `fsync`. Reads are bounded, reject symlinks/hardlinks/FIFOs, require
current-user ownership/private permissions and check identity before/after the
read. Duplicate JSON fields, noncanonical JSON, unknown fields, digest mismatch,
invalid schema/types or changed binding/provenance fail closed.

An interrupted write can leave a torn final file. It remains a blocker; it is
never deleted/repaired by generating a replacement. This prefers preserving an
identity decision over silent rotation. Engine/build/hash, display, locale,
timezone, proxy assignment, generator, dependency or catalogue changes require
an explicit reviewed migration/recovery workflow. No such reset/migration API
ships here.

The digests are not MACs. This is cooperating-client, app-owned immutability on a
local POSIX filesystem, not protection from a malicious process with the same
OS identity or a compromised interpreter. Windows storage, hostile shared hosts,
network filesystems and detached browser ownership are not accepted by this
storage design.

## Callable preparation, validation and ordinary launch

The runtime uses three distinct stages so per-profile acceptance does not require
an impossible generation/acceptance cycle:

1. **Prepare offline.** Call `EngineIdentityStore.load_or_create` under the owned
   profile lease, with explicit trusted binding and reviewed generator. This
   needs no native test record, launches nothing and grants no normal-use access.
2. **Validate under an accepted program.** A trusted native provider supplies
   `CamoufoxGeneratedIdentityPolicy` with the prepared artifact digest, generator,
   `CamoufoxIdentityProgramAcceptance`, exact property observer and fixed probe.
   The program record binds the approved executable/build/Firefox major,
   platform/display, identity schema, complete generator/catalogue provenance,
   engine property digest and fixed probe implementation/schema. The existing
   runtime/signature and proxy-leak acceptance records are still required.
   Call `validation_blockers(profile)`, then `validate_identity(context)` with
   the active exact lease and `initial_url="about:blank"`.
3. **Use an admitted profile.** On successful validation, the returned handle's
   `identity_admission` is a typed `CamoufoxProfileIdentityAdmission`. Supply it
   through the same trusted provider, then use ordinary `blockers`/`start`.
   Normal launch independently observes the new owned context and compares it
   with both expected configuration values and the validated signal baseline
   before readiness or proxy quarantine release.

Validation is a real callable supervised path, tested with fake native drivers.
Proxy-backed validation requires the diagnostic-quarantined proxy route; only
fixed diagnostic destinations can pass that relay and it never releases general
proxy traffic during validation. An explicitly accepted local-origin,
local-direct profile may instead run the same fixed about:blank observations
without a proxy. Direct mode uses ordinary unrestricted browser egress and is
**not** a network sandbox or a fallback for managed/proxy profiles. Both paths
retain the exact native/runtime/program/display gates and suppress session
restore. Neither navigates Gmail nor accepts an arbitrary URL/script. Two fresh
challenged observations must agree. The context is then
closed with a bounded acknowledgement, and the same lease, property/runtime
observation and authority are rechecked. Only then is a typed result published.
The exact close task is retained and shielded so a driver that suppresses
cancellation cannot extend that acknowledgement deadline. A timeout leaves
ownership unknown; even a later close acknowledgement cannot issue admission
or clear that uncertainty automatically.
Unknown process ownership, timeout, instability, close failure, cancellation or
stale authority gives no admission and preserves existing ownership/lease gates.

The result binds profile/binding/artifact/config/program/surface digests, the
validation lease token, a fresh validation ID and bounded expiry. It is native
application evidence, not a JSON trust flag. The UI can request the bounded
native setup actions, but cannot load or manufacture trust/admission records.
The native CLI's signed deployment loader is separate from this per-profile
result. Per-profile admissions remain in memory and are not restored on restart;
diagnostic validation can be rerun against the **same** immutable artifact. A
locally computed config digest by itself does not grant access.

The concrete collector is documented separately in [identity-probe.md](identity-probe.md).
Its fixed v1 measured core includes navigator identity/language, screen/available
screen/depth, timezone, DPR, normalized voice-list digest, and WebGL/WebGL2
vendor/renderer plus parameters 3379, 3386, 34921 and 34930. The four signal
baselines are canvas, voices, WebGL and WebGL2. Audio/font/worker output measurement
is an explicit remaining native-acceptance limit; stored seeds and font lists do
not prove those outputs were observed.

## Runtime integration and acceptance boundaries

- The adapter uses load-only access to an existing generated artifact. Missing,
  deleted, corrupt or legacy-marked state cannot generate a replacement during
  native startup. Both native adapters reject the foreign identity markers;
  legacy Camoufox mode refuses a generated-identity artifact.
- Engine `properties.json` is freshly observed before/after loading, checked
  against the independently accepted digest, and strictly validates every emitted
  property/type. Observer source selection, bounded no-follow reads and publisher
  provenance remain the trusted native observer's responsibility. There is no
  default distribution-layout guess.
- Runtime/property/artifact/policy/lease checks are repeated around asynchronous
  driver setup, route authority, surface collection, page creation, focus and
  navigation. Quarantine remains closed through owned page preparation/focus.
  A non-awaiting final fence precedes spawn, proxy release, readiness and report
  publication. Authority providers must expose bounded local snapshots for that
  final fence, not do remote refreshes on the native owner loop. The fence also
  rechecks the executable's exact identity/content hash and fresh metadata.
  The exact observed property file identity must remain unchanged, not merely
  its JSON digest.
- The config is emitted unchanged in bounded `CAMOU_CONFIG_N` chunks, with no
  inherited ambient identity/proxy environment. Only the two fixed identity
  WebGL preferences are merged with fixed route preferences; collisions fail.
  `launch_options`, download helpers and random generation are never invoked by
  the runtime adapter.
- The native probe runs before normal readiness and before diagnostic quarantine
  release. A slow page/focus/navigation step requires refreshed surface evidence;
  the ten-second bound is checked again at route release and readiness. Route
  evidence must still be unexpired after the identity check. A failed probe
  closes the owned context or retains unknown ownership; coroutine cancellation
  after spawn is explicit unknown ownership with a fail-closed relay, not a
  stuck starting state or proof of process exit. No case authorizes direct fallback.
- Actual distribution/runtime approval, trusted property observation and initial
  native program acceptance are still absent in this environment. Real engine
  behavior, font resources, unsupported surfaces, sandbox/update settings, actual
  display behavior, proxy leakage/failure, account workflow compatibility and
  persistence across real restarts must be measured before a production claim.

## Verification

Default synthetic contracts:

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_engine_identity.py -v
.venv/bin/python -m unittest discover -s tests -p test_client_engine_compatibility.py -v
.venv/bin/ruff check src/team_browser/client/engine_identity.py tests/test_client_engine_identity.py tests/test_client_engine_compatibility.py
.venv/bin/ruff format --check src/team_browser/client/engine_identity.py tests/test_client_engine_identity.py tests/test_client_engine_compatibility.py
```

In a separately provisioned exact-wheel environment containing the project and
reviewed dependencies, opt in to the real **offline generator** tests:

```sh
TBM_TEST_OFFLINE_IDENTITY=1 python -B -m unittest discover -s tests -p test_client_engine_identity.py -v
TBM_TEST_OFFLINE_IDENTITY=1 python -B -m unittest discover -s tests -p test_client_engine_compatibility.py -v
```

There is no installation or download inside the tests. The opt-in tests exercise
actual package imports/helpers, full WebGL data, independent generated seed
sets, private artifact creation and restart reuse, and unavailable-display
rejection. The conversion regressions exercise actual 152/156 configurations,
preserved full-screen and custom available geometry, original preset provenance,
strict source/target ranges, source-UA/OS coherence, complete matching graphics,
unknown display/depth/DPR rejection and v2 migration refusal. They never launch the native browser and must not be reported as
real-Mac/real-Camoufox acceptance.

Generated-runtime contracts (all contexts/probes/providers remain synthetic):

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_engine_identity_runtime.py -v
```

With `TBM_TEST_OFFLINE_IDENTITY=1`, its additional fixture uses a real offline
generated artifact with the fake launcher and probe. This remains separate from
any actual native engine execution.
