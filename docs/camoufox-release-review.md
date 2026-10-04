# Camoufox Linux release candidate and native-qualification handoff

Reviewed 2026-10-04 UTC. Scope: read-only release/source/package inspection for Team Browser Manager. No browser binary was downloaded, installed, or run. No upstream script was executed. No keys, grants, trust anchors, security settings, or repository source were changed.

## Decision

Use **official Camoufox v156.0.1-beta.33, Linux x86_64**, as the exact candidate for an owner-approved, isolated qualification on a compatible Linux host. It is a **prerelease test candidate, not an accepted runtime**. Ordinary activation should remain closed.

Prefer investigating this newer Firefox-base candidate over beginning new qualification on the older stable-channel beta.30. This does not establish that beta.33 is secure, compatible, or current with Mozilla security fixes. Several security defaults need strengthening and native verification; some differences are compile-time and cannot be undone with preferences. If the required security baseline cannot be demonstrated with this official build, stop and require a reviewed rebuild/fork, then qualify that different artifact from scratch.

Keep the application's current SDK/driver pins until a separate complete delta and published-wheel review: camoufox 0.5.6, Playwright 1.62.0, BrowserForge 1.2.4, apify-fingerprint-datapoints 0.15.0. No automatic upgrade is recommended by this report.

## Exact candidate and comparison

These release fields were read from the official GitHub release API. The archive itself was not downloaded or independently hashed during this source review.

| Field | Qualification candidate | Older stable-channel comparison |
|---|---|---|
| Release | v156.0.1-beta.33 | v152.0.4-beta.30 |
| GitHub prerelease flag | true | false |
| Published | 2026-09-30 01:18:08 UTC | 2026-09-01 01:09:00 UTC |
| Age on review date | about 4 days | about 33 days |
| Filename | camoufox-156.0.1-beta.33-lin.x86_64.zip | camoufox-152.0.4-beta.30-lin.x86_64.zip |
| Bytes | 1,294,876,837 | 663,467,670 |
| Published SHA-256 | 730d731153b2a16cac238a0b4a7f849c04d1fd6181c09ec6af29695af0407af8 | 5720d45b894ce1770543de024c6f10d514b38be560fa2dc3226b3d8586caf672 |
| Target | 11969fa44a9f5e9b94b30a3b1f410ee703e30627 | API target_commitish was main; not resolved here to immutable commit |

Primary release records: [beta.33](https://github.com/daijro/camoufox/releases/tag/v156.0.1-beta.33), [beta.33 API](https://api.github.com/repos/daijro/camoufox/releases/tags/v156.0.1-beta.33), [beta.30](https://github.com/daijro/camoufox/releases/tag/v152.0.4-beta.30), [beta.30 API](https://api.github.com/repos/daijro/camoufox/releases/tags/v152.0.4-beta.30). Exact candidate download target: [Linux x86_64 ZIP](https://github.com/daijro/camoufox/releases/download/v156.0.1-beta.33/camoufox-156.0.1-beta.33-lin.x86_64.zip).

The newer candidate names Firefox base 156.0.1; beta.30 names 152.0.4. Four major-version increments and a newer date are reasons to investigate the newer base, not a security advisory audit. Mozilla advisory/backport coverage, exact downstream patch applicability, and the latest upstream security release were not independently established in this bounded review. The stable-channel label alone is insufficient evidence of current security coverage. Conversely, the newer candidate has additional unqualified changes and nearly twice the archive size.

## Release provenance: useful evidence and remaining gates

The review downloaded only the 158-byte [manifest.json](https://github.com/daijro/camoufox/releases/download/v156.0.1-beta.33/manifest.json), reproducing SHA-256 `9a73857269c071f789557ad2c800cdcd0596cf8eeacdfa33a03eca99506e6516`. Its fields are:

- schema: 1
- tag: v156.0.1-beta.33
- source_digest: 8c6b7000d0c8e31954df20606ac6aba7
- commit: 11969fa44a9f5e9b94b30a3b1f410ee703e30627

The exact-tag [release workflow](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/.github/workflows/release.yml#L260-L299) includes GitHub OIDC build-provenance attestations using pinned actions/attest-build-provenance v4.2.2, with subject-path `artifacts/**/*`, before publishing the browser assets. Therefore a meaningful later gate is verification of the exact downloaded ZIP's GitHub artifact attestation against repository daijro/camoufox, the expected workflow, commit, subject digest and trusted identity. **Attestation existence and successful cryptographic verification for this exact ZIP remain unverified.** The workflow's presence is not proof that any particular upload was attested successfully.

GitHub displays the source commit as verified. A verified Git commit is not binary OS signing, Linux package-repository signing, notarization, or proof that downloaded bytes match the build. No independent detached-signature evidence was established here. Linux does not use macOS notarization; the gate should state the actual accepted provenance mechanism rather than demand or claim a nonexistent platform property.

[ci/browser_inputs.py](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/ci/browser_inputs.py#L184-L205) computes source_digest as the first 32 hexadecimal characters of SHA-256 over selected source paths and their content hashes, excluding the release-number line in upstream.sh. It is a source-pairing identifier, **not the browser ZIP SHA-256**, and does not establish a hermetic/reproducible build or independently bind every external toolchain/font/langpack input.

The [package source](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/scripts/package.py) includes fonts and bundled locales and retains the native graphics probe. The workflow downloads and verifies a font bundle; the packager can fetch matching Mozilla language packs. Exact effective external input hashes, complete SBOM/license review, and reproducibility remain review gates.

The [SDK checksum function](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/pythonlib/camoufox/pkgman.py#L940-L965) verifies a published SHA-256 but permits installation when no digest is known. Team Browser Manager must require its exact approved digest and full provenance; it must not inherit this missing-digest fallback. Checksums establish byte agreement with the approved record, not independent publisher authenticity.

## Linux identity and support-tree coverage

Source-established distinctions:

- **Linux executable:** SDK launch filename is camoufox-bin. The packager flattens the intermediate camoufox directory into the ZIP root. This is source evidence, not a direct listing of the candidate ZIP.
- **Firefox base / Camoufox release:** asset parsing separates version 156.0.1 from build beta.33. These are browser identity fields, separate from the Python SDK version.
- **version.json:** the [multiversion installer](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/pythonlib/camoufox/multiversion.py#L392-L453) writes it after extraction using release metadata. It can contain browser version/build, archive SHA and asset metadata. It is installer-maintained data; it is not an engine-issued attestation and may be absent in a directly unpacked official ZIP. Never treat it as an SDK version or authenticity proof.
- **properties.json:** the existing inspected SDK reads it as a list of supported configuration property names/types. It is a browser configuration schema, not release/version identity. Bind its exact bytes because it controls identity-setting compatibility.
- **application.ini / platform.ini:** no genuine installed candidate bytes, sections, Version, BuildID, Milestone, or SourceStamp were observed. Expected Gecko fields such as application.ini `[App] Version`/`BuildID` and platform.ini `[Build] Milestone`/`BuildID`/`SourceStamp` are **inspection targets only**. Do not invent a BuildID, assume the exact version-string shape, or issue a receipt from a fixture. The exact source revision supporting the final field mapping must be recorded.

A composite application identity such as `156.0.1+beta.33.<actual-Gecko-BuildID>` can be a local receipt convention only after actual engine fields and release binding are verified. It is not an upstream version string established by this review. SDK version 0.5.6/0.5.7 must never be substituted for that identity.

The signed local acceptance record must bind the **complete installed support tree**, not merely camoufox-bin plus two JSON/INI files. Include all actual regular files: libxul and dependent libraries, application/platform metadata, omnijar/browser resources, Juggler resources, graphics/media helper executables, defaults/pref/local-settings.js, camoufox.cfg, distribution/policies.json, properties.json, fontconfig, fonts, locales and any packaged extensions. Exact names and total size must come from the approved archive's real inventory. Reject traversal, unsafe links, unexpected new files, replaced roots and mutations; bind file hashes/identities and enforce protected ownership. An operator receipt signature records local acceptance; it is not an upstream publisher signature.

## Security and update assessment

The exact [Camoufox configuration](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/settings/camoufox.cfg), [base mozconfig](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/assets/base.mozconfig), [Linux mozconfig](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/assets/linux.mozconfig) and [policies](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/settings/distribution/policies.json) were read as source only.

| Observed setting | Meaning and qualification action |
|---|---|
| fission.autostart=true but fission.webContentIsolationStrategy=0 | The source explicitly describes all content using the same process/no OOPIFs. A true Fission switch alone does not establish site isolation. Set the exact Gecko-version-appropriate full-isolation strategy in a reviewed startup overlay, then demonstrate cross-site process isolation and working Juggler/profile behavior. Do not preserve strategy 0 to make automation pass. |
| Safe Browsing blocked-URI, download, password, malware and phishing components false; Mozilla provider update URL empty | These are reduced protections. Review/restore the applicable enabled settings **and** working provider configuration/data refresh; merely flipping booleans is not proof that threat lists work. Provider/API availability and resulting network destinations need explicit review. |
| services.settings.server empty; extensions.blocklist.enabled=false | Remote Settings and extension blocklist refresh need review/restoration where used for security data. Verify actual signed data availability; a locally supplied list is not automatically equivalent. |
| security.fileuri.strict_origin_policy=false | Restore true and verify cross-file isolation with harmless local fixtures. No ordinary app function requires weakening this protection. |
| dom.security.https_first=false | Restore the required HTTPS-first behavior and test it. The source says this was disabled for plain-HTTP proxy fixtures; do not use that fixture limitation as the production policy. |
| security.notification_enable_delay=0; tracking protection disabled; developer-tools prompt weakened | Compare against exact-version stock security behavior, restore appropriate protection/delays, and keep remote network debugging unexposed. Pipe-only automation must remain process-owned. |
| security.sandbox.warn_unprivileged_namespaces=false | Hides a Linux warning; it is not itself proof the sandbox is disabled. Restore visibility/diagnostics and directly establish sandbox operation. A hidden warning cannot count as a passing sandbox check. |
| media.gmp-manager.updateEnabled=true | Some media components may download/update even though browser updating is disabled. Inventory, explicitly control and qualify this mutable dependency/network path. |

Most listed configuration entries use `defaultPref`, not `lockPref`; a reviewed profile/startup overlay can strengthen them in principle. The tag's final CAMOU_PREFS environment-processing block also applies supplied defaults at startup. **Neither mechanism was exercised**, and the application currently bypasses SDK launch_options with explicit from_options. Validate effective preferences in the actual persistent-context startup path; do not assume SDK helper behavior reaches this adapter.

Important compile-time differences:

- `--disable-updater`: ordinary Firefox self-updating is compiled out. An app.update preference cannot restore it. A separate managed, fail-closed patch/update process can meet a deliberately defined controlled-update policy, but it is not stock Firefox updating. Define an owner, security-advisory review, maximum tolerated patch lag, exact release approval, whole-tree replacement, and requalification/rollback rules. Otherwise require a rebuilt distribution with an appropriate update design.
- `--disable-system-policies`: do not rely on the packaged policies.json to enforce enterprise security. Preferences cannot recreate compiled-out policy support. Required policy enforcement needs a reviewed build or an equivalent independently enforced application boundary.
- Add-on sideloading is enabled; app/system scopes permit unsigned add-ons, and MOZ_REQUIRE_SIGNING is unset. Inspect exact Gecko enforcement and prove required signature rejection. Setting a preference alone does not establish the same non-optional build-time guarantee as a stock signed-add-on build. If that guarantee is required, a reviewed rebuild is the gate. The app exposing no add-on option reduces its own surface but does not prove the underlying browser enforces signatures.
- The commented `--enable-hardening` line is not enough evidence that compiler hardening is disabled or enabled. Inspect actual build configuration and ELF properties during qualification; do not infer either result from that comment.

There is **no --disable-sandbox** in the inspected base/Linux mozconfig. The already available official Playwright 1.62.0 wheel was inspected as ZIP data: its Firefox launcher uses -no-remote, -profile and -juggler-pipe; it does not add --no-sandbox or MOZ_DISABLE_CONTENT_SANDBOX. Its Linux environment amendment only removes SNAP_NAME/SNAP_INSTANCE_NAME. This does not prove the packaged browser's effective sandbox. The separate Chromium no-sandbox code is unrelated. Verify normal user-namespace/seccomp/process restrictions on the chosen supported host; do not retry this environment's failed Chromium IPC pilot or use flags/OS changes to bypass restrictions.

## SDK delta: partial source review only

Existing official camoufox 0.5.6 wheel SHA-256: `b906836cd952376a466f0e55445f139b8a65adfb9f18ab55cb2cd0c727b11561`. Its metadata allows Playwright <1.63 and BrowserForge >=1.2.4,<2.0.0. [0.5.6 package metadata](https://pypi.org/pypi/camoufox/0.5.6/json).

The review read beta.33's [pyproject.toml](https://github.com/daijro/camoufox/blob/11969fa44a9f5e9b94b30a3b1f410ee703e30627/pythonlib/pyproject.toml): source version 0.5.7, Playwright <1.63. That is **not proof that the published SDK paired to beta.33 is version 0.5.7**. The workflow stamps library versions and browser-pin.json at publication; its development checkout carries an empty pin.

Bounded diffs between the existing 0.5.6 wheel and downloaded tag-source files established:

- Added browser_pin.py and release-stamped exact-browser pairing, unless a user explicitly chooses a channel/build.
- pkgman.py filters selection to the paired browser and warns on explicit unpaired versions; improved prerelease version parsing and missing-install diagnostics.
- multiversion.py prioritizes the release-paired browser rather than whichever cached build happened to be active.
- Playwright >=1.61 still requires browser build at least beta.30 according to the source protocol floor. The two candidates satisfy this declared floor; that does not prove native compatibility.

The 0.5.7 published wheel, its actual pin/provenance, complete dependency delta, async launcher, utilities, fingerprint/catalogue files and all runtime changes were **not fully compared**. Do not approve an upgrade based on this partial diff. The app's explicit executable/from_options path bypasses ordinary SDK auto-discovery/generation, so automatic pairing alone cannot certify the integration. A later upgrade should review the exact published paired wheel, update the complete hash lock, and rerun all applicable offline and native checks. Coordinate identity-generator changes separately; this review made no generator edits.

## Bounded owner approval and qualification plan

A useful first approval is limited to: **download and stage the exact 1,294,876,837-byte ZIP above on a named compatible Linux x86_64 host, verify its SHA-256 and upstream build provenance, inspect/extract it safely, and run a finite native qualification with two new synthetic app-owned profiles and controlled test origins.** Confirm available disk/memory, supported host dependencies and ordinary sandbox availability before downloading. No user account, credentials, existing browser profile, proxy-provider credentials, trust-key provisioning, grant activation, or security-setting relaxation belongs to that approval. Any missing dependency installation or broader network destination should be identified and approved separately.

Qualification sequence and stopping condition:

1. **Artifact admission before execution.** Re-read immutable release identity; download only the exact asset; match byte count and full SHA-256; verify attestation subject/repository/workflow/commit; preserve evidence. Missing/mismatched provenance stops execution. No SDK fetch or fallback repository.
2. **Static installed-tree inspection.** Safely enumerate every ZIP member, reject unsafe paths/links, extract to a protected dedicated root, and compute a complete manifest. Read actual INI/schema/config bytes with bounded no-follow reads. Verify ELF architecture/dependency requirements and inspect build hardening. Establish engine/BuildID/release mapping from genuine files and provenance. An assumed schema or synthetic file is a stop.
3. **Security-policy gate.** Review the exact Gecko baseline and applied strengthening overlay, compiled-out features, add-on-signature enforcement and managed update process. Declare expected values/evidence before running. If achieving the required baseline needs a rebuild, stop this official candidate; do not sign a success statement or weaken the requirement.
4. **Native sandbox/launcher gate.** Launch as the intended unprivileged owner using the pinned SDK/driver and owned pipe on the approved host, with normal sandboxing. Establish process/site isolation and effective preferences; verify no unexpected debug listener. Namespace/seccomp/IPC errors stop the run rather than trigger bypass flags or system-policy changes.
5. **Two-profile behavior.** Use two empty app-owned profiles; test launch, owned navigation, close, one relaunch, persistence and isolation of synthetic cookies/storage, profile leases and no accidental second engine. Run the fixed identity probe and record expected UA/Firefox base, locale/timezone, viewport/screen, fonts, WebGL/media surfaces and stability across restart. Match generator/catalogue/package hashes; no manual UA-major fiction.
6. **Security and egress fixtures.** Use harmless cross-origin/file/TLS/HTTPS-first and reputation-test fixtures; prove certificate errors are rejected, file and site isolation hold, security lists actually work, and update/media/background traffic conforms to the approved policy. Local-direct qualification explicitly accepts ordinary unrestricted browser egress and does not establish proxy leak protection. Managed proxy mode requires its own native route/leak/failure tests and approvals.
7. **Negative acceptance tests.** With test copies/fixtures, verify altered metadata/support-file bytes, wrong version/hash, expired/missing receipt, wrong host and missing qualification fail closed. Test cancellation, failed startup and owned cleanup without killing unrelated processes.
8. **Independent review and separate activation.** Produce pass/fail evidence for the exact archive, whole tree, host, prefs, SDK/driver/dependencies, generator and test report. An independent reviewer may approve only established claims. Provisioning a persistent trust anchor/key/grant and enabling real profiles are separate consequential steps requiring the applicable approval. Any change to the bound inputs invalidates the relevant acceptance and requires requalification.

The finite run ends with either a complete reviewed evidence packet or the first unresolved security/provenance/native blocker. No accepted native result exists today. The loader must remain fail-closed until the real report supports every affirmative receipt claim, particularly normal sandbox/security behavior and controlled updates.

## Review limits

Exact-tag source files, release tree metadata, official SDK/Playwright wheel source and public release metadata supported this review. Genuine installed metadata, binary hashes measured from the actual archive, signature/attestation validation, the complete published SDK delta, Firefox security-advisory coverage and native compatibility remain unverified. The supported next step is the bounded artifact and host approval described above; source inspection alone cannot authorize or certify execution.
