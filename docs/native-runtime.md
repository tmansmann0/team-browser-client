# Installed-browser native pilot

The account-free client can create, edit, favorite and select profiles without
any runtime or manager account. Launch is a separate capability. The normal
startup remains fail-closed until an operator supplies a reviewed runtime policy.

## Supported implementation path and actual acceptance status

The built-in path is installed, signed Chromium-family Chrome on macOS using
system `codesign` and Gatekeeper `spctl`, an exact reviewed SHA-256 policy, and the
official Playwright persistent-context API over its process pipe. The browser is
not bundled or downloaded. Playwright runs only the configured installed
executable and uses only this application's private browser-data directories.

**Implemented and contract-tested does not mean native-accepted.** All runtime
and subprocess tests in this checkout use synthetic bits or fake command/driver
adapters. Actual macOS vendor verification, Chrome startup, window focus, crash
recovery, normal security updates, and real Gmail compatibility have not been
verified here. The restricted environment's existing browser launch failures
have not been retried or worked around. There is no stealth or fingerprint
invisibility claim; this is an automation-controlled browser pilot.

The Linux atomic executable-descriptor/process-group supervisor exists for
contract testing and a separately reviewed integration. Its acceptance record
is bound to an exact runtime/platform. The ordinary CLI does not accept a Linux
JSON file as vendor-authenticity evidence, and it cannot turn a fake test record
into a trusted production release.

The Linux CLI now has its own package-provenance and explicit short-lived artifact-pilot dispatch. See [Linux runtime and actual acceptance attempt](linux-runtime.md); it does not use macOS signing or Keychain as a local-direct prerequisite. The earlier Linux process-group class remains a separate unselected integration.

## Local setup boundary

1. Install the optional official Python dependency from the project's declared
   native extra: `python -m pip install '.[native]'`. The repository pins the
   reviewed Playwright version. **Do not run `playwright install` for this path**;
   no new browser download is needed. Use an already installed vendor browser.
2. A trusted operator reviews the installed release independently. Compare the
   installed bundle's `Contents/Info.plist` `CFBundleShortVersionString` against
   vendor/package release inventory; do not execute an unknown binary merely to
   discover its version. The client observes that version directly and requires
   `CFBundleExecutable` to match the selected executable. Obtain and independently
   review the exact binary SHA-256 and expected vendor signing identity.
3. On the actual Mac, review system checks against the installed `.app` bundle:
   `/usr/bin/codesign --verify --deep --strict /Applications/Google\ Chrome.app`
   and `/usr/sbin/spctl --assess --type execute --verbose=4 /Applications/Google\ Chrome.app`.
   Inspect `/usr/bin/codesign --display --verbose=4` for the expected
   TeamIdentifier and Identifier, and compare both with an independent trusted
   vendor release record. The policy uses `TeamIdentifier:Identifier`. Do not
   copy a guessed Team ID, or treat a same-source file plus same-source hash as
   independent verification.
4. Create a private operator-owned JSON policy file (mode 0600, no symlink or hard
   link). Start from `docs/native-runtime-policy.example.json`, replacing every
   placeholder with reviewed values. The example deliberately does not validate.
   Never add credentials, proxy passwords, browser flags or a `trusted` boolean.
5. Run `tbm-client --workspace /absolute/private/workspace --runtime-policy /absolute/private/runtime-policy.json`.
   The service binds to `127.0.0.1`, disables forwarded-client headers, restricts
   the exact local Host/Origin, and protects mutations with a per-run CSRF token.
6. In a new local profile, explicitly choose **Local direct connection** to use
   the local network without a proxy/privacy claim. The default `unconfigured`
   choice does not authorize network use. Managed profiles require a verified
   proxy and can never select direct as an implicit fallback.

Malformed policies, unsupported platforms, signature/notarization failures,
missing optional dependency and changed runtime pins produce launch blockers.
Profiles and local metadata remain available. A saved managed-server URL is
only metadata: it never enrolls or authenticates a company.

## Runtime and security behavior

- Runtime policy is never accepted through the browser API. The CLI takes an
  absolute operator-owned policy path, and the API accepts neither executables,
  command arguments, proxy credentials nor arbitrary navigation URLs.
- Status-only signing evidence is cached for at most 30 seconds and only while
  both executable identity and observed Info.plist identity/content digest remain
  unchanged. Info.plist is read as a bounded (1 MiB maximum), regular file through
  symlink-refusing directory descriptors; malformed/non-string versions and
  mismatched executable names fail closed. The actual observed bundle version
  must exactly match the reviewed policy; the policy's version is not its own
  evidence. Metadata is checked before and after signing, and again at launch.
- Every new actual launch bypasses the status cache and performs fresh whole-
  bundle codesign/Gatekeeper verification outside the workspace lock. Changed
  resources/frameworks therefore cannot reuse cached main-executable approval.
  Ordinary selection/focus does not invoke signing checks. Before process creation
  the full pinned executable content is checked again, and the Playwright path
  checks it after startup too. Changed release metadata, signatures or binary
  pins block new launches until reviewed. Existing running sessions are not
  silently killed by update detection. Linux policy versions remain unverified
  by the built-in Mac signature path, so Linux CLI launches stay unavailable.
- Playwright's default test flags disable security-sensitive browser behavior.
  The supervisor disables **all** default arguments, supplying a minimal fixed
  set for the owned profile, process pipe, explicit route, first-run suppression
  and background-lifetime control. It does not disable the sandbox, Safe
  Browsing, component/security updates, TLS validation, IPC protections or native
  credential storage. No `--password-store=basic`, `--use-mock-keychain`,
  `--no-sandbox` or remote-debugging TCP port is used. Actual release behavior
  with this minimal argument set remains a native acceptance gate.
- Local direct profiles hold no application-managed proxy or OAuth secrets and
  do not require an unused app vault. Browser-managed storage remains the native
  browser's responsibility; no plaintext substitute is configured. Credentialed
  proxy routing is unavailable until a vetted native-vault/authentication bridge
  is implemented. All real proxy-required launches remain disabled, including
  unauthenticated routes with a one-time preflight: continuous enforcement and
  profile/runtime-bound DNS/IPv6/WebRTC/failure-fallback evidence are still needed.
  Selecting `verified_proxy` or supplying a probe alone grants nothing.
- Only `about:blank` and the fixed Gmail inbox intent can be requested by the
  client. Gmail opens or focuses a page in the exact profile's persistent
  context. It does not call the default browser, combine cookies, use OAuth,
  verify account identity, read messages, or fabricate unread counts.
- Signature/proxy preflight runs outside the metadata lock and is revision-fenced.
  Native startup and stop/cancel have `starting`/`stopping` states. No second
  launch uses an unresolved profile lease. Focus calls have a short bound;
  ambiguous outcomes stay explicit. The selected profile can change while another
  profile starts. Native profiles are never automatically evicted to save memory;
  unknown unsaved work causes a close-profile-or-increase-budget blocker.
- An unexpected connection loss or supervisor restart becomes
  `recovery_required`, not an invented stopped state. No stored PID is killed.
  Recovery is conservative; there is no automatic claim that detached browser
  children or website sessions were revoked.

## Required native acceptance before distribution

On the exact pinned Chrome release and supported macOS version, prove persistent
profile separation, launch/close/crash behavior, sandbox status, native password
storage, Safe Browsing and security-update operation, delayed cancel, repeated
focus, profile-specific Gmail navigation, and update invalidation. Perform
website login/provider tests only when separately authorized. Keep profile
browser content and credentials out of fixtures, logs, screenshots and commits.

References: [persistent-context ownership](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-persistent-context),
[official Chromium test defaults](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/chromium/chromiumSwitches.ts),
[official custom argument plumbing](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/browserType.ts).

## Explicitly gated native acceptance harness

`tests/test_client_native_acceptance.py` is skipped in every ordinary test run.
After approval for an actual Mac and the reviewed installed runtime, run:

```
TBM_NATIVE_ACCEPTANCE=1 TBM_RUNTIME_POLICY=/absolute/private/runtime-policy.json \
  python -m unittest discover -s tests -p test_client_native_acceptance.py -v
```

The harness requires real macOS plus both explicit environment settings. It
creates a fresh private temporary workspace and a loopback-only synthetic page;
it never opens Gmail, signs in, reads an existing browser profile, downloads a
browser, or creates a paid CI job. It covers two-profile cookie/localStorage
separation, persistence across acknowledged stop/restart, exact existing-handle
focus, and early cancel without a late running state. The harness uses internal
supervisor hooks only to navigate to its own local fixture; the user-facing API
still accepts only blank/Gmail intents.

This harness has **not** been run here. It is one part of acceptance, not a
replacement for sandbox/keychain/security-update/proxy-leak inspection. If a
native process outcome becomes uncertain, retain the workspace/profile lease and
inspect the process under the approved platform procedure before deleting test
data; never kill a guessed PID or retry around an OS security denial.


The observed release version uses Apple's [CFBundleShortVersionString](https://developer.apple.com/documentation/BundleResources/Information-Property-List/CFBundleShortVersionString),
not the `CFBundleVersion` build field. Apple's [bundle-key reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CoreFoundationKeys.html)
also defines `CFBundleExecutable`, which must match the exact selected executable.
