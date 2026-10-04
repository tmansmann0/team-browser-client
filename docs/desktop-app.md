# Integrated desktop browser: source candidate and delivery gates

Status, 4 October 2026: integrated desktop source and synthetic contracts are
implemented. **No Electron window, native Mac build, signed/notarized installer,
real profile-storage isolation, real proxy route, or provider login has been
accepted by this work.** The restricted Linux executor's previously observed
Chromium process-singleton IPC denial has not been retried or worked around.
No development or build work was performed on the user's Mac.

## Product and trust boundary

TeamBrowser's intended UX is one desktop browser application. Its own trusted
profile sidebar and address/tab controls surround actual native Electron
`WebContentsView` website surfaces, not iframes or an opened Safari URL. Each
immutable local profile ID selects a stable, opaque persistent Electron session
partition. Each tab owns a separate guest WebContents. Switching changes visible
views; it does not recreate/reload them. Selecting a profile creates no website
tab until the user chooses New tab. Engine identity is **Electron's bundled
Chromium**, displayed with actual runtime versions. It is not installed Chrome,
Firefox, Camoufox, or a fingerprint-protection claim.

The Python sidecar continues to own private durable profile metadata and filesystem
leases. It starts on an OS-assigned IPv4-loopback port, reports readiness on the
owned child pipe, and shuts down on stdin closure. Electron main supplies two
independent per-run secrets through stdin: one permits the isolated UI session's
same-origin requests; the other permits main-only profile claim/release routes.
Neither appears in arguments, URLs, renderer globals, configuration responses, or
logs. Existing Host, Origin, CSRF, JSON and private-workspace checks remain active.
Claims atomically verify the public metadata/revision and hold the existing
profile lease while the native session is active. Changing engine/proxy or deleting
a live profile is rejected. Ordinary Python lifecycle commands cannot mark an
Electron-owned profile stopped. An unacknowledged shutdown remains recovery_required.

Only bundled chrome receives the small frozen TeamDesktop preload API. Main
validates the exact main-frame and WebContents identity on every IPC call.
Guests get no preload, Node, generic IPC, filesystem, credential, or loopback
capability access. Sandbox, context isolation and web security stay enabled.
The chrome session permits only its exact loopback assets/API. Guest navigation
blocks file/custom protocols, credential-bearing URLs, literal local/private/
link-local targets and reserved local names. Permissions and downloads currently
default to denied. TLS errors remain errors. Background-profile/tab popups cannot
change foreground; permitted foreground popups become same-profile guest tabs.
Latest-selection fencing prevents slow setup from displaying an older selection.
Modal/editor layout hides native content immediately; geometry acknowledgments
never emit semantic state changes that could cause render feedback loops.

## Local proxies and honest limits

The main process reads fresh metadata itself; a renderer cannot supply engine,
proxy configuration, executable, route-bypass rule, PAC, credentials or arbitrary
native commands. Only built-in Chromium local profiles can be opened. Explicit
local direct networking is separate from a fixed public HTTP, HTTPS or SOCKS5
endpoint. `session.setProxy` is awaited before the first guest view is created.
No DIRECT fallback is configured for a fixed proxy and Chromium's implicit
localhost protections are not disabled. Guest WebRTC uses
`disable_non_proxied_udp` before navigation. Missing/invalid routes fail closed.

This is an implementation contract, **not verified DNS/IPv6/WebRTC/QUIC leak
prevention or proxy reliability**. URL interception cannot by itself establish
an actual resolved socket's public IP, prevent every DNS-rebinding case, or
prove that every Chromium background service uses a profile proxy. No local
DNS preflight is added that would leak proxied target names. The private sidecar
still requires its unexposed per-run capability even if a guest reaches loopback.
An accepted privacy-grade route requires separately observed packet/egress,
proxy-loss and recovery evidence on the target runtime. Authentication challenges
are denied: no proxy passwords, authenticated SOCKS5 or secrets-vault integration
are delivered. IP-allowlisted/unauthenticated public proxy endpoints are the only
candidate syntax; no actual proxy was purchased or contacted.

Stopping disables a profile's network request fence, closes its guest views
while honoring before-unload protection, closes connections, flushes session
storage and releases the owned metadata lease only after worker shutdown is
observed. Electron's documented ServiceWorkers API cannot force-stop every
worker. The source waits for running workers to become idle; if unconfirmed it
retains ownership rather than wiping registrations/cookies to manufacture a
successful stop. Actual worker/background-task behavior is a native acceptance
gate. The UI must keep configuration changes blocked until a confirmed stop.

The requested use is ordinary websites and their normal sign-in pages; no Gmail API or provider-specific app integration is intended. Google's OAuth policy prohibits embedded user-agents. Google/Gmail/Ads login
compatibility is therefore an early product gate, not an assumed feature. No
user-agent spoofing, popup trick, or system-browser login is claimed to turn
Electron's separate cookie jars into ordinary Chrome. Google or another provider
may require a different browser architecture. Keep real-account tests separately
authorized. Normal password-manager, extensions, download, permissions,
certificate details, update and accessibility UX also need explicit product work.

## Frozen sidecar scope

The candidate bundles the interpreter/libraries ahead of installation using
PyInstaller on a native cloud macOS host. The installed app runs no pip, package
installer, compiler, browser download, shell command supplied by a website, or
system-Python discovery. Python installed-browser launch is intentionally disabled
in integrated mode. Existing installed-Chrome/Camoufox profiles are not migrated
or relabeled as embedded Chromium.

The present Camoufox identity helper depends on an isolated real CPython
`-I/-S/-c` process and original package source provenance. The managed HTTPS
resolver explicitly rejects frozen interpreters. Neither feature is made
compatible by this packaging. Managed login, grants, team profile distribution,
proxy inventory/credentials and background synchronization remain separate work.
A managed profile cannot acquire an embedded local lease.

## Reproducible cloud build contract

`desktop/package-lock.json` pins Electron 44.5.1 and the official packaging,
fuses, signing and notarization tools. `requirements-macos-arm64.lock` pins the
Python 3.12 build/runtime dependency resolution with PyPI distribution hashes.
It was resolved on Linux for macOS arm64, **not installed or tested on a Mac**.
The equivalent wheel-only Intel resolution failed for the existing
cryptography 50.0.2 pin. Intel is not silently supported by downgrading crypto;
it requires its own reviewed build/dependency plan. Electron 44 requires macOS 13 or newer. The packaged sidecar may impose a newer
minimum that must be established on the exact built artifact; no minimum-OS
compatibility has yet been natively accepted.

The checked-in `.github/workflows/desktop-candidate.yml` is manual-only and has
not been dispatched. It targets an authorized GitHub-hosted native Apple Silicon
macOS runner, verifies architecture, installs locked build dependencies on that
host, runs source contracts, freezes the sidecar and packages the app. Publishing
the workflow, consuming paid CI, providing/signing with credentials, submitting
to Apple and distributing artifacts require the appropriate owner authorization.
Nothing here configures new credentials or persistent access.

On an authorized cloud macOS arm64 build host, the pipeline commands are:

```sh
python3.12 -m venv .build-venv
.build-venv/bin/python -m pip install --require-hashes --only-binary=:all: \
  -r desktop/requirements-macos-arm64.lock
npm ci --prefix desktop --ignore-scripts --no-audit --no-fund
PYTHONPATH=src .build-venv/bin/python -m unittest discover -s tests -p test_client_desktop_shell.py -v
npm --prefix desktop test
PYTHONPATH=src .build-venv/bin/python -m PyInstaller --clean --noconfirm \
  --distpath desktop/sidecar --workpath build/desktop-sidecar desktop/sidecar.spec
npm --prefix desktop run package:mac:candidate
```

Packaging stages only desktop source plus frozen public-client code, excludes
private API modules and development caches, and enables Electron fuses disabling
RunAsNode, Node environment overrides and inspector arguments while enabling
cookie encryption and ASAR integrity. The candidate archive has a SHA-256 report
with `native_acceptance:false` and `install_ready:false`. Default output is
explicitly unsigned and must not be presented as a ready installer.

The optional signed-candidate path requires existing authorized Developer ID and
notary keychain configuration on that cloud host. It applies hardened runtime,
signs nested code with official tooling (JIT-only Electron entitlement, no sidecar entitlements), submits/staples notarization, and runs
codesign, stapler and Gatekeeper checks before archiving. It does not upload or
create credentials. No signing/notarization step has been run. Never remove
quarantine, ad-hoc-sign to evade a distribution warning, or tell the user to
bypass Gatekeeper. A successful signed build still reports install_ready:false
until the acceptance record below exists for that exact artifact.

## Before the next install is offered

1. Confirm target Mac architecture/OS and an authorized cloud Mac builder/tester.
2. Produce the exact app bundle entirely off the user's Mac. Verify lockfile,
   license/SBOM, bundle contents, nested signatures, hardened runtime,
   notarization staple and Gatekeeper acceptance. Do not claim reproducible
   byte-identical signed output merely from a dependency lock.
3. In a clean authorized macOS account: launch from Applications without a
   terminal, Python or package downloads; quit/reopen; simulate sidecar/renderer
   failure; verify no orphan false-stopped state or profile overwrite.
4. Create two fresh profiles and real native website views. Prove cookie,
   localStorage, IndexedDB, cache and service-worker separation; same-profile
   persistence across restart; stable live-page switching; startup/repeated-click,
   popup, modal, before-unload and crash behavior. Synthetic adapter tests do not
   prove these browser-engine properties.
5. Test the exact proxy type using approved endpoints: egress, DNS, IPv6,
   WebRTC, connection reuse, proxy loss and route changes. Ensure no direct
   fallback under failure and no cross-profile authentication binding.
6. Separately authorize and test the actual required Google/Meta/work systems
   before claiming their login works. Stop on provider policy incompatibility.
7. Exercise install/update/uninstall in a clean native environment with original
   synthetic profiles. Preserve profile data by default. Keep native captures,
   test results and exact artifact hashes as the acceptance record.

The current source is a reviewable prototype. Several focused native build/QA
iterations are still required; a date for a usable Mac alpha is not established
while build/signing/provider/proxy prerequisites are unresolved.

## Primary references

- [Electron WebContentsView](https://www.electronjs.org/docs/latest/api/web-contents-view)
- [Electron session and proxy APIs](https://www.electronjs.org/docs/latest/api/session)
- [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security)
- [Electron ServiceWorkers](https://www.electronjs.org/docs/latest/api/service-workers)
- [Electron code signing](https://www.electronjs.org/docs/latest/tutorial/code-signing)
- [Electron 44 macOS support](https://www.electronjs.org/blog/electron-44-0)
- [GitHub hosted macOS runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [PyInstaller operating model](https://pyinstaller.org/en/stable/operating-mode.html)
- [Google OAuth secure-browser policy](https://developers.google.com/identity/protocols/oauth2/policies#secure-browsers)

## Additive hosted-Mac packaged smoke (limited proof)

The manual candidate workflow now includes `desktop/scripts/smoke-packaged-mac.cjs`.
This is a **test definition, not a record that a native run passed**. Review the
`native-smoke/summary.json` artifact for the actual exact-commit result. Linux
Node unit tests of the harness do not establish native behavior.

The harness verifies the candidate ZIP SHA-256 and workflow commit, extracts that
same archive, and launches its actual `TeamBrowser.app/Contents/MacOS/TeamBrowser`
twice on the authorized GitHub-hosted `macos-15` Apple Silicon runner. It does not
use development Electron, a fake browser adapter, Playwright browser downloads,
the user's computer, real accounts, proxy endpoints, signing credentials,
accessibility automation, screen-recording permissions, or inspector ports.

An explicit, fixed diagnostic argument selects fresh marked OS-temporary HOME,
user-data and session-data directories before the app takes its instance lock.
Ordinary launches do not change their paths or behavior. The existing packaged
Python sidecar, BrowserWindow, sandboxed WebContentsViews, production adapter,
trusted preload IPC, ownership routes and normal before-quit handler are used.
The diagnostic accepts no arbitrary scripts, fixture URLs, external test server,
credential input or remote-control endpoint.

Production guests intentionally reject local/private web addresses. The smoke
therefore supplies one fixed document at `https://native-smoke.example/` through
Electron's documented per-session HTTPS protocol handler, solely in the two blank
diagnostic sessions. It does not relax guest URL policy, sandbox, web security,
CSP, permission/download denial or certificate-error handling. This controlled
transport has no real network or TLS exchange and must not be called network,
proxy, provider-login or certificate validation.

Narrow checks include:

- Actual packaged process, frozen sidecar and visible BrowserWindow startup.
- Real native guest surfaces attached to the window, distinct Electron sessions,
  sandbox/web-security preferences and absence of Node/preload privileges.
- Same-origin A/B cookie, localStorage and IndexedDB separation, then same-profile
  persistence after full app exit and relaunch with unchanged synthetic data.
- Twelve repeated switches per launch preserving distinct live documents and
  the intended native view visibility. This is privileged fixed test driving of
  the ordinary IPC commands, not a mouse/keyboard UX acceptance test.
- Nonblank native captures of bundled chrome and both guest surfaces, separately.
  These are WebContents captures, not proof of full desktop composition.
- Normal app quit closes native guests, releases profile leases and stops the
  sidecar, confirmed again by the outer process. No forced cleanup counts as pass.

An absent GUI, blocked startup, modal/keychain prompt, empty capture, assertion
failure, crash or timeout fails the smoke; the record retains the exact last
reached check. The harness does not remove quarantine, weaken Gatekeeper, change
OS permissions, disable the sandbox or retry through a different security mode.
Only fixed reports, native PNG captures and bounded logs from the isolated child
are uploaded. Profile stores, cookies/databases, temporary HOME and private
sidecar pipes are excluded.

After editing Mach-O fuses, the official `@electron/fuses` tool resets the local
ad-hoc signature for the unsigned-candidate build on Apple Silicon, as required
by that platform for locally generated executable code. `signature_kind:ad-hoc`
and `developer_id_signed:false` distinguish this from a Developer ID release;
it is not notarization, trust, installability or a Gatekeeper bypass. The candidate
filename retains `unsigned-candidate` to mean no Developer ID distribution signing.
All existing fuse hardening remains enabled.

Even a passed smoke sets only `packaged_synthetic_storage_smoke:true` in its own
summary. `native_acceptance:false` and `install_ready:false` remain unchanged in
both candidate and smoke records. Service workers/cache, actual proxies and
network routing, provider accounts, full UI interaction, crash recovery,
installation, upgrades and signed/notarized distribution remain separate gates.

Primary API references: [session-scoped protocol handlers](https://www.electronjs.org/docs/latest/api/protocol),
[native view visibility](https://www.electronjs.org/docs/latest/api/view),
[WebContents captures](https://www.electronjs.org/docs/latest/api/web-contents), and
[official fuse tooling's Apple Silicon requirement](https://github.com/electron/fuses#apple-silicon).

### Electron 44 diagnostic details

The native smoke checks the exact boolean security fields emitted by Electron
44.5.1's `SaveLastPreferences` and fails by field name if any is missing or wrong.
It does not reinterpret an omitted field as false. That Electron implementation
omits `devTools` and `preload` from `getLastWebPreferences`; it stores the DevTools
control separately. A fixed runtime attempt to open guest DevTools must create no
DevTools contents, open no view and emit no opened event. Fixed guest JavaScript
also checks that `process`, `require`, `Buffer`, `ipcRenderer` and `TeamDesktop`
are unavailable. Only these named boolean/type observations enter the report;
no arbitrary preference object or preload path is logged.

Chrome captures wait for the actual profile manager, an enabled New profile
control and absence of a workspace error/modal. A second capture after an ordinary
UI reload must show both persisted synthetic profiles. Merely rendering the
initial loading shell does not satisfy this check. Existing bundle-signature
verification failures now record bounded `codesign --verify` diagnostics from the
isolated candidate, without modifying signatures or security policy.

Pinned source references:
[preference snapshot serialization](https://github.com/electron/electron/blob/v44.5.1/shell/browser/web_contents_preferences.cc#L362-L383)
and [DevTools enable check](https://github.com/electron/electron/blob/v44.5.1/shell/browser/api/electron_api_web_contents.cc#L3201-L3206).
