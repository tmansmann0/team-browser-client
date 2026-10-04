# TeamBrowser: real browser-chrome feasibility and implementation plan

Research date: 3 October 2026. Scope: read-only source and architecture review. No browser was launched; no add-on/native host was installed; no credentials, permissions, policies, accounts, signing submissions, or deployments were changed. The main repository and sales site were not modified.

## Decision

**Build a Mozilla-signed Manifest V3 TeamBrowser sidebar plus a narrowly scoped native-messaging host. Keep the browser's real address/security controls and native top tab strip. Offer a native horizontal/vertical-tab layout switch using `browserSettings.verticalTabs` on Firefox 142+.** This is real UI inside the browser window, with ordinary web pages occupying the ordinary browser content area. It requires neither page injection nor iframe hosting. [Sidebar API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/sidebarAction), [vertical-tabs API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/browserSettings/verticalTabs), [Firefox 142 API introduction](https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Releases/142).

For the first human-use acceptance pilot, use an **installed, publisher-verified stock Firefox desktop release**, new app-owned profiles, and a small native-process supervisor. This is the recommended official-engine intermediate. It preserves the same extension interface intended for Camoufox while its existing human-browser security/update gates are completed. It is not a drop-in executable replacement in the current Playwright Firefox adapter: stock Firefox lacks Playwright's required patches. Add a separate adapter; do not quietly swap the engine or relabel it Camoufox. [Playwright Firefox limitation](https://playwright.dev/python/docs/browsers), [Firefox process/profile flags](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).

Camoufox remains a separately admitted runtime. The sidebar approach is feasible from its source, but **no reviewed native Camoufox distribution, functional protection/update configuration, or authenticated profile-to-native-host binding has been demonstrated in this environment**. Those are release gates, not a reason to substitute an external manager indefinitely.

For the stock-Firefox adapter, the fixed native launch shape is the verified Firefox executable with `--no-remote --profile <absolute-app-owned-browser-data> about:blank`, passed as separate argv entries, never through a shell. The profile path is not a credential. Capture the actual owned process identity at spawn and reject unverified launcher handoffs; use the extension for subsequent fixed-intent navigation and tab/window focus. Do not enable Marionette, a TCP debugging port, or a Playwright compatibility patch for this pilot. The existing private-directory and lease checks still apply.

The first release deliberately has one native browser instance/profile, each with its own TeamBrowser sidebar. Choosing another profile brings its window forward. A single native tab strip containing tabs from independent browser profiles is not delivered by these extension APIs. That larger requirement needs a maintained browser-shell/fork project and a separate security design.

## 1. What is established, and what is not

| Evidence level | Finding |
| --- | --- |
| Local source inspected | `docs/native-runtime.md`, `docs/camoufox-proxy-runtime.md`, `docs/brand-guide.md`, `client/camoufox_runtime.py`, `client/playwright_supervisor.py`, `client/installed_browser.py`, and `THIRD_PARTY_NOTICES.md`. Existing adapters use distinct persistent app-owned profile directories and process-pipe control. Their documented native acceptance is unrun. |
| Pinned launcher source inspected | PyPI `camoufox==0.5.6` wheel bytes, SHA-256 `b906836cd952376a466f0e55445f139b8a65adfb9f18ab55cb2cd0c727b11561`; its `async_api.py` hash is `3a1091a65a347db49899ad0337b578720dde2ea6d5e07b98dd782acbe91869b7`, matching the previous local source review. ZIP contents were read, never imported or executed. [Version metadata](https://pypi.org/pypi/camoufox/0.5.6/json). |
| Browser-source provenance established | The official `v152.0.4-beta.30` tag resolves to commit `5d06ec1629ac7843508f1e683f83e404fde8db76`. Its `upstream.sh` names Firefox 152.0.4 and beta.30; its Python package metadata names 0.5.6. This associates an upstream release with the launcher era, not an arbitrary installed executable. [Release](https://github.com/daijro/camoufox/releases/tag/v152.0.4-beta.30), [pinned upstream file](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/upstream.sh), [package metadata](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/pythonlib/pyproject.toml). |
| Official API support established | Firefox has sidebar extension pages, tab/window management, native messaging, and a native vertical-tabs setting API. Firefox 152.0.4 source implements the latter through `sidebar.verticalTabs` with the `browserSettings` permission. [Versioned implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_152_0_4_RELEASE/toolkit/components/extensions/parent/ext-browserSettings.js). |
| Not tested | Actual signed XPI installation, API presence in a selected Camoufox build, native sidebar/vertical-tab coexistence, macOS process ancestry/peer identity, window activation, add-on consent presentation, native host lookup under the adapter's altered HOME, security service operation, crash/reconnect, profile isolation, or upgrades. No source review substitutes for these checks. |

### Launcher version is not engine version

The 0.5.6 launcher supports selection of installed browsers and a Playwright-dependent browser floor. Its wheel requires `playwright<1.63`; the application pins 1.62.0. The source floor for Playwright 1.61+ is beta.30. This floor is not an authenticity check, a security-currentness check, or a guarantee for every later engine. Existing nonempty `from_options` bypasses normal launcher option generation, so the application must enforce all admission requirements itself. The application already supplies the executable/profile/config explicitly. [Version constraints](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/pythonlib/camoufox/__version__.py), [launcher interface](https://camoufox.com/python/usage/).

Do not infer engine identity from a user-agent string, a caller-provided version, or the SDK's writable `version.json`. For admission, bind actual signed distribution metadata, engine build/source revision, executable and whole-package identity, platform/architecture, launcher/driver pins, extension artifact, and acceptance record. If metadata cannot be independently mapped to the reviewed binary, remain blocked. Mutable current documentation/source is useful for discovery, not a substitute for this mapping.

## 2. First real chrome UX

Inside every participating native window:

- Native address bar, site identity/lock, permission prompts, download and certificate-warning surfaces remain browser-owned and visible.
- Native horizontal tabs remain the default. TeamBrowser does not paint a fake browser tab strip above an embedded website.
- The TeamBrowser sidebar shows the active profile, favorites, running/stopped status, and a compact local tab list. A click on another running profile performs an acknowledged cross-window focus.
- Layout offers “Horizontal tabs” and “Vertical tabs” where the API is present and controllable. Choosing layout requests optional browser-settings permission if not already granted.
- A compact/comfortable density setting affects only TeamBrowser's sidebar content. Browser sidebar placement/width and native toolbar customization remain native controls unless a separately verified supported API exists.
- Sidebar opening uses the native sidebar entry or a TeamBrowser action button. Call `sidebarAction.open()` directly within the user gesture handler, before unrelated awaits. The API does not permit an unsolicited background command to force it open. [Open restriction](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/sidebarAction/open).

Reuse the project's original Shared Frame mark and forest/paper/lime tokens from `docs/brand-guide.md`; package assets locally. Use live UI text, keyboard profile selection, visible focus rings, reduced-motion support, text plus icons for lifecycle state, and an unmistakable active-profile name. No remote fonts/assets or service-derived avatars are necessary.

### Supported layout boundary

| Requested behavior | Supported approach / boundary |
| --- | --- |
| Profile switcher inside browser | Packaged extension sidebar + authenticated controller bridge. |
| Native top tabs | Leave the native horizontal tab bar enabled. Ordinary tabs API calls can activate, move, pin, create, or close tabs in the caller's profile. |
| Native vertical tabs | Firefox UI introduced this in 136; extension-controlled switching requires 142+. Use `browserSettings.verticalTabs`, feature-detect it, check `levelOfControl`, set the boolean, and read it back. It is a profile-global setting, not a separate per-window layout. [136 release](https://www.mozilla.org/firefox/136.0/releasenotes/), [142 addition](https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Releases/142). |
| Custom grouping/density inside sidebar | Extension HTML/CSS can implement this. It does not change native tab geometry. |
| Fully replace/restyle/reposition the native tab strip | Not exposed by the reviewed ordinary WebExtension APIs. `theme` can change supported theme attributes; it does not provide arbitrary browser-chrome DOM/CSS access. [Theme API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/theme). |
| Hide individual tabs | A separate `tabHide` privilege exists, but hiding tabs is not replacing the top tab bar. Do not request it for this design. [Tabs API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/tabs). |
| Both multiple independent profiles and their pages in one OS window | Not achieved with `tabs.move`, containers, page iframes, or profile-window focus. Requires a separate maintained native browser architecture. |

The extension may show a vertical navigation list while native horizontal tabs remain visible, but label it a TeamBrowser tab list. Do not present that duplicate list as a replacement for the native layout. Test native vertical tabs plus an open TeamBrowser sidebar at narrow window sizes; the two regions can consume substantial width.

## 3. Concrete Firefox extension package

Use one code-only XPI, built reproducibly from a dedicated extension directory. Suggested contents:

- `manifest.json`
- `background.js`: tab event subscriptions, one native port per profile, protocol validation, reconnect state
- `sidebar/sidebar.html`, `sidebar.js`, `sidebar.css`
- `options/options.html`, `options.js`, `options.css`
- `icons/` and a small selected subset of original TeamBrowser brand assets
- source/license notices and a reproducible build recipe supplied with signing submissions

The following is a proposed manifest shape, not an installed or signed artifact. The fixed UUID is an example identity to reserve and keep consistent through signing, host allowlisting and updates; it is not a verified AMO registration.

```json
{
  "manifest_version": 3,
  "name": "TeamBrowser",
  "version": "0.1.0",
  "description": "Profiles and tabs for app-owned TeamBrowser sessions.",
  "browser_specific_settings": {
    "gecko": {
      "id": "{9b5fd7f3-d88e-4c8e-b377-8d2e68d1a582}",
      "strict_min_version": "142.0",
      "data_collection_permissions": {
        "required": ["browsingActivity"]
      }
    }
  },
  "permissions": ["nativeMessaging", "tabs", "storage"],
  "optional_permissions": ["browserSettings"],
  "background": {"scripts": ["background.js"]},
  "action": {
    "default_title": "Open TeamBrowser",
    "default_icon": {"32": "icons/mark-32.png"}
  },
  "sidebar_action": {
    "default_title": "TeamBrowser",
    "default_panel": "sidebar/sidebar.html",
    "default_icon": "icons/mark-32.png",
    "open_at_install": true
  },
  "options_ui": {"page": "options/options.html", "open_in_tab": false},
  "incognito": "not_allowed",
  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'"
  }
}
```

Firefox MV3 uses an event-page `background.scripts` implementation; do not blindly copy Chrome's service-worker-only manifest. No MV3 `persistent:true`, remote code, content scripts, externally-connectable bridge, web-accessible resources, or website host permissions are needed. [Background manifest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background), [sidebar manifest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/sidebar_action).

The proposed `browsingActivity` declaration covers the chosen feature of sharing bounded tab labels/origins and tab state with the user's local controller for tab mirroring/focus. Local native messaging is still data transmission under Mozilla's rules. Before submission, classify the exact final fields accurately; omit full URLs, URL query/fragment values, page bodies, and telemetry. Do not falsely declare `none` simply because there is no cloud upload. Title strings can themselves contain private content, so never put them in logs and make the local sharing clear. If a narrower first release keeps all titles/origins inside the extension, reevaluate its actual native-message fields and consent declaration rather than retaining an inaccurate template. [Built-in data consent](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/), [add-on policies](https://extensionworkshop.com/documentation/publish/add-on-policies/).

### Minimum privileges

- `nativeMessaging`: only for the signed local helper protocol.
- `tabs`: needed for tab titles, URLs and favicons, not for most basic tab manipulation. For a profile-only sidebar that neither reads nor mirrors these fields, omit it. [Tabs permission semantics](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/tabs).
- `storage`: only non-secret display preferences, schema version and consent UI state. No session capabilities, credentials, cookies, browser profiles, or authentication tokens in `storage.local`/`sync`/IndexedDB.
- Optional `browserSettings`: request only when the user chooses the native layout control; use it solely for `verticalTabs`. Honor denied permission, policy control, and other-extension control. `clear()` releases the setting when appropriate instead of overwriting a user's later choice. [BrowserSetting control semantics](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/types/BrowserSetting).
- No `cookies`, `history`, `sessions`, `proxy`, `privacy`, `management`, `scripting`, `webRequest`, `<all_urls>`, `tabHide`, or `activeTab` for this slice. No separate `windows` permission is needed for normal window focus.

Do not fetch a remote favicon URL merely because it appears in `Tab.favIconUrl`. Prefer a local generic icon or an already available safe local/data image, preserving the restrictive CSP and avoiding an extra website request.

## 4. Native host packaging and protocol

Package a small dedicated compiled host in the signed TeamBrowser desktop bundle. It is not a general shell/Python launcher. Use a fixed host name, e.g. `com.teambrowser.chrome`, and a stdio native manifest with only the exact signed add-on ID:

```json
{
  "name": "com.teambrowser.chrome",
  "description": "TeamBrowser supervised profile interface",
  "path": "/Applications/TeamBrowser.app/Contents/MacOS/TeamBrowserChromeHost",
  "type": "stdio",
  "allowed_extensions": ["{9b5fd7f3-d88e-4c8e-b377-8d2e68d1a582}"]
}
```

That path is illustrative. The installer writes the verified actual absolute bundle path, checks ownership, file identity and directory safety, and never accepts a caller-supplied executable or socket path. Firefox's documented per-user macOS registration location is `~/Library/Application Support/Mozilla/NativeMessagingHosts/com.teambrowser.chrome.json`; Linux and Windows have different directories/registry entries. Registration is OS-user-scoped, **not Firefox-profile-scoped**. The existing Camoufox adapter's per-profile HOME does not prove which native manifest directory its particular build resolves. Verify lookup; do not use an environment variable as authentication. [Native manifest locations](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests).

The extension opens `browser.runtime.connectNative("com.teambrowser.chrome")`. Messages are length-prefixed UTF-8 JSON over dedicated stdin/stdout pipes. Implement a far smaller application limit, e.g. 64 KiB per message and bounded tab batches, rather than accepting the browser protocol's theoretical large input. No debug text goes to stdout; stderr diagnostics are fixed identifiers because Firefox can display them in its console. [Native messaging framing and lifecycle](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

Use a private local IPC endpoint between this host and the already-running controller. It is not the browser-facing loopback HTTP API and does not reuse its CSRF token. The helper never exposes the controller's automation pipe, a bearer token, an arbitrary URL opener, filesystem reader, shell, process kill, browser protocol, or credential access.

Proposed operation allowlist after binding:

- `snapshot` / `snapshot_changed`: controller-authorized profile labels and current running state; a monotonically increasing revision
- `focus_profile`: an opaque controller-issued target reference from the authorized snapshot
- `focus_tab`: a target profile reference plus session-scoped tab reference
- `open_intent`: only existing fixed `blank` or `gmail_inbox` intents, subject to controller policy
- `tab_snapshot` / `tab_delta`: bounded, sanitized metadata for this bound source profile, if disclosed and consented
- `ack` / `error`: operation ID, session generation, revision, fixed result codes

Do not include close/stop, profile deletion, proxy changes, extension installation, layout mutation of another profile, or generic navigation in v1. Those need separate explicit product flows. Incoming messages never establish their own source-profile identity. Snapshot refs are selectors, not credentials; validate authorization server-side on every request.

## 5. The critical profile-binding problem

**Native messaging alone cannot authenticate the browser profile.** On Firefox, the host receives the manifest path and the invoking add-on ID. Neither is an OS-authenticated profile identifier. A legitimate copy of the same signed extension installed in an ordinary personal Firefox profile can invoke the same OS-user-registered host. A command-line-launched copy of the helper can also supply those arguments. Signing proves package identity, not which profile is calling. [Firefox native-messaging launch arguments](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging), [Mozilla launch implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_152_0_4_RELEASE/toolkit/components/extensions/NativeMessaging.sys.mjs).

The following are insufficient by themselves: extension ID; `runtime.id`; an extension-generated profile UUID; browser window/tab IDs; HOME; a disk marker; a claimed PID; matching executable name/signature; `getpeereid`/same UID; or a random endpoint pathname. Do not build a generic `hello(profile_id, token)` bridge with a token in command arguments, URLs, environment, or persistent extension storage.

### Recommended bounded macOS binding

This is a proposed native implementation with an acceptance gate, **not an existing facility of the current Python adapters**:

1. The controller directly owns or independently verifies each native browser spawn. Retain a live launch record containing the exact runtime identity, kernel process identity/birth information, immutable lease generation, canonical private browser-data directory identity, and profile ID. Permit one browser-root process per profile. Do not recover ownership from a stale saved PID or process-name search.
2. The native helper connects to the controller's private AF_UNIX endpoint. The controller obtains the peer's **kernel-supplied** audit identity, checks the expected user, and verifies the running helper's designated code-signing requirement. The helper similarly authenticates the controller. Apple's XNU exposes `LOCAL_PEERTOKEN`; Apple's Security framework accepts an audit token through `kSecGuestAttributeAudit`/`SecCodeCopyGuestWithAttributes`. Availability and behavior must be tested on the minimum supported macOS version. [XNU socket definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h), [Apple audit attribute](https://developer.apple.com/documentation/security/ksecguestattributeaudit), [code lookup](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes%28_%3A_%3A_%3A_%3A%29).
3. Independently inspect the authenticated helper's live process ancestry and birth identities and require it to originate from exactly one live admitted browser root. Record and allow only the exact observed Firefox subprocess chain for the supported build; do not allow arbitrary descendants or trust helper-supplied ancestry. Mozilla can use intermediary/portal launch machinery on some platforms. If there is no unambiguous authenticated chain, reject. Recheck liveness and lease generation before committing the binding. Apple process information includes parent PID and start-time fields; race-resistant lifetime checks and actual chain observation are additional engineering, not conferred by the header. [Process fields](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
4. Resolve the source profile from that trusted launch record only. The registry says which leased profile that root was created to own; no profile path or ID supplied by the extension can override it. Require the installed approved signed XPI/package state, supported helper version, and browser/runtime acceptance as part of admission.
5. Bind permissions to the accepted live connection and launch generation. Use fresh in-memory session state and request sequencing; there need not be a reusable bearer secret at all. Disconnect/restart/lease change revokes the binding and outstanding cross-profile refs. Rebinding repeats OS verification. A nonce can prevent replay but cannot substitute for OS caller verification.

Do not confuse code-signing identity with authorization: a perfectly valid helper started by an unsupervised browser must still fail at step 3. PID alone is racy; a signed browser process launched by some other application is not ours. Browser self-relaunch, launcher handoff, update, parent death and driver loss invalidate the old relation unless independently re-established.

### Threat-model limit and fail-closed rule

This design can protect the controller from websites, other extensions, other OS users, and accidental same-user unsupervised browsers **if the tested OS/process chain is reliable**. It does not establish a cryptographic profile attestation against an attacker already able to tamper with the user's controller/profile files, inject code into an allowed process, use an exposed automation channel, or alter unsigned extension loading. Hardened runtime, code-signature validation, private file ownership and no debugging exposure matter, but are not a blanket same-user compromise defense.

If hostile same-user processes are in scope, do not claim this recipe solves them. Use a separately reviewed OS isolation/service entitlement model, or a maintained browser change that provides a narrowly authenticated supervisor channel. That is a different project. In particular, current Playwright context ownership does not automatically expose a supported race-resistant OS process identity for native-host binding: add that evidence or keep bridge authorization disabled.

**Acceptance invariant:** installing the genuine TeamBrowser XPI in a personal/unmanaged profile must reveal no profile list and execute no controller command. Reject before sending even names/counts. Do not fall back to a user-typed profile ID or pasted controller token.

## 6. Fast cross-profile focus without session movement

Keep recently used profiles alive within the existing explicit resource budget. The extension knows only its own native tabs/windows. It sends a target reference; the controller checks access, source binding, target lease and generation, then routes the request to the target profile's own authenticated extension connection or its verified existing native handle.

Within the target extension, resolve a session-scoped tab reference, confirm it still belongs to the target window/profile, call `tabs.update(tabId, {active:true})`, and then `windows.update(windowId, {focused:true})`. Confirm results/events before reporting focused. Tab IDs are valid only within a browser session; namespace them by profile and launch generation and discard stale refs. [Tab identity scope](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/tabs), [window focus API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/windows/update).

Use latest-selection-wins sequencing so a slow A-to-B operation cannot steal focus after the user has selected C. Separate “selected in manager”, “native tab activated” and “OS foreground acknowledged”; macOS Spaces/fullscreen/window-manager rules can still affect observed focus. Measure warm-switch latency on real hardware; do not advertise a number from source review.

A stopped target goes through the existing approved launch/admission path. A crashed, unbound, budget-blocked or uncertain target remains explicitly unavailable. Never kill another browser or migrate its tabs to appear fast. No cookie reads/copies, storage export, profile-directory cloning, or cookie-jar merging are involved. Shared controller metadata is not shared website session storage.

Firefox MV3 background code must tolerate shutdown/reconnect and persist only harmless preferences. Firefox 152.0.4 source exempts an active native-messaging port from normal event-page idle termination, but extension-process crashes and updates can still disconnect it. Reconnect with a new authenticated generation; do not replay queued mutations blindly. [Versioned event-page lifetime implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_152_0_4_RELEASE/toolkit/components/extensions/parent/ext-backgroundPage.js).

## 7. Camoufox integration: configuration versus distribution work

These are existing human-use acceptance issues, not evidence that any real browser has run here.

### A. Native chrome restoration: profile/config candidate

The pinned Camoufox global stylesheet patch loads `chrome.css` from the engine directory when legacy profile stylesheet loading is enabled. The loader also checks Camoufox's `disableTheming` configuration. Thus there is a source-backed way to skip this stylesheet: explicitly disable `toolkit.legacyUserProfileCustomizations.stylesheets` in the owned profile, and verify the result; alternatively review the `disableTheming` configuration switch in the exact runtime. The preference route is a bounded first candidate and requires no downloaded theme. [Loader patch](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/patches/global-style-sheets.patch), [default configuration](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/settings/camoufox.cfg).

The stylesheet specifically contains hiding rules for `#tracking-protection-icon-container`, `#tab-notification-deck`, `#unified-extensions-button`, the toolbar pin menu entry, tab close controls, and several ordinary toolbar/bookmark controls. It also changes tab dragging and URL-bar dimensions. These source rules must be checked against actual element IDs/rendering in the selected build. They do **not** show removal of the URL site-identity/lock control, disabling certificate verification, or bypassing the TLS warning page. Do not turn an extension-button hiding observation into a certificate-warning allegation. [Exact stylesheet](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/settings/chrome.css).

Any changed preference/configuration set must be added to the reviewed runtime/acceptance digest, including managed-route acceptance where relevant; do not silently reuse an old acceptance record. Disabling this stylesheet will not undo source patches that automatically pin extensions or other browser-init changes. Evaluate the resulting native toolbar, notification deck, keyboard focus and horizontal/vertical layout together. Restore focus-indicator defaults overridden by the configuration as part of accessibility acceptance; CSS removal alone is insufficient.

### B. Safe Browsing/security services: configuration plus functioning service evidence

The pinned config disables phishing/malware/download protection, clears a Mozilla provider update URL and the Remote Settings server, and disables add-on blocklist updates. Some are ordinary default preferences and may be overridden in an app-owned profile; that fact is not functional protection. Restore a reviewed, complete configuration derived from the exact Gecko version, including necessary provider tables, HTTPS update/hash endpoints, Remote Settings/blocklist services and any legitimate distribution-specific service credentials/entitlements. Keep browser TLS verification and sandbox enforcement intact. [Camoufox defaults](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/settings/camoufox.cfg).

Firefox 152.0.4's Safe Browsing code refuses table registration without a provider update URL and clears Google update/hash URLs when its required API key is absent. Therefore, simply setting protection booleans to true is insufficient. Do not borrow Mozilla's or another product's service credentials, set a “skip key check” switch, or claim arbitrary vendor endpoints are authorized for a redistributed fork. Where service access/configuration is missing, a maintained distribution arrangement is necessary. [Exact Gecko service logic](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_152_0_4_RELEASE/toolkit/components/url-classifier/SafeBrowsing.sys.mjs).

Acceptance needs both successful fresh protected-list/service updates and harmless official/synthetic protection checks, including clean-path controls and stale/offline behavior. Seeing an interstitial backed by a built-in test entry alone does not prove fresh production lists. Do not browse real malware, bypass warnings, or send private browsing data during acceptance.

### C. Engine updates: distribution/controller obligation

The pinned base build uses `--disable-updater`, and the macOS configuration disables the update agent. Runtime preferences cannot bring compiled-out updater functionality back. Packaged policies/configuration also disable engine/extension/system-addon update paths. Manager-owned signed/verified engine updates are a valid design, but must actually exist before distribution. [Build options](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/assets/base.mozconfig), [macOS options](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/assets/macos.mozconfig), [packaged policy](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/settings/distribution/policies.json).

Implement trusted release inventory, authenticated update metadata, independent publisher verification, exact package/version/source mapping, dependency/extension compatibility matrix, safe staging, whole-bundle verification, update interruption recovery, and timely security-release admission. Reverify on next launch after a changed binary; never freeze an old accepted hash indefinitely. Do not overwrite an in-use runtime, silently downgrade a profile, or reuse a newer profile with an older engine. Keep existing running sessions explicit and request a safe restart when needed.

### D. Add-on installation/signing and private browsing: distribution gate

Camoufox's documented `addons` parameter accepts extracted extension folders. The pinned browser-init patch installs these as temporary add-ons. The current application's nonempty `from_options` does not invoke that helper path, so adding `addons=...` beside it is not a working integration. Do not reenable broad SDK option generation merely to load the sidebar. [Camoufox add-ons docs](https://camoufox.com/fingerprint/addons/), [temporary-install patch](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/patches/browser-init.patch).

For a distributed product, prefer normal installation of the signed XPI inside each new owned profile, with the actual permission/data-consent flow. Do not represent a temporary/developer load as a persistent signed production installation. The pinned build permits unsigned scopes and does not require signing as a stock release does. Its private-mode patch adds private-browsing permission broadly. A signed TeamBrowser XPI alone does not restore system-wide signature enforcement or normal private-access controls. Keep this extension's manifest `incognito:not_allowed`, filter private windows defensively, and verify that the fork honors the prohibition. If it does not, restore the browser implementation through a maintained distribution change. [Build signing settings](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/assets/base.mozconfig), [private-mode patch](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/patches/all-addons-private-mode.patch).

### E. Password/UI policy and remaining evidence

The packaged policy disables password-manager offers and form-history features. A profile preference cannot be assumed to override an enforced policy. Determine which policies are actually loaded in the exact distribution; its build flags also affect policy sources. If product requirements include native password storage, demonstrate the actual supported provider and consent behavior or keep the feature absent. Do not substitute plaintext storage. Altering files inside an already signed bundle invalidates the original integrity evidence; publish a separately reviewed signed distribution when bundle changes are necessary.

## 8. Signing, updates, licenses and setup approvals

### Extension distribution

Submit the reproducible extension to Mozilla for signing, initially as an unlisted self-distributed add-on. Unlisted does not waive automated validation, review, policies or the distribution agreement. Release/Beta stock Firefox requires signed add-ons. For a pilot, let the user install the signed local XPI through Firefox's normal install-from-file flow in each owned profile; do not copy arbitrary existing-profile extension databases or silently force-install globally. [Signing](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/), [self-distribution](https://extensionworkshop.com/documentation/publish/self-distribution/).

The manifest above intentionally has no invented production update URL. Before general release, establish either an authorized HTTPS signed-XPI/update-manifest endpoint or an explicit manager-delivered signed update flow, and test it. Mozilla signing authenticates an add-on package; it does not authenticate the native helper or engine. Bind the controller protocol to accepted helper/XPI versions; preserve user permission choices across updates. Never disable signature checks to reduce signing friction.

### License obligations

The Python launcher declares MIT; the browser is MPL-2.0 with additional bundled dependencies. Keep exact notices/SBOM, and if distributing a modified browser make covered source, modifications and license notices available as required. Original extension/controller files are not automatically MPL merely because they talk to Firefox. Mozilla trademarks are a separate matter; use TeamBrowser identity without implying Mozilla endorsement. Verify all bundled fonts, libraries and other components rather than treating the root license as the complete inventory. [Pinned browser license](https://github.com/daijro/camoufox/blob/5d06ec1629ac7843508f1e683f83e404fde8db76/LICENSE), [Mozilla MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), [Mozilla licensing/trademarks](https://www.mozilla.org/en-US/foundation/licensing/).

### Approvals required before actually doing setup

Nothing in this architecture review authorizes installation or grants. Bundle the concrete requested scope before implementation setup:

1. Installing/running the reviewed browser/add-on/helper: identify exact artifacts, source, publisher, version and owned test profiles. Unknown-source software requires action-time confirmation; official-vendor installation still needs specific approval.
2. Native host registration and enabling persistent controller access: action-time approval describing that TeamBrowser can read disclosed tab metadata and focus/open fixed intents across the listed app-owned profiles. This is a meaningful persistent-access grant, not merely a visual preference. No access to personal browser profiles.
3. Add-on API/data permission prompts: present the exact native-messaging/tab-data scope and local destination. Request optional `browserSettings` only when the user chooses layout. No unrelated browser/OS permissions; no Accessibility/Automation permission assumed for ordinary WebExtension window focus.
4. Signing submission/publication: approval to upload the extension source/package to Mozilla, accept the linked distribution agreement, and create/use the authorized developer account. Any API key creation is a separate credential/access action; do not place signing credentials in chat, source, arguments or logs.
5. Any OS isolation/firewall/security configuration or expanded security-service/network access needs its own scoped approval. No security-warning bypass. Actual website login/provider acceptance stays a separate authorized test.

Once the user has specifically approved ordinary non-sensitive layout/focus operations, do not interrupt every click with repeated confirmations. Enforce the scope in the product protocol and use browser-native prompts where required.

## 9. Alternatives and tradeoffs

**Existing installed Chrome adapter + MV3 side panel:** strong alternate official-engine path that reuses current persistent-context ownership. Replace Firefox `sidebar_action` with `side_panel.default_path`, use `sidePanel` permission and a background service worker, retain native tabs, and port the same narrow native host protocol (`allowed_origins` in the Chrome native manifest). Chrome's side-panel API is available from 114; programmatic open from 116 requires a user gesture. It does not expose Firefox's `browserSettings.verticalTabs`. [Chrome side panel](https://developer.chrome.com/docs/extensions/reference/api/sidePanel).

On macOS/Windows, ordinary distribution generally goes through the Chrome Web Store; self-hosted enterprise installation is a separate managed-environment route. Do not add `--load-extension` to the installed Chrome adapter or download a test Chromium to evade its distribution restrictions. Playwright specifically warns that branded Chrome/Edge removed command-line extension sideloading flags. [Chrome distribution](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions), [Playwright extension guidance](https://playwright.dev/python/docs/chrome-extensions). This route is attractive if reusing the existing official-engine adapter outweighs Firefox-native layout switching and unlisted-XPI distribution.

**Firefox containers:** can segregate some site storage inside a single profile, but are not equivalent to independent profile/runtime/proxy identities. Do not migrate the product to containers while calling them the existing isolated profiles.

**`userChrome.css`, privileged AutoConfig, WebExtension Experiments:** can reach beyond ordinary extensions, but are brittle/privileged and expand maintenance/security scope. Do not use them for the first implementation. The bounded Camoufox stylesheet-disable remediation above removes an existing override; it is not a new custom-chrome framework.

**Maintained browser fork / native multi-profile shell:** appropriate only if one native window containing truly separate-profile tabs or fully bespoke top chrome is mandatory. It entails browser security UI, sandbox/process separation, updates, accessibility, signing, service access and license stewardship. It is not an iframe wrapper, reparented browser window or Electron webview that silently loses normal browser/provider compatibility.

## 10. Bounded implementation and acceptance checklist

First implementation scope: signed-XPI-ready sidebar package, a native host with disabled-by-default authority, mock protocol tests, and a new stock-Firefox-owned-process adapter. No browser download or real launch is implied by creating this code. Leave Camoufox launch/admission unchanged until the separate gates pass.

Before any real-use claim, prove on exact macOS/browser/helper/XPI versions:

- Two fresh app-owned profiles: separate cookies/local storage, separate native tabs, persistence on restart, and no existing personal-profile access.
- Genuine signed add-on in an unsupervised profile is refused before profile enumeration; direct helper launch, forged profile/PID, stale generation, replayed request, replaced helper/XPI, and cross-user IPC are refused.
- Verify actual host process ancestry, peer audit identity and browser launch ownership under first launch, multiple profiles, normal restart, crash, update, and parent/driver loss. Unknown state fails closed.
- Normal signed-XPI install and data/API consent; optional layout denial; native-host missing; extension disabled/updated; event-page reconnect. No unsigned/developer-install equivalence claim.
- Horizontal tabs, native vertical tabs, sidebar reopen, minimal width, keyboard navigation and theme contrast. Actual native address/site identity, permission/download prompts and TLS warning UI remain visible and functional.
- Repeated A/B/C focus, slow/stopped/crashed target, minimized/fullscreen/Spaces behavior, closed tab, stale tab/window IDs, and no late focus steal. Record real warm/cold timings.
- Actual protection/service freshness, sandbox status, native credential behavior if offered, engine update delivery and integrity, extension update delivery, and runtime-policy invalidation after update.
- Managed/proxy use remains blocked until its independent exact-context DNS/IPv6/WebRTC/failure-fallback acceptance passes. The sidebar must not alter network policy or introduce remote assets.

Completion means this evidence exists and is bound to exact artifacts. Passing extension unit tests or rendering an attractive sidebar in a synthetic page is useful development progress, not native-browser acceptance.

Research validation: both illustrative JSON manifests parse and use the same extension ID. All 48 unique source links were checked; 46 returned HTTP 200 in the direct link audit. The Camoufox add-ons path and URL-encoded Apple function link were corrected against primary web results; the Camoufox site blocks the direct command-line fetch, while its official documentation content was readable through web search. This validates the research artifact, not the extension or native implementation.
