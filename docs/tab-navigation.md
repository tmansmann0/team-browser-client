# Manager-controlled profile and tab navigation

This pre-release slice controls existing native browser windows from the local
manager. It does not put a sidebar inside browser chrome or embed Gmail or any
other site in an iframe. The browser retains its own address bar, security UI,
site isolation, session storage and native tab strip. A separately reviewed
extension/browser-chrome integration is required for literal in-browser controls.

## Callable local interface

- `LifecycleCoordinator.selected_tabs()` returns the selected profile ID and
  generation, a typed snapshot status, at most 128 tab entries, an optional
  active-tab ID, and the current focus intent/status. Each entry contains only
  an opaque process-local ID, a sanitized title (at most 160 characters), an
  exact HTTPS origin or null, and a visibility-derived active hint.
- `LifecycleCoordinator.focus_tab(profile_id, tab_id, generation=...,
  expected_revision=...)` accepts an existing opaque ID in the selected ready
  context. It returns `outcome: queued`, never invented native completion.
  Poll the snapshot's `focus` field for `focused`, `stale_tab`, `not_ready`,
  `empty`, `superseded` or `unavailable`. `queued` and `pending` are not success.
- Snapshot statuses include `ready`, `limited`, `changed`, `busy`, `not_ready`,
  `unsupported`, `unavailable`, `superseded` and `no_selection`. Failed reads
  return no fabricated tabs. `limited` means the context exceeded the bound;
  active selection and mirroring are then intentionally unknown/disabled.
- The coordinator settings accept `profile_navigation: sidebar|grid`,
  `tab_navigation: top|side` and an exact boolean `mirror_same_origin`.
  Layout/mirror-only edits do not evict or stop a profile. These preferences
  control the manager layout; they do not change native browser chrome.

The loopback application exposes GET `/local/v1/tabs` and POST `/local/v1/profiles/{profile_id}/tab-focus`. Focus requires the exact opaque tab ID, generation and profile revision. Host/Origin/CSRF gates and strict models reject arbitrary URL/script fields. The real local manager has a default profile rail, top/side tab layouts, and saved mirror/layout preferences. Tab titles are text nodes and remain local. Snapshot expiry clears stale choices even while a later poll is still in flight.

The existing loopback application owns authentication/CSRF and strict HTTP input
models/routes. The tab helpers expose no arbitrary URL, executable, JavaScript,
page-creation, close-tab or navigation input. Only concrete owned Playwright
handles (including the Camoufox subclass) support this native slice. Synthetic
adapters/contexts used in tests remain explicitly synthetic.

## Optional mirror rule

Mirroring is OFF by default, including on older settings records through
`settings.get("mirror_same_origin", False)`. It is considered only on an explicit
profile selection, never on listing tabs or an automatic startup transition.

If enabled, a fresh complete source snapshot must report exactly one visible
web tab. The new profile must already be ready and have exactly one open tab
with the same canonical HTTPS scheme, ASCII/punycode host and effective port.
Only that existing tab can be brought forward. Default HTTPS port 443 is omitted
from serialized origins; non-default ports stay explicit. Subdomains, different
ports, HTTP and different hosts are distinct. Unicode host input not already
serialized by the browser is rejected rather than using Python's differing
IDNA2003 rules to guess browser UTS46 identity. Credentials and malformed or
oversized URLs are rejected. A registrable-domain/site-name match is insufficient.

Zero or multiple matching tabs cause no mirror action. Unknown, non-web,
ambiguous, changing, closed or incomplete source/target contexts also cause no
mirror action. Ordinary profile switching still focuses the target's last
manager-focused existing tab, or an existing fallback if that tab has closed.
An empty context remains empty. It never creates, duplicates, transfers, reloads
or navigates a tab, and never copies session data. A newer settings revision or
OFF toggle fences a mirror before native admission.

### Visibility is a limited DOM hint

`active_evidence: dom_visibility_hint` explicitly describes a fresh, fixed
`document.visibilityState === 'visible'` evaluation. It is not trusted browser
chrome selection evidence, a cryptographic assertion, or verified account
identity. Main-world getters can be affected by page scripts. Multiple windows
may have multiple visible tabs; those are unknown, never guessed. A user can
also change native tabs after an observation. The implementation does not reuse
a stale manager-focused URL as the active source after manual tab changes.
Titles and visibility are untrusted metadata; the UI must render titles as text,
never as HTML. A misleading hint can only affect which already-open target tab
is focused; it cannot grant navigation, data transfer, cookie access, or broader
context authority. A future signed extension's browser tab-activation events
need their own proven supervised-profile IPC binding before replacing this hint.

## Ownership, concurrency and limits

Every read/focus checks the current process, exact immutable launch binding,
active profile lease, profile generation, owned persistent context and current
selection intent around asynchronous work. Closed/detached pages are pruned;
context replacement or unknown ownership invalidates opaque IDs. IDs are never
persisted, reused across context lifetimes, or accepted as URLs. Unexpected
context loss retains the lease and becomes recovery-required. Tab selection
never marks a profile stopped or releases its lease; only existing genuine exit
acknowledgement logic may do that.

A latest-intent pump has at most one executing request and one replacement
pending request. API selection callers do not wait for native focus. Newer
profile/tab requests invalidate older queued work. All native bring-to-front
calls, including startup and the existing fixed Gmail intent, share an owner-loop
serialization lock. The pump waits for an admitted command's acknowledgement
before applying the newest selection, preventing a normally acknowledged late
old command from finishing after it.

An already-admitted OS/browser command cannot be recalled. The prior window may
briefly appear before the latest one. If native focus never acknowledges, later
focus remains pending; there is no honest unconditional convergence guarantee
for a hung/disconnected browser. The queue stays bounded and callers stay
responsive. Cancelling a Python future would not prove cancellation of its native
side effect, so it is not used as fake completion. Stop/unknown-ownership fences
prevent subsequent work, without inventing process-exit evidence.

Reads are bounded to 128 tabs, eight simultaneous per-page metadata reads, one
snapshot per context, and a two-second metadata deadline. Concurrent reads
return `busy`; metadata timeout/error returns `unavailable`. Titles are bounded,
control/bidi characters removed, and URL-shaped title tokens redacted to origin
or `[URL]`. Only origin metadata leaves the handle: URL paths, queries,
fragments, userinfo, cookies, storage, page text and favicon fetches are absent.
No third-party favicon requests, telemetry, or account-identity inference is
introduced. Titles themselves can contain private text chosen by a website;
this local-only metadata is neither stored in the workspace nor sent remotely.

## Verification and remaining acceptance

`tests/test_client_tabs.py` uses generated synthetic pages and fake driver
contexts for both `PlaywrightHandle` and `CamoufoxHandle`. It covers stable opaque
IDs, bounds/redaction, current visibility hints, exact unique-origin matching,
multiple/no-match/off behavior, closed/detached/unknown-process fences, changed
generation, settings-off during an asynchronous read, snapshot timeout/busy
states, delayed and rapid focus, and absence of navigation/page creation.
The existing lifecycle/Playwright/Camoufox suites remain applicable.

These source/fake-driver tests are not native acceptance. No browser binary was
installed or executed for this work. Actual Chrome and Camoufox window/tab
behavior, visibility observations across real native windows, responsiveness,
manual tab changes, startup/focus/cancel races, browser updates and OS-specific
foreground behavior remain opt-in acceptance gates on the exact approved
runtime/platform. No stealth, undetectability or authenticated Google identity
claim is made.
