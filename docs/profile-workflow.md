# Profile-first UI and selection regression milestone

4 October 2026. This is a cloud source milestone, not a verified Mac release.
The user’s Mac was not used for development, compilation or testing.

## Diagnosed causes

- The API ordered profiles by favorite and last-selected time, and the UI sorted
  them by last-selected time again. Every selection moved its row.
- Selection used the general mutation path: it rebuilt the workspace, reloaded
  unrelated settings, retired tab/setup components and restored focus to an edit
  button. A simple navigation action became a full reset.
- The local lifecycle coordinator focused existing browser windows during
  selection. A slow launch could also retain its foreground intent after a newer
  same-profile selection. Both behaviors conflicted with predictable app navigation.

## Implemented behavior

The profile manager has a fixed-order sidebar and primary Configuration view.
The editor saves a name, icon (Browser/Facebook/Google Ads/YouTube or bounded
local PNG/JPEG/WebP), local assignment label, actual engine and explicit direct
or proxy configuration. Local assignment labels are not team access grants.
No arbitrary user-agent/Safari impersonation or fabricated RAM figure is shown.

Selection preserves the profile rail/search DOM, serializes writes and coalesces
intermediate rapid clicks. Only the latest accepted selection is shown. Explicit
sort controls are independent of selection time. Revision/transport uncertainty
blocks changes until a verified reload; known validation errors retain the form.
Icon reads use a latest-file fence and pending reads cannot be saved early.

The real integrated engine is Electron-bundled Chromium, named distinctly from
installed Chrome and Camoufox. Browse uses main-owned native WebContentsViews,
not an iframe. Each profile retains its existing tabs/session during switches.
Configuration and dialogs hide native guest content with an acknowledged bridge
operation. Layout-only IPC cannot trigger semantic redraw loops. Native view
bounds track resize and scrolling and stay inside the visible browser pane.
Closing a profile returns to Configuration so a reload cannot immediately reopen
it. The editor does not discard unsaved form data to open browser controls.

Legacy external-engine selection now changes manager context only, never raises
or launches a window. An explicit existing-profile Start remains the deliberate
focus action; generation/lease/stale-focus fences stay in place. A superseded
start may finish warm, but cannot claim foreground solely because the same
profile became selected again.

## Verification and limits

New regression coverage includes source-DOM/transport scenarios, durable metadata
migration/validation, native lifecycle fixtures and mocked Electron adapters.
These establish code contracts, not real browser storage, proxy routing,
provider compatibility, rendered layout, native focus or macOS packaging.

- Source reference screenshot was materialized and inspected before redesign.
- The cloud browser rejected the local UI URL with ERR_BLOCKED_BY_CLIENT.
- The existing Linux native-browser IPC restriction was not bypassed.
- Real UI rendering, signed/notarized macOS build, persistent site-storage
  isolation, live proxy failures/leaks and ordinary website sign-in remain unrun.
- New engine source deliberately does not activate managed profiles or deliver
  proxy credentials. No real service, provider, account or live backend changed.

Run the current source checks from the repository:

```sh
python -m unittest discover -s tests -v
ruff check src tests scripts
ruff format --check src tests scripts
python -m compileall -q src
node --check src/team_browser/static/workspace.js
node --check src/team_browser/static/embedded_browser.js
node tests/frontend_workspace.cjs
node tests/frontend_desktop_regressions.cjs
npm --prefix desktop test
```

The browser E2E suite is retained for an explicitly permitted, sandboxed browser
runtime; it is not counted as passed while unavailable. See
[desktop architecture and delivery gates](desktop-app.md) before offering an
installer or claiming that the integrated product is ready.
