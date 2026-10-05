# Rendered workspace CI runtime

The rendered workspace workflow uses the `ubuntu-24.04` GitHub-hosted runner's
preinstalled official Google Chrome through Playwright's `chrome` channel.
`chromium_sandbox=True` remains explicit. A browser launch failure is fatal;
there is no unsandboxed fallback, skipped acceptance, or host-policy change.
The workflow logs the runner's Chrome version and installs Playwright FFmpeg
because these tests record videos as well as screenshots.

## Why the browser channel changed

[Run 37322932169](https://github.com/tmansmann0/team-browser-client/actions/runs/37322932169)
failed during browser setup with `No usable sandbox!`, before running any UI
test. It used Ubuntu 24.04.5 and Playwright's downloaded Chromium 151. This is a
launch-runtime failure, not a failed UI assertion.

Chromium documents Ubuntu 23.10+ restrictions on unprivileged user namespaces
for binaries outside existing AppArmor profiles. That is consistent with the
failure; the run did not capture policy/audit evidence proving that mechanism.
The existing Chrome profile covers `/opt/google/chrome/chrome`, which is the
Linux path selected by Playwright 1.62.0's `chrome` channel. This candidate uses
that already installed browser without editing AppArmor, sysctls, permissions,
or the browser's executable location.

## Coverage and acceptance limits

This changes the rendered test browser from Playwright's pinned Chromium to
runner-managed stable Chrome. Keep the reviewed Playwright 1.62.0 pin; do not
silently upgrade it or weaken sandbox settings if a compatibility issue occurs.
The current runner manifest lists Chrome 154 while Playwright 1.62 documents
Chrome 151 testing, so a real workflow run is required to establish compatibility.
Source contract tests cannot establish that a browser launches, that its sandbox
works on the runner, or that the UI passes. Acceptance requires the patched job
to run all three E2E cases and upload screenshots and videos. This does not prove
packaged native desktop acceptance, profile storage, Keychain, or sign-in.

For permitted local testing, use an existing official Chrome installation and
Playwright FFmpeg, then opt in with `TBM_RUN_BROWSER_TESTS=1`. Do not disable the
sandbox to work around an unsupported executor.

Ubuntu 22.04 is not the preferred fix: deprecation began September 17, 2026, and
GitHub plans retirement April 17, 2027.

## References

- [Chromium AppArmor restrictions](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)
- [Playwright 1.62 channel paths and FFmpeg installation](https://github.com/microsoft/playwright/blob/v1.62.0/packages/playwright-core/src/server/registry/index.ts)
- [Playwright sandbox option](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox)
- [Playwright 1.62 release notes](https://playwright.dev/python/docs/release-notes#version-162)
- [Ubuntu 24.04 runner software](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
- [Official Chrome runner installation](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/install-google-chrome.sh)
- [Ubuntu 22.04 deprecation](https://github.com/actions/runner-images/issues/14254)
