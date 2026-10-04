# Offline Linux Chromium smoke

This opt-in check launches the Chromium already installed at
`/usr/lib/chromium/chromium`. It does not download or install a browser, run
Camoufox, enable the team launch path, or prove production proxy isolation.

## Run

From the repository in a non-root Linux environment:

```sh
PYTHONPATH=src python -m team_browser.local.smoke
```

The command accepts no URL, executable, profile, environment, or browser-flag
overrides. It requires `/usr/bin/unshare` and working user/network namespaces.
When those requirements or Chromium's existing sandbox are unavailable, it
fails and prints the exact child-process error. Do not retry by disabling the
Chromium sandbox or weakening host security settings.

## What is checked

1. The fixed Chromium/unshare system paths are regular executables with no
   writable/symlinked named path components. The OS-provided root mount is
   trusted; the result is not protection against a compromised host/root user.
2. A temporary private HOME, XDG configuration/cache/runtime and browser profile
   are created. No user configuration, tokens or proxy environment is inherited.
3. Each child runs inside a fresh user/network namespace. No outbound network
   interface is configured; only a generated local HTML file is opened.
4. The fixed page has restrictive CSP and writes a synthetic localStorage
   counter. Two separate Chromium processes must report visit 1 and visit 2.
5. Chromium's normal sandbox remains enabled. No remote-debugging port or
   security-disabling flag is provided. Temporary data is removed on completion.

The result prints installed version and SHA-256 as observations, not a reviewed
production release approval. Success establishes an actual headless process and
synthetic profile persistence in this environment. It does not establish
macOS behavior, Keychain support, signed-package provenance, proxy routing,
DNS/WebRTC isolation, cloud authentication, or production launch readiness.

The normal and Camoufox engine adapters still refuse execution. Production
runtime trust and proxy gates remain unchanged.

## Actual executor result: 2026-10-03

Observed installed version: `Chromium 154.0.8037.57`.
The version command and user/network namespace creation both ran successfully.
The actual headless launch was attempted with the exact isolation above, both
under the normal executor and its approved escalation route. Chromium aborted
before rendering the synthetic page:

```text
exit -6
FATAL:chrome/browser/process_singleton_posix.cc:297
socket() failed: Operation not permitted (1)
crashpad: ptrace: Operation not permitted (1)
```

This is a blocked browser smoke, not a pass. Profile persistence has not been
demonstrated in this executor. No sandbox-disabling workaround was used. The
runner's synthetic contract tests pass; they are explicitly separate from the
real-browser result. Rerun this command in an authorized non-root Linux runtime
that permits Chromium's local IPC sockets and normal sandbox operation.
