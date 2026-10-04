# Fixed-candidate cookie-hang diagnosis

This manual workflow reproduces the cookie-read boundary once using the existing
candidate from commit `62d56b353bcb1c9981c31d8fbb6089322368a2f7`, build run
`37224078859`, artifact `11310884356`, archive SHA-256
`9a4a80e2115b0c8629518edfc5cb724308cf6cc3d626a08f27e5c308314e9d27`.
It does not rebuild or modify the archived app. The observer commit is reported
separately. Hashes and bundle-signature integrity are checked before launch;
archive, executable and ASAR hashes are checked again after collecting evidence.

## Evidence already established

The exact candidate builds, passes strict bundle-signature integrity validation,
launches its frozen sidecar and native app window, and renders settled profile
manager captures. A native guest with nonzero visible bounds passes the strict
preference and privilege checks. The first `document.cookie` read does not return
before its six-second deadline. The normal shutdown path then remains incomplete.
No IndexedDB operation or cookie isolation/persistence test has passed.

## Leading hypothesis, not a finding

Electron 44.5.1's persistent NetworkContext connects encrypted cookies to
`CookieEncryptionProviderImpl`, which obtains an OSCryptAsync encryptor. The macOS
key provider performs blocking Keychain work on a worker thread, eventually using
`SecItemCopyMatching` and potentially adding the app's encryption item if absent.
That mechanism is consistent with the renderer cookie read hanging while the
main-process deadline still fires. It does not establish that a prompt occurred.
The synthetic HOME and ad-hoc code identity are possible contributors; neither
has been confirmed as the cause, and Developer ID signing is not a proven fix.
The fixed in-memory HTTPS fixture supplies document bytes, not a cookie backend.

Pinned primary sources:

- [Electron cookie-encryption setup](https://github.com/electron/electron/blob/v44.5.1/shell/browser/net/network_context_service.cc#L104-L115)
- [Electron macOS provider selection](https://github.com/electron/electron/blob/v44.5.1/shell/browser/browser_process_impl.cc#L486-L495)
- [Chromium 152 Keychain worker](https://github.com/chromium/chromium/blob/152.0.7977.130/components/os_crypt/async/browser/keychain_key_provider.mm#L30-L78)
- [Chromium Keychain read path](https://github.com/chromium/chromium/blob/152.0.7977.130/crypto/apple/keychain_v2.mm#L195-L218)
- [Pinned Electron signing caveats](https://github.com/electron/electron/blob/v44.5.1/docs/tutorial/code-signing.md#L68-L84)

## Bounded observation

The separately dispatched public `macos-15` job has only repository contents/read
and Actions/read access, downloads only the fixed artifact, and uses one fresh
synthetic profile root with the failing launch environment unchanged. It waits
up to 45 seconds for the existing app report to identify the cookie-read failure.
It then observes only:

- Presence/absence of a process named SecurityAgent, before and during the stall.
  Presence alone does not prove a Keychain prompt, its purpose, or its owner.
- One one-second `/usr/bin/sample` call per verified owned candidate executable,
  at most four. Each process must be descended from the spawned app and run an
  allowlisted executable inside that exact extracted bundle. No Keychain daemon
  or unrelated/system process is sampled.
- Existing fixed app reports and settled chrome captures from synthetic profiles.

Total uploaded evidence is capped at 1 MiB with one-day retention; oversized
individual items are explicitly omitted. No candidate ZIP is uploaded.
Only bounded call-graph sections are retained from the samples. Environment,
arguments, binary-image inventories, raw memory, profile databases, cookies,
Keychain items and temporary HOME are not uploaded. Temporary root/home paths and
instruction addresses are redacted. If sampling lacks permission or symbols, the
limitation is reported without elevation, entitlement changes or a workaround.

There is no Keychain enumeration, unlocking, creation, ACL change, prompt approval,
credential input, mock keychain, encryption downgrade, Gatekeeper/quarantine
change, sandbox change, GPU change or user-Mac operation. The candidate may request
its normal OS-backed cookie encryption while reproducing the existing failure;
the observer does not interact with any resulting permission prompt. No
screen-recording or accessibility permission is requested.

After evidence collection, only the owned app is terminated if still running;
this is diagnostic cleanup and is explicitly not normal-shutdown acceptance.
Review the observed stacks before deciding whether the block is Keychain access,
cookie-service initialization, IPC, or something else. No automated root-cause
claim is made. `native_acceptance` and `install_ready` remain false.
