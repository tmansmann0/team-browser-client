# Bounded normal-HOME comparison

Manual diagnostic only, on a fresh standard GitHub-hosted macOS 15 Apple Silicon runner. The exact candidate archive from run 37224078859/artifact 11310884356 is downloaded, hash-checked, and extracted without rebuilding or changing the executable, ASAR, signatures, sandbox, or encryption settings.

The process keeps the disposable runner's existing HOME so normal macOS cookie encryption can use that account's existing Keychain. The app may create its own cookie-encryption item. The existing packaged diagnostic separately redirects app home, the workspace, userData and sessionData into an empty private temporary fixture. No user computer, account, cookie, proxy or credential is used.

Read-only SecurityAgent and window-metadata observations run before each launch and approximately every 200 ms while running. Missing required window metadata, SecurityAgent, security/permission-like UI, unexpected windows, a native failure, or a deadline causes a stop without clicking anything. Only the owned app is terminated for cleanup. No Keychain is created/reset/unlocked, no default or search list is changed, and no security/ACL setting is changed. There is no automatic retry. Very short-lived UI between observations can be missed; this is not a proof that no transient OS UI existed.

There is at most one seed and one reopen. Reopen is gated on the seed's successful exit, explicit normal-shutdown report, released native views/leases, and disappearance of its owned sidecar. Forced termination can never satisfy that gate. The same original archive, executable and ASAR hashes are checked afterward.

The artifact contains at most one MiB of fixed synthetic diagnostic reports, bounded process logs and selected fixture images, retained for one day. It excludes HOME contents, profile databases, Keychain data, binaries and the full candidate archive. The observer's native CoreGraphics helper only classifies window metadata and never requests accessibility/screen-recording permission or controls a window.

A passing comparison establishes only the packaged synthetic cookie/localStorage/IndexedDB isolation and restart checks actually reported. Real website sign-in, anti-detect qualification, proxies/leaks, service workers/cache, installation, Developer ID/notarization and Gatekeeper remain separate gates. native_acceptance and install_ready stay false. Node tests are helper contracts, not native evidence.
