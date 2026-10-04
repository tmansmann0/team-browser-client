# Default-Keychain reference comparison

This manual, one-comparison workflow observes **reference availability only** on a
fresh standard GitHub-hosted `macos-15` runner. It does not launch TeamBrowser or
download/rebuild a candidate. `native_acceptance` and `install_ready` remain false.

## Exact probe

Two fresh short-lived native helper processes receive the same narrow environment,
except for `HOME`: the existing runner HOME, then a newly created empty temporary
directory. Each calls **only `SecKeychainCopyDefault`** and releases any returned
reference. There are no explicit item queries, keychain path queries, setters,
unlock/create/reset calls, credentials, UI controls, or security-setting changes.
Each helper has a five-second deadline; failures are not retried. A stalled or
malformed first result prevents the second call. The parent process HOME is never
changed. No application is launched under either HOME.

The native helper emits only `copy_default_status` (the API's numeric OSStatus),
`default_reference_returned` (boolean), and `lock_status_known: false`. A successful
reference lookup **does not prove the underlying database exists, can be opened,
is unlocked, or supports cookie encryption**. Lock state remains unknown. A failed
lookup is recorded as evidence, not interpreted as a native application failure.

Only `desktop/out/default-keychain-metadata.json` is uploaded, limited to 8 KiB,
with one-day retention. The artifact name identifies the exact workflow source
commit. No binary, profile, HOME contents, item data, paths, raw stderr, or archive
is uploaded. Normal host filesystem inspection is limited to validating HOME is
a directory; the synthetic directory is checked only for emptiness before/after.

## Why lock status is excluded

Apple's [CopyDefault implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecKeychain.cpp#L284-L292)
uses the [default-reference getter](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/StorageManager.cpp#L524-L545),
which is separate from the login/default-keychain creation UI path. It need not
open the database, so a returned reference is deliberately not called usable.

`SecKeychainGetStatus` was considered and omitted: its lock-state query can
[lazily open a database](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_cdsa_client/lib/dlclient.cpp#L100-L119).
The resulting [default-credential builder](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/defaultcreds.cpp#L60-L93)
can follow existing unlock referrals. A referral search can reach the conditional
[keychain-upgrade path](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/KCCursor.cpp#L338-L345).
The narrower helper avoids that additional database-opening call. Apple public
source supports this design but is not a binary-level verification of the exact
runner OS; normal framework initialization/transient caches are not claimed to
have literally zero internal effects.

## Electron HOME distinction

Pinned [Electron 44.5.1 `App::SetPath`](https://github.com/electron/electron/blob/v44.5.1/shell/browser/api/electron_api_app.cc#L904-L916)
changes Chromium's path-service mapping (`home` maps to `base::DIR_HOME`) through
[`OverrideAndCreateIfNeeded`](https://github.com/chromium/chromium/blob/152.0.7977.130/base/path_service.cc#L255-L287).
It does not set the process environment's HOME. Apple Security separately uses
[environment/account home resolution](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/DLDBListCFPref.cpp),
including `getenv("HOME")`, subject to sandbox overrides. Therefore an empty
process HOME is a distinct variable from TeamBrowser's internal app-path override.

Any future changed-HOME application comparison is a separate decision. This
workflow neither performs nor authorizes it. A normal cookie-encryption app run
may create its own encryption item; that effect requires explicit review before
such a run. Reference metadata alone does not establish that ad-hoc signing caused
the earlier hang or that Developer ID signing would fix it.

## Verification scope

The Node tests exercise schemas, environment isolation, subprocess bounds, fixed
artifact scope, and C output through compile-time API stubs. They do not call real
Security APIs and must not be presented as native Keychain evidence. The hosted
workflow compiles the actual helper against the runner's existing Apple SDK.
