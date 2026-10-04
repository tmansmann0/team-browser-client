# Native macOS Keychain adapter

## Current status

`team_browser.local.macos_keychain.MacOSKeychainStore` is a concrete, opt-in
`SecretStore` implementation using Apple's Security.framework through PyObjC.
It is not wired into the local HTTP/UI bridge or managed sign-in. The existing
`local.secrets.MacOSKeychainStore` export remains the unavailable placeholder.
Importing the new module performs no native operations; construction requires
an explicit typed configuration and verifies the signed host. Linux fails
before importing any framework.

**Verification is synthetic Linux contract testing only.** No Mac Keychain item
has been written, read or deleted, no authentication UI has run, and no access
grant or signing/provisioning change has been made. This does not establish a
working, signed Mac release. The acceptance checklist below remains mandatory.

## Integration contract

The reviewed native application must supply `KeychainConfiguration(team_id,
bundle_id, namespace)`. There are no default identities or discovered keyrings.
The namespace is an opaque use label such as `proxy`, not an account name or
credential. The app-private access group is derived as `team_id.bundle_id`;
arbitrary shared groups cannot be configured. The service is
`bundle_id.keychain.v1.namespace`, and the account is `v1:SecretRef.account_id`.
Both are non-secret metadata. Account references remain validated opaque IDs.

`put(reference, value)` accepts exactly `bytes`, 1–65,536 bytes inclusive, and
returns exactly `None` on success. The add uses device-only, unlocked
accessibility. An exact duplicate causes one constrained `SecItemUpdate`, never
delete-then-add. If the item disappears or has different protection, update
fails; it does not retry creation or silently migrate another record.

`get(reference)` returns bytes only after validating returned service, account,
access group, accessibility, explicit non-sync attribute, NSData type and
bounded length. `SecretNotFound` identifies only native `errSecItemNotFound`
with no result. Lock/authentication errors and unavailable/missing-entitlement
errors are not converted into a missing credential or an empty byte string.

`delete(reference)` is idempotent for an absent item, but returns exactly `None`
only after a separate exact-scope metadata query confirms absence. It never
requests credential bytes during that check. Success is point-in-time absence
of this non-synchronizing item, not permanent erasure, website-session revocation,
or proof that no concurrent process can create a new item later.

All queries bind generic-password class, the exact service/account/access group,
`kSecAttrSynchronizable = false`, and `kSecUseDataProtectionKeychain = true`.
Read/absence queries use a single-item match limit. `SecItemDelete` deliberately
omits `kSecMatchLimit`: Apple's data-protection server rejects finite delete
limits with `errSecMatchLimitUnsupported`. The complete generic-password primary
key (access group, service, account and non-sync state) limits the affected item.
Update likewise omits match flags and result flags: `s3dl_query_update` rejects
match-query attributes, and the server rejects return-data/attributes/reference
flags. The update dictionary contains only the new `kSecValueData`; its query
retains the complete primary key plus the existing accessibility constraint.
No wildcard search, Keychain
enumeration, file-based Keychain, shared access-group selection, or synchronizing
counterpart is used. Existing synchronizing counterparts are outside this
adapter's scope and are neither read nor deleted.

Each operation uses a fresh `LAContext` with `interactionNotAllowed = true`,
checks that setting, then invalidates the context. There is no policy evaluation,
prompt, cached authenticated context, Keychain unlock, biometric bypass, or
fallback to the deprecated authentication-UI flags. The bindings manage native
object ownership; an autorelease pool bounds transient Objective-C objects.

Errors expose a fixed operation/reason and optionally numeric OSStatus. Native
exception text is suppressed, and there is no logging or shell execution. Do
not enable capture of local variables or query dictionaries in crash reports.
Python bytes and native bridging copies cannot be reliably zeroized by this
implementation; callers must minimize their lifetime and never send them to a
web bridge, subprocess arguments, logs, manifests or telemetry.

## Signed-host and dependency gates

The constructor builds an Apple-anchored requirement restricted to the supplied
bundle identifier and signing team, validates the running code and its static
signed resources, and reads signed metadata. It requires the matching
`com.apple.application-identifier` entitlement and a strictly typed unsigned
32-bit `kSecCodeInfoFlags` value containing `kSecCodeSignatureRuntime`. Missing
runtime flags fail closed even if no runtime-exception entitlements are present.
Optional `keychain-access-groups`
must be empty or contain only that same application identifier. It rejects
debug task access, disabled library validation and DYLD environment exceptions.
It does not grant entitlements, modify an ACL, or allow a general Python
interpreter to inherit trust by naming a desired application.

The application must package the PyObjC `Security`, `Foundation`,
`LocalAuthentication`, and `objc` modules from the reputable upstream project.
The relevant distributions are `pyobjc-framework-Security`,
`pyobjc-framework-LocalAuthentication`, `pyobjc-framework-Cocoa`, and
`pyobjc-core`. Use one compatible, reviewed, exact release, macOS-only dependency
markers, hashes and preserved license notices. These dependencies were not
installed or added to the base Linux lock by this slice. Missing frameworks or
symbols fail closed. Import paths must be sealed by the signed application;
untrusted plugins, writable Python modules, environment-injected import paths,
or arbitrary code execution inside the host defeat an in-process adapter.

The installer/release owner must select the real Apple team and bundle ID,
obtain approved provisioning and sign/notarize the app and embedded components.
The host must run in the logged-in user's context. Do not weaken library
validation or broaden Keychain sharing to make an unsigned development script
work. This constructor is not a substitute for notarization, approved install,
provisioning-profile verification, or a release's dependency-integrity checks.
Another app from the same development team can potentially be granted the same
access group by that team's provisioning process; release policy must forbid
such sharing. The adapter cannot audit another installed app's provisioning.

## Why this is not SessionVault

The managed sign-in `SessionVault` requires durable pre-commit operation/
quarantine markers, crash recovery, expiry checks on every read and exact
acknowledgements. A successful single SecItem call is not a multi-item
transaction or a persistent quarantine protocol. If a mutation raises, a
native write may already have happened; automatic compensating deletion could
also remove a newer writer's record. This adapter deliberately does not add
`assert_available`, `store_session` or `delete_session`, cannot be substituted
directly for that contract, and performs no expiry inference for opaque bytes.
A separately reviewed native vault design must handle cross-process ownership,
crash states and clock/expiry semantics before sign-in integration.

## Target-Mac acceptance checklist

Only run native checks after permission for that machine, explicit synthetic
test items and any installation/signing setup. Never inspect unrelated items.

- Package a sealed, signed app with approved private entitlement and exact
  dependency hashes; verify effective signature, provisioning and notarization.
- Confirm wrong team/bundle, missing entitlement, debug entitlements, unsigned
  host, missing hardened runtime and modified package resources block before
  any SecItem operation.
- Verify bound synthetic binary round-trip, maximum-size value, update and
  idempotent delete in the data-protection Keychain on supported OS/architectures.
- Verify actual PyObjC return types, false non-sync attribute and NSData behavior;
  fail the release if strict shape checks differ instead of weakening them blind.
- Lock/unlock and cancel/error paths must never show an authentication prompt or
  treat interaction-required as item-not-found. Confirm this on actual hardware.
- Confirm isolation from a different app, namespace, reference and sync record;
  no access-list exemptions or broad sharing entitlements are acceptable.
- Exercise interrupted calls, duplicate/update races and deletion followed by a
  concurrent writer. Failures must remain explicit; never claim rollback.
- Use a background native worker thread, check the UI stays responsive, and
  inspect approved synthetic-only logs/crash reports for data exposure.
- Decide and separately verify crash/quarantine/expiry behavior before any
  managed-session integration. Review authorization before real credential use.

## Sources

Reviewed October 3, 2026. These are API/design references, not native execution
evidence or claims of endorsement of this adapter.

- [Apple TN3137: Mac Keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Apple: Keychain access group](https://developer.apple.com/documentation/security/ksecattraccessgroup)
- [Apple: Restricting item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
- [Apple: LAContext interactionNotAllowed](https://developer.apple.com/documentation/localauthentication/lacontext/interactionnotallowed)
- [Apple: Deprecated authentication UI fail flag and replacement](https://developer.apple.com/documentation/security/ksecuseauthenticationuifail)
- [Apple: SecItem pitfalls and best practices](https://developer.apple.com/forums/thread/724013)
- [Apple's SecItem header](https://github.com/apple-oss-distributions/Security/blob/main/keychain/headers/SecItem.h)
- [Apple's data-protection SecItem server](https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/SecItemServer.c)
- [Apple's update-query validation](https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/SecItemDb.c)
- [Apple's match-query parser](https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/SecDbQuery.c)
- [Apple's code-signature flags](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/CSCommon.h)
- [PyObjC Security API metadata](https://github.com/ronaldoussoren/pyobjc/blob/main/pyobjc-framework-Security/Lib/Security/_metadata.py)
- [Apple: Generic-password composite primary key](https://developer.apple.com/documentation/security/ksecclassgenericpassword)
- [PyObjC Security binding API notes](https://pyobjc.readthedocs.io/en/latest/apinotes/Security.html)
- [PyObjC LocalAuthentication binding API notes](https://pyobjc.readthedocs.io/en/latest/apinotes/LocalAuthentication.html)
- [PyObjC SecItem binding tests](https://github.com/ronaldoussoren/pyobjc/blob/main/pyobjc-framework-Security/PyObjCTest/test_secitem.py)
