# Native short-lived session vault

## Delivered scope and limits

`team_browser.client.session_vault.MacOSSessionVault` is a concrete adapter for
`auth_flow.SessionVault`, layered on the separately reviewed native
`local.macos_keychain.MacOSKeychainStore`. It is opt-in and is composed by the
native managed host behind the fixed local UI bridge; it is **not activated for
live sign-in**. Importing it performs no native I/O. Production
construction verifies the signed native host through the Keychain adapter; Linux
fails closed. There is no selectable byte-store backend or file, environment,
plaintext, or in-memory production fallback.

This pilot holds **one short-lived session at a time**. It deliberately does not
restore login across application starts. The OS records survive process exit,
but a new vault instance starts quarantined and refuses every session operation
until explicit native recovery has discarded the old payload and confirmed its
absence. Even a valid-looking `ready` journal is not authority to reuse a
previous process's material. Restart alone never completes recovery.

Verification is Linux synthetic testing only. No real Keychain item, account,
OAuth grant, browser, device enrollment, access permission, or native signing
configuration was used or changed. Signed-Mac acceptance is still mandatory.

## Trusted construction and lifecycle

Only reviewed native application code may create this object. Supply an exact
`KeychainConfiguration` with the installed Apple team, bundle identifier and the
reserved namespace `managed-signin`. Other namespaces, dictionaries and subclass
configuration objects are rejected. Never derive configuration or a vault
instance from JS, browser input, account claims or environment variables.

For a configured provider, pass the **same immutable `TrustedOIDCConfiguration`**
to the vault's explicit keyword and the sign-in core:

```python
vault = MacOSSessionVault(keychain_configuration, oidc_configuration=oidc_configuration)
# Perform explicit native startup discard before constructing the core.
vault.recover_discard_all()
core = ManagedSignIn(oidc_configuration, transport=native_transport, vault=vault)
```

These are native integration instructions, not an installed/live setup. The
constructor accepts only the exact configuration type, re-runs its reviewed
validation before native construction, and snapshots an immutable vault policy:
exact issuer, exact ordered approved scope tuple, and `local_session_ttl_seconds`.
For the current Entra builder these are its pinned single-tenant issuer,
`openid`, `profile`, and the one `api://<approved-API-client-ID>/access_as_user`
resource scope. The local limit is at most ten minutes, even when provider tokens
last longer. A policy is never inferred from `NativeSessionMaterial` or provider
claims, and another resource/tenant, dropped/extra scope, duplicate scope or
refresh/offline permission cannot broaden it. Issuer/scope mismatch is rejected
before any OS-store access, including before payload mutations. The payload
serializes the actual validated scope tuple rather than replacing it with
`openid`.

The omitted-keyword compatibility mode preserves the original generic,
openid-only contract with a one-hour maximum; it does not bind an issuer. It
exists for legacy native integrations/tests, cannot store the expanded Entra
scope set, and should not be used for new provider integration. Supported Entra
sign-in requires the explicit trusted configuration. Even legacy callers can and
should supply their trusted configuration to pin issuer and a shorter local TTL.

The trusted native coordinator must follow this lifecycle:

1. Construct the vault on a native worker. The constructor verifies the native
   store and acquires exclusive ownership, but performs no session-record reads.
2. Explicitly call `recover_discard_all()` before constructing `ManagedSignIn`.
   This is the reviewed startup policy, including the first launch: discard
   previous local sign-in rather than restore it. The host must make that policy
   clear in its UX; it is not a silent recovery-after-error mechanism.
3. Only exact `None` from that operation permits construction of a fresh sign-in
   core. Keep the same vault and its lease alive for the complete core lifetime.
4. Pass the adapter to the existing core's `vault` argument. Successful
   `assert_available`, `store_session` and `delete_session` return exactly `None`.
   Every other outcome raises a fixed, secret-free exception.
5. If a store/delete operation becomes uncertain, retire that core. Do not
   automatically retry, reopen the vault, call recovery and resume the old core,
   or claim provider cleanup. Explicit recovery can establish an empty local
   vault for a separately coordinated fresh attempt. It never clears an existing
   core's `recovery_required` state.
6. Close the vault after retiring its core. `close()` invalidates in-memory
   authority and releases ownership. It leaves OS records for next-start
   explicit discard and is not sign-out or provider revocation.

The `assert_session_current(session_id)` native liveness operation returns only
`None`, after integrity and expiry checks. There is no public token getter,
callback accepting arbitrary credential consumers, generic request proxy, or
material-returning vault API. The implemented `NativeManagedSession` is the sole
exact-typed backend consumer, with a pinned origin and fixed read operations;
see [its contract](managed-session.md). Do not expose this object or any of its methods
through the web/JS bridge. Neither successful identity verification nor a vault
record establishes company membership, device enrollment, or managed access.

## Exact bounded OS scope

The namespace reserves precisely these `SecretRef` account IDs:

- `managed-signin-journal-v1`: a small canonical operation/quarantine journal
- `managed-signin-payload-v1`: at most one canonical session payload

The byte-store adds its existing `v1:` account prefix and exact service, access
group, non-synchronizing and device-only protection. The vault never enumerates
items, interpolates session references into storage keys, uses wildcard queries,
changes sharing, or touches records belonging to another feature. Recovery can
replace even malformed journal contents without interpreting them and deletes
only this reserved payload. It never reads a previous-process payload before
attempting its deletion; the subsequent read is an absence confirmation.

Every returned record must be exact `bytes` of 1–65,536 bytes. Material accepts
only an exact `NativeSessionMaterial`, exact `AccountIdentity`, printable ASCII
access/ID tokens of at most 16,384 characters each, integer expiry, and the exact
approved scope tuple from its native policy (`("openid",)` only in compatibility
mode). The canonical payload must also fit the byte-store limit. Session
references are bounded opaque URL-safe strings; they are never filesystem paths.
Only one payload is allowed, and at most 128 distinct session references may be
used in an ownership epoch. Deleted references cannot be reused in that epoch.
A new explicit recovery creates a fresh random epoch before any new session.

## Journal and commit protocol

The byte store acknowledges **individual operations, not transactions**. This
adapter does not assert that multiple `SecItem` calls are atomic or roll back a
failed operation. Logical publication is gated by the exclusive owner, its
in-memory expected journal and payload digest, and completion of every required
acknowledgement in this process.

A successful session write does the following under the thread lock and
process lease:

1. Check ownership, the exact current journal, expected slot state and clocks.
2. Write a new `quarantined` journal to the OS store and require exact `None`.
   Read it back and require byte-for-byte equality before touching the payload.
3. Write the payload, require exact `None`, and require exact read-back equality.
4. Write/read back a new `ready` journal bound to the current epoch, revision and
   payload SHA-256 digest, with an exact acknowledgement.
5. Establish current-process authority and recheck payload integrity and expiry
   before returning success. No other thread can observe an intermediate state.

Deletion likewise writes and confirms `quarantined` first, deletes the fixed
payload, requires exact `None`, separately confirms `SecretNotFound`, then
writes/read-verifies the empty `ready` journal. A different session ID cannot
delete the current record. The journal is retained rather than removed.

Explicit recovery uses a new epoch, writes/read-verifies quarantine, deletes
and confirms absence of the fixed payload, then writes/read-verifies an empty
ready journal. It does not trust previous journal contents or restore sessions.

Any exception, interrupted call, unexpected record, failed read-back, malformed
acknowledgement (`False`, `True`, numeric zero or anything other than `None`), or
ownership failure quarantines the instance. It cannot regain availability
merely because a subsequent read works. A failure after the underlying native
write may have left bytes behind or even written a ready-looking marker: those
bytes still have no publication authority. A new instance also remains blocked
until explicit confirmed discard, regardless of the persisted marker's state.
This conservative design avoids needing an unavailable multi-record transaction.

After a failed store, the core's normal cleanup call is refused by a quarantined
adapter, preserving `recovery_required`. No automatic compensating delete can
remove a later owner's data. Pure argument validation failures before operations
may raise without poisoning the vault; those failures performed no native write.
A health-check exception is represented by the existing core as `vault_unavailable`;
the vault itself remains quarantined and cannot authorize a subsequent exchange.

## Exclusive ownership

All cooperating instances for the same OS user, service and access group use one
canonical lock directory, derived from the OS account database home (not `HOME`)
and a digest of that public Keychain scope. It is under:

`Library/Application Support/TeamBrowserSessionVault/<scope-digest>/owner.lock`

The lock is a permanent, **empty** mode-0600 file in a private directory. It
contains no session ID, journal, token, credential or account identity. Directory
traversal rejects symlinks; the lock rejects symlinks, hard links, non-regular
files, incorrect ownership, public permissions and nonempty files. The kernel
`flock` is exclusive and nonblocking. Never unlink or replace this file to fix an
ownership conflict: two inodes would permit two independent locks.

The owner validates its process ID, descriptor and named-file/directory identity
before operations. Threads are serialized. Fork-inherited objects cannot perform
vault operations; closing such a copy does not explicitly unlock the parent's
shared descriptor. Process exit releases the kernel lease, but does not authorize
restoration. Tests exercise real Linux cross-process exclusion and abrupt process
exit; they do not establish macOS filesystem or Keychain acceptance.

This lease protects cooperating signed native hosts on a stable local filesystem.
It is not protection against malicious code already executing as the same OS
user, root, direct Keychain writers ignoring this protocol, library injection,
or filesystem/OS tampering. Do not use a network filesystem, arbitrary workspace
lock path, parallel native store implementation for these reserved keys, or
writable/unsealed plugin host. After application-data migration, renaming, OS
home changes or backup restoration, ensure no old host remains active; never
run two different lock locations against the same Keychain scope.

## Expiry and clocks

The input expiry must be in the future and no further away than the configured
local-session TTL (30–600 seconds). The legacy omitted-policy mode retains its
one-hour maximum. The core already supplies the earliest validated ID/access-token
and local-session bound; the vault independently enforces the policy limit and
does not extend or refresh it. At commit it captures a monotonic deadline for the remaining
wall-clock lifetime. Every session liveness/integrity read checks both wall and
monotonic bounds before and after the OS read, including slow/blocking reads.
Expired payloads are deleted through the same quarantine/confirmed-absence
protocol before `SessionExpired` is returned. No UI polling is required.

A clock moving backward relative to the last observed wall or monotonic reading,
a negative/nonfinite timestamp, or a malformed clock result fails closed. This is
a conservative local-clock policy, not a trusted-time service; an OS compromise
or unobserved clock manipulation is outside its guarantees. Normal suspension
is bounded by the wall clock; monotonic behavior across sleep remains a target-Mac
acceptance item. Deadlines are never reconstructed from a prior-process record.

No API returns secret material. Internal write read-back is integrity validation,
not credential consumption; validity is rechecked before logical publication.
Expired-session cleanup uncertainty requires explicit recovery rather than
reporting successful expiry/deletion. Keychain deletion establishes scoped local
absence only. **It never revokes provider tokens, browser cookies, company
membership, or device grants.**

## Data handling and remaining acceptance

Secret material exists only in the OS store and transient native-process memory.
Neither files, command arguments, environment variables, stdout/stderr, telemetry,
nor exception messages receive it. Python immutable strings/bytes and native
bridging copies cannot be reliably zeroized. Never serialize native secret-bearing
objects with `dataclasses.asdict`, enable local-variable crash capture, or mistake
repr suppression for a security boundary. The payload digest and expected journal
held in memory are integrity evidence, not an in-memory credential fallback.

Before any real credential use, separately authorize and verify:

- The signed/sealed Mac host, exact private entitlements and dependency integrity
  from [the native byte-store checklist](macos-keychain.md).
- Actual native add/update/delete/absence results, lock/unlock failures and no-UI
  behavior for approved synthetic test records only.
- Stable local canonical lease location, multiple app launches, thread behavior,
  process interruption at all mutation phases and home/app-data migration policy.
- Explicit startup discard UX, old-core retirement, recovery failure UX, clock
  adjustments/sleep, and absence of token/record capture in approved synthetic logs.
- Independent native protocol review and authorized end-to-end provider/transport/
  loopback/browser integration; this adapter alone makes none of those ready.

## Synthetic verification

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_session_vault.py -v
.venv/bin/ruff check src/team_browser/client/session_vault.py tests/test_client_session_vault.py
.venv/bin/ruff format --check src/team_browser/client/session_vault.py tests/test_client_session_vault.py
```

Tests use an in-memory fake byte store solely as a test fixture. They cover every
store/recovery operation's before/after interruption boundary, every deletion
boundary's uncertain outcome, each mutation's exact-None acknowledgement,
write/absence verification, previous-process and same-process replay, record
bounds and corruption, expiry and backward clocks, concurrent threads/processes,
fork refusal, actual process-exit lease release, unsafe/replaced lock files,
namespace isolation, output/filesystem sanitization and the core's irreversible
recovery-required state after an uncertain payload acknowledgement. Provider
coverage also executes the real Entra-configured core through this concrete
vault's synthetic store, verifies its exact persisted scopes and local expiry,
and rejects changed issuers, resources, scopes or policy types before secret
writes. No test in this suite performs provider/network or real Keychain I/O.
