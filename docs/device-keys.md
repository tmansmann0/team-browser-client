# Native device-key lifecycle

## Status and boundaries

`client/device_keys.py` implements an opt-in, synchronous macOS device identity
using the existing concrete `MacOSKeychainStore`. Importing it does no native I/O.
Construction verifies the signed host and acquires a per-user cross-process kernel
lease; it never generates a key, reads a prior key, deletes a record, performs a
network request, opens a browser or restores authorization automatically.

This slice is exercised only with ephemeral synthetic Ed25519 keys and mocked OS
stores on Linux. It has no production enrollment transport, enrollment UI, JS
proof/token bridge or automatic/background work. No real Keychain, credentials,
device keys, grants, provider calls or backend calls were used to build or test it.
Real signed-app macOS acceptance remains a separate gate.

The concrete constructor requires exactly:

- `KeychainConfiguration` with the fixed namespace `managed-device-keys` and the
  reviewed installed application's Apple team and bundle identifiers;
- `TrustedDeviceScope` with the approved canonical HTTPS API origin, product
  organization ID and product member ID from authenticated `/v1/me`.

There is no environment/file/plaintext/in-memory fallback store, arbitrary store
argument, shared access group or UI-selected native configuration. The Keychain
adapter verifies signing requirements, hardened runtime, exact app identity and
entitlements. Items are app-private, non-synchronizing data-protection Keychain
items with `WhenUnlockedThisDeviceOnly` accessibility. The namespace is separate
from managed sign-in and proxy credentials. One installed app namespace owns one
device identity; company/member changes cannot silently select a different slot.

Ed25519 keys are encrypted by Keychain at rest, not generated in Secure Enclave.
Signing necessarily brings private bytes into native process memory. Python does
not promise secure zeroization. No method returns a private key, serializes a key
handle, signs arbitrary data, or sends any network request. Key bytes never enter
filesystem files, public status, repr, diagnostics or tests' output.

## Usable explicit first-enrollment path

These methods belong exclusively to trusted signed native worker code, never a
browser/JSON dispatcher:

1. Construct `MacOSDeviceKeys(configuration, scope)` and call `restore()` explicitly.
   Consistent existing records yield an opaque `DeviceKeyHandle`; empty storage
   yields `None`. `status().public()` contains only local state, public key,
   fingerprint, and explicit server-authoritative/integration-gated flags.
2. After the user's explicit enrollment action and a fresh authenticated operating
   membership read, call `generate_pending(authority)`. This generates one key and
   durably persists it before returning its handle. An existing pending or active
   key causes `rotation_not_supported` without modifying that key. This build calls
   generation only inside fake-store tests.
3. The future native enrollment client submits the returned public key to
   `POST /v1/device-enrollments` using the current managed bearer. After validating
   the complete response, call `bind_pending(handle, authority)` with the exact
   server device ID, request ID, generation and fingerprint. The key remains
   pending while approval is requested and completed separately on the server.
4. Obtain a current approved binding and fresh challenge through the authenticated
   enrollment API. Serialize completion JSON once. Call
   `sign_enrollment_completion(handle, authority, body_bytes)`. This accepts only
   the exact stored request/generation, a canonical challenge UUID and bounded
   nonce. It derives the fixed completion route from stored device identity.
   Send the returned exact bytes and proof with the current managed bearer.
5. Only after validated server completion, or a fresh authenticated read proving
   that the same request/key/generation is active, call
   `mark_active(handle, authority)`. This records observed server state; it does
   not approve, enable or enroll anything on the server.
6. For each agent operation obtain fresh current membership and active server
   binding evidence. Call `sign_agent_request(handle, authority, operation, body)`.
   `AgentOperation` permits only heartbeat, poll and command acknowledgement.
   Acknowledgement requires its exact canonical command UUID. The origin, company,
   member, device, generation, method and route cannot be selected by the caller.

`NativeSignedRequest` carries exact wire body bytes, route, compact proof and expiry
for the trusted native client. Its repr is redacted. It is not a public response or
proof bridge. The caller must never reserialize the body or log/forward this object
to JS. Server authorization and current bearer membership are mandatory for every
actual request, even while a local key is marked active.

An interrupted enrollment can resume after an ordinary application restart:

- An unbound pending public key can be resubmitted only after native code resolves
  whether an earlier server request succeeded. Reconcile authenticated inventory;
  do not blindly create duplicate device requests after an uncertain response.
- A bound pending key preserves request/device/generation, awaits explicit server
  approval, and can complete a fresh challenge. No nonce or challenge is persisted.
- If completion succeeded but its response was lost, a validated current active
  inventory binding can finish the local `mark_active` step for the same key.
- An active key can be restored locally but cannot produce an agent proof without
  fresh current membership and matching active server evidence.

## Native authorization evidence is an integration boundary

`NativeDeviceAuthorization` is an exact, immutable, native-only typed value. It
requires a `TrustedDeviceScope`, exact `ManagedMembership`, optional exact
`ServerDeviceBinding`, observation wall/monotonic times and an expiry. Operating
roles are owner, admin and member; auditor is rejected. Product member/company
must match the scope exactly. Do not substitute email, Entra directory tenant,
desktop ID-token subject, token role claims or a cached UI snapshot.

This value does **not** authenticate its creator. It has no `verified=true` flag
and is never decoded from UI JSON. The future exact `NativeDeviceClient` must
construct it only from validated current native managed-session membership and
same-origin authenticated enrollment responses. Existing `NativeManagedSession`
has no enrollment/inventory transport in this slice. Consequently this module
alone is not end-to-end production device enrollment.

Capture both observation clocks before the authenticated reads. Evidence expiry
must be no later than the managed-session expiry, applicable server approval/
challenge expiry, or 30 seconds after that observation, whichever is first.
The module enforces exact types, native scope/role, the 30-second ceiling, wall and
monotonic freshness, no future observation and no local clock rollback. It checks
again after slow Keychain reads and signing before returning a proof. No evidence
is persisted or reused automatically. Current server authorization can change
immediately; evidence freshness never replaces the server's transaction-time
membership, generation, approval, replay and command checks.

Proofs use the existing version-2 Ed25519/JWS helper, product `/v1/me.id`, fresh UUID
identifiers and a 60-second maximum lifetime. Enrollment proofs and active-request
proofs have separate methods, purposes and local/server state requirements. Exact
bounded strict JSON bodies are validated before signing, including generation,
operation-specific fields, duplicate keys, UTF-8, depth and node limits. There is
no generic caller-controlled URL, HTTP method, arbitrary body signer or raw-key API.

## Persistence, acknowledgements and quarantine

There are exactly two bounded, versioned OS records:

- `managed-device-payload-v1`: scope, random local epoch, pending/active state,
  private/public key and optional exact request binding;
- `managed-device-journal-v1`: scope, epoch, state, payload digest and kernel lease
  identity digest. The empty state has no payload and a null payload digest.

All records are at most 4 KiB. Parsing rejects unsupported field sets/versions,
invalid strict types, duplicate properties, mismatched private/public keys,
incorrect fingerprints, scopes, epochs and digests. Reads rely on the Keychain
adapter's exact app/service/account/accessibility authentication. The payload
hash is a consistency check, not an independent MAC or device attestation.

The reviewed private `_ProcessLease` implementation is reused unchanged. It uses
an owner-private, nofollow-opened path derived from the OS account home, fixed app
service and access group, never HOME/environment/UI input. It holds a permanent
empty lock inode using a nonblocking kernel flock. Every operation rechecks owner,
permissions, file type, link count, process ID and directory/lock inode identity.
Cooperating instances and processes cannot share ownership. Inherited descriptors
cannot unlock the parent's lease. Ordinary process exit releases ownership.

The lease directory additionally holds an empty `quarantined` marker during
mutations. It contains no key, token, identifier, journal or application data.
Creation and its directory entry are fsynced and verified before the first OS
mutation. It uses nofollow/nonblocking opening, strict owner/mode/type/link/size
checks, and never follows or clears a symlink/FIFO as a recovery shortcut.

Each commit then:

1. Writes and reads back a quarantined Keychain journal.
2. Writes and reads back the payload, or deletes it and confirms exact absence.
3. Writes and reads back the ready journal, then rereads the consistent pair.
4. Removes the empty marker, fsyncs its directory and checks absence/lease ownership.

Every OS mutation must return exactly `None`. False, zero, truthy wrappers, unusual
return values, exceptions, missing readback and ambiguous deletion are failures.
Any failure blocks signing, clears usable process state, and retains/recreates
quarantine. In particular, a final ready write that persisted but returned an
uncertain acknowledgement is still blocked after restart: the filesystem marker
was not cleared. Failed marker removal or post-removal directory fsync is also
quarantined. Because marker removal occurs only after all Keychain acknowledgements
and readbacks, interruption during its removal cannot bless an uncertain OS write.

The journal also binds the permanent kernel lease directory and lock identities.
Replacing either ownership path cannot hide an interrupted write by presenting a
new empty directory after restart. Such changes, including reinstall/storage
migration that changes the permanent inode, require explicit recovery. Native
production acceptance must verify these filesystem/fsync semantics on supported
macOS versions. This is not tamper resistance against an OS administrator, a
compromised signed host, or an attacker able to roll back both Keychain and private
filesystem state. Restoring stale but internally consistent records never overrides
current server authorization.

## Explicit forgetting and rotation limits

`forget_local()` is explicit destructive local recovery. The native review flow
must explain its scope and obtain the applicable user approval before invoking it.
It confirms the exact payload is absent and writes a ready empty journal before
reporting success. All old handles are invalid immediately, including on uncertain
deletion; a replacement key gets a new local epoch. A recognizable journal belonging
to another product origin/company/member cannot be erased under a different scope.
Unrelated Keychain items and namespaces are never touched. Corrupt records can only
be discarded through this explicit recovery method; there is no automatic retry,
repair, key generation or deletion. `close()` only retires the object and releases
its lease, leaving consistent OS records intact.

Local forgetting does not revoke a server registration, invalidate already-issued
proofs, terminate website sessions, delete browser cookies or wipe browser data.
Server revocation is a separate explicit enrollment API action. An existing key
holder remains subject to the server's current binding until that binding is
revoked/rotated, even if this local app has forgotten its copy.

In-place rotation is deliberately unsupported. Do not forget a live key as an
implicit rotation step. A safe future implementation needs separate old/new key
slots, a durable server-rotation intent with expected generation and request
identity, explicit authorization to disable the old server binding, and an
authenticated reconciliation strategy for a submitted rotation whose response is
lost. It must distinguish unsubmitted, accepted, rejected, approved and completed
replacement requests, retain the correct material until that result is known, and
never reactivate an old generation merely because its private key still exists.
Those states and the concrete native network/UI flow are not implemented here.

## Synthetic verification

`tests/test_client_device_keys.py` uses a fake byte store and temporary empty
ownership/quarantine files only. It exercises normal pending/active restart,
product-member proof v2, exact wire/body/path/generation binding, fresh proof IDs,
fixed purposes, stale/future/nonfinite clocks, malformed evidence and request JSON,
rotation refusal, strict OS acknowledgements, all store-boundary interruptions,
ambiguous final commit, unconfirmed readback/deletion, failed quarantine creation/
clear/fsync, replaced lease paths, symlink/FIFO refusal, concurrent process exclusion,
process exit, concurrent signing/recovery and absence of secret output/files.

Run the focused suite with the repository's configured environment:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_client_device_keys.py' -v
.venv/bin/ruff check src/team_browser/client/device_keys.py tests/test_client_device_keys.py
.venv/bin/ruff format --check src/team_browser/client/device_keys.py tests/test_client_device_keys.py
```

Passing these checks is not evidence of real Mac Keychain access, application
signing/notarization, successful remote enrollment, authorized browser execution,
site-session revocation, secure memory erasure, or physical power-loss recovery.
