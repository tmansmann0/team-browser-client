# Native foreground enrollment client

## Implemented boundary

`client/device_client.py` composes the exact `NativeManagedSession` and
`MacOSDeviceKeys` implementations. It implements a callable native-worker request,
status-poll, approved challenge/completion and current-device heartbeat path.
Import and construction perform no native or network I/O. The client is not wired
to the web UI, the CLI's default configuration, a background service or managed
browser execution. The existing native host does not silently enroll on sign-in.

All verification in this slice uses ephemeral synthetic Ed25519 keys, invented
memberships, temporary empty lease files, fake Keychain byte stores and fake
sockets. No real Keychain item, device registration, access grant, credentials,
provider traffic, browser process or network service was created or contacted.
Actual signed-app macOS and authenticated production acceptance remain required.

## Native composition and explicit consent

An approved signed native host owns:

1. An existing `NativeManagedSession` bound to its current `MacOSSessionVault`.
2. The exact reviewed `TrustedDeviceScope`: canonical backend origin and product
   organization/member IDs, derived from authenticated `/v1/me`, not token email,
   Entra directory tenant, pairwise IdP subject or web-supplied claims.
3. `MacOSDeviceKeys` in the fixed `managed-device-keys` Keychain namespace.
4. `NativeDeviceClient(session, keys, scope)`.

The constructor requires exact native types and matching scopes; it accepts no
network adapter, token provider, key getter, URL, header or arbitrary signer.
All methods are synchronous and belong on a native worker. None is a browser/JSON
handler. The host owns retirement, local key forgetting, native object closing,
logout and its foreground worker lifecycle separately.

Call `restore()` explicitly first. It reads the key owner's consistent local
state but grants no backend authority. A restored key is presented as unverified
until a new authenticated read succeeds.

A `NativeEnrollmentApproval` is an immutable exact native decision containing:

- the `EnrollmentAction`, exact scope and device label;
- an actual approved/declined Boolean and canonical decision UUID;
- observation wall/monotonic clocks and an expiry at most 300 seconds later;
- for activation, the exact device ID, request UUID, generation and fingerprint
  displayed in the native approval surface.

The signed native review surface must obtain the user's explicit decision and
explain the backend/company/member, persistent local key storage, registration
and activation consequences before constructing an approved value. The value
does not authenticate its creator or manufacture consent. Never deserialize it
from JS, an HTTP body, a generic `verified=true` flag or a stored preference.
No real consent UI or live approval is supplied by this implementation.

Each decision can be consumed only once per client instance (64-decision bound).
A declined, stale, future, reused, wrong-action, wrong-scope or wrong-label value
is refused. Activation also compares all four binding identity fields. Its expiry
is incorporated in the transport deadline, so slow native/network work cannot
emit a request after that decision expires.

## First enrollment

`request_enrollment(device_name, approval)`:

- requires a fresh request decision before any generation or enrollment request;
- reads `/v1/me` with the current native bearer and requires the exact company,
  product member and owner/admin/member role; auditor is insufficient;
- captures wall and monotonic clocks before the read and limits evidence to the
  earlier of 30 seconds, managed-session expiry and native-decision expiry;
- generates and durably stores a pending key through `MacOSDeviceKeys`;
- sends only name, claimed `macos` platform and the public key to the fixed
  `POST /v1/device-enrollments` route;
- accepts only an exact bounded 201 JSON response matching member, public-key
  fingerprint, name, platform, generation 1, pending status and disabled state;
- persists the exact server request/device/generation/fingerprint binding.

The return remains `pending`. It neither approves the request nor enables a
browser. The server owner/admin approval is a separate consequential action; this
client has no approve endpoint, including for an owner's own device.

`poll_enrollment()` performs a fresh `/v1/me` and authenticated inventory read.
This is enrollment-status polling, not command polling or leasing. The complete
response is parsed strictly, duplicate device/request IDs are rejected, and
exactly one current-member record must match the local fingerprint. The key
owner's read-only `validate_binding` checks the durable request and generation;
a fingerprint match alone cannot bless a replacement registration. Missing,
ambiguous, revoked, expired, wrong-member and changed bindings do not authorize
agent work. Polling never promotes a pending local key to active.

The server returns member-only inventory for ordinary members and company-wide
inventory for owner/admin/auditor. The native client still accepts only its own
operating member's unique binding. The server caps inventory at 1,000 company
records. Native HTTPS retains its stricter 64 KiB response limit, and the client
limits JSON to 16 levels and 16,384 visited nodes. Large or incomplete/unparseable
inventory fails closed; there is no best-effort partial-list authorization.

## Approved activation

After separate server approval, the native surface obtains an activation decision
for the exact displayed binding and calls `activate(approval)`:

1. Re-read current membership and the exact inventory binding.
2. Require `approved`, an unexpired server approval, and the matching decision.
3. Send the exact request UUID/generation to the fixed challenge route.
4. Validate every challenge field, request/generation match, canonical challenge
   UUID, bounded nonce, expiry no later than 120 seconds ahead or server approval.
5. Serialize completion JSON once, use the key owner's enrollment-purpose signer,
   and send those exact bytes plus its short-lived `Device-Proof` with the bearer.
6. Validate the exact active/enabled response and unchanged binding before recording
   local active state with `mark_active`.

Evidence keeps its original observation clocks and is further clamped by server
approval/challenge expiry. Proof v2 binds the product `/v1/me.id`, exact origin,
organization, device, generation, method, route, raw body digest and nonce. Native
proof/challenge values have redacted representations and never enter public status.

The server consumes challenge completion once. No automatic retries occur. If the
server completes but its reply is lost, the local key remains pending; reconnect
with a new exact managed-session consumer and poll. A fresh native activation
decision for the confirmed active binding allows recording local active state
without a second challenge/completion. A plain poll itself performs no activation.

## Foreground heartbeat

`heartbeat(agent_version)` obtains new membership and exact current active binding
evidence, verifies the local active key, signs the fixed heartbeat body and sends
it using the same native session. It always sends `profiles: []`. It does not claim
that profiles are ready, cookies transferred, a setup executed or data wiped.

The exact heartbeat reply must identify the same member, device, generation,
label and macOS platform, an enabled nonsynthetic device, secure enrollment support,
online state, matching agent version and a bounded current UTC timestamp.
The online value is only the server's acknowledged presence observation.

There is no command lease/acknowledgement, browser launch, remote executor,
provider integration, destructive deletion or revocation API here. A server
registration alone does not enable those capabilities.

## Shared trusted transport

The client constructs private `_DeviceWireRequest` values. `_DeviceOperation`
permits only inventory, first request, challenge, completion and heartbeat. Method
and route are derived, IDs are bounded, JSON fields are operation-specific,
heartbeats cannot inject replica reports, and only completion/heartbeat accept an
exact `NativeSignedRequest`. Proof body/path/method must match exactly.

`NativeManagedSession._device_exchange` and
`MacOSSessionVault._managed_device_exchange` share the existing managed exchange
path. `_BackendHTTPS._device` uses the same `_exchange` as the three existing fixed
managed reads. Credentials remain inside the vault and its exact trusted transport;
no callback or caller receives a bearer. The refactor preserves:

- exact approved HTTPS origin and company header, verified TLS and public address
  checks, no proxy/environment redirect destination or alternate origin;
- exact native consumer, configuration, vault epoch/session, record digest and
  process-lease ownership checks before and after network work;
- managed expiry rechecks after slow OS reads and DNS/connect/handshake;
- an additional dual-clock evidence/decision/proof check immediately before sending;
- one 10-second request bound, strict socket acknowledgements/cleanup and transport
  retirement after uncertain execution;
- strict status/content type/size/framing/JSON validation, no redirects/retries and
  credential-reflection rejection in all typed response fields, including challenge
  fields and other company inventory rows.

201 uses the existing 200 HTTP framing/body parser without loosening its limits;
the actual status is restored and checked against the exact expected operation.
No error body is reflected to callers. Public failures contain only fixed reasons.

## Uncertainty, revocation and remaining gates

A mutating request with an unconfirmed response is reported as uncertain. The
client never assumes that a network error rolled back server state. Existing key
material is not deleted/rotated as a retry mechanism.

A lost *initial request* response can leave a generated key without its durable
server binding. This version deliberately blocks further submission and refuses
to infer that binding from inventory alone. An explicit future recovery workflow
must reconcile it; automatic resubmission, local forgetting or duplicate device
creation is not implemented. Lost completion has the narrower same-binding
recovery described above. Invalid or changed native storage remains quarantined
under the key owner's existing rules.

Server revocation or generation changes stop subsequent fresh evidence/signing.
A local active key is historical storage state, never an offline authorization
grant. Server transaction-time membership, generation and proof checks remain
authoritative, including when revocation happens after a native evidence read.
Local forgetting/logout does not revoke server registrations or website sessions.

The foreground user bearer is required for every call. Managed session expiry,
logout, changed membership, failed ownership checks or malformed responses stop the
client. It has no refresh token, unattended token renewal, periodic heartbeat loop
or autonomous agent. New native session consumers do not revive expired sessions.

`DeviceClientSnapshot.public()` includes observation freshness and marks device
enrollment current only while active evidence is fresh. It always marks native
integration unverified, foreground-only, managed browsing disabled and remote
execution disabled. It is presentation data, never authorization evidence.

## Verification

Run from the repository's configured environment:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_client_device_client.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_client_managed_session.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_client_session_vault.py' -v
.venv/bin/ruff check src/team_browser/client/device_client.py src/team_browser/client/managed_session.py src/team_browser/client/session_vault.py tests/test_client_device_client.py
.venv/bin/ruff format --check src/team_browser/client/device_client.py src/team_browser/client/managed_session.py src/team_browser/client/session_vault.py tests/test_client_device_client.py
```

Tests verify exact signed wire bodies and product-member proof v2, request/poll/
activation/heartbeat, explicit decision and role/scope boundaries, expiry before
emission, malformed/redirected/ambiguous response rejection, credential reflection,
rotation/revocation, no duplicate request after uncertainty, active reconciliation
after a lost completion, and absence of secret public/file output. Fake sockets
exercise the concrete transport; they are not a live HTTPS deployment or real-Mac
acceptance result.

Device labels must already be canonical: leading/trailing whitespace is rejected before a decision is consumed or any key is generated. The client never silently changes a label the native approval surface displayed. This matches the server’s trimmed storage boundary.

The native transport also fences operating roles immediately before bearer emission and before returning device results. A same-identity downgrade to auditor that the client has already observed cannot reuse older enrollment authority. The server still rechecks live membership and device authorization on every request.
