# Native managed session and backend reads

## Delivered scope

`team_browser.client.managed_session.NativeManagedSession` is a callable native
consumer of the concrete `MacOSSessionVault`. It makes only three fixed backend
HTTPS reads and returns bounded, typed public projections. It is public-client
code and imports no private `team_browser.api` or `demo` modules. Neither import
nor construction makes a network request.

This is synthetic-tested implementation, **not live identity or signed-Mac
acceptance**. There are no live credentials, provider requests, registrations,
consent grants, membership creation, device enrollment, cookie operations or
browser launches in this slice. No production backend origin or operator
configuration is supplied. The existing account-free local mode is independent.

The default implementation has no fake/in-memory/file credential adapter,
transport-injection argument, environment-selected server, TLS override, token
getter, arbitrary credential callback or HTTP/JS credential bridge. Tests patch
private native storage/socket seams; those patches are not runtime options.

## Trusted native wiring

A reviewed native host uses the same immutable `TrustedOIDCConfiguration` for
sign-in, the vault and the backend binding. The backend configuration additionally
requires one exact HTTPS origin, with no path or trailing slash:

```python
from team_browser.client.managed_session import (
    NativeManagedSession,
    TrustedBackendConfiguration,
)

# approved_origin and oidc_configuration are reviewed native/operator settings.
# native_vault is the same concrete vault used by the completed sign-in.
backend = TrustedBackendConfiguration(approved_origin, oidc_configuration)
session = NativeManagedSession(backend, vault=native_vault)

# All calls run on a bounded native worker, never the UI event-loop thread.
membership = session.me()
profiles = session.profiles()
presets = session.presets()
public_status = session.snapshot().public()
public_profiles = [profile.public() for profile in profiles]

# Explicit user-initiated local sign-out, also on the native worker.
local_logout = session.logout().public()
```

This is an integration sketch, not a command to activate live identity. The host
must first complete the separately reviewed explicit startup-discard workflow,
then wait until its sign-in coordinator publishes terminal identity success with
no pending cancellation or native operations. Only then construct the managed
consumer. Never bind to a merely pending/unpublished vault commit. Retain the
same vault and process lease until that host/session is retired.

Configuration accepts only the exact frozen native configuration types and
revalidates them. The current delegated-resource integration is Entra-only;
legacy `openid` alone is insufficient to authorize a resource API request. The
vault's exact ordered approved scope tuple, issuer and local TTL must match.
Another issuer, resource or TTL, reordered/dropped/extra scopes, a compatibility
vault without explicit issuer policy, or a fake/subclass vault fails closed.
The backend origin is independently approved; it is never derived from the
issuer, user email/domain, JWT claims, discovery, browser input or a response.

"Pinned origin" means the exact HTTPS scheme, DNS host and permitted port, with
normal certificate-chain and hostname verification. It does not mean leaf/SPKI
certificate pinning. Only canonical DNS origins on port 443 are supported.
Local/private addresses, IP URL hosts, userinfo, queries, fragments, encoded
paths and alternate ports are rejected. An explicit `:443` remains exact.

## Public contract and authorization

The fixed methods are:

- `me() -> ManagedMembership`: GET `/v1/me`.
- `profiles() -> tuple[ManagedProfile, ...]`: the authorized profile list.
- `presets() -> tuple[ManagedPreset, ...]`: the authorized preset list.
- `snapshot() -> ManagedSnapshot`: checks local vault liveness and projects the
  most recent membership observation. It does not contact the server.
- `logout() -> ManagedSnapshot`: confirms scoped local deletion only.

Each projection has an explicit `public()` method. Never serialize the native
client, its vault, its transport, raw HTTP responses, callback objects or stack
locals. `ManagedSessionError.reason` contains only a fixed diagnostic.

`ManagedMembership` maps the current API's `id`, `org_id`, `display_name` and
`role` to `member_id`, `tenant_id`, `display_name` and the typed `MemberRole` enum.
The product `tenant_id` is an application organization ID, not the Entra
configuration's directory tenant GUID. It is obtained only from the authenticated
API. It is never guessed from the native ID-token subject or email. Supported
roles are exactly `owner`, `admin`, `member` and `auditor`.

Initial status is `membership_unverified`, with no membership or managed
availability. `me()` must succeed before list methods are allowed. Identity
verification and a valid local vault record do not establish company membership.
Subsequent `/v1/me` results must preserve the original member/organization pair;
a changed pair invalidates this consumer instead of silently switching context.
Role changes returned by the server are observed, never assigned locally.

Initial `/v1/me` has no organization header. Its validated product tenant is
then pinned in native memory. Every subsequent `me()`, `profiles()` and
`presets()` request sends exactly one `X-TBM-Organization` header with that
pinned value. It is never taken from UI input or configured as a free-form
header. The server must compare it to the current enabled actor's organization
before each route handler and return 409 on mismatch. That conflict invalidates
this consumer with `membership_changed`; it cannot silently switch companies.
The header does not create identity, membership, role or authorization. Each
list call still makes just one request. Activation requires the reviewed
server-side header contract; do not point this client at an older server that
ignores it. No retry or compatibility downgrade exists.

The snapshot contains `status`, `managed_available`, `membership`,
`expires_at`, `server_authoritative=True`, `native_integration_verified=False` and
`device_enrolled=False`. An `available` snapshot is a recent observation, **not
an offline authorization capability**. The API authorizes every request against
its current database membership. A member disabled server-side receives 403;
401/403 from any allowed operation clears managed availability immediately and
latches `membership_denied`. A malformed 200 response with an unexpected
`enabled` field, including `enabled: false`, fails closed as invalid schema.
The current real `/v1/me` success shape has no `enabled` field because its
principal dependency already requires an active membership.

A snapshot cannot observe a server-side revocation without another API request.
The host must perform an authorized fresh read before acting on managed data,
clear its presentation caches on logout/denial/expiry, and generation-fence all
worker results so an old response cannot restore a newer UI session. Retained
immutable projections are historical observations. The public expiry is the
vault's original bounded expiry, never an extension. Cached snapshot public
serialization also clamps an elapsed wall-clock expiry; fresh snapshots perform
both vault wall and monotonic checks. Do not schedule browser
launches, enrollment or policy actions based solely on these list projections.

Profiles expose only `id`, `name`, `preset_id`, `assigned_user_id`, `revision`
and current API metadata state (`unprovisioned` or `proxy-simulated`). Presets
expose only `id`, `name`, `engine`, `locale`, `timezone`, `proxy_required` and
`revision`. A false/nonboolean `proxy_required` is rejected; no direct-network
fallback is created. These are portable metadata, never local runtime grants or
credential/cookie material. Unknown fields, duplicate IDs, unknown roles/engines
or states, unsafe identifiers, noninteger revisions and malformed text are
rejected. A future API schema change requires an explicit client review.

## Credential and lifetime boundary

The consumer is bound once to the vault's current process epoch and opaque
session reference, which remain native-only. Recovery, replacement login,
missing records or another process's data cannot rebind it. Stale consumers
cannot read or delete a later session, including a reused opaque reference in a
new recovery epoch.

Only private vault methods for this exact concrete consumer can read the
integrity-bound payload. They perform fixed-policy, epoch/session, journal,
digest, wall/monotonic expiry and lease checks around native I/O. The vault lock
remains held through network I/O and projection validation. The fixed transport
checks again after DNS/connect/TLS and immediately before emitting the bearer.
Checks after response, parsing and cleanup prevent a late response from becoming
managed availability after local expiry, clock failure, lost lease or changed
record. The short local TTL is never extended or refreshed.

Only the access token is used as the Authorization bearer. The ID token is never
sent to the backend. Neither token is returned by any native method or included
in a public projection. Error bodies are discarded. Even a valid-looking
projection containing an exact access/ID-token reflection is rejected after JSON
normalization. Python immutable strings/bytes and native bridging copies cannot
be reliably zeroized; disable secret-bearing local-variable capture, traces,
core dumps and crash reporting in the packaged native host.

Expiry performs the vault's existing quarantine/confirmed-absence deletion. An
uncertain native-store operation reports `recovery_required`; it does not imply
safe deletion. Network/schema failure reports `unavailable`, and no operation on
that consumer retries or restores availability. Retire it and reconcile the
native lifecycle explicitly. Reconstructing an object must never be used as an
automatic retry/reset strategy.

## Network and response limits

The private `_BackendHTTPS` wrapper reuses the reviewed `oidc_https` DNS process,
public-address policy, numeric peer pinning, TLS-root construction, deadline
checks and successful HTTP response reader. It does not subclass or widen
`NativeOIDCHTTPSTransport` endpoint permissions. OIDC continues to allow only its
exact JWKS/token operations; backend use is a separate internal boundary.

Each request has a ten-second monotonic I/O budget, one validated public numeric
address, one connection and no automatic retry, address failover or redirect.
The configured host is used for certificate validation, SNI and Host. There is
no ambient proxy/PAC/netrc/cookie use, custom CA parameter, ambient
`SSL_CERT_FILE`/`SSL_CERT_DIR` override or TLS key logging. TLS 1.2 or newer and
verified hostname/chain checks are mandatory. The inherited resolver helper is
bounded and quarantines uncertain cleanup. See [native HTTPS limits](oidc-transport.md)
for CPython/frozen-runtime, OpenSSL trust and OS process-start caveats.

Successful responses use the unchanged reviewed strict parser: 16 KiB headers,
64 fields, 4,096-byte lines, at most 64 KiB decoded body, JSON MIME, identity
encoding, bounded Content-Length/chunked/clean-EOF framing and no trailing bytes.
The backend wrapper first reads a bounded, syntactically valid status/header
block. Non-200 bodies and metadata are discarded and the connection is closed;
it does not follow Location, store cookies, parse diagnostics or drain an
unbounded error stream. 401/403 produce only `membership_denied`, and 409 produces
`membership_changed`; every other non-200 result invalidates availability
without retry.

JSON is strict UTF-8 with duplicate fields and nonfinite constants rejected.
Each response must match exactly the approved projection keys and types. Lists
are additionally capped at 256 rows; this pilot has no pagination or truncation
fallback. A larger team/list fails explicitly instead of presenting partial data
as complete. Secrets, raw exception text and response content are never logged.

## Logout and concurrency

Native methods are synchronous. The host must run them on owned bounded native
workers and show pending state without blocking its UI thread. An individual
HTTPS call is bounded by its application deadline; OS scheduling, process
creation or a blocked native Keychain call is not a hard real-time guarantee.

Calls on the same consumer are serialized, and the vault lock covers final
projection publication. Each method makes at most one ten-second HTTPS call,
plus native storage and scheduling time. Logout waits for an in-flight read
to settle, then checks the bound epoch/session and deletes precisely that local
vault payload through the existing journal protocol. It does not cancel a
request already sent or pretend an OS/thread can be safely killed. After logout
returns, that consumer is terminal and cannot publish fresh availability.
Idempotent repeated logout of its confirmed absent record is harmless. A later
login's record is never deleted by the old consumer. Uncertain deletion reports
`local_logout_unconfirmed`/`recovery_required`, never successful logout.

Local logout does **not** revoke provider tokens, clear website/provider cookies,
remove company membership, wipe browser profiles or de-enroll devices. The host
must retire the old sign-in core as well, since that core's identity observation
must not be presented as a still-usable managed session after local deletion.

## Synthetic verification and remaining acceptance

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_managed_session.py -v
.venv/bin/python -m unittest discover -s tests -p test_client_session_vault.py -v
.venv/bin/ruff check src/team_browser/client/managed_session.py src/team_browser/client/session_vault.py tests/test_client_managed_session.py
```

The public-client suite uses invented contract snapshots and mocked HTTPS/native
storage, with no private-server imports. It covers explicit policy/origin
binding, the exact operation allowlist, all typed roles/projections, malformed
schema/JSON/framing, auth denial, disabled-field rejection, tenant/member changes,
credential reflection, no-retry uncertainty, DNS/TLS/peer restrictions,
expiry before sending/after slow responses/after parsing, current-record and
lease failure, initial/subsequent pinned tenant headers and 409 refusal,
generation/recovery isolation, scoped logout and concurrent
read/logout. A composed test verifies an ephemeral signed Entra ID token through
the real sign-in core into the concrete synthetic-backed vault before the
managed consumer can obtain a membership projection. Private integration tests
must separately exercise actual API handlers without putting API imports into
the public client export.

Still unverified: actual packaged macOS Keychain/signature/entitlement behavior,
real DNS/TLS and backend interoperability, provider consent and registrations,
actual application membership, target-platform cancellation/suspend/resume,
complete native/UI worker integration and installer acceptance. No test count,
`identity_verified` or `available` projection establishes those acceptance gates.
