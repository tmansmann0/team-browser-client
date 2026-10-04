# Native managed application host

## Delivered scope and activation boundary

`team_browser.client.managed_host.NativeManagedHost` composes the existing exact
native OIDC HTTPS adapter, callback coordinator, macOS session vault and managed
API consumer. Its constructor accepts only reviewed, typed native/operator
configuration. Import and construction do not access Keychain, open a browser,
connect a socket, request provider/API data or start workers.

This implementation and its tests are **not live activation or signed-Mac
acceptance**. There is no deployed operator configuration, provider
registration, credential, app consent, company enrollment, device grant or
browser installation. Account-free local mode remains independent. With no
host supplied, `unconfigured_snapshot().public()` reports the complete disabled
managed projection without constructing an adapter.

The local application may mount this host behind its existing same-origin,
loopback, Host, Origin, no-store and CSRF protections. Those protections are
mandatory: a local HTTP server is not an authorization boundary merely because
it uses localhost. The host is not a token getter, general request proxy,
provider selector, vault bridge or browser-launch service. A site, web route,
remote response, environment variable or token claim must never construct its
configuration.

## Native construction and fixed actions

Only trusted native/operator code constructs:

```python
host = NativeManagedHost(
    oidc_configuration,
    backend_configuration,
    keychain_configuration,
)
```

The three positional parameters must be exact `TrustedOIDCConfiguration`,
`TrustedBackendConfiguration` and `KeychainConfiguration` instances, rather than
dictionaries or subclasses. They are revalidated. The backend's OIDC settings
must equal the sign-in settings, and Keychain's namespace must be exactly
`managed-signin`. No arbitrary production transport, vault, credential callback
or session consumer can be supplied. Existing configuration types continue to
apply their exact issuer, scopes, origin, redirect, resource and TTL rules.
The host itself constructs `NativeOIDCHTTPSTransport`, `MacOSSessionVault`,
`NativeSignInCoordinator` and `NativeManagedSession` on its worker. Tests may
patch private construction/native seams; these are not runtime settings.

The nonblocking methods all return `ManagedHostSnapshot`:

- `prepare()` and `recover()`: the same explicit scoped startup/recovery action.
  Create the native vault if needed and discard the reserved previous managed
  login payload, including on first start. This never restores a previous login,
  enumerates Keychain or deletes other feature namespaces. It is admitted only
  after previous operations settle and no available session is being presented.
- `sign_in()`: start one user-initiated native callback/browser attempt after
  successful preparation. It takes no URL, scope, account or token argument.
- `cancel_sign_in()`: request callback cancellation only when the coordinator's
  own authoritative terminal/cancellation rule permits it. It is never logout.
- `refresh_records()`: one explicit bounded operation making `/v1/me`, then the
  profile list, then the preset list. Each request remains independently
  server-authorized and uses the consumer's native organization fence. No
  subsequent read is admitted once a newer retirement/expiry generation wins.
- `sign_out()`: immediately hide identity, membership and records; then retire
  only the current/exact callback-owned local record after native work settles.
- `shutdown()`: immediately hide presentation and request lifecycle retirement;
  retain the vault and workers until they settle, then close the vault.
- `snapshot()`: clocks, cached presentation and the coordinator's nonblocking
  status only. It never calls the synchronous managed consumer's `snapshot()`
  or accesses the native vault on the calling/UI thread.

`wait_closed(timeout=None)` is a blocking native-worker/test helper, never a UI
or web request handler operation. It reports completion of host-owned cleanup
and close, not provider revocation or deletion success. Inspect the final
snapshot: an uncertain result remains `recovery_required`, even when closed.

Preparation and sign-in are separately explicit. Recovery is never automatic.
A confirmed cancellation or successful local logout can permit another explicit
sign-in using the still-prepared vault; errors require explicit reconciliation.
A failed action never reconstructs an adapter or retries a network operation on
its own. Duplicate clicks neither create multiple launches nor queue a backlog.

## Identity, membership and presentation

An identity-success result is usable only after the coordinator has published
terminal success, all callback/native work has settled, and no accepted
cancellation is pending. Only then bind the exact `NativeManagedSession` to the
same live vault and request `/v1/me`. Identity alone never enables company
membership or managed access. Device enrollment always remains false.

Only `ManagedHostSnapshot.public()` may cross the UI bridge. Its fixed fields
include:

- `status` and `reason`: enums, never provider text, exception messages or reprs
- `configured`, `identity_verified`, `company_membership_verified`,
  `managed_access_available`, `device_enrolled`, `native_integration_verified`,
  `server_authoritative` and `expires_at`
- `pending_operation`, `native_operations_pending`, `can_cancel`,
  `cancellation_requested`, `shutting_down` and `closed`
- `capabilities`: `can_prepare`, `can_sign_in`, `can_cancel_sign_in`,
  `can_refresh_records` and `can_sign_out`
- `records_loaded`, bounded `membership`, `profiles` and `presets`

No identity issuer/subject, configured URL, scope list, token, callback query,
provider error, native session reference or native object is serialized.
Membership/profile/preset fields are precisely the previously reviewed managed
consumer projections, including its 256-row bound and strict schema rules.
The host has no generic operation or configurable destination action.

`records_loaded` starts false, including after the initial `/v1/me` succeeds.
It becomes true only after a complete explicit profile-and-preset refresh for
the current session. Thus an unrequested list is distinguishable from a
successfully loaded empty list. During refresh, previous successful lists may
remain visible as a previous observation. Denial, schema/network failure,
expiry, recovery, logout and shutdown clear them immediately. These records do
not authorize browser launch, proxy acquisition, enrollment or any offline
managed operation. Every backend request is authorized by the server's current
membership and organization checks.

The full status enum is: `unconfigured`, `preparation_required`, `preparing`,
`ready`, `signing_in`, `cancelling`, `membership_unverified`, `available`,
`refreshing`, `cancelled`, `expired`, `membership_denied`, `unavailable`,
`recovery_required`, `signing_out`, `signed_out_locally`, `shutting_down`, `closed`.
UI labels should translate these fixed values, never display native errors.

## Ownership, races and expiry

One non-daemon host worker handles every vault construction/recovery, adapter
construction, consumer operation and vault close. There is at most one queued
ordinary operation plus one coalesced priority retirement intent. The callback
coordinator retains its existing one-attempt listener and bounded native pool.
The UI does not join workers, hold the vault lock or kill a thread.

Sign-out advances a response generation and clears all presentation immediately.
A read admitted before the retirement generation wins may still emit a bearer
subsequently, or may already have caused a server read; local cancellation cannot
undo that. Admission is the locked generation check before each synchronous
consumer method. It is not cancellation at the later network-send instruction. The host waits for it to settle and then
performs the consumer's exact bound-record logout. Its result can never restore
identity, membership or data after the sign-out generation wins. The local UI
must additionally generation-fence HTTP responses, since a prior immutable
snapshot already serialized by the server can arrive later over the network.
Historical snapshot objects and rendered records are observations, not grants.

If sign-out wins between terminal callback publication and managed consumer
binding, the host waits for the callback's workers and invokes the coordinator's
private exact committed-handle retirement. This narrow composition boundary
reads no token or session handle into the host or web layer and does not call
broad `recover_discard_all()`. If callback cancellation already removed its
unpublished commit, the host does not delete it a second time. A failed or
uncertain cleanup is attempted once and reports `recovery_required`; shutdown
does not retry it automatically. Another/new session is never a fallback deletion
target. Expired callback snapshots without a consumer must likewise prove exact
retirement or report recovery, rather than claim absence from cached expiry.

Cached availability is clamped by both wall-clock expiry and an independent
monotonic deadline. The latter is conservatively bounded from the start of the
sign-in attempt by the approved local TTL, and never extended by slow callback,
API or Keychain work. Backward/nonfinite clocks fail closed. Expiry latches in
the host, clears presentation and fences late worker results without doing
native I/O from snapshot polling. The vault separately checks its exact record
and both clocks around every credential use. Cached expiry does not by itself
claim an OS record was deleted. Explicit local logout or recovery reconciles
that lifecycle.

Individual HTTPS calls retain their reviewed deadline; OS scheduling, framework
calls and Keychain can still block beyond it. A blocked operation keeps host
ownership, pending state and the vault lease; recovery, a new sign-in and native
close cannot overtake it. Shutdown returns promptly but the non-daemon workers
can keep process exit pending until the OS call settles. There is no artificial
timeout that claims cleanup or force-kills a credential operation. A deployment
must disclose this limitation and test actual suspension/shutdown behavior.

## Verification and remaining acceptance

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_managed_host.py -v
.venv/bin/ruff check src/team_browser/client/managed_host.py tests/test_client_managed_host.py
.venv/bin/ruff format --check src/team_browser/client/managed_host.py tests/test_client_managed_host.py
```

The synthetic suite covers inert construction and exact config types, explicit
preparation/recovery, no arbitrary adapter arguments, duplicate clicks,
identity-versus-membership publication, authoritative cancellation, bounded
refresh, late-response and local logout races, exact unpublished-commit cleanup,
cleanup uncertainty without automatic retries, replacement-record isolation,
wall/monotonic expiry, blocked native shutdown/close, and secret-free projection.
Concrete composition tests use the actual coordinator/core/vault/consumer,
fresh ephemeral RSA-signed Entra claims, a temporary process-lease directory,
mocked native/provider/backend seams and real disposable loopback sockets. They
exercise membership, records, exact logout and cancellation during exchange.
No test imports private server/API modules or uses live identity material.

Real signed-Mac Keychain and external-browser behavior, actual provider
registration/consent, approved native operator configuration, live TLS/backend
interoperability, revocation, deployment lifecycle, device enrollment and
installer acceptance remain explicit review/approval gates. See
[managed sign-in](managed-signin.md), [callback coordinator](signin-callback.md),
[session vault](session-vault.md) and [managed session](managed-session.md).
