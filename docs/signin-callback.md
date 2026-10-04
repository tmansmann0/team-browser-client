# Native sign-in callback and browser coordinator

## Delivered scope

`team_browser.client.signin_callback.NativeSignInCoordinator` is a concrete,
native-only, one-attempt orchestration slice. It binds the exact configured
loopback destination, begins the pinned PKCE core, requests the external macOS
HTTPS handler, and passes callback URLs only to that same core. There is no web
route, JavaScript bridge, arbitrary-URL launch method, dynamic discovery,
provider selection, token getter, or production configuration in this module.
Importing and construction perform no socket, browser, provider or vault I/O.

Verification is synthetic Linux testing, including disposable IPv4/IPv6
loopback sockets, a fake browser opener, fake vault/provider adapters and one
fresh ephemeral test signing key. No DNS lookup, real provider request, browser
launch, user credential, consent grant, Keychain operation, app registration or
native platform acceptance took place. The fake framework test exercises only
the Python call contract; it does not establish real macOS behavior.

This slice is composed by the [native host](managed-host.md) and fixed local UI
bridge, but is **not activated with live provider configuration**. The concrete
SessionVault must receive its explicit scope policy matching this same Entra
configuration before an Entra success can be stored. Its matching typed policy
support is separately implemented and synthetic-tested. Do not downcast scopes
to `openid` or substitute a fake vault to bypass that requirement. The native HTTPS
adapter, native lifecycle, scoped managed API consumer and local logout are now
implemented with synthetic integration tests. Signed Mac distribution, provider
registration/consent, target-platform acceptance and actual device rollout remain
activation gates.
Every public snapshot retains `native_integration_verified: false` and the
core's false membership, device-enrollment and managed-access flags.

## Trusted native integration

Only reviewed native application code may construct this coordinator. Supply an
exact `TrustedOIDCConfiguration`, the approved native transport, and the prepared
native SessionVault. The coordinator constructs its own `ManagedSignIn` using
that same configuration; callers cannot supply a differently configured core.
Its configuration is never accepted from a callback, web page, JSON settings,
remote discovery, environment variable or account claim.

The host must follow [SessionVault's lifecycle](session-vault.md), including
explicit startup discard/recovery and ownership of its lease. This coordinator
does not create, recover or close the vault. It also does not change or request
scopes beyond those already pinned by [the core](managed-signin.md).

From an explicitly initiated native Sign in action, call
`start(expected_account=...)`. An optional binding must be an exact previously
verified `AccountIdentity`, never a guessed email. Repeated `start` calls reuse
the same attempt and never launch a second browser or restart a finished flow.
Each coordinator is one-shot, even after a normal cancellation or bind failure.
There is no automatic retry or recovery reset. A separately initiated new
attempt still has to satisfy the vault/recovery and authorization requirements.

`start`, `cancel`, `shutdown` and `snapshot` return promptly without provider,
vault or OS-launch I/O on the calling thread. They return `SignInSnapshot`,
whose `public()` method contains only sanitized status, fixed reason codes,
listener state, `can_cancel`, cancellation intent, pending-native-operation state
and whether this attempt's workers have finished. Do not serialize the coordinator, inspect
its private fields from JS, dump native frames, or use dataclass serialization
on native request/session objects.

The host should poll snapshots on its UI timer and enable Cancel only while
`can_cancel` is true. Terminal publication and accepting Cancel use the same
lock. Once terminal publication wins, Cancel is an explicit no-op and does not
set `cancellation_requested`, even if socket cleanup is still pending. Accepted
cancellation stays pending until `attempt_finished` is true. No identity is
published while the OS-launch call or the accepted callback worker remains
outstanding. Observing the core's commit alone is insufficient: the worker must
return successfully before identity publication; a late worker failure requires
recovery without an identity. `wait_finished`
is a blocking join for a native worker or tests, never a UI-thread operation.
`shutdown` requests local cancellation; it is not permission to terminate a
process or close its vault while work is outstanding.

A finished snapshot is the last native observation, not a proof of current
backend membership or authorization. Cached identity is suppressed once its
record expiry passes. This does not claim that expiry polling deleted an OS
record. The vault must enforce expiry on every read, and the eventual native
session consumer/logout lifecycle must maintain and clean up the session.
Calling `shutdown` after successful completion does not sign out, clear browser
cookies, delete a committed vault record or revoke a provider grant.

## Exact binding and dispatch

The socket binds only the configured literal `127.0.0.1` or `::1`, exact fixed
nonprivileged port, and address family. IPv6 is explicitly `IPV6_V6ONLY`.
No wildcard, DNS hostname, alternate port, alternate address, dynamic redirect,
`SO_REUSEPORT`, `SO_REUSEADDR`, proxy forwarding or provider rerouting is used.
The socket is listening **before** the core's `begin` and before external launch.
A busy port produces `callback_bind_failed` without beginning or launching.

The path must match the configuration byte-for-byte. In Entra mode this means
the full issuer-bound path generated by `issuer_bound_loopback_redirect`, not a
friendly label or the earlier `entra-jt` proposal. The registered URI must match
that exact value; this module does not register it or select another redirect
when a port is occupied.

The listener validates the actual HTTP Host against the canonical configured
literal host and port. It then builds the callback URL from **trusted
configuration plus the bounded request query**, never an observed Host or
forwarded value. At most one received callback waits for the OS opener to settle
successfully before it can reach the core. Cancellation, expiry or failed launch
while it waits prevents token redemption entirely. State, issuer, nonce and one-use semantics remain exclusively
the core's responsibility. A wrong-state, wrong-issuer or malformed query
rejected by the core does not consume the valid waiting attempt or close its
listener. Requests arriving while one core callback is running are rejected
without being queued or retried. The core independently prevents a second
redemption if requests race.

## Bounded HTTP surface

The installed, locked `h11` 0.16 parser handles HTTP grammar. Direct package
metadata should retain `h11>=0.16,<0.17`; this is an explicit dependency, even
though uvicorn also installs it. There is no custom general-purpose HTTP
parser, request router, static-file service or URL dispatch proxy.

The surface deliberately accepts only:

- One HTTP/1.1 GET message per connection, followed by connection close
- The exact configured Host and path, and a query yielding at most 8,192 total
  callback-URL characters, matching the core's upper bound
- At most 16 KiB of complete request-line/header wire data, 48 headers,
  64 bytes per header name and 2,048 bytes per header value
- Printable ASCII header values and request targets, CRLF framing and no
  obsolete folded headers, fragment, absolute-form target or backslash

All `Content-Length` headers, including zero, and all `Transfer-Encoding`,
`Expect`, `Upgrade`, `Authorization`, `Proxy-Authorization`, `Origin`,
`Forwarded`, `X-Forwarded-*` and `X-Real-IP` headers are rejected. HTTP framing
therefore permits no request body. No body or subsequent pipelined request is
consumed or interpreted; the connection is closed. Incidental transport
read-ahead remains bounded by the stream buffer limits.
Other headers, including any ambient Cookie, confer no identity and are never
passed to the core. There is no CORS response or OPTIONS support.

The handler enforces a two-second total read deadline and bounded write/close
waits. At most eight connection handlers are admitted, with no unbounded thread
or callback queue. asyncio's bounded stream buffering and h11's incomplete-head
limit supplement the full wire-head cap. This is a short-lived local listener,
not a public server; it cannot prevent an already compromised local process
from occupying the registered port or causing local denial of service.

Every handled response uses the same tiny, fixed completion page. It tells the
person to return to the native app; it never says authentication succeeded or
reflects a callback, token, header, account, provider error or exception. It has
`Cache-Control: no-store`, restrictive `default-src 'none'`/frame/form CSP,
`Referrer-Policy: no-referrer`, nosniff and frame denial, with no script, link,
stylesheet, image or third-party asset. Invalid framing may instead result in a
closed socket. A 200 response indicates only that a bounded callback was handed
to the native core, not that its state, identity or token was accepted.

There is no access logging. Callback queries, provider errors, URLs, tokens and
native exceptions are neither logged nor reflected. The eventual host must
also disable secret-bearing crash reports, tracing and object/stack dumps.
The external browser and OS have their own history and privacy behavior; this
module cannot promise that they never retain visited authorization/callback URLs.

## Time, cancellation and uncertain outcomes

A separate event-loop timer bounds the whole listener lifetime by the configured
30–600 second authorization window, normally 180 seconds, starting at binding.
That conservative window includes startup work and never extends the core's
own monotonic deadline. It closes the listener even if native startup, launch,
status or exchange work is blocked. It also retires the core through its local
cancellation protocol. Confirmed cancellation due only to this local deadline
is reported as `expired`; uncertainty is never rewritten as expiry or success.

Cancellation closes the listener and requests the core's cancellation without
blocking UI calls. The independent callback task and fixed three-worker native
pool remain owned until they settle. A code exchange is never retried, its
future is never cancelled to hide its result, and no native worker is an
abandoned daemon. A blocked adapter can keep `native_operations_pending` true
and `attempt_finished` false; the module intentionally does not claim that a
Python thread or an unknown provider issuance can be safely killed or undone.
The approved transport must still enforce its own bounded network deadlines.

During exchange or vault I/O the core may return `cancelling`. A cancellation
accepted before public terminal publication can race a completed core commit.
A private native vault wrapper delegates the original store/delete operations
unchanged and retains only this attempt's committed opaque session ID. In that
race it deletes precisely that not-yet-published record once and requires exact
confirmed success before reporting cancellation. It reads or exposes no material,
does not broaden vault scopes, and is not a general session-deletion API. The
core is retired afterward; it is never reused with a deleted session. Failed or
malformed deletion becomes `recovery_required` without a cleanup retry.

A late response or uncertain token/vault result otherwise retains the core's
exact sanitized terminal result, including `recovery_required`. Local cleanup does not prove
provider-side revocation. Do not recover/relaunch automatically, reset the core
or claim that cancellation revoked a grant.

A failed or malformed external-launch acknowledgement sets only the fixed
`external_browser_launch_uncertain` diagnostic and requests local cancellation.
It does not assert no provider page opened. A callback awaiting launch acknowledgement
is discarded without exchange after that failure. There is no alternate browser,
command-line retry, pasted authorization URL or embedded login fallback.

## macOS external-browser adapter

The private launcher uses Apple's documented `NSWorkspace.openURL:` through
PyObjC `AppKit`, `Foundation` and `objc`. Imports occur only inside an explicit
Darwin launch call; Linux fails closed before importing native frameworks.
The reviewed Mac distribution must package compatible, pinned PyObjC Cocoa and
core releases, alongside its already required native vault dependencies.
No packages were installed or updated for this slice.

The URL must still match the pinned canonical HTTPS authorization endpoint,
contain a query, and have no fragment, control character or backslash. The
launcher uses `NSURL` and the system workspace API, not a shell, subprocess
arguments, environment-selected browser command, embedded WebView or browser
cookie access. The API is documented safe from a worker thread on supported
macOS versions. Only an exact successful BOOL is acknowledged; other results
are sanitized as uncertain.

The OS-configured default HTTPS handler must be a reviewed external browser in
the signed-Mac acceptance environment. This code does not change the handler,
choose an arbitrary application path or certify its identity. An OS
acknowledgement is not evidence of user sign-in or consent. Native acceptance
must verify actual PyObjC return types, launch behavior, privacy/logging,
background-thread behavior and callback receipt on the exact configured URI.

## Verification

Run the focused synthetic checks:

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_signin_callback.py -v
.venv/bin/ruff check src/team_browser/client/signin_callback.py tests/test_client_signin_callback.py
.venv/bin/ruff format --check src/team_browser/client/signin_callback.py tests/test_client_signin_callback.py
```

The 32 tests cover inert construction, exact binding before begin/launch,
busy-port fail-closed behavior, repeated start, malformed methods/Host/path,
forwarded identity, body-framing rejection, request/header/query caps, slow
clients and bounded concurrency, invalid callbacks preserving the attempt,
fixed no-store responses, denial, same-core account binding, replay, IPv6,
Entra's issuer-bound callback without `iss`, synthetic signature/vault success,
responsive cancellation during begin/exchange/launch, independent listener
expiry during blocked work, uncertain exchange retention, no redemption before
launch acknowledgement, cancellation of just-committed unpublished records,
uncertain cleanup without retry, honest late-cancel no-op, late callback-worker
failure after core commit, sanitized output,
expiry-safe cached snapshots and synthetic macOS-framework call contracts.
Timer tests accelerate only the synthetic event-loop delay; production bounds
remain enforced by the typed core configuration.

The complete repository suite and public-export review remain parent integration
checks. These tests do not establish any real IdP, TLS/DNS, OS browser, Keychain,
backend membership, enrollment, real-user consent or signed-app acceptance.

## Sources

- [Apple NSWorkspace](https://developer.apple.com/documentation/appkit/nsworkspace?language=objc)
- [Apple openURL / open, including worker-thread safety](https://developer.apple.com/documentation/appkit/nsworkspace/open%28_%3A%29)
- [h11 documentation](https://h11.readthedocs.io/en/stable/)
- [RFC 8252: native-app OAuth and loopback redirects](https://datatracker.ietf.org/doc/html/rfc8252)
