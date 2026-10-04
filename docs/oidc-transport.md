# Native OIDC HTTPS transport

## Delivered boundary

`team_browser.client.oidc_https.NativeOIDCHTTPSTransport` is a concrete,
standard-library implementation of the native `auth_flow.OIDCTransport`
protocol. It can issue an HTTPS request when explicitly called by reviewed
native code. Construction itself performs no DNS or network request.

This is **offline-tested implementation, not accepted live identity support**.
All verification for this change uses synthetic socket/process adapters and
synthetic, freshly signed ID tokens. No identity provider was contacted, no
account or application was registered, no credential or token was transmitted,
no browser was opened, and no membership or device access was granted.

The earlier managed-sign-in core document describes HTTP as an integration
gate. This module supplies that callable implementation; it does not remove
its real-platform/provider acceptance gate or change the core's
`native_integration_verified=False` result.

## Native-only integration

After separate review of the operator configuration and authorization of the
live identity integration, native code can construct:

```python
from team_browser.client.auth_flow import ManagedSignIn
from team_browser.client.oidc_https import NativeOIDCHTTPSTransport

# config is an already reviewed TrustedOIDCConfiguration.
# vault is a separately accepted SessionVault, not a test dictionary.
transport = NativeOIDCHTTPSTransport(config)
sign_in = ManagedSignIn(config, transport=transport, vault=vault)
```

This is an integration example, not a runnable sign-in command or instruction
to send real credentials during development. The callback listener, trusted
external browser launcher, session-vault integration, user consent, provider
registration, membership lookup and device enrollment remain separate work.
Do not use the lower-level proxy credential vault as though it implemented
`SessionVault`; the session commit, quarantine, expiry and cleanup contract is
different.

There is deliberately no web route, CLI network operation, JSON settings
loader, discovery fetcher, arbitrary HTTP method, custom header interface,
client-secret grant, refresh-token grant, configurable proxy or generic URL
bridge. Native code supplies an exact `TrustedOIDCConfiguration`; its fields
are revalidated and copied. The only network operations are:

- GET of the exact configured JWKS URL.
- POST of an authorization-code form to the exact configured token URL, with
  the exact configured client ID and redirect URI, bounded code and PKCE
  verifier, and no extra fields.

The method and full URL must match, including any explicitly configured
`:443`. Queries, credentials, fragments, IP URL hosts and other noncanonical
URLs are rejected by the core configuration validator. Additional local/special
name and ambiguous numeric-name checks apply here. Configuring a different
origin requires trusting that endpoint independently. A web page, token claim,
JWT header or provider response cannot select a destination.

## TLS and egress policy

The implementation opens one TCP socket directly to a validated numeric
address on port 443. It never reads proxy environment variables, PAC files,
netrc credentials or cookie jars. It neither follows redirects nor retries,
including address failover. No automatic connection reuse or cookie storage
occurs. A second operation, such as JWKS retrieval, has its own explicitly
allowed endpoint and a fresh validated resolution and connection.

A `PROTOCOL_TLS_CLIENT` context requires the certificate chain and configured
hostname to validate, TLS 1.2 or newer, and HTTP/1.1 (or no negotiated ALPN).
The original configured DNS hostname is used for SNI, certificate hostname
verification and HTTP Host; the numeric address is only for connection.
Verification settings are checked before connection and again before sending.
The connected peer address and port must match the selected validated address.
An invalid certificate or peer sends no HTTP request. No insecure-context
injection, custom CA parameter or certificate-error bypass exists.

Trust roots are loaded from the current Python interpreter's built-in OpenSSL
CA file/directory paths. Ambient `SSL_CERT_FILE`, `SSL_CERT_DIR` and
`SSLKEYLOGFILE` settings are not adopted. This is **not a claim of direct macOS
Keychain trust integration**. The packaged Python/OpenSSL trust distribution,
root freshness and certificate-policy behavior require target-platform review.
Missing paths fail closed; do not repair them by disabling verification.
The current platform gate accepts ordinary CPython on Darwin and Linux only,
with an absolute executable file. Frozen runtimes (including `sys.frozen` and
PyInstaller `_MEIPASS`) and other interpreter implementations fail closed. A
frozen application's `sys.executable` may be a GUI bootloader; it must never be
recursively spawned with interpreter flags. Signed/native packaging needs a
separately reviewed compatible resolver executable design. There is no PATH
search or arbitrary executable-configuration escape hatch.

The system resolver receives an absolute DNS name (a trailing dot), avoiding
search-suffix expansion. Every returned address must pass a conservative
public-unicast policy. Mixed public/private answers fail as a whole. Loopback,
private, link-local, multicast, unspecified, reserved, carrier-grade NAT,
benchmark and documentation ranges are rejected. IPv6 is limited to current
2000::/3 global unicast with additional special/documentation exclusions;
IPv4-mapped, NAT64, Teredo and 6to4 destinations are unsupported. This explicit
policy supplements Python's patch-version-dependent `ipaddress` classification.

Resolution returns at most 32 addresses. The first validated address is used
once; the socket connects to its literal numeric sockaddr, with **no second
hostname resolution at connect**. This closes the check-then-resolve rebinding
gap. DNS is not authenticated by this adapter, and TLS still must independently
validate the configured server identity. OS routing, DNS resolver configuration,
NSS plugins and network egress remain trusted platform components. This is not
an OS firewall, DNSSEC validator or defense against a compromised host.

## Deadline and resolver lifecycle

Each call accepts an integer timeout from 1 through 10 seconds. The core passes
10. One monotonic deadline starts at call entry and covers validation, resolver
startup/wait, DNS, connect, TLS handshake, request write, all response reads and
cleanup checks. Socket waits get only the remaining budget, and elapsed time is
checked after I/O. Slow-drip headers/body cannot reset the deadline. Late results
are never returned as success. Calls on one transport are nonconcurrent; another
call fails immediately rather than queuing outside the budget.

A blocking `socket.getaddrinfo` in a thread does **not** gain a deadline from
socket timeouts, cancelling a future, or cancelling an asyncio task. Therefore
DNS runs in a fixed, isolated Python helper process. It receives only the
configured public hostname over a pipe, not a URL, form, verifier or token.
Its argv is fixed trusted code, its environment is empty, its working directory
is `/`, and other file descriptors are closed. The helper emits at most 4096
bytes. Standard error is discarded; no resolver diagnostic is logged.

The helper is waited for only within the remaining budget, with 250 ms reserved
for termination/reaping. On timeout it is killed, then waited for within the
remaining reserve. There is no unbounded cleanup wait, background resolver
thread, retry loop or growing pool. A process-global nonblocking slot permits
at most one resolver at once across transport instances. If process termination
or pipe cleanup cannot be confirmed, that slot and the child handle remain
quarantined, preventing more helpers from being launched. There is no automatic
reset or recovery-by-retry path. Host supervision must reconcile that state.

The ten-second bound is an **application I/O deadline, not a hard real-time
operating-system guarantee**. Python documents that initial process creation
cannot be interrupted on many platforms. Scheduling pauses, process creation,
and abnormal kernel close/kill behavior can exceed the requested wall time.
Late startup/cleanup is detected and rejected rather than reported as success.
No claim is made that `Popen` or native DNS cancellation has been accepted on
macOS here. Shipping requires real packaged-runtime process-lifecycle and
unresponsive-resolver tests; a stricter hard deadline would require a separately
reviewed OS service/supervisor contract. Replacing this with `getaddrinfo` in a
thread plus a timeout would weaken the bounded-worker guarantee.

## Bounded HTTP response parsing

The transport intentionally implements a small HTTP/1.x response surface:

- Only status 200 is accepted. Redirects, errors, informational responses and
  protocol upgrades fail without following another location or resending.
- Headers are bounded to 16 KiB, 64 fields and 4096 bytes per line. Invalid
  names, folded lines, control/non-ASCII bytes and duplicate framing/content
  metadata are rejected. Unused metadata is discarded; cookies are ignored.
- Content type must be `application/json`, optionally UTF-8 charset. Gzip and
  other content encodings are unsupported; the request asks for identity.
- Body size is capped at 64 KiB while reading, before constructing HTTPResponse.
  Supported framing is a single Content-Length, simple HTTP/1.1 chunked, or
  clean TLS EOF. Every framing mode also requires clean TLS EOF within the same
  deadline, because the request explicitly asks for Connection: close. Conflicting
  framing, short bodies, any trailing bytes, unsupported encodings and oversized
  bodies fail closed independently of read fragmentation. Servers that ignore
  Connection: close or omit TLS close_notify are conservatively unsupported.
- Chunk extensions and trailers are deliberately unsupported. Chunk count and
  framing overhead are bounded independently of decoded size. Unclean TLS EOF
  is not treated as a complete EOF-framed body.
- Native void acknowledgements must be exactly None, resolver outputs and
  socket reads must have exact supported types, and socket peer shapes are
  validated. Truthy/falsy malformed returns do not establish success.

These conservative constraints can reject otherwise valid providers. Verify
compatibility with the explicitly chosen provider before rollout; do not
silently enable redirects, compression, richer grants or alternate URLs.
The core remains responsible for strict JSON shape, duplicate fields, signed
ID-token/nonce/issuer/audience validation and native-vault/session semantics.

## Failures and secret handling

Every I/O failure latches the transport unavailable. It cannot know whether a
failed POST already caused remote token issuance. A fixed `OIDCTransportError`
reaches the core, which marks an uncertain token POST as recovery-required and
will not redeem that authorization code again. The adapter itself makes no
retries. Reconstructing a transport/core is not an authorized reconciliation or
provider-side revocation procedure. JWKS failures after issuance still require
the core's normal token-validation failure handling; no vault write occurs.

There is no URL, header, body, code, verifier, token or raw-exception logging,
no secret file output, and no secrets in helper argv or environment. TLS key
logging is disabled. HTTPResponse's existing repr hides URL and body, and
response MIME metadata is normalized. Suppressing exception chaining does not
erase traceback frames or immutable Python objects. The native host must not
capture locals, full argument dumps, core dumps or secret-bearing crash reports.
Python does not guarantee zeroization. This module does not introduce secret
persistence or an insecure fallback.

## Verification and remaining gates

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_oidc_https.py -v
.venv/bin/python -m unittest discover -s tests -p test_client_auth_flow.py -v
.venv/bin/ruff check src/team_browser/client/oidc_https.py tests/test_client_oidc_https.py
.venv/bin/ruff format --check src/team_browser/client/oidc_https.py tests/test_client_oidc_https.py
```

Synthetic tests exercise exact endpoint/method/form restrictions, IPv4/IPv6
pinning, mixed/private/metadata destinations, TLS settings and chain failures,
proxy/keylog environment isolation, frozen-runtime refusal, status/framing/malformed I/O failures,
header/body/chunk limits, shared deadlines and slow drips, resolver termination
and unreaped-child quarantine, sanitized errors, core-issued no-retry behavior,
and successful core verification of a synthetic signed token using fake I/O.

Still unverified: actual TLS handshakes and trust-chain behavior, real DNS/helper
process cancellation and packaging, macOS behavior, live IdP interoperability,
any user account, callback/browser/vault composition, membership or enrollment.
No test count should be interpreted as acceptance of those separate gates.
The module and tests also need inclusion in the explicit public-client source
export manifest by the repository owner; this change does not edit that manifest.

## Primary references

- [Python subprocess lifecycle and timeout caveats](https://docs.python.org/3/library/subprocess.html)
- [Python TLS contexts, verification and key logging](https://docs.python.org/3/library/ssl.html)
- [Python socket timeouts and getaddrinfo](https://docs.python.org/3/library/socket.html)
- [Python IP address classification](https://docs.python.org/3/library/ipaddress.html)
