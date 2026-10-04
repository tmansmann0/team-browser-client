# Managed sign-in: native public-client core

## Delivered scope

`team_browser.client.auth_flow` implements an Authorization Code + PKCE S256
state machine for a desktop public client. It is public-client code and does
not import or distribute private `api` or `demo` modules. It requires the
existing `PyJWT[crypto]>=2.10,<3` dependency in the public-client distribution.

This is a tested core, **not a live identity integration**. No provider was
registered, no real authentication took place, no live token was generated or
stored, and no company membership or device grant was created. Unit tests use
reserved `.test` endpoints or synthetic Entra tenant/client GUIDs with fake
in-memory transports/vaults and fresh ephemeral test signing keys. No tests in
the provider-contract suite perform network I/O. Fake adapters belong only in tests.

The core module supplies no callback listener, OS-browser launcher, production
configuration, refresh mechanism, backend membership client, enrollment client
or logout/revocation client. Separately implemented native HTTPS and macOS
SessionVault adapters have their own review and target-platform acceptance
gates; see [HTTPS transport](oidc-transport.md) and [SessionVault](session-vault.md).
**The current concrete SessionVault accepts only `("openid",)` and must receive
matching, explicitly reviewed scope-policy wiring before Entra activation.**
The new core does not silently downcast Entra material to openid, weaken the
vault, or claim the combined integration works. These are explicit integration
and approval gates, not inferred capabilities.

## Security boundaries

- `TrustedOIDCConfiguration` is constructed by trusted native/operator code. Do
  not deserialize browser/JS settings, a company-provided URL, token claims or
  remote discovery directly into it. The issuer, authorization endpoint, token
  endpoint and JWKS endpoint are individually trusted canonical HTTPS DNS URLs.
  Cross-origin endpoints are allowed only because each is explicitly configured.
  Credentials, queries, fragments, encoded/dot path traversal, localhost/IP
  endpoints and nonstandard TLS ports are rejected. No token header may choose
  a key URL or embed a key.
- The callback is an exact fixed HTTP URL on `127.0.0.1` or `[::1]`, with an
  explicit nonprivileged port and path. Host aliases, wildcard binds, dynamic
  redirects and user-selected callback destinations are unsupported. A native
  listener must bind that literal interface and port **before** browser launch;
  failure to bind means fail closed, never choose another destination. Register
  that exact redirect URI with the separately approved provider.
- The legacy default supports only `openid`. A typed `EntraNativePolicy`
  permits exactly `openid profile api://API_CLIENT_ID/access_as_user`, tied to
  one explicit custom API GUID and exact single-tenant Microsoft endpoints.
  `email`, Graph, Gmail, mailbox permissions, `.default`, application permissions
  and `offline_access` are unsupported. Request scopes are a set and can be
  ordered differently, but must have no duplicates or additions. No scope is
  supplied by JS or accepted from a callback. An unsolicited refresh token,
  including an empty or null value, is rejected. Persistent refresh, added
  scopes or another provider flow require separate approval, work and review.
- Native code opens the provider authorization URL in an external system browser.
  There is no embedded OAuth/Gmail iframe, WebView password capture, imported
  browser cookie jar or Gmail API integration.
- `AuthorizationRequest.authorization_url` is native-only and suppressed from
  repr. It contains state, nonce and PKCE challenge but no verifier or tokens.
  Do not serialize it to a web bridge, logs or files. Only `AuthResult.public()`
  and `AuthCapabilities` are intended for UI presentation. Tokens, verifier,
  token response, callback query and vault session references stay native.
- The OS vault is mandatory even for short-lived material. Failure never selects
  a plaintext file, environment variable or in-memory production fallback. The
  injectable fake vault is only a test fixture, not a production option.

## Native integration contract

1. Load reviewed operator configuration and vetted `OIDCTransport` and
   `SessionVault` adapters into `ManagedSignIn`. Default construction is explicitly
   unconfigured and cannot start authentication. `capabilities().can_begin`
   means a configured core can attempt a flow, not that an actual platform or
   provider has passed acceptance. `native_integration_verified` stays false in
   this core.
2. Establish the exact loopback listener. It must accept only the expected GET
   callback, validate the actual Host/target, avoid proxy-forwarded headers, and
   enforce request/body/query size limits. Do not assemble the callback URL from
   an untrusted Host header. No access logging of callback URLs or query strings.
   Send only a fixed completion page with `Cache-Control: no-store`, restrictive
   CSP and no third-party resources, and close the listener when finished.
3. Call `begin(expected_account=...)` from a trusted user-initiated native action.
   The optional account binding is an exact previously verified issuer/subject,
   never a guessed email/domain or a claim of company membership. The default
   prompts account selection. Do not repeatedly launch when a flow is pending.
4. Open the returned URL with the trusted external-browser launcher. State,
   nonce and verifier each use 256 bits of entropy. Only the S256 challenge is
   transmitted to the authorization endpoint. A public client has no embedded
   client secret. The default authorization window is 180 seconds and uses a
   monotonic clock; the configurable maximum is ten minutes.
5. Pass the observed fixed callback URL to `complete_callback`. Operator
   configuration selects `AuthorizationResponseIssuer.RFC9207_REQUIRED` (the
   legacy default) or `ISSUER_BOUND_REDIRECT` before the flow starts. The former
   requires the exact `iss` on success and error responses. The latter requires
   the mechanically issuer-bound callback described below and permits missing
   `iss`; any present `iss` must still be exact and nonempty. There is no
   callback-driven autodetection, retry downgrade or discovered-provider switch.
   Duplicate critical fields, code/error mixtures and wrong redirect/state/issuer
   fail closed. The Entra policy ignores bounded harmless extensions; the legacy
   default retains its closed field list. Invalid callbacks do not consume a
   legitimate waiting attempt. A valid callback consumes state atomically before
   exchanging anything, including a provider denial. Replays and simultaneous
   callbacks cannot redeem twice.
6. `OIDCTransport.post_form` receives the code, verifier, exact redirect URI and
   public client ID. The adapter must enforce certificate verification, explicit
   destination/DNS egress policy, ten-second timeouts, a 64-KiB response cap while
   reading, no ambient proxy credentials, no automatic retries, and
   `follow_redirects=False`. GET of the configured JWKS endpoint has the same
   transport requirements. The core checks exact final response URL,
   `redirected=False`, status, JSON MIME/type/size and duplicate JSON fields.
   Adapter attestation alone cannot prove TLS, DNS or logging behavior; review
   and real-platform acceptance are required. Never repair a certificate or
   destination failure by weakening TLS or following a redirect.
7. The core verifies ID-token signatures with PyJWT/cryptography and explicitly
   allowed RS256 (RSA >=2048 bits) or ES256 (P-256). It requires an unambiguous
   configured-endpoint key ID, signing purpose/key operations, no private key
   material, exact issuer, a single exact string audience, exact nonce, valid
   subject, strict integer timestamps and bounded provider lifetime. Expired
   ID tokens are rejected even within clock skew; future `iat` and `nbf` have
   at most the configured 0–60-second skew. If present, `nbf` must precede `exp`.
   The legacy default retains its recent-issue check. The nonce-bound Entra code
   flow permits `iat` earlier than the local attempt, while still validating
   signature, nonce, audience, issuer, expiry and maximum `exp - iat`. This does
   not prove recent credential entry; a separate fresh-user-authentication
   requirement would need an explicit policy. Multi-audience tokens are
   conservatively unsupported. If `azp` or `at_hash`
   are supplied, they must match the client or returned access token. Provider
   token roles, organization IDs and emails confer no authorization here.
8. Only verified material enters `SessionVault.store_session`, under an opaque
   native session key, carrying the exact configured scope tuple. Legacy
   provider defaults remain at most ten minutes for ID-token lifetime and one
   hour for access-token response lifetime. The Entra builder selects one hour
   for ID tokens and 90 minutes for access-token `expires_in`, accommodating
   documented normal provider lifetimes. Independently, local usable-session
   TTL defaults to ten minutes and can be shortened to 30–600 seconds. Record
   expiry is the minimum of ID-token `exp`, response receipt plus `expires_in`,
   and response receipt plus local TTL. Fetching keys or storing the record
   never extends it. The access token is opaque to this native core; the
   resource API verifies its signature and access-token claims independently.
   The vault must enforce record expiry on every read, not wait for UI polling.
   The core removes expired records when status is polled.
9. Send only `result.public()` to presentation code. `identity_verified` means
   the provider identity was verified and a short-lived native record committed.
   `company_membership_verified`, `device_enrolled` and
   `managed_access_available` remain false in every public result.

The implemented [native managed session](managed-session.md) exposes only fixed
backend reads, and the [host](managed-host.md) composes sign-in and scoped local
logout. Neither exposes a generic “get token” bridge to JS. Nothing in this core
grants a web page arbitrary vault or network access.

## Reviewed Entra native configuration

Construct configuration only in trusted native/operator code, using approved
registration IDs. The following GUIDs are synthetic examples, not registrations:

```python
from team_browser.client.auth_flow import entra_native_configuration

config = entra_native_configuration(
    tenant_id="11111111-1111-4111-8111-111111111111",
    desktop_client_id="22222222-2222-4222-8222-222222222222",
    api_client_id="33333333-3333-4333-8333-333333333333",
    loopback_port=43821,
    local_session_ttl_seconds=600,
)
```

This builder performs no I/O, registration, login, consent or credential work.
It pins public-cloud Microsoft authority and JWKS paths to the exact canonical
single-tenant GUID, uses a distinct public desktop-client GUID, selects RS256,
and permits exactly the three approved scopes. `common`, `organizations`, other
clouds, arbitrary discovery, alternate endpoints, Graph's resource GUID and a
shared API/desktop client ID are rejected. Additional tenants, sovereign clouds,
providers or resource scopes require explicit review rather than relaxed parsing.

### Mechanically bound redirect

The exact callback is generated by `issuer_bound_loopback_redirect`:

`http://127.0.0.1:43821/auth/callback/issuer/<64 lowercase hex characters>`

The suffix is the complete SHA-256 of the exact ASCII issuer URL, without
normalization. Distinct issuer URLs receive distinct paths (subject to SHA-256
collision resistance). A configuration in distinct-redirect mode must match
this function byte-for-byte; an operator boolean, arbitrary friendly path or a
callback hash belonging to another tenant is insufficient. The fixed port can
be changed by the operator before registration, but not dynamically during a
flow. Generic RFC 9207 mode continues to allow its existing exact loopback form.

This shape supersedes the earlier `/auth/callback/entra-jt` proposal. Before any
registration, generate the exact value from the approved issuer and port and
review/register that value. Microsoft's literal `127.0.0.1` HTTP registration
requires its documented manifest route. The host must route only the exact
path to this pinned issuer's flow and never register/reuse it for another issuer,
proxy it to another provider, or select a provider from untrusted callback data.
The redirect, issuer, client, endpoints, state and nonce remain fixed for an
attempt. The native listener must bind before external-browser launch.

The builder explicitly selects the distinct-URI mix-up defense because the
reviewed Entra contract does not promise RFC 9207 `iss`. This does not assert
that Entra can never return `iss`. If it does, both success and error callbacks
must carry the exact pinned issuer. A reviewed provider that promises RFC 9207
should continue to use the required-issuer mode.

### Token-response scope normalization

For Entra, `scope` must be an explicit bounded RFC 6749 space-delimited scope
string. Treat it as a case-sensitive set; order and duplicate entries do not
change the grant. Require the one exact qualified
`api://API_CLIENT_ID/access_as_user` scope. Permit only the requested `openid`
and `profile` aliases alongside it; those OIDC aliases may be omitted from the
access-token scope listing. A valid signed nonce-bound ID token is still
mandatory. An absent `scope` field is rejected for this resource-bearing policy,
while the legacy openid-only mode keeps its established omission behavior.

No bare `access_as_user`, other resource GUID, Graph shorthand, extra OIDC scope,
`.default`, mailbox permission or offline scope is normalized into approval.
The bare `access_as_user` value expected in the API JWT's `scp` claim is a
separate resource-verifier contract, not an alias accepted in this OAuth response.
`NativeSessionMaterial.scopes` retains the configured requested set and does not
purport to be an authorization decision. The API must independently verify the
intended resource audience, tenant, delegated scope and authorized client.
Any additional response spelling discovered during approved live acceptance
must first receive a narrowly reviewed normalization rule.

### Callback extensions

Entra mode accepts at most 32 query pairs and 8,192 raw URL characters, with
ASCII extension names of 1–64 characters and decoded extension values of at
most 2,048 characters (code remains capped at 4,096). Control characters,
malformed encoding, malformed query syntax and oversized data are rejected.
Extensions such as `session_state`, `client_info` or callback `scope` are ignored;
they do not select an account, add a permission, change a redirect or enter the
public result. Unknown extension values, including URLs, are never followed.

`state`, `code`, `iss`, `error`, `error_description` and `error_uri` must not be
duplicated. Code cannot coexist with error metadata. Implicit/hybrid token
fields, refresh tokens, client secrets, verifier fields and a wrapped `response`
are rejected. Error descriptions/URIs are bounded, ignored and never reflected.
Duplicate harmless extension names may be ignored, since none affect security
or flow behavior. The legacy mode retains its existing strict unknown-field
rejection rather than silently changing an already-tested provider contract.

### Activation gates

This is synthetic-tested core compatibility, not evidence of live-provider
acceptance. In addition to app-registration and grant approval, integration
requires matching explicit scope wiring in the currently openid-only concrete
SessionVault, an exact loopback listener, a trusted system-browser launcher,
the signed native host and target-platform acceptance, control-plane membership
checks, and clear local logout behavior. Do not change the material's scopes to
`("openid",)` just to pass existing vault checks. No real-user authentication or
refresh grant is authorized by constructing this configuration.

## Membership and enrollment are separate

After explicit future integration, the private backend's `/v1/me` must establish
current company membership, role, disable state and any policy. Selecting a
company URL, signing into an email domain, or passing ID-token validation is not
membership. Backend policy must enforce tenant isolation on every operation.

An `openid` access token is **not automatically a valid control-plane bearer**.
The private API must independently verify its intended audience and scopes, and
any separately approved backend session exchange must enforce that contract.
Never send an ID token to the backend as an access-token substitute or loosen
backend audience checks to make a login work.

Device enrollment requires a separate approved device-bound grant and proof of
possession. This core cannot auto-enroll, create device keys, approve devices,
provision members, issue backend tokens or enable remote commands.

## Cancellation, errors and uncertain outcomes

- `cancel()` cancels a pending attempt. A waiting flow ends immediately. During
  network or vault I/O it returns `cancelling`, so the UI remains responsive,
  but must wait for the terminal result before declaring cleanup complete.
- A late token response after cancellation or expiry is discarded without
  vault storage. If cancellation/expiry races a vault commit, the new record
  must be deleted and its absence confirmed before reporting completion.
- `wrong_account` returns no identity/token and writes no vault material.
  `consent_denied` consumes the attempt without a token request. Provider text,
  error descriptions, JWT exceptions and adapter diagnostics are not reflected
  into results or logs.
- A timeout, redirect, error status, malformed/untrusted token response or
  uncertain vault cleanup produces `recovery_required`. No automatic POST
  retry, fresh authorization or reset is available on that core instance.
  Unknown remote token issuance cannot be claimed undone. Provider-side cleanup
  or revocation, if needed, is separate authorized work.
- A failed vault write triggers deletion of that session. Confirmed cleanup
  returns an error without an identity; unconfirmed cleanup requires recovery.
  Every vault health/write/delete operation must return exactly `None` on
  success. `False`, `True` or any other malformed acknowledgement requires
  recovery, even if a subsequent single cleanup attempt reports success.
  Cleanup is never automatically retried or treated as confirmed by truthiness.
  Production vault adapters must persist an operation/quarantine marker before
  writes and reconcile it before making any record available after a crash or
  restart. Killing/restarting the process is not a valid recovery procedure.
- `cancel()` is deliberately not sign-out. It does not clear an already verified
  identity, browser provider cookies, company membership or a device grant.
  A real sign-out/revocation UX remains a separate integration gate.
- Python does not guarantee zeroization of immutable strings. Adapter and host
  logging/crash-reporting must avoid secret dumps; OS isolation, vault policy and
  short expiry remain necessary. Repr suppression is not a general serialization
  guard: never apply `dataclasses.asdict` to native secret-bearing objects.

## Verification

Run the synthetic unit suite:

```sh
.venv/bin/python -m unittest discover -s tests -p test_client_auth_flow.py -v
.venv/bin/python -m unittest discover -s tests -p test_client_provider_signin.py -v
.venv/bin/python -m unittest discover -s tests -p test_independent_signin.py -v
.venv/bin/ruff check src/team_browser/client/auth_flow.py tests/test_client_auth_flow.py tests/test_client_provider_signin.py
```

Coverage includes public configuration boundaries, minimal scopes, exact callback,
PKCE, entropy separation, required issuer response, required signed claims,
RS256/ES256, tampered/weak/ambiguous keys, token-supplied key URLs, time limits,
wrong account, nonce reuse, simultaneous replay, concurrent cancellation,
expired commit, denied consent, no-redirect transport, sanitized failures,
partial/uncertain vault operations and token-free UI results. Provider tests add
issuer-bound missing-issuer callbacks, cross-issuer redirects, qualified API
scope normalization and expansion rejection, normal provider lifetimes with
shorter app TTL, ignored bounded extensions, denial, cancellation and replay.
The original 55 core tests and 14 independent sign-in tests remain unchanged.
The intentional broader behavior is behind reviewed typed provider settings;
local expiry now also has an independent ten-minute ceiling. Tests do not validate
any real IdP, TLS adapter, OS vault, loopback listener, external browser,
backend membership or device enrollment.

## Standards consulted

- [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- [OpenID Connect Core ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/stable/api.html)

- [RFC 9207: OAuth authorization-server issuer identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 6749 §3.3: access-token scope](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)
- [RFC 9700 §4.4.2: distinct redirect mix-up defense](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4.2)
- [Microsoft authorization-code flow and response](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft redirect URI restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Microsoft ID-token lifetime](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens)
- [Microsoft access-token lifetime](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Microsoft exposing custom API scopes](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-protected-web-api-expose-scopes)
