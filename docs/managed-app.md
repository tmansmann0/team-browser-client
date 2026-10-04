# Native managed application integration

The local application's Managed choice now uses the native host bridge when it is served by the local workspace API. It does not fall through to invented managed records. The older synthetic preview remains available only as the separate explicit demonstration path.

## Delivered composition

- A trusted native launcher can construct `NativeManagedHost` from the same reviewed `TrustedOIDCConfiguration`, `TrustedBackendConfiguration`, and `KeychainConfiguration`, then pass it as `managed_host` to `create_local_app`.
- The host owns real transport, callback, vault and managed-session implementations. No web input can select a provider, backend, scope, keychain namespace or arbitrary native adapter.
- The app exposes fixed same-origin loopback endpoints: `GET /local/v1/managed-native` for sanitized status and `POST /local/v1/managed-native/actions` for an argument-free action enum. Existing Host, loopback-peer, Origin, JSON and CSRF checks apply.
- Preparing/recovering native storage and starting sign-in are explicit actions. Sign-in opens the configured provider in the external system browser. Only verified identity followed by successful backend membership verification enables the read-only team view.
- An explicit refresh loads current assigned profiles and presets. An unrequested collection is not shown as an empty server result. Managed browser launch remains disabled until device enrollment and verified proxy/runtime setup are integrated.
- UI request generations discard old responses after a newer sign-out intent. Sign-out hides displayed identity and records immediately; uncertain completion stays hidden until the native outcome is confirmed. No automatic request retry occurs.
- Local account-free profiles continue working without managed configuration. The default CLI currently supplies no managed host; production identity registrations, approved configuration and signed native launcher packaging must be completed before enabling this path.

The public bridge contains no token getter, auth URL, vault reference, browser cookie or credential input. Saved legacy server-label metadata is not configuration and cannot activate a connection.

## Server tenant binding

The initial `/v1/me` discovers the explicitly enabled product membership. Subsequent native requests send `X-TBM-Organization` with that exact product organization ID. The API checks the bounded, single header against the request's enabled database member before running the handler. A mismatch returns 409, and the native session becomes unavailable instead of silently changing company. This header is a consistency fence, never authorization or a way to choose another company. Older clients without it still receive only their own current database scope.

## Verification scope

The new bridge, UI-state and host tests use synthetic data. Native host composition tests use real ephemeral signed claims and disposable callback sockets with mocked provider/OS seams. Mixed-repository tests exercise the native core/vault/consumer against the real private API handlers and SQLite, including revocation, changed-company rejection, scoped records and local logout. That mixed integration test is excluded from both isolated source exports.

Actual rendered local-browser testing, macOS Keychain/browser acceptance, provider grants, device setup and a deployed authenticated backend remain separate gates. The public sales-site browser checks and video do not establish these results.
