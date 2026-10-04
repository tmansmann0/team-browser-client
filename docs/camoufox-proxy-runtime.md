# Camoufox and HTTPS-proxy runtime slice

## What is implemented and what remains gated

`client/camoufox_runtime.py` now contains a callable `CamoufoxAdapter`,
`CamoufoxSupervisor`, persistent-context handle, exact native-acceptance checks,
profile identity binding, and continuous route-observation handling.
`client/proxy_relay.py` contains a real bounded asyncio loopback SOCKS5 CONNECT
relay to one HTTPS CONNECT proxy. It is not a simulated provider allocator.

Ordinary startup remains disabled. No real native acceptance record, vendor
signature policy, official-distribution metadata observer, accepted native secret
store integration or real browser-context leak probe ships in this change. The CLI does not deserialize a `trusted: true` flag or accept these
objects through the browser API. A trusted integration can call this adapter;
it does not end with an unconditional “not implemented” exception.

All verification here uses fake browser contexts, synthetic runtime files, and
local TLS/socket fixtures. No browser binary was downloaded or executed. No
provider was contacted, no live account/credential/cookie was used, no OS
firewall/network/security setting was changed, and no Linux browser/file-policy
restriction was retried or bypassed. Real Camoufox behavior is **unverified**.

## Source review and supported launcher interface

The PyPI release inspected on October 3, 2026 was **camoufox 0.5.6**. Its metadata
allows `playwright<1.63`; this implementation additionally requires the existing
reviewed **playwright 1.62.0** pin. A later launcher or driver version needs review
and updated native acceptance. This is a compatibility pin, not a claim that the
latest browser engine is accepted or safe.

- [Official PyPI version metadata](https://pypi.org/pypi/camoufox/0.5.6/json)
- [Official Camoufox usage](https://camoufox.com/python/usage/)
- [Official async launcher source](https://github.com/daijro/camoufox/blob/main/pythonlib/camoufox/async_api.py)
- [Official launch-option builder](https://github.com/daijro/camoufox/blob/main/pythonlib/camoufox/utils.py)
- [Playwright 1.62 Firefox process arguments](https://github.com/microsoft/playwright/blob/v1.62.0/packages/playwright-core/src/server/firefox/firefox.ts)

The official wheel was read as ZIP data for source inspection, without importing
or running it. Its SHA-256 was
`b906836cd952376a466f0e55445f139b8a65adfb9f18ab55cb2cd0c727b11561`.
The inspected wheel's `camoufox/async_api.py` SHA-256 was
`3a1091a65a347db49899ad0337b578720dde2ea6d5e07b98dd782acbe91869b7`.
The mutable `main` branch above can differ from that wheel. These source-review
identifiers are not independent publisher-authenticity or complete dependency
supply-chain evidence. Installation/deployment must review the whole pinned
launcher/driver/dependency environment and signed browser distribution.

The call is `AsyncNewBrowser(playwright, from_options=options,
persistent_context=True)`. `from_options` is nonempty and fully built by this
application, so the SDK does not run its `launch_options()` generator. In the
reviewed wheel that generator otherwise performs random identity generation,
addon handling, runtime discovery, and optional geo-IP work. This path invokes
none of those helpers. It does not run `camoufox fetch`, `playwright install`,
upstream shell scripts, or SDK browser-selection commands.

The launcher is imported lazily after runtime/acceptance/version checks. The
browser executable path and persistent directory are explicit. Browser debug
TCP ports, external control servers, arbitrary arguments, addons, custom
scripts, and user-provided navigation URLs are not exposed. The reviewed
Playwright Firefox default process arguments provide profile ownership and the
Juggler process pipe. Native acceptance must separately inspect the chosen
engine's built-in preferences, sandbox, security features and update behavior;
this module does not certify upstream defaults simply by using the API.

## Fresh observed engine metadata

`CamoufoxAdapter` requires a trusted `metadata_observer(executable)` returning
`CamoufoxRuntimeMetadata(version, source_path, source_identity, source_sha256)`.
The source path is absolute; identity is the bounded file observation tuple
`(device, inode, size, mtime_ns, ctime_ns)`, and the hash binds exact metadata
bytes. The record validates structure but is not publisher authenticity.
A trusted observer must use bounded no-symlink reads, check unchanged file
identity/content during its read, and verify the exact selected distribution's
engine/build-version mapping. This module deliberately supplies **no default
observer** and does not guess an official macOS package layout.

The old constructor `observed_version` string, if supplied, is only an additional
assertion to compare against fresh metadata. It cannot enable execution without
an observer. Metadata is freshly read before and after runtime signature/hash
admission; the exact evidence is carried into approval, checked at start, and
re-observed around binary hashing immediately before and after native startup.
Mutation of metadata alone, unchanged version with changed source bytes, a
source replacement, a mismatched version, missing observer or observation error
fails closed. Tests use explicitly synthetic inventory files and observers.

The SDK's cached `version.json` is installer/release metadata and must not be
promoted into publisher-authenticity evidence. The current SDK also inspects
`Version=` in `application.ini` for its executable-specific version path. Neither
behavior establishes a trusted distribution mapping by itself. An eventual
observer needs independently reviewed source selection and signed-bundle /
approved-release evidence, without executing an unknown binary or downloading
an engine. See [official package metadata handling](https://github.com/daijro/camoufox/blob/main/pythonlib/camoufox/pkgman.py)
and [official executable-version resolution](https://github.com/daijro/camoufox/blob/main/pythonlib/camoufox/utils.py).

Ordinary Camoufox runtime CLI integration remains unavailable until that actual
distribution mapping and native acceptance are verified.

## Persistent profiles and deterministic settings

`CamoufoxProfilePolicy` is trusted local configuration with:

- exact profile ID and preset ID plus a deterministic binding of stable
  profile ID/engine/preset/network-policy/origin fields
- explicit language-region locale and IANA timezone
- exact proxy-configuration fingerprint, or no proxy for explicit local-direct

The code emits a deterministic bounded Camoufox environment configuration for
locale/languages and timezone, and passes the matching Playwright context
options. It does not rotate or generate a fingerprint on restart. This slice
uses the installed engine's native identity plus those explicit settings; it
does not promise that all engine internals are invariant or offer a richer
fingerprint preset. Verify the actual language/timezone behavior on the exact
accepted build. Proxy geography is not guessed or queried automatically: the
trusted profile/route policy must explicitly choose and accept a consistent
locale/timezone/exit location.

The adapter requires the active matching `ProfileStore` lease and only accepts
that profile's private application-owned `browser-data` path. On first use the
directory must be empty. A private `.camoufox-identity.json` marker outside the
browser-data directory binds the engine/profile/preset and configuration hash.
Later launches require an exact marker match. A preexisting unmarked directory,
foreign engine directory, changed identity, unsafe marker permissions, hard
link, or symlink is rejected. This does not import a user's existing browser.
Identity migration/reset is a separate explicit workflow, not an automatic
clear or conversion of website sessions. Chromium integration must also refuse
Camoufox-marked directories when a user changes presets.

Name, favorite, selection and lifecycle-only metadata revisions do not alter
that stable binding or require another identity review. The coordinator still
uses the complete optimistic metadata revision to fence concurrent actions.
Engine/preset/network-policy/origin changes require a matching trusted binding;
locale/timezone changes still conflict with the persistent identity marker.
The provider must not treat browser/API JSON as acceptance. This slice does not
add a metadata editor or silently relax the identity/route checks.

`about:blank` and the fixed Gmail inbox intent are the only initial navigation
choices. Inbox focus/navigation uses this same owned persistent context. There
is no Gmail API access, account verification, cookie transfer, merging of
accounts, or claim that different tabs represent verified different accounts.

## Proxy relay behavior

Each managed profile gets its own fresh `127.0.0.1` listener on an OS-selected
port. It accepts SOCKS5 CONNECT only; UDP ASSOCIATE, BIND and target ports other
than 80/443 are rejected. Explicit nonpublic IP targets and obvious local domain
names are rejected. Ambiguous legacy numeric IPv4 forms such as `127.1`,
`0177.0.0.1`, and `0x7f.0.0.1` are rejected without DNS, rather than handed to an
upstream resolver that might interpret them as loopback. Other domain names are transmitted in HTTPS CONNECT
requests without local target resolution. Only the configured upstream proxy
hostname is resolved locally. A provider can resolve a public-looking name to a
private address remotely; the relay cannot establish remote DNS policy by
performing a local lookup without leaking that lookup.

The upstream must be `https`, with TLS 1.2 or newer, certificate-chain validation
and hostname verification. The default context uses the interpreter's OS/OpenSSL
trust paths without environment-selected CA overrides or SSLKEYLOGFILE. Injected
contexts are rejected if key logging is configured, including after mutation.
There is no insecure TLS flag, plaintext credentialed
upstream fallback, alternate provider, direct target socket, or inherited proxy
environment. Upstream failures never retry directly. A provider must actually
support CONNECT for both required web ports; providers offering only HTTP or
SOCKS endpoints are not accepted by this implementation.

Credentials are retrieved from `SecretStore` only after authenticating the
upstream TLS peer. The reference points to bounded UTF-8 `username:password`
bytes; the value is used transiently for a Basic proxy-authentication header.
It never appears in a browser option, command line, environment, profile file,
API response, exception message or diagnostic log. The store must be a reviewed
OS-native implementation, with no plaintext fallback. The mere presence of a
Keychain class does not satisfy actual platform health and acceptance checks. Python immutable
bytes cannot be reliably zeroized; the implementation minimizes their lifetime
without claiming guaranteed erasure. The provider necessarily receives the
credentials inside its authenticated TLS connection.

Default resource limits: 32 concurrent connections, 16 KiB chunks, 10-second
handshake limit, 60-second tunnel-idle limit, bounded 8 KiB upstream headers, and
bounded shutdown. The idle clock is shared across both directions: a live
one-way download/stream remains active even when the other peer is quiet. Write
backpressure also has a separate bounded drain wait. Invalid local client requests and normal EOF/idle expiry close
only the affected tunnel. Failed upstream negotiation or tunnel I/O trips a
sticky failure latch: abort all active tunnels, close the listener, and request
owned browser shutdown. A failed relay cannot restart. Failure diagnostics are
fixed and do not include provider responses or credentials. Limits are bounded
at construction. Local client I/O errors can conservatively stop the whole
profile, which is an availability tradeoff.

### Startup diagnostic quarantine

`CamoufoxProxyRoute.diagnostic_targets` is a required trusted tuple of 1–8 exact
`(host, port)` pairs. It is never populated from browser/API input. Targets are
validated using the same public-address/domain/port restrictions; comparison is
case-insensitive and exact, with no wildcard/subdomain/port expansion. The
controlled diagnostic servers must not themselves act as open proxies.

A managed relay starts quarantined before native launch. Only its configured
diagnostic destinations can be tunneled. Restored-tab, background or other
non-diagnostic requests receive a bounded SOCKS refusal and close; they are not
queued for later release and do not trip an upstream-failure latch. Quarantine
is snapshotted when a TCP client is accepted, so delaying part of its handshake
until after release does not widen that connection's authority.

Trusted current route authority is checked again immediately before native
spawn, after potentially slow driver setup. The exact-context startup proof
checks authority both before and after collection. After the last awaited
check, evidence expiry and relay health are checked again. Only then can the
owner synchronously release quarantine and admit new general web connections.
Failed proof, revoked assignment or expired evidence leaves quarantine closed
and requests acknowledged browser shutdown.

This limits traffic **through this relay**. It does not prove that the actual
engine uses the relay for every background channel or prevent an engine/OS
component from bypassing it. Native leak/failure acceptance remains required.

### The local-process boundary is explicit

The local SOCKS listener has **no per-user or per-process authentication**.
Binding to `127.0.0.1` only limits network reachability; any local process able to
reach that host's loopback can use a live relay. No unsupported Firefox SOCKS
password is presented as protection. Managed acceptance therefore requires an
explicit trusted-single-user-host decision. This is inappropriate for a hostile
multi-user/shared host; that environment needs a separately reviewed isolation
or authenticated browser-facing proxy design. Existing same-user filesystem
and process-tampering limitations remain.

## Gecko route preferences are defense in depth

The fixed route-preference set selects manual SOCKS5 to the local relay, remote
SOCKS DNS, empty bypass/PAC lists, proxying of localhost requests, disabled direct
failover/channel bypass, disabled speculative DNS/prefetch/predictor connections,
disabled DoH, WebRTC peer connections and HTTP/3. Managed startup is also set to
a blank page with normal/crash/session-once restore disabled as defense in depth;
these keys are part of the acceptance preference digest. IPv6 DNS lookups are disabled;
a public IPv6 literal can still be tunneled through the relay, so this is not a
claim that all IPv6 is globally disabled.

The preferences are based on real Gecko implementation/source, including:

- [Gecko current proxy preferences and build-conditional failover/bypass behavior](https://github.com/mozilla-firefox/firefox/blob/main/modules/libpref/init/StaticPrefList.yaml)
- [Gecko proxy selection implementation](https://searchfox.org/firefox-main/source/netwerk/base/nsProtocolProxyService.cpp)
- [Gecko DNS prefetch implementation](https://searchfox.org/firefox-main/source/netwerk/dns/DNSServiceBase.cpp)
- [Gecko session restoration decisions](https://searchfox.org/mozilla-central/source/browser/components/sessionstore/SessionStore.sys.mjs)

A preference name's existence in current Gecko does not prove a chosen Camoufox
release honors it. Some behavior is build-conditional. Neither preferences nor
a Python relay provide an OS-wide egress boundary: engine background services,
plugins/native components, custom protocols, future regressions, a malicious
extension/user/local process, and direct sockets outside the browser's proxy
stack remain potential gaps. No OS firewall/security setting is altered.

For that reason proxy-required real launches require exact engine/hash/version,
platform, launcher/driver and preference-set acceptance plus a trusted
single-user-host decision. They also require a trusted probe of the **actual
owned browser context**. It must satisfy the existing profile/runtime/proxy-bound
`validate_proxy_preflight` checks for exit networks, direct baseline, DNS,
WebRTC/UDP, IPv6, TLS and failure fallback. An HTTP IP-echo test is insufficient.

The first context probe runs during diagnostic quarantine, before reporting
ready or opening Gmail. The adapter requests a blank startup page; it does not
infer that this alone suppresses every restored/background request. It is bounded to five seconds. Follow-up
probes complete before prior evidence expires. Each observation rechecks the
trusted current profile/route assignment and native-acceptance validity;
revocation or changed assignment closes the route on the next bounded check.
Stale, mismatched, failed or missing evidence stops the relay and requests browser close. The probe is a
trusted injected interface with no fabricated production implementation here.
Outage/leak acceptance should use controlled test profiles; routine observations
must not destructively disrupt a user's in-progress page. A disconnected browser
context immediately closes its route but retains uncertain process ownership.
Before acknowledging shutdown, the handle uses the pinned Playwright public
`is_closed()` API. An already-closing/closed context can make `close()` a no-op,
so it retains unknown ownership rather than treating that no-op as process-exit
proof. See [the pinned Playwright close implementation](https://github.com/microsoft/playwright-python/blob/v1.62.0/playwright/_impl/_browser_context.py).

There is still a detection interval, and no claim of protection against engine
traffic that ignores the application proxy settings. Managed rollout remains
gated until actual acceptance establishes the supported threat model, including
whether application controls are sufficient on the proposed host.

## Feasible pilot and team-release approval paths

The secure default requires independently verified runtime provenance and native
acceptance. Missing upstream notarization evidence is an unresolved deployment
choice, not a claim that Camoufox can never be used.

1. **Team release:** select a reviewed complete upstream distribution, preserve
   its license/source obligations, and distribute through a properly signed and
   notarized package with controlled updates. Verify the real signing identity,
   full bundle resources, engine metadata, exact executable/archive hashes and
   native acceptance on each supported OS/architecture. Signing or notarization
   services, credentials and provisioning require separate owner authorization.
2. **Bounded synthetic pilot:** where platform policy permits, the owner may
   give explicit informed approval for installation/execution of one verified
   official artifact. The review must identify its exact release/commit, source
   URL, archive and executable hashes, observed build/architecture, available
   publisher/provenance evidence, unresolved signature/notarization risks and
   test scope. Begin with app-owned disposable profiles and synthetic local data;
   real accounts, proxies and credential use need their own approvals. Record
   the owner's approval through a real auditable deployment mechanism, bound to
   that artifact, machine, purpose and bounded validity. Never infer it from a
   JSON `trusted` flag, a server role, or a fabricated signature result.

The second path needs a separately reviewed **pilot-approval enforcement adapter**;
it is not implemented by the existing signature-only RuntimeGate. Owner approval
and cryptographic publisher verification are different evidence types and must
remain visible as such. The normal launcher cannot be made to accept an unsigned
artifact by returning `signature_valid=True` from a pretend verifier. Design and
verify the narrower approval adapter only against an actual selected artifact
and supported platform workflow; a synthetic test receipt is never deployable
approval.

Neither path authorizes suppressing Gatekeeper, clearing quarantine, weakening
the sandbox, disabling OS protections, or clicking through a security warning.
If the OS presents a warning, stop and use the owner's supported manual workflow
or choose an acceptable signed distribution. Passing owner approval does not
establish proxy leak prevention, browser compatibility, account isolation or
maintained security updates; those tests still must pass before a staff pilot.

## Native acceptance and integration checklist

1. Review a specific installed Camoufox release and its entire distribution,
   signer/provenance, exact executable hash and trusted observed version. Do not
   execute an unknown binary to discover its version. Preserve existing runtime
   signature/downgrade checks. A Python dependency version alone is not provenance.
2. Provide `RuntimeGate` with a real trusted platform verifier and an independently
   reviewed, fresh Camoufox distribution metadata observer as described above.
   Neither an asserted version nor installer cache metadata substitutes for that
   observation/provenance. No default observer or genuine acceptance record ships.
3. Test the exact release/platform/launcher/driver combination: launch and close
   ownership, delayed cancellation, crashes/disconnects, sandbox and built-in
   security defaults, persistent two-profile separation, restart identity,
   locale/timezone, profile-specific Inbox focus, and runtime-update invalidation.
4. Separately authorize provider use and native secret-store integration. Exercise
   HTTPS certificate/name failures, authentication expiry, DNS/IPv4/IPv6/UDP
   leaks, startup/background traffic, bypass targets, mid-session outages,
   unchanged/stale probes, assignment changes and stop behavior. Validate public
   IPv6 literal and CONNECT:80 behavior rather than inferring it from DNS prefs.
5. Bind an independently reviewed `CamoufoxAcceptance` to the runtime hash/version,
   platform, test ID, exact launcher/driver versions, bounded validity period, and
   route-preference digest for proxy use. Explicitly accept the local-process
   boundary on the actual trusted host. Never manufacture this from synthetic
   tests or accept it from the control plane/web UI.
6. Supply trusted `ProfilePolicies`, `CamoufoxRoutes`, bounded diagnostic target
   pairs and context probe objects.
   Recheck assignment and settings changes before launch. The supervisor checks
   runtime content immediately before and after startup. Detected pre-launch
   changes block admission, and detected post-start changes request shutdown.
   Signature verification runs on each admission. Path-based Playwright spawning
   is not an atomic executable-descriptor handoff: these checks do not eliminate
   all same-user replacement races. An accepted distribution/install/update
   policy must control the complete runtime tree and concurrent updates.
7. Wire `LifecycleCoordinator.installed` to explicitly recognize the concrete
   `CamoufoxAdapter`; do not trust an arbitrary `execution_kind` string. Native
   errors after possible process creation return an uncertain handle and retain
   the profile lease. Stop acknowledgement is required before releasing it.
8. Optional package installation belongs in an explicit reviewed dependency
   extra (`camoufox==0.5.6`, `playwright==1.62.0`) with whole-environment review.
   Do not install/download an engine as a side effect. No native test is authorized
   merely because the optional dependency can be installed.

The launcher is MIT-licensed; the engine includes MPL-2.0 and other components
with additional obligations such as LGPL. No upstream runtime/code is vendored
here. Any future binary distribution needs a separate complete license/source
and update-maintenance review. There are no stealth, undetectability or service
policy-evasion claims.

## Verification

Run the focused synthetic tests:

```
.venv/bin/python -m unittest discover -s tests -p 'test_client_camoufox*.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_client_proxy_relay*.py' -v
```

They cover admission/version/provenance changes, owned-directory/lease binding,
identity markers, fixed API options/targets, cancellation, uncertain process
ownership, exact-context probes, continuous evidence failure and relay shutdown;
and actual loopback TLS, certificate/hostname failure, auth placement, no local
target DNS, ambiguous numeric aliases, malformed/oversized inputs, public IPv6
tunnel literals, unsupported UDP/ports, concurrency/timeouts, active one-way
streams, diagnostic quarantine and sticky failure. They do not certify native
Camoufox or real residential-provider behavior.
