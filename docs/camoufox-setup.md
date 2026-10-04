# Camoufox setup in the local app

## Implemented path and actual status

The ordinary `tbm-client` application now has a Camoufox deployment loader,
offline identity preparation, bounded native-diagnostic operation, cancellation,
and in-memory per-profile admission. An admitted profile then uses the same
normal lifecycle Start action, owned persistent browser directory, lease and
process supervisor as the rest of the product. The UI does not submit evidence.
Synthetic app tests cover that complete path with inert files and fake contexts.

**No real Camoufox distribution is installed, approved, launched or accepted by
this work.** No signing key, account, proxy credential, grant, engine, extension
or GeoIP data was created/downloaded. This does not turn the earlier failed
Chromium-only Linux pilot into Camoufox authorization. The current Linux executor
already failed normal Chromium startup on process-singleton IPC; no security,
file/loopback policy or sandbox bypass is part of this implementation.

The declarative loader currently supports one independently reviewed **Linux,
local-direct** deployment with a fixed accepted profile template. Managed profiles
still require a verified proxy. The existing programmatic proxy adapter retains
its native route/leak/secret-store and diagnostic quarantine requirements; this
loader does not invent a production proxy probe or expose provider secrets.

## Three separate approvals and the first-run handoff

1. **Artifact installation and first qualification permission.** Select the exact
   official archive and supported host; verify its published hash and any
   available upstream provenance attestation independently. Inspect the complete
   extracted distribution without running it. Record exact executable/support
   hashes, actual version/BuildID, architecture, OS, display geometry, available
   publisher evidence and remaining risks. Obtain the owner's explicit bounded
   permission before installation or first native qualification. This application
   performs neither step. An observed hash or copied test identifier is not that
   permission.
2. **Release-wide native qualification.** On the approved compatible host, a
   separately authorized reviewer must establish normal sandbox/security defaults,
   controlled updates, exact owned launch/close, two-profile persistence,
   native display behavior, locale/timezone and the fixed identity collector.
   Measure the actual engine/generator/probe combination. Include accepted
   unsupported-surface limits and ordinary direct-egress scope. Proxy use
   additionally needs the existing leak/failure/host-boundary acceptance; local
   direct cannot substitute for it. The reviewer signs an authentic report-backed
   deployment receipt only after those results exist. First qualification is
   intentionally separate from per-profile normal-use admission; no fake success
   flag is used to bootstrap it. A stock upstream archive must not be approved
   merely because it starts: reviewed upstream configurations change several
   browser security defaults and compile out built-in updates. Restore/qualify
   the required behavior or use an independently reviewed rebuild/update channel
   before attesting these requirements. There is no receipt-signing or automatic
   qualification tool in the client.
3. **Per-profile preparation and diagnostic validation.** The ordinary app loads
   the independently authenticated deployment, prepares a fresh immutable identity
   offline, then runs two fresh fixed observations in a supervised native context
   when qualification authorizes it. Only acknowledged close under the same
   current lease/profile/authority publishes a typed admission. Ordinary Start
   re-verifies the runtime and checks the newly owned context against the admitted
   baseline. No release signature is needed for every newly created profile.

The smallest useful next real step is therefore to choose one exact archive and
compatible host and obtain explicit permission for its first qualification,
including its security-default/update issues. An independently provisioned
release authority must also exist before production setup is activated. Neither
exists implicitly because the Python SDK is installed. The setup UI honestly
shows missing approval instead of creating a circular or forged acceptance.

## Trusted deployment input

Two distinct protected inputs are required:

- An administrator-provisioned, root-owned Ed25519 **public** trust anchor, default
  `/etc/team-browser/camoufox-authorities.json`. All traversed parents must be
  root-owned, non-group/world-writable and non-symlinked; the client must run as a
  non-root user. The anchor declares schema version 1, authority ID, public-key
  hex, host ID and platform `linux`. Its key cannot be supplied by the receipt or
  HTTP API. Provisioning this persistent authority requires separate approval;
  this work does not create or install one.
- A private owner-only setup file and signed receipt, using descriptor-relative
  no-follow reads, bounded sizes and duplicate-key rejection. All configuration
  and receipt fields are strict; unknown fields are rejected. Changing their
  bytes or the anchor invalidates an active deployment until an explicit restart
  and new verification. Malformed/deeply nested JSON becomes a fixed safe setup
  blocker, never raw diagnostics in the UI.

This offline loader checks receipt expiry and exact anchor/configuration/receipt
bytes. It does not provide online per-receipt revocation or a persistent
anti-rollback ledger; controlled release updates remain a separate operational
and activation requirement.

The setup file selects an existing receipt and opts into its already accepted
profile template. For example, this **non-approval** configuration shape is:

```json
{
  "schema_version": 1,
  "receipt_file": "/absolute/private/reviewed-camoufox-receipt.json",
  "use_accepted_profile_defaults": true
}
```

A template binds the `isolated` Camoufox preset, exact locale/timezone and explicit
`local_direct` policy. Creating a Local profile with that preset and choosing
Local direct binds its actual profile ID and stable settings to that template.
There is no new signature or manual file-edit step for each normal new profile.
Optional private `profiles` selections bind exact profile IDs/stable hashes and
must match the same accepted template; they cannot widen its policy.

The receipt envelope has only `payload` (canonical ASCII JSON string) and
`signature_hex` (Ed25519 signature over exactly those bytes). The independently
signed payload has:

- Schema, authority/host/platform, issue time and expiry, no more than 30 days
- Official `https://github.com/daijro/camoufox/releases/download/.../*.zip` source,
  separately reviewed archive SHA-256, absolute protected installation root
- Exact `camoufox-bin`, `application.ini`, `properties.json` layout and complete
  relative regular-file inventory with SHA-256 pins; no symlinks/hardlinks,
  unknown resources or arbitrary launch files
- Independently observed Firefox version, Gecko BuildID and Camoufox release tag,
  with the explicit combined engine label
  `FirefoxVersion+CamoufoxRelease.GeckoBuildID`
- The accepted native display geometry/depth/DPR and bounded profile template
- Optional native qualification record with its genuine report reference,
  affirmative measured security/update/persistence/direct-egress scope, exact
  generator provenance and fixed collector ID

The exact schema lives in `client/camoufox_deployment.py`. No ready-made accepted
receipt or test signing authority ships. A signed artifact selection may omit
native qualification: offline preparation is available, but validation and
normal native use remain blocked. Changing approval from missing to accepted
requires a new authentic receipt and app restart, preserving the same identity.

The Linux INI mapping is an explicitly supported **qualification hypothesis**,
not observed evidence for an actual archive in this environment. The loader
requires actual `[App] Version` and `[App] BuildID`, exact signed metadata bytes,
and the independently reviewed full-tree inventory; missing or differing layout
fails closed. Confirm those semantics on the selected distribution before issuing
any receipt. SDK-written `version.json` is installer cache/release metadata, not
publisher or extracted-engine verification. `properties.json` is a property
schema, not engine-release identity. Python SDK, Firefox, Camoufox tag and Gecko
BuildID are distinct versions. No unknown executable is run with `--version`.

An authenticated deployment receipt is an organization/operator provenance
attestation, **not** an invented upstream publisher signature or notarization.
The gate returns explicitly labeled `deployment-ed25519:<authority>` provenance;
it never manufactures `SignatureEvidence`. Root-controlled installation and
no concurrent privileged updates are assumptions. Every signed resource and
bounded directory inventory is stamped before/after hashing using device/inode,
size, mtime/ctime, mode, ownership and link count. The accepted full metadata
inventory is rechecked through native metadata guards before spawn/admission;
changes or newly added resources fail closed. Playwright still launches by path,
so a privileged change after the final check is not an atomic executable/resource
handoff. A changed complete distribution requires a newly reviewed deployment
and explicit identity migration decision.

## Start the local app after real configuration exists

```sh
tbm-client --workspace /absolute/private/team-browser-workspace \
  --camoufox-policy /absolute/private/camoufox-setup.json \
  --camoufox-trust /etc/team-browser/camoufox-authorities.json --port 8765
```

This is mutually exclusive with `--runtime-policy`. No engine discovery,
download, add-on, GeoIP, package installation or native execution happens merely
by starting the app. Invalid configuration leaves a usable management UI with a
concrete setup blocker. Never use an HTTP request to select a filesystem path,
trust key, program, probe, artifact digest or success claim.

Open the permitted local manager, create/select a Local Camoufox profile, choose
Local direct explicitly, then Prepare. Accepted display geometry comes from the
trusted deployment, not editable UI values. Unsupported exact screen/depth/DPR,
engine conversion, available geometry or missing catalogue data is a concrete
blocker; no nearest display, invented taskbar or silent reseeding is permitted.
Native acceptance still has to verify those actual values. When qualification is
present, Validate runs only the fixed blank diagnostic. Ready means a current
typed per-profile diagnostic admission exists, not that an SDK or JSON file was
found. Start then executes the normal independently gated native launch.

## Stable loopback contract

All routes inherit exact-loopback Host/Origin, no-cache and CSRF protections.

- `GET /local/v1/camoufox-setup`: `supported`, `configured`, `usable`, `state`,
  fixed `blockers`, `next_step`, `fresh_execution_checks_required`.
  `usable` means release qualification is configured, not a new native result.
- `GET /local/v1/profiles/{id}/camoufox-setup`: profile/setup revisions, state,
  operation ID, fixed blockers/next step, available actions, network scope/warning,
  `admission_acknowledged`, `launch_available`, `admission_expires_at`,
  `runtime_observed_at`, `fresh_execution_checks_required`.
- `POST /local/v1/profiles/{id}/camoufox-setup/actions`: only `action`
  (`prepare`, `validate`, `cancel`), `expected_revision` and
  `expected_setup_revision`. Returns HTTP 202 and current snapshot. A POST response
  is not proof; read the current profile and setup again. Extra fields fail.

Profile states are `unavailable`, `needs_approval`, `not_prepared`, `preparing`,
`prepared`, `validating`, `ready`, `recovery_required`. The overview also uses
`available`. Prepare can be offered while `usable=false`; native Validate cannot.
Validation advances profile lifecycle/generation/revision, so clients refresh
profile metadata before comparing ready state. Setup revision fences concurrent
commands. Ordinary profile edits/removal/actions are blocked during its operation.

## Lifetime, networking and performance

A single bounded setup worker owns an exact profile lease. Native validation
reserves a resource slot shared with ordinary launch/budget accounting, including
pending startup and unknown native ownership. It cannot evade warm-profile or
memory limits. Cancellation never deletes/reseeds the artifact or assumes process
exit. Unacknowledged close/crash/disconnect retains the lease, resource reservation
and durable `recovery_required`; there is no reset, guessed-PID kill or force
unlock API. Application restart never restores a typed admission from JSON: it
prepares/reuses the same immutable artifact and revalidates explicitly.

Proxy-backed validation retains diagnostic quarantine throughout. Explicit
account-free local-direct validation has **ordinary network egress**: a blank
probe is not an offline browser or OS network sandbox. Session restore is
suppressed for that diagnostic, but background egress is not falsely denied.
Only the reviewed fixed collector is run, no user URL/script/Gmail navigation.
Managed origin, missing policy and proxy-bound identities cannot use direct mode.

Passive setup polls read bounded authority/metadata/property evidence and report
the last full runtime observation timestamp. Once verified, full-inventory metadata
stat checks also detect changed support files; they do not reread every file's
contents and are bounded to 32,768 filesystem entries. They do not hash a multi-gigabyte
engine on every poll. Prepare, validation and ordinary launch still freshly verify
the full protected inventory; native final fences retain the existing executable
rehash checks. Those full/large-file checks can be expensive on real disks and
remain a measured performance limitation. Cached UI readiness never authorizes
execution or substitutes for a fresh launch gate. No full-tree rehash is added to
ordinary warm-profile focus. Security guards are not weakened for speed.

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_client_camoufox_setup*.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_client_engine_identity_runtime.py' -v
```

Only synthetic signatures/files/fake contexts are used here. Tests do not certify
native display behavior, stock Camoufox security, actual distribution mapping,
upstream attestation, proxy routing, production account compatibility or a working
window in the current restricted executor.
