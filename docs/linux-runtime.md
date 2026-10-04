# Linux account-free browser runtime

## Scope and current result

The client now has a separate Linux admission path for Debian's installed
Chromium. It reuses the same account-free profile manager, owned persistent
contexts, lifecycle leases, tab control and official Playwright pipe supervisor.
It does not use Apple Keychain, macOS bundle metadata, codesign or Gatekeeper.

This is an implemented pilot path, not native-browser acceptance. The current
managed Linux executor cannot satisfy its package-provenance requirements:
`/var/lib/dpkg` is absent, and its supplied browser/package-helper files are
mapped to `nobody:nogroup` instead of root-owned Debian package files. The gate
rejects those facts before launching anything. An existing platform-controlled
Chromium window does not establish an app-owned profile launch.

The separate historical offline smoke failed on process-singleton IPC sockets.
On October 4, 2026 at 02:00:50 UTC, an explicitly owner-approved exact-artifact
pilot established the current normal headful result too: the actual manager
factory and Playwright supervisor launched the supplied Chromium with a fresh
app-owned profile, `headless=False`, `chromium_sandbox=True`, all default test
flags disabled, a private control pipe and `about:blank`. No extra user/network
namespace was introduced. Chromium aborted before a window or public page with
`process_singleton_posix.cc:297: socket() failed: Operation not permitted (1)`;
crashpad also reported a ptrace denial. The manager retained `recovery_required`
and blocked another launch. The three-profile switching, public-page storage,
restart-persistence and acknowledged-close stages therefore did not execute.

The real setup and failure were captured as native desktop frames. No browser
sandbox was disabled, browser extension removed, host security setting changed,
prohibited loopback/file route retried, or replacement browser downloaded.
Raw diagnostics and private owner-approval records remain outside the source
tree. This is evidence of a current executor IPC blocker, not a passing demo.

## Supported preparation

1. Use an authorized non-root Debian graphical session with its real, protected
   package database and existing sandbox/IPC support. Install Chromium only
   through the organization's approved authenticated package workflow. This
   client never downloads or installs a browser.
2. Independently review the exact release and executable SHA-256. Record the
   architecture-qualified installed versions of `chromium`, `chromium-common`
   and `chromium-sandbox`. The policy's `version` is the full Debian Chromium
   package version, including an epoch or distribution revision when present;
   it is not merely the browser's four-part version string.
3. Copy `linux-runtime-policy.example.json` to an absolute private file and
   replace every placeholder with reviewed values. Use the actual architecture
   in all three package keys. Keep mode 0600, owner-only access, no symlink or
   hard link. The example deliberately does not validate.
4. Install the repository's pinned official `native` Python extra if needed.
   Do not run `playwright install`: this path uses only the existing Chromium.
5. Start the actual manager:

   ```sh
   .venv/bin/tbm-client \
     --workspace /absolute/private/team-browser-workspace \
     --runtime-policy /absolute/private/linux-policy.json \
     --port 8765
   ```

6. In a browser permitted to access the local manager, open
   `http://127.0.0.1:8765/preview/`, create a fresh Local profile, explicitly
   select Local direct connection and launch a blank tab. A network-policy
   restriction is a blocker, not a reason to tunnel or expose the private API.

No real login, private data or proxy service is needed for this first test.
Initial acceptance must use fresh app-owned profiles and synthetic page data.
Confirm window launch, two-profile isolation, stop/restart persistence, exact
focus and acknowledged shutdown before claiming the flow works. The opt-in
native acceptance harness remains a separate explicit test action.

## What the Linux gate establishes

- Fixed actual ELF executable `/usr/lib/chromium/chromium`, protected root-owned
  system helpers, package database, checksum/list metadata and package payloads
- Exact reviewed architecture-qualified package identities, installed state and
  versions for Chromium plus its common resources and sandbox package
- Canonical, nonempty checksum metadata and file inventories, with every
  checksum-covered payload present in the package file list
- Clean `dpkg --verify` for all three packages: any stdout, stderr or nonzero
  exit fails, because dpkg can return zero for modified or missing files
- Independently reviewed executable SHA-256, with metadata and executable
  rechecks around verification and fresh checks before every actual launch
- Fixed command arguments, an anchored root/database, scrubbed environment,
  bounded output and timeouts

This uses a trusted local package database plus an independent executable pin.
It does not manufacture a vendor digital signature, prove past authenticated
APT installation, or certify the host and all system libraries. The existing
`VerifiedRuntime.signer_identity` field carries the explicit legacy-compatible
label `debian-installed-package:chromium`; no `SignatureEvidence` is created.
The macOS policy continues to require its own signature/notarization checks.

The supervisor retains Chromium's normal sandbox, security updates, native
credential storage and pipe-only automation. Its default Playwright test flags
remain disabled. Unknown process ownership keeps the profile lease. Managed or
proxy-required launches remain unavailable, and direct networking is still an
explicit per-local-profile choice.

## Exact-artifact pilot boundary

This adapter does not silently convert a package-verification failure into an
approval of whatever bytes are installed. An image-supplied runtime without its
package records would need an independently reviewed image/runtime manifest or
a separately designed, explicitly authorized exact-artifact pilot trust path.
Such a path includes support resources and sandbox helpers as well as the
main executable, is labeled honestly, and retains the same operating-system and
browser protections. The separate `owner-approved-linux-pilot` policy now
implements that narrow option. It requires a real owner approval reference,
the exact full artifact manifest digest, a fresh workspace, explicit permission
for the fixed public example.com fixture if requested, and an approval lifetime
of no more than two hours. No tool or loader creates approval automatically.
The observation manifest alone cannot enable execution. Native focus/tab
actions recheck expiry, and expiry requests normal owned shutdown while
preserving uncertain ownership. Gmail intent remains refused.

After actual approval is recorded privately, the same manager factory can be
exercised without requesting a prohibited loopback/file browser route:

```sh
PYTHONPATH=src .venv/bin/python scripts/run_linux_pilot_acceptance.py \
  --runtime-policy /absolute/private/approved-pilot-policy.json \
  --workspace /absolute/new/disposable-workspace \
  --public-page --hold-seconds 10
```

The harness requires a previously nonexistent workspace. It starts three real
manager-owned profiles only if the first native launch succeeds, navigates only
to the fixed public synthetic fixture, checks storage separation and restart
persistence, switches actual owned handles and requests acknowledged closure.
Raw startup diagnostics are private harness output, never public API fields.
A failed or uncertain launch is recorded as such; no guessed PID is killed and
no unresolved profile data is deleted. This is an actual acceptance attempt,
not a simulator or a vendor-provenance claim.

Observed only on October 4, 2026: the current executor reports Chromium
154.0.8037.57 at the fixed path; its main executable SHA-256 is
`4dc9f9f9b20e9bd95bf201f43d2d643f48938f36a70ddcb6fce3dd611a178180`.
That observation is not an independent release approval and is not shipped as
an enabled policy.

References: [dpkg verification semantics](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html),
[dpkg-query inventory APIs](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html),
[APT authentication boundary](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html),
[Chromium common-resource inventory](https://packages.debian.org/bookworm/amd64/chromium-common/filelist).
