'use strict';
// Run only on the approved cloud macOS build host, never on a user's install.
const { existsSync, mkdirSync, readFileSync, writeFileSync, cpSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { platform, arch } = require('node:os');
const root = resolve(__dirname, '../..');
const desktop = join(root, 'desktop');
function hash(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
async function main() {
  if (platform() !== 'darwin' || arch() !== 'arm64') throw new Error('This candidate requires a native cloud macOS arm64 host; cross-builds are not accepted');
  const mode = process.env.TBM_PACKAGE_MODE || 'unsigned-candidate';
  if (!['unsigned-candidate', 'signed-candidate'].includes(mode)) throw new Error('Unknown candidate mode');
  const identity = process.env.TBM_SIGNING_IDENTITY;
  const keychainProfile = process.env.TBM_NOTARY_KEYCHAIN_PROFILE;
  if (mode === 'signed-candidate' && (!identity || !keychainProfile)) throw new Error('Existing authorized Developer ID and notary keychain profile are required');
  const sidecar = join(desktop, 'sidecar/tbm-sidecar');
  if (!existsSync(join(sidecar, 'tbm-desktop-sidecar'))) throw new Error('Build the frozen sidecar first');
  // Stage only reviewed desktop source. Never bundle the mixed repository,
  // private API, development node_modules, local profile store, or environment.
  const stage = join(desktop, 'out/stage');
  if (existsSync(stage)) throw new Error('Choose a clean build workspace');
  mkdirSync(stage, { recursive: true });
  cpSync(join(desktop, 'src'), join(stage, 'src'), { recursive: true });
  const packageInfo = JSON.parse(readFileSync(join(desktop, 'package.json')));
  writeFileSync(join(stage, 'package.json'), JSON.stringify({ name: packageInfo.name, version: packageInfo.version, private: true, main: packageInfo.main, license: 'UNLICENSED' }, null, 2));
  const { default: packager } = await import('@electron/packager');
  const { flipFuses, FuseVersion, FuseV1Options } = await import('@electron/fuses');
  const paths = await packager({
    dir: stage, out: join(desktop, 'out/packages'), name: 'TeamBrowser', executableName: 'TeamBrowser',
    appBundleId: 'app.teambrowser.desktop', appVersion: packageInfo.version.split('-')[0], buildVersion: packageInfo.version.split('-')[0],
    platform: 'darwin', arch: 'arm64', electronVersion: packageInfo.devDependencies.electron,
    asar: true, prune: false, overwrite: false,
    icon: join(root, 'src/team_browser/static/brand/TeamBrowser.icns'),
    extraResource: [sidecar],
    extendInfo: { LSMinimumSystemVersion: '13.0' },
  });
  const bundle = join(paths[0], 'TeamBrowser.app');
  await flipFuses(bundle, {
    version: FuseVersion.V1,
    // Apple Silicon requires a valid local code signature after Mach-O fuse edits.
    // This is an ad-hoc build signature, never Developer ID/Gatekeeper acceptance.
    resetAdHocDarwinSignature: mode === 'unsigned-candidate',
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  });
  let signed = false, notarized = false;
  if (mode === 'signed-candidate') {
    const { signAsync } = await import('@electron/osx-sign');
    const { notarize } = await import('@electron/notarize');
    // Sign all nested code with no generic device/location/photo entitlement.
    // Electron's V8 needs JIT; the fixed Python sidecar receives no entitlement.
    await signAsync({ app: bundle, identity, platform: 'darwin', optionsForFile: file => ({
      hardenedRuntime: true,
      entitlements: join(desktop, file.includes('/Resources/tbm-sidecar/') ? 'entitlements-sidecar.plist' : 'entitlements-electron.plist'),
    }) });
    execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle], { stdio: 'inherit' });
    signed = true;
    await notarize({ appPath: bundle, keychainProfile });
    execFileSync('/usr/bin/xcrun', ['stapler', 'validate', bundle], { stdio: 'inherit' });
    execFileSync('/usr/sbin/spctl', ['--assess', '--type', 'execute', '--verbose=4', bundle], { stdio: 'inherit' });
    notarized = true;
  }
  const archive = join(desktop, 'out', `TeamBrowser-${packageInfo.version}-mac-arm64-${mode}.zip`);
  execFileSync('/usr/bin/ditto', ['-c', '-k', '--sequesterRsrc', '--keepParent', bundle, archive]);
  const report = {
    kind: 'desktop-build-candidate', version: packageInfo.version, platform: 'darwin', architecture: 'arm64',
    mode, signed, developer_id_signed: signed, notarized,
    signature_kind: signed ? 'developer-id' : 'ad-hoc',
    native_acceptance: false, install_ready: false,
    archive: archive.split('/').pop(), archive_sha256: hash(archive),
    electron: packageInfo.devDependencies.electron,
    node_lock_sha256: hash(join(desktop, 'package-lock.json')),
    python_lock_sha256: hash(join(desktop, 'requirements-macos-arm64.lock')),
    source_commit: process.env.GITHUB_SHA || 'unrecorded-local-source',
    note: 'Packaging success is not profile isolation, proxy, provider-login, installer, or upgrade acceptance.',
  };
  writeFileSync(join(desktop, 'out/candidate.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
