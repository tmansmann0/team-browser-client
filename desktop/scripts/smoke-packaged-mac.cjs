'use strict';
// Hosted-Mac diagnostic only. Launch the exact archived candidate, never a dev Electron.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const assert = require('node:assert/strict');
const desktop = path.resolve(__dirname, '..');
const out = path.join(desktop, 'out');
const evidence = path.join(out, 'native-smoke');
const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } }
function childEnvironment(root) {
  // Never inherit repository tokens, signing identities, Python/Node overrides,
  // browser instrumentation flags, real profiles, or proxy settings.
  const result = { HOME: path.join(root, 'home'), PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'en_US.UTF-8', TZ: 'UTC' };
  for (const key of ['TMPDIR', 'USER', 'LOGNAME']) if (process.env[key]) result[key] = process.env[key];
  return result;
}
async function launch(executable, root, phase) {
  const child = spawn(executable, [`--tbm-native-smoke-root=${root}`, `--tbm-native-smoke-phase=${phase}`], {
    cwd: root, env: childEnvironment(root), shell: false, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const chunks = []; let bytes = 0;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', data => {
    if (bytes < 128 * 1024) { chunks.push(data.subarray(0, 128 * 1024 - bytes)); bytes += data.length; }
  });
  let timer, forceTimer, timedOut = false;
  const result = await new Promise(resolve => {
    timer = setTimeout(() => {
      timedOut = true; child.kill('SIGTERM');
      forceTimer = setTimeout(() => child.kill('SIGKILL'), 10000);
    }, 120000);
    child.once('error', error => resolve({ code: null, signal: null, error: error.code || 'spawn_error' }));
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer); clearTimeout(forceTimer);
  fs.writeFileSync(path.join(evidence, `${phase}-process.log`), Buffer.concat(chunks));
  // Copy only explicit reports and captures. Never upload profile databases,
  // browser/keychain data, child pipes, or the temporary HOME directory.
  for (const suffix of ['.json', '-chrome.png', '-profiles-chrome.png', '-profile-A.png', '-profile-B.png']) {
    const source = path.join(root, 'evidence', phase + suffix);
    if (fs.existsSync(source)) fs.copyFileSync(source, path.join(evidence, phase + suffix));
  }
  const reportPath = path.join(evidence, phase + '.json');
  const report = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, 'utf8')) : null;
  if (report?.sidecar_pid) {
    const deadline = Date.now() + 10000;
    while (alive(report.sidecar_pid) && Date.now() < deadline) await sleep(100);
    result.sidecar_process_gone = !alive(report.sidecar_pid);
  }
  assert.equal(timedOut, false, `${phase}: packaged app did not finish within 120 seconds; possible startup/modal/rendering limitation`);
  assert.equal(result.error, undefined, `${phase}: could not start packaged executable`);
  assert.equal(result.signal, null, `${phase}: packaged app terminated by ${result.signal}; inspect isolated process log/signature diagnostics`);
  assert.equal(result.code, 0, `${phase}: packaged app exited unsuccessfully`);
  assert.ok(report, `${phase}: app did not reach the native diagnostic; startup/signature/GUI remains unverified`);
  assert.equal(report.status, 'passed', `${phase}: ${report.failure || report.status}`);
  assert.equal(result.sidecar_process_gone, true, `${phase}: sidecar process survived app exit`);
  return { ...result, checks: report.checks };
}
function signatureDiagnostic(error, root) {
  const raw = [error.stdout, error.stderr].filter(Boolean).map(value => String(value)).join('\n');
  return { exit_status: Number.isInteger(error.status) ? error.status : null,
    signal: typeof error.signal === 'string' ? error.signal.slice(0, 32) : null,
    output: raw.split(root).join('[SMOKE_ROOT]').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '').slice(0, 8192) };
}
async function main() {
  fs.mkdirSync(evidence, { recursive: true });
  const result = { kind: 'packaged-native-smoke-summary', status: 'failed', native_acceptance: false, install_ready: false, packaged_synthetic_storage_smoke: false };
  try {
    assert.equal(process.platform, 'darwin', 'Must run on the approved native macOS host');
    assert.equal(process.arch, 'arm64', 'Must run on native Apple Silicon');
    const candidate = JSON.parse(fs.readFileSync(path.join(out, 'candidate.json'), 'utf8'));
    assert.equal(candidate.native_acceptance, false); assert.equal(candidate.install_ready, false);
    assert.match(candidate.source_commit, /^[a-f0-9]{40}$/);
    assert.equal(candidate.source_commit, process.env.GITHUB_SHA, 'Candidate does not match this workflow commit');
    assert.equal(path.basename(candidate.archive), candidate.archive, 'Invalid candidate archive');
    const archive = path.join(out, candidate.archive);
    assert.equal(digest(archive), candidate.archive_sha256, 'Candidate archive hash changed');
    Object.assign(result, { source_commit: candidate.source_commit, archive: candidate.archive, archive_sha256: candidate.archive_sha256, runner: 'macos-15 arm64', fixture_transport: 'fixed in-memory HTTPS responses; real Chromium cookies/localStorage/IndexedDB', claims_excluded: ['installation', 'signing/notarization', 'Gatekeeper', 'real accounts', 'provider login', 'proxies/network/TLS', 'service workers/cache', 'full product/native acceptance'] });
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-native-smoke-'));
    fs.chmodSync(root, 0o700);
    fs.writeFileSync(path.join(root, 'fixture-marker'), 'TeamBrowser blank native smoke v1\n', { mode: 0o600 });
    for (const name of ['home', 'evidence']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
    const extracted = path.join(root, 'extracted'); fs.mkdirSync(extracted, { mode: 0o700 });
    execFileSync('/usr/bin/ditto', ['-x', '-k', archive, extracted]);
    const app = path.join(extracted, 'TeamBrowser.app');
    const executable = path.join(app, 'Contents/MacOS/TeamBrowser');
    assert.ok(fs.statSync(executable).isFile(), 'Archived executable missing');
    result.executable_sha256 = digest(executable);
    result.asar_sha256 = digest(path.join(app, 'Contents/Resources/app.asar'));
    // Diagnostic only. Never reset signatures, remove quarantine or change policy.
    try { execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=4', app], { stdio: 'pipe', timeout: 20000, maxBuffer: 65536 }); result.existing_signature_valid = true; }
    catch (error) { result.existing_signature_valid = false; result.signature_diagnostic = signatureDiagnostic(error, root); }
    result.seed = await launch(executable, root, 'seed');
    result.reopen = await launch(executable, root, 'reopen');
    assert.equal(digest(archive), candidate.archive_sha256, 'Archive mutated during test');
    assert.equal(digest(executable), result.executable_sha256, 'Executable mutated during test');
    assert.equal(digest(path.join(app, 'Contents/Resources/app.asar')), result.asar_sha256, 'ASAR mutated during test');
    result.status = 'passed'; result.packaged_synthetic_storage_smoke = true;
  } catch (error) { result.failure = error.message; process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, 'summary.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}
if (require.main === module) void main();
module.exports = { childEnvironment, signatureDiagnostic };
