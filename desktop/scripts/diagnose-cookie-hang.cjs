'use strict';
// One reproduction of one immutable archived candidate. No app rebuild or patch.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { childEnvironment } = require('./smoke-packaged-mac.cjs');
const EXPECTED = Object.freeze({
  source_commit: '62d56b353bcb1c9981c31d8fbb6089322368a2f7',
  archive_sha256: '9a4a80e2115b0c8629518edfc5cb724308cf6cc3d626a08f27e5c308314e9d27',
  artifact_id: '11310884356', run_id: '37224078859',
});
const APP_NAMES = new Set(['TeamBrowser', 'TeamBrowser Helper', 'TeamBrowser Helper (Renderer)', 'TeamBrowser Helper (GPU)', 'TeamBrowser Helper (Plugin)']);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function verifyCandidate(candidate, archiveHash) {
  assert.equal(candidate.source_commit, EXPECTED.source_commit, 'Wrong candidate commit');
  assert.equal(candidate.archive_sha256, EXPECTED.archive_sha256, 'Wrong recorded archive hash');
  assert.equal(archiveHash, EXPECTED.archive_sha256, 'Downloaded archive bytes do not match');
  assert.equal(candidate.native_acceptance, false); assert.equal(candidate.install_ready, false);
}
function parseProcesses(raw) {
  return raw.split('\n').flatMap(line => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.+?)\s*$/);
    return match ? [{ pid: Number(match[1]), ppid: Number(match[2]), executable: match[3] }] : [];
  });
}
function ownedSampleTargets(rows, ownerPid, bundles = []) {
  const inBundle = executable => bundles.some(bundle => executable.startsWith(bundle + path.sep));
  if (!rows.some(row => row.pid === ownerPid && path.basename(row.executable) === 'TeamBrowser' && inBundle(row.executable))) return [];
  const descendants = new Set([ownerPid]);
  for (let changed = true; changed;) {
    changed = false;
    for (const row of rows) if (descendants.has(row.ppid) && !descendants.has(row.pid)) { descendants.add(row.pid); changed = true; }
  }
  return rows.filter(row => descendants.has(row.pid) && inBundle(row.executable) && APP_NAMES.has(path.basename(row.executable)))
    .sort((a, b) => (a.pid === ownerPid ? -1 : b.pid === ownerPid ? 1 : a.pid - b.pid)).slice(0, 4);
}
function redact(text, roots) {
  let value = String(text);
  for (const root of [...roots].filter(Boolean).sort((a, b) => b.length - a.length)) value = value.split(root).join('[ISOLATED_PATH]');
  return value.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
}
function callGraphOnly(raw, roots) {
  const start = raw.indexOf('Call graph:');
  if (start < 0) return null;
  const section = raw.slice(start).split(/\n(?:Total number in stack|Sort by top of stack|Binary Images:)/, 1)[0];
  // Retain sampled function/thread call graphs, not memory, environment, full
  // command lines, binary-image inventories, loaded profile files, or key data.
  return redact(section, roots).replace(/0x[0-9a-f]+/gi, '[ADDRESS]').slice(0, 128 * 1024) + '\n';
}
function processRows() {
  return parseProcesses(execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,comm='], { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 }));
}
function securityAgentPresence() {
  try {
    execFileSync('/usr/bin/pgrep', ['-x', 'SecurityAgent'], { stdio: 'ignore', timeout: 3000 });
    return { observed: true, proves_keychain_prompt: false };
  } catch (error) {
    return { observed: error.status === 1 ? false : null, observation_status: error.status === 1 ? 'absent' : 'unavailable', proves_keychain_prompt: false };
  }
}
async function main() {
  const desktop = path.resolve(__dirname, '..');
  const input = path.join(desktop, 'diagnostic-input');
  const output = path.join(desktop, 'out/cookie-diagnostic');
  fs.mkdirSync(output, { recursive: true });
  const report = { kind: 'immutable-candidate-cookie-hang-diagnostic', status: 'running', ...EXPECTED,
    observer_source_commit: process.env.GITHUB_SHA || null, native_acceptance: false, install_ready: false,
    reproduction_count: 0, diagnosis: 'unproven', limitations: ['No Keychain contents queried', 'No prompt accepted', 'No cryptographic/security setting changed', 'Process samples may lack symbols or permissions', 'SecurityAgent presence alone does not prove a prompt'] };
  function writeOutput(name, value, reserve = 65536) {
    const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const existing = fs.readdirSync(output).filter(file => file !== name)
      .reduce((total, file) => total + fs.statSync(path.join(output, file)).size, 0);
    if (existing + data.length + reserve > 1024 * 1024) {
      (report.omitted_evidence ||= []).push({ name, reason: 'one_MiB_total_evidence_limit' }); return false;
    }
    fs.writeFileSync(path.join(output, name), data); return true;
  }
  const save = () => writeOutput('diagnostic.json', JSON.stringify(report, null, 2) + '\n', 0);
  let child, exited = false, root, executable, asar;
  const logs = []; let logBytes = 0;
  save();
  try {
    assert.equal(process.platform, 'darwin'); assert.equal(process.arch, 'arm64');
    const candidate = JSON.parse(fs.readFileSync(path.join(input, 'candidate.json'), 'utf8'));
    assert.equal(path.basename(candidate.archive), candidate.archive);
    const archive = path.join(input, candidate.archive);
    verifyCandidate(candidate, hash(archive));
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-native-smoke-')); fs.chmodSync(root, 0o700);
    fs.writeFileSync(path.join(root, 'fixture-marker'), 'TeamBrowser blank native smoke v1\n', { mode: 0o600 });
    for (const name of ['home', 'evidence', 'extracted']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
    execFileSync('/usr/bin/ditto', ['-x', '-k', archive, path.join(root, 'extracted')], { timeout: 60000 });
    const bundle = path.join(root, 'extracted/TeamBrowser.app');
    executable = path.join(bundle, 'Contents/MacOS/TeamBrowser'); asar = path.join(bundle, 'Contents/Resources/app.asar');
    report.executable_sha256 = hash(executable); report.asar_sha256 = hash(asar);
    execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle], { stdio: 'pipe', timeout: 30000, maxBuffer: 65536 });
    report.bundle_signature_integrity = true;
    report.security_agent_before = securityAgentPresence();
    // Preserve the failing harness environment exactly. Do not restore a real
    // HOME, initialize/unlock a keychain, or change encryption to manufacture pass.
    child = spawn(executable, [`--tbm-native-smoke-root=${root}`, '--tbm-native-smoke-phase=seed'], {
      cwd: root, env: childEnvironment(root), shell: false, stdio: ['ignore', 'pipe', 'pipe'],
    });
    report.reproduction_count = 1;
    child.on('error', error => { report.spawn_error = error.code || 'spawn_error'; exited = true; });
    child.on('exit', (code, signal) => { report.process_exit = { code, signal }; exited = true; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      if (logBytes < 32768) { logs.push(chunk.subarray(0, 32768 - logBytes)); logBytes += chunk.length; }
    });
    const seedPath = path.join(root, 'evidence/seed.json');
    const deadline = Date.now() + 45000; let seed;
    while (!exited && Date.now() < deadline) {
      try { seed = JSON.parse(fs.readFileSync(seedPath, 'utf8')); } catch {}
      if (seed?.failed_operation === 'A_initial_storage:read_cookie') break;
      if (seed?.status === 'passed' || seed?.status === 'failed') break;
      await sleep(200);
    }
    report.last_native_operation = seed?.failed_operation || seed?.active_operation || null;
    report.cookie_hang_reproduced = seed?.failed_operation === 'A_initial_storage:read_cookie';
    report.security_agent_during = securityAgentPresence(); save();
    if (!exited && report.cookie_hang_reproduced) {
      const targets = ownedSampleTargets(processRows(), child.pid, [bundle, fs.realpathSync(bundle)]);
      report.samples = [];
      report.verified_owned_sample_targets = targets.length;
      if (!targets.length) report.sample_limitation = 'Process listing did not expose verified owned candidate executable paths';
      const roots = [root, fs.realpathSync(root), process.env.HOME];
      for (let index = 0; index < targets.length; index++) {
        const target = targets[index];
        // Re-establish ancestry immediately before each sample; never target an
        // arbitrary PID from a report or a system Keychain/security process.
        if (!ownedSampleTargets(processRows(), child.pid, [bundle, fs.realpathSync(bundle)]).some(row => row.pid === target.pid && row.executable === target.executable)) continue;
        const item = { name: path.basename(target.executable), pid: target.pid, status: 'unavailable' };
        const rawFile = path.join(root, `private-sample-${index}.txt`);
        try {
          execFileSync('/usr/bin/sample', [String(target.pid), '1', '10', '-file', rawFile], {
            stdio: 'pipe', timeout: 15000, maxBuffer: 65536,
          });
          const raw = fs.readFileSync(rawFile, 'utf8');
          const graph = callGraphOnly(raw, roots);
          if (graph) {
            item.file = `owned-process-${index}-callgraph.txt`; item.status = 'captured';
            if (!writeOutput(item.file, graph)) item.status = 'omitted_size_limit';
          } else item.status = 'no_callgraph_returned';
        } catch (error) {
          item.status = 'sample_unavailable'; item.exit_status = Number.isInteger(error.status) ? error.status : null;
          // Do not escalate, add debugger entitlements, sudo, or try a bypass.
          item.detail = redact(String(error.stderr || error.code || 'sample failed'), roots).slice(0, 2048);
        }
        report.samples.push(item); save();
      }
    }
    // Copy only fixed diagnostic records/screenshots from the blank fixture.
    for (const name of ['seed.json', 'seed-chrome.png', 'seed-profiles-chrome.png']) {
      const from = path.join(root, 'evidence', name);
      if (fs.existsSync(from)) {
        if (fs.statSync(from).size <= (name.endsWith('.png') ? 131072 : 65536)) writeOutput(name, fs.readFileSync(from));
        else (report.omitted_evidence ||= []).push({ name, reason: 'individual_evidence_size_limit' });
      }
    }
    assert.equal(hash(archive), EXPECTED.archive_sha256);
    assert.equal(hash(executable), report.executable_sha256); assert.equal(hash(asar), report.asar_sha256);
    report.status = 'diagnostic_collected';
    report.diagnosis = 'Requires human/source review of sampled call graphs; no automatic Keychain conclusion';
  } catch (error) { report.status = 'diagnostic_failed'; report.failure = error.message.slice(0, 4096); process.exitCode = 1; }
  finally {
    if (child && !exited) {
      report.diagnostic_cleanup = 'owned app termination requested after evidence; not normal-shutdown acceptance';
      child.kill('SIGTERM');
      const deadline = Date.now() + 10000;
      while (!exited && Date.now() < deadline) await sleep(100);
      if (!exited) { child.kill('SIGKILL'); report.diagnostic_cleanup = 'owned app force termination required; not normal-shutdown acceptance'; await sleep(500); }
    }
    writeOutput('isolated-process.log', redact(Buffer.concat(logs).toString('utf8'), root ? [root, fs.realpathSync(root)] : []).slice(0, 32768));
    save(); console.log(JSON.stringify(report, null, 2));
  }
}
if (require.main === module) void main();
module.exports = { EXPECTED, verifyCandidate, parseProcesses, ownedSampleTargets, callGraphOnly };
