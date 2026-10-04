'use strict';
// One metadata comparison, not a candidate launch or native acceptance run.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const REPORT_LIMIT = 8192;
const FIELDS = ['copy_default_status', 'default_reference_returned', 'lock_status_known'];
const statusCode = value => Number.isInteger(value) && value >= -2147483648 && value <= 2147483647;
function parseMetadata(raw) {
  assert.equal(typeof raw, 'string'); assert.ok(Buffer.byteLength(raw) <= 1024);
  const value = JSON.parse(raw);
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...FIELDS].sort());
  assert.ok(statusCode(value.copy_default_status));
  assert.equal(typeof value.default_reference_returned, 'boolean');
  assert.equal(value.lock_status_known, false);
  return Object.fromEntries(FIELDS.map(key => [key, value[key]]));
}
function probeEnvironment(source, home) {
  assert.ok(typeof home === 'string' && path.isAbsolute(home));
  // Same narrow environment for both processes, with HOME as the only difference.
  // No GitHub token, credential, preload, or dynamic-loader environment is passed.
  const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', HOME: home };
  for (const key of ['TMPDIR', 'USER', 'LOGNAME']) if (typeof source[key] === 'string') env[key] = source[key];
  return env;
}
function probe(helper, env, spawn = spawnSync) {
  const result = spawn(helper, [], { env, shell: false, encoding: 'utf8', timeout: 5000,
    killSignal: 'SIGKILL', maxBuffer: 4096, stdio: ['ignore', 'pipe', 'ignore'] });
  const report = { completed: false, timed_out: result.error?.code === 'ETIMEDOUT',
    exit_status: Number.isInteger(result.status) ? result.status : null, output_valid: false, metadata: null };
  if (result.error || result.signal || result.status !== 0) return report;
  report.completed = true;
  try { report.metadata = parseMetadata(result.stdout); report.output_valid = true; } catch {}
  return report;
}
function main() {
  const desktop = path.resolve(__dirname, '..');
  const output = path.join(desktop, 'out/default-keychain-metadata.json');
  const report = { schema: 1, native_acceptance: false, install_ready: false,
    comparison_completed: false, setup_valid: false, normal: null, synthetic: null,
    synthetic_home_empty_before: false, synthetic_home_empty_after: false };
  fs.mkdirSync(path.dirname(output), { recursive: true });
  try {
    // This is deliberately unavailable as an accidental user-Mac diagnostic.
    assert.equal(process.platform, 'darwin'); assert.equal(process.arch, 'arm64');
    assert.equal(process.env.GITHUB_ACTIONS, 'true');
    assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
    const home = process.env.HOME;
    assert.ok(typeof home === 'string' && path.isAbsolute(home));
    assert.ok(fs.statSync(home).isDirectory());
    const helper = path.join(desktop, 'out/default-keychain-metadata-helper');
    assert.ok(fs.statSync(helper).isFile());
    const syntheticHome = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-keychain-metadata-'));
    report.synthetic_home_empty_before = fs.readdirSync(syntheticHome).length === 0;
    assert.equal(report.synthetic_home_empty_before, true);
    report.setup_valid = true;
    report.normal = probe(helper, probeEnvironment(process.env, home));
    // If the read-only helper stalls or returns malformed output, stop. No retry.
    if (report.normal.completed && report.normal.output_valid) {
      report.synthetic = probe(helper, probeEnvironment(process.env, syntheticHome));
      report.comparison_completed = report.synthetic.completed && report.synthetic.output_valid;
    }
    report.synthetic_home_empty_after = fs.readdirSync(syntheticHome).length === 0;
  } catch {
    // Do not persist arbitrary error text, paths, environment, or native stderr.
  }
  const json = JSON.stringify(report, null, 2) + '\n';
  assert.ok(Buffer.byteLength(json) <= REPORT_LIMIT);
  fs.writeFileSync(output, json, { flag: 'wx' });
  if (!report.comparison_completed || !report.synthetic_home_empty_after) process.exitCode = 1;
}
if (require.main === module) main();
module.exports = { REPORT_LIMIT, parseMetadata, probeEnvironment, probe };
