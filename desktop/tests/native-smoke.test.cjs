'use strict';
// Harness contracts only. These tests never count as native-browser proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { config, configure, fixture, verifyStorage, ORIGIN } = require('../src/native-smoke.cjs');
const { childEnvironment } = require('../scripts/smoke-packaged-mac.cjs');

test('ordinary launch has no smoke configuration or path changes', () => {
  assert.equal(config(['TeamBrowser']), null);
  assert.equal(configure({ setPath() { throw new Error('ordinary launch changed'); } }, ['TeamBrowser']), null);
});
test('smoke rejects non-Mac, unknown/duplicate arguments, relative or unmarked roots', () => {
  const args = ['--tbm-native-smoke-root=/tmp/no', '--tbm-native-smoke-phase=seed'];
  assert.throws(() => config(args, 'linux', 'arm64'));
  assert.throws(() => config(args, 'darwin', 'x64'));
  assert.throws(() => config([...args, '--tbm-native-smoke-extra=x'], 'darwin', 'arm64'));
  assert.throws(() => config(['--tbm-native-smoke-root=relative', args[1]], 'darwin', 'arm64'));
});
test('smoke isolates empty first launch and same-root reopening; never silently reuses seed data', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-native-smoke-'));
  try {
    const args = phase => [`--tbm-native-smoke-root=${root}`, `--tbm-native-smoke-phase=${phase}`];
    assert.throws(() => config(args('seed'), 'darwin', 'arm64'));
    fs.writeFileSync(path.join(root, 'fixture-marker'), 'TeamBrowser blank native smoke v1\n');
    assert.equal(config(args('seed'), 'darwin', 'arm64').phase, 'seed');
    fs.writeFileSync(path.join(root, 'user-data', 'synthetic-data'), 'fixture');
    assert.throws(() => config(args('seed'), 'darwin', 'arm64'));
    assert.equal(config(args('reopen'), 'darwin', 'arm64').phase, 'reopen');
  } finally { fs.rmSync(root, { recursive: true }); }
});
test('fixed fixture does not forward external requests or provide arbitrary files/scripts', async () => {
  const response = fixture({ url: ORIGIN + '/' });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Controlled in-memory HTTPS document/);
  assert.match(response.headers.get('content-security-policy'), /connect-src 'none'/);
  for (const url of ['https://example.com/', ORIGIN + '/secret', 'http://127.0.0.1/']) assert.equal(fixture({ url }).status, 403);
});
test('storage validation independently rejects crossed values and privileged guest globals', () => {
  const value = { cookie: 'tbm_smoke=A', local: 'A', indexed: 'A', live: 'A-live', origin: ORIGIN, node: 'undefined', require: 'undefined', bridge: 'undefined' };
  verifyStorage(value, 'A', 'A-live');
  for (const key of ['cookie', 'local', 'indexed', 'live', 'node', 'require', 'bridge', 'origin']) assert.throws(() => verifyStorage({ ...value, [key]: 'wrong' }, 'A', 'A-live'));
});
test('launcher environment excludes credentials, overrides, proxies and alternate app arguments', () => {
  const env = childEnvironment('/blank-fixture');
  assert.equal(env.HOME, '/blank-fixture/home');
  for (const key of Object.keys(env)) assert.ok(['HOME', 'PATH', 'LC_ALL', 'TZ', 'TMPDIR', 'USER', 'LOGNAME'].includes(key));
});
test('packaged hook retains controls and workflow only uploads bounded evidence', () => {
  const root = path.resolve(__dirname, '../..');
  const main = fs.readFileSync(path.join(root, 'desktop/src/main.cjs'), 'utf8');
  const packageSource = fs.readFileSync(path.join(root, 'desktop/scripts/package-mac.cjs'), 'utf8');
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/desktop-candidate.yml'), 'utf8');
  assert.match(main, /app\.enableSandbox\(\)/);
  assert.match(main, /if \(smoke\) await nativeSmoke\.run/);
  assert.match(packageSource, /const \{ packager \} = await import\('@electron\/packager'\)/);
  assert.match(packageSource, /resetAdHocDarwinSignature: mode === 'unsigned-candidate'/);
  assert.match(packageSource, /native_acceptance: false, install_ready: false/);
  assert.match(workflow, /node desktop\/scripts\/smoke-packaged-mac\.cjs/);
  assert.match(workflow, /path: desktop\/out\/native-smoke\//);
  for (const text of [main, packageSource, workflow]) assert.doesNotMatch(text, /--no-sandbox|ignore-certificate-errors|xattr|spctl[^\n]*--master-disable|remote-debugging-port/);
});
