'use strict';
// Pure observer contracts. Never presented as a native diagnostic result.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EXPECTED, verifyCandidate, parseProcesses, ownedSampleTargets, callGraphOnly } = require('../scripts/diagnose-cookie-hang.cjs');
test('observer accepts only the reviewed immutable candidate bytes and commit', () => {
  const candidate = { ...EXPECTED, native_acceptance: false, install_ready: false };
  verifyCandidate(candidate, EXPECTED.archive_sha256);
  assert.throws(() => verifyCandidate({ ...candidate, source_commit: 'a'.repeat(40) }, EXPECTED.archive_sha256));
  assert.throws(() => verifyCandidate(candidate, 'b'.repeat(64)));
  assert.throws(() => verifyCandidate({ ...candidate, install_ready: true }, EXPECTED.archive_sha256));
});
test('sample targets require spawned ancestry, candidate bundle path and allowlisted executable', () => {
  const root = '/fixture/TeamBrowser.app';
  const rows = parseProcesses(`10 1 ${root}/Contents/MacOS/TeamBrowser
11 10 ${root}/Contents/Frameworks/TeamBrowser Helper (Renderer).app/Contents/MacOS/TeamBrowser Helper (Renderer)
12 10 ${root}/Contents/Resources/tbm-sidecar/tbm-desktop-sidecar
13 1 /System/SecurityAgent
14 1 ${root}/Contents/MacOS/TeamBrowser
15 10 /elsewhere/TeamBrowser Helper
`);
  assert.deepEqual(ownedSampleTargets(rows, 10, [root]).map(row => row.pid), [10, 11]);
  assert.deepEqual(ownedSampleTargets(rows, 99, [root]), []);
  assert.deepEqual(ownedSampleTargets(rows, 10, ['/other']), []);
  assert.deepEqual(ownedSampleTargets(rows, 10), []);
});
test('sample filtering retains bounded stack symbols without image inventories or header data', () => {
  const raw = 'Process: private header\nArguments: secret\nCall graph:\n  99 thread worker\n    SecItemCopyMatching /fixture/file 0x123abc\nBinary Images:\n private loaded file list';
  const graph = callGraphOnly(raw, ['/fixture']);
  assert.match(graph, /SecItemCopyMatching/);
  assert.doesNotMatch(graph, /secret|private|0x123abc|\/fixture/);
  assert.match(graph, /\[ADDRESS\]/); assert.match(graph, /\[ISOLATED_PATH\]/);
  assert.equal(callGraphOnly('No stack; access denied', []), null);
  assert.ok(callGraphOnly('Call graph:\n' + 'x'.repeat(200000), []).length <= 128 * 1024 + 1);
});
test('manual observer workflow has only read access and downloads one fixed existing artifact', () => {
  const file = fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/desktop-cookie-diagnostic.yml'), 'utf8');
  assert.match(file, /workflow_dispatch/); assert.match(file, /runs-on: macos-15/);
  assert.match(file, /contents: read/); assert.match(file, /actions: read/);
  assert.match(file, /artifact-ids: '11310884356'/); assert.match(file, /run-id: '37224078859'/);
  assert.doesNotMatch(file, /pip install|npm ci|PyInstaller|package:mac|schedule:|self-hosted|write/);
});
test('observer cannot rebuild or modify candidate or manipulate keychains/security controls', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/diagnose-cookie-hang.cjs'), 'utf8');
  assert.match(source, /reproduction_count = 1/);
  assert.match(source, /\/usr\/bin\/sample/);
  assert.match(source, /\/usr\/bin\/pgrep/);
  assert.doesNotMatch(source, /execFileSync\('\/usr\/bin\/security'|--no-sandbox|--use-mock-keychain|password-store|setUsePlainTextEncryption|codesign[^\n]*--sign|xattr|execFileSync\('sudo'/);
});
