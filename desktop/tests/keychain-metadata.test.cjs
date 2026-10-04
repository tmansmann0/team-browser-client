'use strict';
// Pure schema/launcher contracts. These tests never call Apple's Security APIs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { REPORT_LIMIT, parseMetadata, probeEnvironment, probe } = require('../scripts/compare-keychain-metadata.cjs');
const reference = { copy_default_status: 0, default_reference_returned: true, lock_status_known: false };
const unavailable = { copy_default_status: -25307, default_reference_returned: false, lock_status_known: false };
test('metadata schema preserves reference errors without inferring database availability or lock state', () => {
  for (const value of [reference, unavailable]) assert.deepEqual(parseMetadata(JSON.stringify(value)), value);
  assert.throws(() => parseMetadata(JSON.stringify({ ...reference, lock_status_known: true })));
  assert.throws(() => parseMetadata(JSON.stringify({ ...reference, path: '/private/path' })));
  assert.throws(() => parseMetadata(JSON.stringify({ ...reference, copy_default_status: 1.5 })));
  assert.throws(() => parseMetadata('x'.repeat(1025)));
});
test('comparison changes only HOME and excludes credentials and loader overrides', () => {
  const source = { HOME: '/Users/runner', USER: 'runner', LOGNAME: 'runner', TMPDIR: '/tmp',
    GITHUB_TOKEN: 'must-not-pass', DYLD_INSERT_LIBRARIES: 'must-not-pass', NODE_OPTIONS: 'must-not-pass' };
  const normal = probeEnvironment(source, source.HOME), empty = probeEnvironment(source, '/tmp/empty');
  assert.deepEqual({ ...normal, HOME: '/tmp/empty' }, empty);
  assert.deepEqual(Object.keys(normal).sort(), ['HOME', 'LANG', 'LC_ALL', 'LOGNAME', 'PATH', 'TMPDIR', 'USER']);
  assert.equal(source.HOME, '/Users/runner');
  assert.throws(() => probeEnvironment(source, 'relative'));
});
test('probe invokes only fixed helper without arguments, bounds it, and discards raw failures', () => {
  const env = { HOME: '/fixture' };
  const result = probe('/fixture/helper', env, (file, args, options) => {
    assert.equal(file, '/fixture/helper'); assert.deepEqual(args, []); assert.equal(options.env, env);
    assert.equal(options.timeout, 5000); assert.equal(options.killSignal, 'SIGKILL');
    assert.equal(options.maxBuffer, 4096); assert.equal(options.shell, false);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'ignore']);
    return { status: 0, stdout: JSON.stringify(reference) };
  });
  assert.equal(result.output_valid, true); assert.deepEqual(result.metadata, reference);
  for (const failure of [{ status: null, error: { code: 'ETIMEDOUT', message: 'private' }, stdout: 'private' },
    { status: 1, stdout: 'private', stderr: 'private' }, { status: 0, stdout: '{"secret":"private"}' }]) {
    const report = probe('/fixture/helper', env, () => failure);
    assert.equal(report.output_valid, false); assert.equal(report.metadata, null);
    assert.doesNotMatch(JSON.stringify(report), /private|secret/);
  }
});
test('native helper calls only CopyDefault and never opens, queries items, or asks for lock status', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/default-keychain-metadata.c'), 'utf8');
  assert.deepEqual([...source.matchAll(/\b(Sec\w+)\s*\(/g)].map(match => match[1]), ['SecKeychainCopyDefault']);
  assert.doesNotMatch(source, /getenv|system\(|exec|fopen|SecItem|Authorization|SecKeychainGetStatus|SetUserInteraction/);
});
test('C output contract with compile-time API stubs is not native Keychain evidence', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-keychain-contract-'));
  fs.mkdirSync(path.join(root, 'Security')); fs.mkdirSync(path.join(root, 'CoreFoundation'));
  fs.writeFileSync(path.join(root, 'CoreFoundation/CoreFoundation.h'), 'static void CFRelease(const void *ref) { (void)ref; }\n');
  fs.writeFileSync(path.join(root, 'Security/Security.h'), `#include <stddef.h>
    typedef const void *SecKeychainRef; typedef int OSStatus;
    static OSStatus SecKeychainCopyDefault(SecKeychainRef *out) {
      *out = COPY_RESULT == 0 ? (const void *)1 : NULL; return COPY_RESULT;
    }
\n`);
  const source = path.resolve(__dirname, '../scripts/default-keychain-metadata.c');
  for (const [copy, expected] of [[0, reference], [-25307, unavailable]]) {
    const exe = path.join(root, `stub-${copy}`);
    execFileSync('cc', ['-std=c11', '-I', root, `-DCOPY_RESULT=${copy}`, source, '-o', exe], { timeout: 15000, stdio: 'pipe' });
    assert.deepEqual(parseMetadata(execFileSync(exe, { encoding: 'utf8', timeout: 2000 })), expected);
  }
});
test('manual hosted workflow uploads only one bounded metadata report with one-day retention', () => {
  const workflow = fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/desktop-keychain-metadata.yml'), 'utf8');
  assert.match(workflow, /workflow_dispatch/); assert.match(workflow, /runs-on: macos-15/);
  assert.match(workflow, /contents: read/); assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /retention-days: 1/);
  assert.match(workflow, /path: desktop\/out\/default-keychain-metadata\.json/);
  assert.doesNotMatch(workflow, /download-artifact|schedule:|self-hosted|actions: write|npm ci|pip install|package:mac|security |\.zip/);
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/compare-keychain-metadata.cjs'), 'utf8');
  assert.match(source, /RUNNER_ENVIRONMENT, 'github-hosted'/);
  assert.match(source, /if \(report\.normal\.completed && report\.normal\.output_valid\)/);
  assert.doesNotMatch(source, /\/usr\/bin\/security|codesign|spawn\([^\n]*TeamBrowser|xattr|SetUserInteraction|keychain.*password/i);
  assert.ok(REPORT_LIMIT <= 1024 * 1024);
});
