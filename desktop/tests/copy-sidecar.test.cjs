'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { copyBundledSidecar, inspectSidecar } = require('../scripts/copy-sidecar.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tbm-sidecar-copy-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'), destination = path.join(root, 'bundle');
  fs.mkdirSync(path.join(source, '_internal/Python.framework/Versions/3.12/Resources'), { recursive: true });
  fs.writeFileSync(path.join(source, '_internal/Python.framework/Versions/3.12/Python'), 'synthetic executable');
  fs.symlinkSync('3.12', path.join(source, '_internal/Python.framework/Versions/Current'));
  fs.symlinkSync('Versions/Current/Python', path.join(source, '_internal/Python.framework/Python'));
  fs.symlinkSync('Versions/Current/Resources', path.join(source, '_internal/Python.framework/Resources'));
  fs.symlinkSync('Python.framework/Python', path.join(source, '_internal/Python'));
  return { root, source, destination };
}
test('bundled sidecar preserves relative framework links after build source is removed', t => {
  const { source, destination } = fixture(t);
  const before = inspectSidecar(source);
  assert.equal(copyBundledSidecar(source, destination).relative_internal_symlinks, 4);
  assert.deepEqual(inspectSidecar(destination), before);
  fs.rmSync(source, { recursive: true });
  assert.equal(fs.readFileSync(path.join(destination, '_internal/Python'), 'utf8'), 'synthetic executable');
  assert.equal(inspectSidecar(destination).size, 4);
});
test('absolute, escaped and dangling sidecar links fail before copying', t => {
  const { root, source, destination } = fixture(t);
  const bad = path.join(source, 'bad-link');
  for (const target of [path.join(source, '_internal/Python'), '../outside', 'missing']) {
    fs.symlinkSync(target, bad);
    assert.throws(() => copyBundledSidecar(source, destination), /Sidecar symlink/);
    assert.equal(fs.existsSync(destination), false);
    fs.unlinkSync(bad);
  }
  fs.mkdirSync(destination);
  assert.throws(() => copyBundledSidecar(source, destination), /must be new/);
  assert.ok(fs.existsSync(root));
});
