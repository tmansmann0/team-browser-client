'use strict';
// Keep PyInstaller's internal relative framework links portable when bundling.
const fs = require('node:fs');
const path = require('node:path');

function contained(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep));
}
function inspectSidecar(root) {
  if (!fs.lstatSync(root).isDirectory()) throw new Error('Sidecar root must be a real directory');
  const canonical = fs.realpathSync(root);
  const links = new Map();
  function visit(directory) {
    for (const name of fs.readdirSync(directory)) {
      const entry = path.join(directory, name), info = fs.lstatSync(entry);
      if (info.isSymbolicLink()) {
        const target = fs.readlinkSync(entry);
        if (path.isAbsolute(target) || !contained(canonical, path.resolve(path.dirname(entry), target))) {
          throw new Error('Sidecar symlink must stay relative and internal');
        }
        let resolved;
        try { resolved = fs.realpathSync(entry); } catch { throw new Error('Sidecar symlink must have a valid internal target'); }
        if (!contained(canonical, resolved)) throw new Error('Sidecar symlink resolves outside its bundle');
        links.set(path.relative(canonical, entry), target);
      } else if (info.isDirectory()) visit(entry);
      else if (!info.isFile()) throw new Error('Sidecar contains an unsupported filesystem entry');
    }
  }
  visit(canonical);
  return links;
}
function copyBundledSidecar(source, destination) {
  const expected = inspectSidecar(source);
  if (fs.existsSync(destination)) throw new Error('Bundled sidecar destination must be new');
  fs.cpSync(source, destination, { recursive: true, verbatimSymlinks: true, force: false, errorOnExist: true });
  const actual = inspectSidecar(destination);
  if (expected.size !== actual.size || [...expected].some(([name, target]) => actual.get(name) !== target)) {
    throw new Error('Bundled sidecar symlinks changed while copying');
  }
  return { relative_internal_symlinks: actual.size };
}
module.exports = { inspectSidecar, copyBundledSidecar };
