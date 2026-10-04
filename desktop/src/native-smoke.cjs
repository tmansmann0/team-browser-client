'use strict';
// Fixed, opt-in diagnostic. No IPC/network listener, arbitrary script, or user data.
// Exercises the real packaged main/sidecar/adapter; only fixture transport is synthetic.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { guestURL } = require('./browser-engine.cjs');
const ORIGIN = 'https://native-smoke.example';
const FLAGS = ['--tbm-native-smoke-root=', '--tbm-native-smoke-phase='];
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
function config(argv, platform = process.platform, arch = process.arch) {
  const requested = argv.filter(arg => arg.startsWith('--tbm-native-smoke'));
  if (!requested.length) return null;
  assert.equal(platform, 'darwin', 'Native smoke requires macOS');
  assert.equal(arch, 'arm64', 'Native smoke requires Apple Silicon');
  assert.equal(requested.length, 2, 'Both exact smoke arguments are required');
  const values = FLAGS.map(flag => {
    const matches = requested.filter(arg => arg.startsWith(flag));
    assert.equal(matches.length, 1, 'Invalid smoke arguments');
    return matches[0].slice(flag.length);
  });
  const [root, phase] = values;
  assert.ok(['seed', 'reopen'].includes(phase), 'Invalid smoke phase');
  assert.ok(path.isAbsolute(root), 'Smoke root must be absolute');
  const canonical = fs.realpathSync(root);
  const temp = fs.realpathSync(os.tmpdir());
  assert.equal(path.dirname(canonical), temp, 'Smoke root must be directly inside OS temporary directory');
  assert.match(path.basename(canonical), /^tbm-native-smoke-[A-Za-z0-9]+$/, 'Invalid smoke root');
  assert.equal(fs.lstatSync(root).isSymbolicLink(), false, 'Smoke root cannot be a symlink');
  assert.equal(fs.readFileSync(path.join(root, 'fixture-marker'), 'utf8'), 'TeamBrowser blank native smoke v1\n');
  for (const name of ['home', 'user-data', 'session-data', 'evidence']) {
    const directory = path.join(canonical, name);
    if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
    assert.equal(fs.realpathSync(directory), directory, 'Smoke directories cannot redirect');
  }
  if (phase === 'seed') {
    for (const name of ['home', 'user-data', 'session-data']) assert.equal(fs.readdirSync(path.join(canonical, name)).length, 0, 'Seed smoke requires empty profiles');
  }
  return { root: canonical, phase };
}
function configure(app, input) {
  const value = config(input);
  if (!value) return null;
  assert.ok(app.isPackaged, 'Smoke must launch the packaged app');
  app.setPath('home', path.join(value.root, 'home'));
  app.setPath('userData', path.join(value.root, 'user-data'));
  app.setPath('sessionData', path.join(value.root, 'session-data'));
  return value;
}
async function until(check, message, ms = 15000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (await check()) return; await wait(100); }
  throw new Error(message);
}
function fixture(request) {
  const url = new URL(request.url);
  if (url.origin !== ORIGIN || url.pathname !== '/') return new Response('No external fixtures', { status: 403 });
  return new Response('<!doctype html><html><head><meta charset="utf-8"><title>TeamBrowser native fixture</title><style>body{margin:0;background:#edf5fc;color:#12314a;font:24px system-ui;padding:48px}h1{font-size:38px}#value{padding:24px;background:#164c72;color:white;border-radius:16px}</style></head><body><h1>Native profile storage fixture</h1><p>Controlled in-memory HTTPS document. No real account or network server.</p><div id="value">Uninitialized</div></body></html>', {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; frame-src 'none'; base-uri 'none'" },
  });
}
// Fixed test expressions only. No expression comes from arguments, a file, or a website.
const OPEN_DATABASE = `(async () => {
  await new Promise((resolve, reject) => {
    let settled = false;
    const fail = code => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error(code)); } };
    const timer = setTimeout(() => fail('indexeddb_open_renderer_timeout'), 4000);
    const r = indexedDB.open('tbm-native-smoke', 1);
    r.onblocked = () => fail('indexeddb_open_blocked');
    r.onerror = () => fail('indexeddb_open_' + (r.error?.name || 'error'));
    r.onupgradeneeded = () => { try { r.result.createObjectStore('values'); } catch { fail('indexeddb_upgrade_error'); } };
    r.onsuccess = () => { if (settled) { r.result.close(); return; } settled = true; clearTimeout(timer); window.smokeDatabase = r.result; resolve(); };
  }); return true;
})()`;
const READ_DATABASE = `(async () => {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('indexeddb_read_renderer_timeout')), 4000);
    const t = window.smokeDatabase.transaction('values');
    const r = t.objectStore('values').get('marker'); let value = null;
    r.onsuccess = () => { value = r.result ?? null; };
    t.oncomplete = () => { clearTimeout(timer); resolve(value); };
    t.onerror = t.onabort = () => { clearTimeout(timer); reject(new Error('indexeddb_read_' + (t.error?.name || 'aborted'))); };
  });
})()`;
async function boundedOperation(name, action, ms = 6000) {
  let timer;
  try { return await Promise.race([Promise.resolve().then(action), new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`Native operation timed out: ${name}`)), ms);
  })]); } finally { clearTimeout(timer); }
}
async function readStorage(wc, step) {
  const value = await step('read_origin_and_globals', () => wc.executeJavaScript(`({
    origin: location.origin, live: window.smokeLive ?? null, node: typeof process,
    require: typeof require, bridge: typeof TeamDesktop })`));
  value.cookie = await step('read_cookie', () => wc.executeJavaScript('document.cookie'));
  value.local = await step('read_localStorage', () => wc.executeJavaScript("localStorage.getItem('marker')"));
  await step('open_indexedDB_for_read', () => wc.executeJavaScript(OPEN_DATABASE));
  try { value.indexed = await step('read_indexedDB_transaction', () => wc.executeJavaScript(READ_DATABASE)); }
  finally { await step('close_indexedDB_after_read', () => wc.executeJavaScript('window.smokeDatabase?.close(); delete window.smokeDatabase; true')); }
  return value;
}
async function writeStorage(wc, label, step) {
  assert.ok(['A', 'B'].includes(label));
  await step('write_cookie', () => wc.executeJavaScript(`document.cookie = 'tbm_smoke=${label}; Max-Age=86400; Path=/; Secure; SameSite=Strict'; true`));
  await step('write_localStorage', () => wc.executeJavaScript(`localStorage.setItem('marker', '${label}'); true`));
  await step('open_indexedDB_for_write', () => wc.executeJavaScript(OPEN_DATABASE));
  try {
    await step('write_indexedDB_transaction', () => wc.executeJavaScript(`new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('indexeddb_write_renderer_timeout')), 4000);
      const t = window.smokeDatabase.transaction('values', 'readwrite');
      t.objectStore('values').put('${label}', 'marker');
      t.oncomplete = () => { clearTimeout(timer); resolve(true); };
      t.onerror = t.onabort = () => { clearTimeout(timer); reject(new Error('indexeddb_write_' + (t.error?.name || 'aborted'))); };
    })`));
  } finally { await step('close_indexedDB_after_write', () => wc.executeJavaScript('window.smokeDatabase?.close(); delete window.smokeDatabase; true')); }
  await step('set_live_document_marker', () => wc.executeJavaScript(`window.smokeLive = '${label}-live'; document.getElementById('value').textContent = 'Profile ${label}'; true`));
}
function verifyStorage(value, expected, live = null) {
  assert.equal(value.origin, ORIGIN, 'Fixture origin was not preserved');
  assert.equal(value.cookie, expected ? `tbm_smoke=${expected}` : '', 'Cookie isolation/persistence failed');
  assert.equal(value.local, expected, 'localStorage isolation/persistence failed');
  assert.equal(value.indexed, expected, 'IndexedDB isolation/persistence failed');
  assert.equal(value.live, live, 'Live document was recreated or crossed profiles');
  for (const key of ['node', 'require', 'bridge']) assert.equal(value[key], 'undefined', 'Guest exposed privileged capability');
}
// Electron v44.5.1 SaveLastPreferences serializes these booleans explicitly.
// devTools and preload are omitted from that snapshot; absence is not false.
// See shell/browser/web_contents_preferences.cc and api/electron_api_web_contents.cc.
const EXPECTED_PREFERENCES = Object.freeze({
  sandbox: true, contextIsolation: true, nodeIntegration: false,
  nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
  webviewTag: false, webSecurity: true, allowRunningInsecureContent: false,
});
function preferenceEvidence(preferences) {
  return Object.fromEntries(Object.keys(EXPECTED_PREFERENCES).map(key => [key,
    typeof preferences[key] === 'boolean' ? preferences[key] :
      preferences[key] === undefined ? 'missing' : 'unexpected_non_boolean']));
}
function verifyPreferences(evidence) {
  for (const [key, expected] of Object.entries(EXPECTED_PREFERENCES)) {
    assert.equal(evidence[key], expected, `Native guest preference ${key} must be ${expected}`);
  }
}
async function probeDevToolsDisabled(wc) {
  let opened = false;
  const observed = () => { opened = true; };
  wc.on('devtools-opened', observed);
  try {
    // This exercises the normal disabled control without changing any preference.
    // Pinned Electron returns immediately before creating DevTools when disabled.
    wc.openDevTools({ mode: 'detach', activate: false });
    await wait(150);
    const evidence = { opened_event: opened, is_open: wc.isDevToolsOpened(), contents_created: Boolean(wc.devToolsWebContents) };
    return evidence;
  } finally { wc.removeListener('devtools-opened', observed); }
}
function verifyDevToolsDisabled(evidence) {
  assert.deepEqual(evidence, { opened_event: false, is_open: false, contents_created: false }, 'Native guest allowed DevTools to open');
}
const GUEST_PRIVILEGES = `({ process: typeof process, require: typeof require,
  Buffer: typeof Buffer, ipcRenderer: typeof ipcRenderer, TeamDesktop: typeof TeamDesktop })`;
function verifyGuestPrivileges(evidence) {
  for (const key of ['process', 'require', 'Buffer', 'ipcRenderer', 'TeamDesktop']) {
    assert.equal(evidence[key], 'undefined', `Native guest exposed privileged global ${key}`);
  }
}
const CHROME_READY = `Boolean(document.readyState === 'complete' && window.TeamDesktop &&
  document.querySelector('.profile-manager') && document.querySelector('#new-profile') &&
  !document.querySelector('#new-profile').disabled &&
  !document.querySelector('#workspace-status .workspace-alert.error') && !document.querySelector('dialog[open]'))`;
async function capture(contents, target, step) {
  const frame = await step('wait_for_native_paint_frames', () => contents.executeJavaScript(`new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Native renderer did not produce two animation frames')), 4000);
    requestAnimationFrame(() => requestAnimationFrame(() => { clearTimeout(timer); resolve({ frames: 2, visibility: document.visibilityState }); }));
  })`));
  assert.equal(frame.visibility, 'visible', 'Native capture target was not visible');
  // rAF callbacks precede paint. Yield the main process before copying the frame.
  await wait(100);
  const image = await step('capture_native_surface', () => contents.capturePage());
  assert.equal(image.isEmpty(), false, 'Native capture was empty; rendering not established');
  const size = image.getSize();
  assert.ok(size.width >= 300 && size.height >= 100, 'Native surface was too small');
  const bitmap = image.toBitmap(), colors = new Set();
  for (let i = 0; i < bitmap.length && colors.size < 16; i += 4) colors.add(bitmap.readUInt32LE(i));
  assert.ok(colors.size >= 8, 'Native capture was blank; rendering not established');
  const png = image.toPNG();
  fs.writeFileSync(target, png);
  return { ...size, paint: frame, sha256: createHash('sha256').update(png).digest('hex') };
}
async function run({ smoke, app, window, engine, sidecar }) {
  const evidence = path.join(smoke.root, 'evidence');
  const report = { kind: 'packaged-native-synthetic-storage-smoke', phase: smoke.phase, status: 'running', native_acceptance: false, install_ready: false,
    platform: process.platform, architecture: process.arch, electron: process.versions.electron, chromium: process.versions.chrome,
    fixture_transport: 'session-scoped in-memory HTTPS handler; no network/TLS/proxy validation',
    limitations: ['Not real-account/provider login acceptance', 'Not network/proxy/DNS/TLS/leak acceptance', 'Not service-worker/cache acceptance', 'Not install/update/Gatekeeper acceptance', 'Not end-to-end mouse/keyboard or composited desktop verification'], checks: [] };
  const save = () => fs.writeFileSync(path.join(evidence, `${smoke.phase}.json`), JSON.stringify(report, null, 2) + '\n');
  const check = name => { report.checks.push(name); save(); };
  report.completed_operations = [];
  const step = prefix => async (name, action) => {
    const operation = `${prefix}:${name}`;
    report.active_operation = operation; save();
    try {
      const result = await boundedOperation(operation, action);
      report.completed_operations.push(operation); report.active_operation = null; save();
      return result;
    } catch (error) {
      report.failed_operation ||= operation; save(); throw error;
    }
  };
  save();
  try {
    assert.ok(app.isPackaged, 'Expected packaged Electron');
    assert.ok(sidecar.child && !sidecar.exited, 'Frozen sidecar did not remain running');
    report.sidecar_pid = sidecar.child.pid;
    check('packaged_app_and_frozen_sidecar_started');
    await until(() => window.isVisible(), 'Packaged app window was not shown');
    const chrome = expression => window.webContents.executeJavaScript(expression);
    await until(() => chrome(CHROME_READY), 'Bundled workspace did not settle into its usable profile manager');
    report.chrome_capture = await capture(window.webContents, path.join(evidence, `${smoke.phase}-chrome.png`), step('initial_chrome'));
    check('real_browser_window_and_settled_profile_manager_rendered');
    const api = (method, url, body) => chrome(`(async () => { const config = await (await fetch('/local/config')).json(); const response = await fetch(${JSON.stringify(url)}, {method:${JSON.stringify(method)}, headers:{'Content-Type':'application/json','X-Local-CSRF':config.csrf_token}, ${body === undefined ? '' : 'body:' + JSON.stringify(JSON.stringify(body))}}); if(!response.ok) throw new Error('Smoke workspace API failed'); return response.json(); })()`);
    let profiles = await api('GET', '/local/v1/profiles');
    if (smoke.phase === 'seed') {
      assert.equal(profiles.length, 0, 'Expected blank sidecar workspace');
      for (const label of ['A', 'B']) await api('POST', '/local/v1/profiles', { name: `Native smoke ${label}`, preset_id: 'desktop', network_policy: 'local_direct' });
      profiles = await api('GET', '/local/v1/profiles');
    }
    assert.equal(profiles.length, 2, 'Expected exactly two synthetic profiles');
    for (const label of ['A', 'B']) assert.equal(profiles.filter(item => item.name === `Native smoke ${label}`).length, 1);
    if (smoke.phase === 'reopen') { assert.ok(profiles.every(item => item.state === 'stopped'), 'Prior shutdown did not release profile leases'); check('metadata_persisted_and_previous_leases_released'); }
    // Reload the ordinary bundled UI after fixture creation so its own fetch/render
    // path displays the two durable profiles before any native tabs are opened.
    await window.webContents.loadURL(window.webContents.getURL());
    await until(() => chrome(CHROME_READY + " && document.querySelectorAll('[data-select]').length === 2"), 'Bundled workspace did not render both synthetic profiles');
    report.profiles_chrome_capture = await capture(window.webContents, path.join(evidence, `${smoke.phase}-profiles-chrome.png`), step('profiles_chrome'));
    if (smoke.phase === 'seed') assert.notEqual(report.chrome_capture.sha256, report.profiles_chrome_capture.sha256, 'Compositor returned unchanged chrome after profiles were created');
    check('bundled_profile_manager_displays_both_durable_synthetic_profiles');
    report.guest_security = {};
    const command = value => chrome(`window.TeamDesktop.command(${JSON.stringify(value)})`);
    const views = new Map(), sessions = new Set();
    for (const label of ['A', 'B']) {
      const profile = profiles.find(item => item.name === `Native smoke ${label}`);
      await command({ action: 'activate_profile', profile_id: profile.id, expected_revision: profile.revision });
      const owned = engine.profiles.get(profile.id);
      assert.ok(owned, 'Real engine did not claim profile');
      assert.equal(sessions.has(owned.session), false, 'Profiles shared one Electron session'); sessions.add(owned.session);
      // This does not relax guestURL, webRequest, sandbox, CSP, or permission policy.
      // It substitutes fixed response bytes only for this diagnostic's blank sessions.
      assert.equal(guestURL(ORIGIN + '/'), ORIGIN + '/');
      owned.session.protocol.handle('https', fixture);
      await command({ action: 'create_tab', profile_id: profile.id, url: ORIGIN + '/' });
      const tab = engine.tabs.get(engine.snapshot().active_tab_id);
      assert.ok(tab && window.contentView.children.includes(tab.view), 'Guest is not a native child view');
      await command({ action: 'set_content_bounds', x: 280, y: 140, width: 950, height: 500, visible: true });
      assert.equal(tab.view.getVisible(), true, 'Native guest must be displayed before storage probes');
      const wc = tab.view.webContents;
      const security = { preferences: preferenceEvidence(wc.getLastWebPreferences()),
        snapshot_omissions: ['devTools', 'preload'],
        native_view: { visible: tab.view.getVisible(), bounds: tab.view.getBounds() } };
      report.guest_security[label] = security; save();
      verifyPreferences(security.preferences);
      await until(() => !wc.isLoading() && wc.getURL() === ORIGIN + '/', 'Native fixture navigation did not finish');
      await until(() => wc.executeJavaScript("Boolean(document.getElementById('value'))"), 'Native fixture DOM did not render');
      security.privileged_globals = await wc.executeJavaScript(GUEST_PRIVILEGES); save();
      verifyGuestPrivileges(security.privileged_globals);
      security.devtools_probe = await probeDevToolsDisabled(wc); save();
      verifyDevToolsDisabled(security.devtools_probe);
      check(`native_guest_${label}_strict_preferences_and_privilege_probes_passed`);
      verifyStorage(await readStorage(wc, step(`${label}_initial_storage`)), smoke.phase === 'seed' ? null : label);
      await writeStorage(wc, label, step(`${label}_write_storage`));
      verifyStorage(await readStorage(wc, step(`${label}_after_write`)), label, label + '-live');
      views.set(label, { profile, tab, wc });
    }
    const first = views.get('A');
    await assert.rejects(command({ action: 'navigate', profile_id: first.profile.id, tab_id: first.tab.id, url: 'http://127.0.0.1:8765/' }));
    check('production_guest_private_address_policy_remains_enforced');
    check(smoke.phase === 'seed' ? 'real_A_B_cookie_localStorage_IndexedDB_isolation' : 'real_A_B_cookie_localStorage_IndexedDB_restart_persistence');
    for (let index = 0; index < 12; index++) {
      const label = index % 2 ? 'B' : 'A';
      const current = views.get(label);
      await command({ action: 'activate_tab', profile_id: current.profile.id, tab_id: current.tab.id });
      await command({ action: 'set_content_bounds', x: 280, y: 140, width: 950, height: 640, visible: true });
      assert.equal(engine.snapshot().profile_id, current.profile.id);
      assert.ok(current.tab.view.getVisible(), 'Selected native view was not visible');
      for (const [otherLabel, other] of views) if (otherLabel !== label) assert.equal(other.tab.view.getVisible(), false, 'Background native view remained visible');
      verifyStorage(await readStorage(current.wc, step(`${label}_switch_${index}`)), label, label + '-live');
    }
    check('twelve_switches_keep_distinct_live_native_documents');
    for (const [label, item] of views) {
      await command({ action: 'activate_tab', profile_id: item.profile.id, tab_id: item.tab.id });
      await command({ action: 'set_content_bounds', x: 280, y: 140, width: 950, height: 640, visible: true });
      await wait(150);
      report[`${label}_capture`] = await capture(item.wc, path.join(evidence, `${smoke.phase}-profile-${label}.png`), step(`${label}_capture`));
      assert.ok(item.wc.getOSProcessId() > 0, 'Native renderer process absent');
    }
    check('both_native_guest_surfaces_have_nonblank_captures');
    // Normal before-quit handler must close views, flush storage, release leases,
    // and stop the owned sidecar. Do not set quitApproved or bypass that path.
    app.once('will-quit', () => {
      try {
        assert.equal(sidecar.exited, true, 'Sidecar shutdown was not confirmed');
        assert.equal(engine.profiles.size, 0, 'Native profile ownership was not released');
        assert.equal(engine.tabs.size, 0, 'Native guest views survived shutdown');
        report.status = 'passed'; check('normal_app_quit_closed_views_released_leases_and_stopped_sidecar');
      } catch (error) { report.status = 'failed'; report.failure = error.message; save(); }
    });
    report.status = 'awaiting_normal_shutdown'; save(); app.quit();
  } catch (error) {
    report.status = 'failed'; report.failure = error.message; save(); app.quit();
  }
}
function startupFailure(smoke, message) {
  fs.writeFileSync(path.join(smoke.root, 'evidence', `${smoke.phase}.json`), JSON.stringify({
    kind: 'packaged-native-synthetic-storage-smoke', phase: smoke.phase, status: 'failed',
    native_acceptance: false, install_ready: false, checks: [], failure: message,
  }, null, 2) + '\n');
}
module.exports = { config, configure, run, fixture, verifyStorage, ORIGIN, startupFailure, preferenceEvidence, verifyPreferences, probeDevToolsDisabled, verifyDevToolsDisabled, verifyGuestPrivileges, CHROME_READY, boundedOperation, readStorage, writeStorage, OPEN_DATABASE, READ_DATABASE };
