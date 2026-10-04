'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { BrowserEngine, partitionFor, guestURL, routing, validateCommand, publicHost } = require('../src/browser-engine.cjs');
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function fixture() {
  const profiles = new Map(['alpha', 'beta', 'gamma'].map(id => [id, { id, origin: 'local', engine_id: 'electron_chromium', network_policy: 'local_direct', proxy_config: null, revision: 1, state: 'stopped' }]));
  const sessions = new Map(), calls = [], leases = new Set(), views = [];
  const metadata = {
    async get(id) { if (!profiles.has(id)) throw new Error('Missing'); return { ...profiles.get(id) }; },
    async claim(id, revision) { assert.equal(profiles.get(id).revision, revision); calls.push(['claim', id]); leases.add(id); const value = { ...profiles.get(id), revision: revision + 1, state: 'running' }; profiles.set(id, value); return { ...value }; },
    async release(id) { calls.push(['release', id]); leases.delete(id); profiles.get(id).state = 'stopped'; },
  };
  const adapter = {
    versions: { electron: 'fixture', chromium: 'fixture' },
    session(partition) {
      if (!sessions.has(partition)) sessions.set(partition, {
        partition, cookies: new Map(), storage: new Map(),
        async setProxy(route) { calls.push(['proxy', partition, route]); this.route = route; },
        async closeAllConnections() { calls.push(['closeConnections', partition]); },
        flushStorageData() { calls.push(['flush', partition]); },
      });
      return sessions.get(partition);
    },
    secureSession(session, permit) { session.permit = permit; },
    createView(session) {
      const wc = new EventEmitter(); let url = '', destroyed = false;
      wc.navigationHistory = { canGoBack: () => false, canGoForward: () => false, goBack() {}, goForward() {} };
      wc.getURL = () => url; wc.getTitle = () => ''; wc.isLoading = () => false; wc.isDestroyed = () => destroyed;
      wc.setWebRTCIPHandlingPolicy = policy => { wc.policy = policy; };
      wc.setWindowOpenHandler = handler => { wc.popup = handler; };
      wc.loadURL = async value => { calls.push(['navigate', value]); url = value; };
      wc.reload = () => { calls.push(['reload']); }; wc.stop = () => { calls.push(['stop']); };
      wc.close = () => { destroyed = true; wc.emit('destroyed'); };
      const view = { webContents: wc, session }; views.push(view); return view;
    },
    attach(view) { calls.push(['attach', view]); }, detach(view) { calls.push(['detach', view]); },
    show(view, visible) { view.visible = visible; },
    async close(view) { view.webContents.close(); return true; },
    async stopWorkers(session) { calls.push(['workers', session.partition]); },
  };
  const changes = [];
  const engine = new BrowserEngine({ adapter, metadata, emit: x => changes.push(x) });
  return { engine, metadata, adapter, profiles, sessions, calls, leases, views, changes };
}
const activate = id => ({ action: 'activate_profile', profile_id: id });
const create = (id, url = 'about:blank') => ({ action: 'create_tab', profile_id: id, url });

test('partition identity is stable, distinct, opaque and rejects path-like identifiers', () => {
  assert.equal(partitionFor('alpha'), partitionFor('alpha')); assert.notEqual(partitionFor('alpha'), partitionFor('beta'));
  assert.match(partitionFor('alpha'), /^persist:tbm-[a-f0-9]{64}$/);
  for (const id of ['../../elsewhere', '', 'UPPER', 'a/b']) assert.throws(() => partitionFor(id));
});
test('guest navigation rejects local, encoded-local, link-local, file, and credential-bearing destinations', () => {
  for (const url of ['http://localhost/', 'http://127.1/', 'http://2130706433/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://10.0.0.1/', 'http://169.254.169.254/', 'http://172.16.0.1/', 'http://192.168.1.1/', 'http://100.64.0.1/', 'file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@example.com/', 'http://metadata.google.internal/', 'http://printer.local/', 'https://a\\@127.0.0.1/']) assert.throws(() => guestURL(url), url);
  assert.equal(guestURL('https://example.com/'), 'https://example.com/');
  assert.equal(guestURL('about:blank'), 'about:blank');
  assert.equal(publicHost('8.8.8.8'), true);
});
test('fixed public proxy syntax has no direct fallback, PAC, credentials, or bypass fields', () => {
  const profile = { origin: 'local', engine_id: 'electron_chromium', network_policy: 'verified_proxy', proxy_config: { protocol: 'socks5', hostname: 'proxy.example.com', port: 1080, label: 'Work' } };
  assert.deepEqual(routing(profile), { mode: 'fixed_servers', proxyRules: 'socks5://proxy.example.com:1080', proxyBypassRules: '' });
  for (const proxy of [{ ...profile.proxy_config, username: 'secret' }, { ...profile.proxy_config, hostname: 'proxy.example.com;DIRECT' }, { ...profile.proxy_config, hostname: 'localhost' }, { ...profile.proxy_config, protocol: 'pac' }]) assert.throws(() => routing({ ...profile, proxy_config: proxy }));
  assert.throws(() => routing({ ...profile, engine_id: 'camoufox' }));
  assert.throws(() => routing({ ...profile, origin: 'managed' }));
});
test('activation never creates/navigates a tab; profile switching keeps the same live views', async () => {
  const f = fixture(); await f.engine.command(activate('alpha')); assert.equal(f.views.length, 0);
  await f.engine.command(create('alpha', 'https://example.com/a')); const alpha = f.views[0];
  await f.engine.command(create('beta', 'https://example.org/b')); const beta = f.views[1];
  await f.engine.command({ action: 'set_content_bounds', x: 260, y: 180, width: 800, height: 600, visible: true });
  const navigations = f.calls.filter(x => x[0] === 'navigate').length;
  for (let i = 0; i < 8; i++) { await f.engine.command(activate('alpha')); await f.engine.command(activate('beta')); }
  assert.equal(f.views[0], alpha); assert.equal(f.views[1], beta); assert.equal(alpha.visible, false); assert.equal(beta.visible, true);
  assert.equal(f.calls.filter(x => x[0] === 'navigate').length, navigations);
  assert.notEqual(alpha.session, beta.session); assert.equal(alpha.webContents.policy, 'disable_non_proxied_udp');
  const snapshot = f.engine.snapshot(); assert.equal(snapshot.profile_id, 'beta'); assert.equal(snapshot.profile.revision, snapshot.profile_revision);
});
test('session proxy completes before any guest view or navigation is created', async () => {
  const f = fixture(), gate = deferred(); const session = f.adapter.session(partitionFor('alpha'));
  session.setProxy = async () => gate.promise;
  const pending = f.engine.command(create('alpha', 'https://example.com/'));
  await new Promise(setImmediate); assert.equal(f.views.length, 0);
  gate.resolve(); await pending; assert.equal(f.views.length, 1);
  assert.equal(session.permit('http://127.0.0.1:1234/local/config'), false);
});
test('latest selection wins across slow configuration and hiding never waits behind it', async () => {
  const f = fixture(); await f.engine.command(create('alpha'));
  await f.engine.command({ action: 'set_content_bounds', x: 200, y: 160, width: 600, height: 400, visible: true });
  const gate = deferred(); f.adapter.session(partitionFor('beta')).setProxy = async () => gate.promise;
  const beta = f.engine.command(activate('beta')); await new Promise(setImmediate);
  const gamma = f.engine.command(activate('gamma'));
  await f.engine.command({ action: 'hide_content' }); assert.equal(f.views[0].visible, false);
  gate.resolve(); await Promise.all([beta, gamma]); assert.equal(f.engine.snapshot().profile_id, 'gamma');
  assert.equal(f.changes.some(x => x.profile_id === 'beta'), false);
});
test('slow website loads do not block tab switching or closing commands', async () => {
  const f = fixture(); await f.engine.command(create('alpha')); const tab = f.engine.snapshot().tabs[0];
  f.views[0].webContents.loadURL = () => new Promise(() => {});
  await f.engine.command({ action: 'navigate', profile_id: 'alpha', tab_id: tab.id, url: 'https://example.com/slow' });
  await f.engine.command(activate('beta')); assert.equal(f.engine.snapshot().profile_id, 'beta');
  await f.engine.command({ action: 'close_tab', profile_id: 'alpha', tab_id: tab.id }); assert.equal(f.engine.tabs.size, 0);
});
test('main rereads metadata; renderer cannot override routing or cross profile tab ownership', async () => {
  const f = fixture(); await f.engine.command(create('alpha')); const tab = f.engine.snapshot().tabs[0];
  await assert.rejects(f.engine.command({ action: 'close_tab', profile_id: 'beta', tab_id: tab.id }));
  assert.throws(() => validateCommand({ ...create('alpha'), proxy: { mode: 'direct' } }));
  f.profiles.get('alpha').proxy_config = { protocol: 'http', hostname: 'proxy.example.com', port: 8000 };
  f.profiles.get('alpha').network_policy = 'verified_proxy';
  await assert.rejects(f.engine.command(activate('alpha')), /Close this profile/);
});
test('stopping fences network and closes workers/connections before releasing ownership, without clearing storage', async () => {
  const f = fixture(); await f.engine.command(create('alpha')); const session = f.views[0].session;
  session.cookies.set('fixture', 'kept'); session.storage.set('fixture', 'kept');
  await f.engine.command({ action: 'close_profile', profile_id: 'alpha' });
  assert.equal(session.permit('https://example.com/'), false); assert.equal(f.leases.size, 0);
  assert.equal(session.cookies.get('fixture'), 'kept'); assert.equal(session.storage.get('fixture'), 'kept');
  const events = f.calls.map(x => x[0]); assert.ok(events.lastIndexOf('workers') < events.lastIndexOf('release'));
  assert.ok(events.lastIndexOf('closeConnections') < events.lastIndexOf('release'));
  await f.engine.command(create('alpha')); assert.equal(f.views[1].session, session);
});
test('unconfirmed close/worker stop retains ownership and never silently loses active state', async () => {
  const f = fixture(); await f.engine.command(create('alpha'));
  f.adapter.close = async () => false;
  await assert.rejects(f.engine.command({ action: 'close_profile', profile_id: 'alpha' }));
  assert.equal(f.leases.has('alpha'), true); assert.equal(f.views[0].session.permit('https://example.com/'), true);
  f.adapter.close = async view => { view.webContents.close(); return true; };
  f.adapter.stopWorkers = async () => { throw new Error('unconfirmed'); };
  await assert.rejects(f.engine.command({ action: 'close_profile', profile_id: 'alpha' }));
  assert.equal(f.leases.has('alpha'), true); assert.equal(f.views[0].session.permit('https://example.com/'), false);
});
test('guest popup is a new same-profile isolated tab, never a native popup window', async () => {
  const f = fixture(); await f.engine.command(create('alpha'));
  assert.deepEqual(f.views[0].webContents.popup({ url: 'https://example.com/popup' }), { action: 'deny' });
  await f.engine.queue; assert.equal(f.engine.snapshot().tabs.length, 2);
  assert.equal(f.views[0].session, f.views[1].session);
  assert.deepEqual(f.views[0].webContents.popup({ url: 'file:///etc/passwd' }), { action: 'deny' });
  await f.engine.queue; assert.equal(f.engine.snapshot().tabs.length, 2);
});

test('layout-only bounds and hide never emit semantic updates or recurse into renderer redraw', async () => {
  const f = fixture(); await f.engine.command(create('alpha'));
  const count = f.changes.length;
  for (let i = 0; i < 10; i++) {
    await f.engine.command({ action: 'set_content_bounds', x: 240, y: 180, width: 600, height: 400, visible: true });
    await f.engine.command({ action: 'hide_content' });
  }
  assert.equal(f.changes.length, count);
});

test('background profile or tab popup cannot change selected profile or visible guest', async () => {
  const f = fixture(); await f.engine.command(create('alpha')); const alpha = f.views[0];
  await f.engine.command(create('beta')); const beta = f.views[1];
  await f.engine.command({ action: 'set_content_bounds', x: 240, y: 180, width: 600, height: 400, visible: true });
  const sequence = f.engine.selectionSequence;
  assert.deepEqual(alpha.webContents.popup({ url: 'https://example.com/steal-focus' }), { action: 'deny' });
  await f.engine.queue;
  assert.equal(f.engine.selectionSequence, sequence); assert.equal(f.engine.activeProfile, 'beta');
  assert.equal(f.views.length, 2); assert.equal(alpha.visible, false); assert.equal(beta.visible, true);
  await f.engine.command(create('beta')); const count = f.views.length;
  assert.deepEqual(beta.webContents.popup({ url: 'https://example.com/background-tab' }), { action: 'deny' });
  await f.engine.queue; assert.equal(f.views.length, count);
});
