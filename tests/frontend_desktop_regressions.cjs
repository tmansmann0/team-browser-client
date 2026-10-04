'use strict';
// Desktop integration source contracts using a small synthetic DOM and bridge.
// This is not rendered-browser, native Electron, focus-trapping, or site acceptance QA.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(process.argv[2] || path.join(root, 'src/team_browser/static/workspace.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'src/team_browser/static/index.html'), 'utf8');
const nativeManagedSource = fs.readFileSync(path.join(root, 'src/team_browser/static/managed_workspace.js'), 'utf8');
const managedSource = fs.readFileSync(path.join(root, 'src/team_browser/static/managed.js'), 'utf8');
const legacy = fs.readFileSync(path.join(root, 'src/team_browser/static/app.js'), 'utf8');
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const decode = value => String(value).replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
function scenario({savedMode = null, configAvailable = true, synthetic = false, autoMount = true, nativeSupported = false} = {}) {
  const elements = new Map();
  const windowListeners = {};
  const all = [];
  const document = {title: '', activeElement: null};
  function parseAttributes(raw) {
    const attrs = {};
    for (const match of raw.matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[match[1]] = decode(match[2] ?? '');
    return attrs;
  }
  function applyAttributes(el, attrs) {
    el.attrs = {...el.attrs, ...attrs};
    el.disabled = Object.hasOwn(attrs, 'disabled'); el.hidden = Object.hasOwn(attrs, 'hidden');
    el.checked = Object.hasOwn(attrs, 'checked');
    if (Object.hasOwn(attrs, 'value')) el.value = attrs.value;
    for (const [key, value] of Object.entries(attrs)) if (key.startsWith('data-')) el.dataset[key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  function element(key = 'anonymous-' + all.length) {
    if (elements.has(key)) return elements.get(key);
    const el = {key, tagName: '', attrs: {}, dataset: {}, listeners: {}, children: [], value: '', textContent: '', disabled: false, hidden: false, open: false, checked: false, scrollTop: 0,
      classList: {toggle() {}},
      addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
      async dispatch(name, event = {}) { const e = {target: this, preventDefault() { this.defaultPrevented = true; }, ...event}; for (const fn of this.listeners[name] || []) await fn(e); return e; },
      setAttribute(k, v) { this.attrs[k] = String(v); }, removeAttribute(k) { delete this.attrs[k]; },
      focus() { document.activeElement = this; }, scrollIntoView() {},
      showModal() { this.open = true; }, close() { this.open = false; for (const fn of this.listeners.close || []) fn(); },
      appendChild(child) { this.children.push(child); },
      querySelector(selector) { return this.querySelectorAll(selector)[0] || element(key + ' ' + selector); },
      querySelectorAll(selector) {
        if (selector === 'input,select,button') return all.filter(e => ['INPUT', 'SELECT', 'BUTTON'].includes(e.tagName));
        const candidates = this.key === 'detail-dialog' ? element('drawer-content').children : this.children;
        if (selector.startsWith('.')) return candidates.filter(e => (e.attrs.class || '').split(' ').includes(selector.slice(1)));
        const attr = selector.match(/^\[([\w-]+)\]$/);
        return attr ? candidates.filter(e => Object.hasOwn(e.attrs, attr[1])) : [];
      }
    };
    let inner = '';
    Object.defineProperty(el, 'innerHTML', {get() { return inner; }, set(value) {
      inner = String(value); this.children = [];
      for (const match of inner.matchAll(/<(button|input|select|form|div|span|a|p|option|h[1-6]|section|meter|article)\b([^>]*)>/g)) {
        const attrs = parseAttributes(match[2]);
        const child = element(attrs.id || key + '/' + this.children.length);
        child.listeners = {}; child.tagName = match[1].toUpperCase(); applyAttributes(child, attrs);
        this.children.push(child);
      }
      // A select defaults to its first option, as it does in the browser.
      for (const match of inner.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g)) {
        const attrs = parseAttributes(match[1]);
        const options = [...match[2].matchAll(/<option\b([^>]*)>/g)].map(m => parseAttributes(m[1]));
        if (attrs.id && options.length) element(attrs.id).value = (options.find(o => Object.hasOwn(o, 'selected')) || options[0]).value || '';
      }
    }});
    elements.set(key, el); all.push(el); return el;
  }
  document.getElementById = element;
  document.querySelector = selector => element(selector.startsWith('#') ? selector.slice(1) : selector);
  document.querySelectorAll = () => [];
  document.createElement = tag => { const el = element(); el.tagName = tag.toUpperCase(); return el; };
  // Static shell elements are represented by their real IDs and all bindings are
  // exercised against the generated markup parsed above, not screenshot claims.
  element('root').innerHTML = html;
  const data = {
    profiles: [
      {id: 'local_one', name: 'Research', preset_id: 'standard', engine_id: 'chromium', favorite: false, created_at: '2026-10-01T00:00:00Z', network_policy: 'unconfigured', origin: 'local', revision: 1, state: 'stopped', selected: false, last_selected_at: null, blockers: []},
      {id: 'local_two', name: 'Creative', preset_id: 'focused', engine_id: 'chromium', favorite: true, created_at: '2026-10-02T00:00:00Z', network_policy: 'local_direct', origin: 'local', revision: 2, state: 'blocked', selected: false, last_selected_at: '2026-10-02T10:00:00Z', blockers: ['Runtime not verified.']}
    ],
    presets: [{id: 'standard', name: 'Standard', engine_id: 'chromium'}, {id: 'focused', name: 'Focused', engine_id: 'chromium'}],
    settings: {revision: 1, max_warm_profiles: 3, memory_budget_mb: 2048, estimated_profile_mb: 512},
    native: {status: 'unconfigured', configured: false, identity_verified: false, company_membership_verified: false, managed_access_available: false, device_enrolled: false, native_integration_verified: false, server_authoritative: true, expires_at: null, pending_operation: null, native_operations_pending: false, can_cancel: false, cancellation_requested: false, shutting_down: false, capabilities: {}, membership: null, profiles: [], presets: []},
    managed: {revision: 1, server_url: null, status: 'not_enrolled'}, selected: null
  };
  const config = () => ({mode: 'local', account_required: false, persistent: true, api_base: '/local/v1', csrf_token: 'csrf-fixture', managed_native: nativeSupported ? {supported: true, configured: false} : undefined, selected_profile_id: data.selected, launch: {available: synthetic, actual_process_available: false, execution_kind: synthetic ? 'synthetic' : 'unavailable', blockers: synthetic ? [] : ['A verified, pinned and signed browser runtime is not configured.']}, inbox: {native_open_available: false}});
  const calls = [], notices = [], control = {failure: null, failRead: false, pending: false, holdSelection: false, releaseSelection: null};
  const response = (status, body) => ({ok: status >= 200 && status < 300, status, json: async () => structuredClone(body)});
  const fetch = async (url, options = {}) => {
    calls.push({url, options});
    assert.equal(options.credentials, 'omit');
    if (url === '/local/config') return response(configAvailable ? 200 : 404, config());
    assert(url.startsWith('/local/v1/'), 'Only the fixed local endpoint is used');
    const suffix = url.slice('/local/v1'.length);
    const method = options.method || 'GET';
    if (method === 'GET') {
      if (control.failRead) throw new Error('service offline');
      if (suffix === '/profiles') return response(200, data.profiles);
      if (suffix === '/presets') return response(200, data.presets);
      if (suffix === '/settings') return response(200, data.settings);
      if (suffix === '/managed-native') return response(200, data.native);
      if (suffix === '/managed-connection') return response(200, data.managed);
      throw new Error('Unexpected route ' + suffix);
    }
    assert.equal(options.headers['X-Local-CSRF'], 'csrf-fixture');
    assert.equal(options.headers.Authorization, undefined);
    if (control.pending) return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})), {once: true}));
    if (control.failure) { const failure = control.failure; control.failure = null; return response(failure.status || 409, {detail: failure}); }
    const body = options.body ? JSON.parse(options.body) : {};
    if (suffix === '/managed-native/actions') { if (body.action === 'sign_out') Object.assign(data.native, {status: 'signed_out_locally', managed_access_available: false, membership: null, profiles: [], presets: [], native_operations_pending: false}); return response(200, data.native); }
    const id = decodeURIComponent(suffix.split('/')[2]?.split('?')[0] || '');
    const p = data.profiles.find(p => p.id === id);
    if (suffix === '/profiles' && method === 'POST') {
      const record = {...data.profiles[0], ...body, id: 'local_new', created_at: '2026-10-03T00:00:00Z', revision: 1, selected: false}; data.profiles.push(record); return response(201, record);
    }
    if (suffix === '/settings') { assert.equal(body.expected_revision, data.settings.revision); data.settings = {...data.settings, ...body, revision: data.settings.revision + 1}; return response(200, data.settings); }
    if (suffix === '/managed-connection') { assert.equal(body.expected_revision, data.managed.revision); data.managed = {...data.managed, ...body, revision: data.managed.revision + 1}; return response(200, data.managed); }
    assert(p, 'Mutation profile exists');
    if (method === 'DELETE') { assert(suffix.endsWith('expected_revision=' + p.revision)); data.profiles = data.profiles.filter(row => row !== p); return response(204, null); }
    assert.equal(body.expected_revision, p.revision);
    if (method === 'PATCH') { Object.assign(p, body, {revision: p.revision + 1}); return response(200, p); }
    if (control.holdSelection) { control.holdSelection = false; await new Promise(resolve => { control.releaseSelection = resolve; }); }
    assert.equal(body.action, 'select', 'Native start must be intercepted by a synthetic typed response in this harness');
    assert.match(body.idempotency_key, /^[A-Za-z0-9_-]{8,100}$/);
    data.profiles.forEach(row => { row.selected = row.id === p.id; });
    data.selected = p.id; p.last_selected_at = '2026-10-03T17:00:00Z'; p.revision++;
    return response(200, {profile: p, selected_profile_id: p.id, outcome: 'selected'});
  };
  const location = {protocol: 'http:', hash: '#profiles'};
  const storage = new Map(savedMode ? [['tbm.workspace-mode', savedMode]] : []);
  const context = {document, location, window: {addEventListener(n, fn) { (windowListeners[n] ||= []).push(fn); }}, localStorage: {getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v)}, fetch, URL, AbortController, setTimeout, clearTimeout, console, crypto: {randomUUID: () => '11111111-1111-4111-8111-111111111111'}};
  vm.createContext(context); if (nativeSupported) vm.runInContext(nativeManagedSource, context); vm.runInContext(source, context);
  const api = context.window.TeamWorkspace;
  const managed = {routes: 0, discoveries: 0};
  const app = autoMount ? api.mount({icon: name => `<svg aria-hidden="true" class="icon icon-${name}"></svg>`, esc: escape, notify: message => notices.push(message), managedRoute: () => { managed.routes++; }, managedDiscover: async () => { managed.discoveries++; }}) : null;
  return {app, api, calls, notices, elements, element, data, control, managed, location, windowListeners, storage, document, context};
}

const settle = () => new Promise(resolve => setTimeout(resolve, 0));
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };

function desktopScenario() {
  const t = scenario({savedMode: 'local', autoMount: false});
  const activations = [], bridgeCalls = [];
  const controls = {hide: () => Promise.resolve()};
  const embedded = {activate: async (_root, profile) => { activations.push(profile.id); }, deactivate() {}, hide: () => controls.hide(), resume() {}, bounds() {}};
  t.context.window.TeamEmbeddedBrowser = {mount: () => embedded};
  t.context.window.TeamDesktop = {command: async command => {
    bridgeCalls.push(command);
    if (command.action === 'close_profile') { const p = t.data.profiles.find(p => p.id === command.profile_id); p.state = 'stopped'; p.revision++; }
    return {};
  }};
  t.data.profiles.forEach(p => Object.assign(p, {engine_id: 'electron_chromium', preset_id: 'desktop', network_policy: 'local_direct'}));
  t.data.presets = [{id: 'desktop', name: 'Built-in Chromium', engine_id: 'electron_chromium'}, ...t.data.presets];
  t.data.selected = 'local_one'; t.data.profiles[0].selected = true;
  const originalFetch = t.context.fetch;
  t.context.fetch = async (url, options) => {
    const result = await originalFetch(url, options);
    if (url !== '/local/config') return result;
    const json = result.json;
    return {...result, json: async () => ({...await json(), desktop_shell: true})};
  };
  t.app = t.api.mount({icon: () => '', esc: escape, notify: message => t.notices.push(message), managedRoute() {}, managedDiscover: async () => {}});
  return {...t, activations, bridgeCalls, controls};
}

function embeddedScenario() {
  const t = scenario({autoMount: false});
  let rect = {x: 600, y: 300, width: 700, height: 500, right: 1300, bottom: 800};
  t.document.querySelector = selector => selector === 'dialog[open]' ? (t.element('detail-dialog').open ? t.element('detail-dialog') : null) : t.element(selector);
  const getElement = t.document.getElementById;
  t.document.getElementById = id => {
    const el = getElement(id);
    el.getBoundingClientRect = () => rect;
    el.closest = () => ({getBoundingClientRect: () => ({top: 160, bottom: 920})});
    return el;
  };
  t.context.window.innerWidth = 1440; t.context.window.innerHeight = 960;
  const profile = {id: 'local_one', revision: 1, engine_id: 'electron_chromium'};
  const snapshot = {profile_id: profile.id, profile, profile_revision: 1, tabs: [{id: 'tab1', title: 'Example', url: 'https://example.com', loading: false}], active_tab_id: 'tab1', capabilities: {engine_id: 'electron_chromium'}};
  let subscriber, emitted = 0;
  const commands = [];
  const bridge = {subscribe: callback => { subscriber = callback; }, command: async command => {
    commands.push(command);
    // Reproduce a noisy layout-emitting bridge too; the renderer must converge.
    if (emitted < 50) { emitted++; queueMicrotask(() => subscriber(structuredClone(snapshot))); }
    return structuredClone(snapshot);
  }};
  vm.runInContext(fs.readFileSync(path.join(root, 'src/team_browser/static/embedded_browser.js'), 'utf8'), t.context);
  const app = t.context.window.TeamEmbeddedBrowser.mount({icon: () => '', esc: escape, notify() {}, document: t.document, bridge});
  return {...t, app, commands, profile, snapshot, setRect: value => { rect = value; }, emit: value => subscriber(value)};
}

(async () => {
  let checks = 0;
  async function test(name, run) { await run(); checks++; console.log('ok', checks, name); }

  await test('Close profile stays stopped across metadata reload', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    t.app.model.profileSection = 'activity'; t.app.render(); t.activations.length = 0;
    await t.app.lifecycleAction('local_one', 'stop');
    assert.equal(t.app.model.profileSection, 'configuration');
    assert.deepEqual(t.activations, []);
    assert.equal(t.bridgeCalls.filter(x => x.action === 'close_profile').length, 1);
  });

  await test('Closing from editor removes its stale revision and disabled controls', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    t.app.model.profiles[0].state = 'running'; t.data.profiles[0].state = 'running';
    t.app.openEditor('local_one'); await settle();
    assert.equal(t.element('detail-dialog').open, true);
    assert.equal(t.element('profile-network-input').disabled, true);
    await t.app.lifecycleAction('local_one', 'stop');
    assert.equal(t.element('detail-dialog').open, false);
  });

  await test('Integrated editor does not offer browser controls that discard unsaved fields', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    t.app.model.profiles[0].state = 'running'; t.data.profiles[0].state = 'running';
    t.app.openEditor('local_one'); await settle();
    assert.equal(t.element('detail-dialog').open, true);
    const editor = t.element('drawer-content').innerHTML;
    assert(!editor.includes('id="profile-start-action"'));
    assert(!editor.includes('id="profile-stop-action"'));
    assert(editor.includes('Save or cancel'));
    t.element('profile-name-input').value = 'Unsaved name';
    t.activations.length = 0;
    await t.app.lifecycleAction('local_one', 'start');
    assert.equal(t.element('detail-dialog').open, true);
    assert.equal(t.element('profile-name-input').value, 'Unsaved name');
    assert.equal(t.app.model.profileSection, 'configuration');
    assert.deepEqual(t.activations, []);
  });

  await test('Switcher and editor wait for a confirmed hide and fail closed', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    const hidden = deferred(); t.controls.hide = () => hidden.promise;
    t.app.openSwitcher(); assert.equal(t.element('switcher-dialog').open, false);
    hidden.resolve(); await settle(); assert.equal(t.element('switcher-dialog').open, true);
    t.element('switcher-dialog').close();
    t.controls.hide = () => Promise.reject(new Error('hide rejected'));
    t.app.openEditor('local_one'); await settle(); assert.equal(t.element('detail-dialog').open, false);
    assert(t.notices.some(x => x.includes('not opened')));
  });

  await test('Latest profile click wins without painting intermediate selections', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    t.app.model.profileSection = 'activity'; t.app.render(); t.activations.length = 0;
    const firstWrite = deferred(), originalFetch = t.context.fetch;
    let delayed = false;
    t.context.fetch = async (url, options) => {
      if (url.endsWith('/actions') && !delayed) { delayed = true; await firstWrite.promise; }
      return originalFetch(url, options);
    };
    const selection = t.app.selectProfile('local_two');
    t.app.selectProfile('local_one');
    assert.equal(t.app.model.selectedId, 'local_one');
    assert.deepEqual(t.activations, []);
    firstWrite.resolve(); await selection;
    assert.equal(t.app.model.selectedId, 'local_one');
    assert.deepEqual(t.activations, ['local_one']);
    const reads = t.calls.filter(x => x.url === '/local/v1/profiles');
    assert(reads.every(x => x.options.signal), 'Every profile collection read is timeout bound');
    assert.equal(t.calls.filter(x => x.url.endsWith('/actions')).length, 2);
  });

  await test('Custom icon reads cannot overwrite a newer selection or save halfway', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.openEditor('local_one');
    t.element('profile-icon-input').value = 'custom';
    const readers = []; t.context.FileReader = class {constructor() { readers.push(this); } readAsDataURL() {}};
    const fileInput = t.element('profile-icon-file');
    fileInput.files = [{name: 'first.png', type: 'image/png', size: 5}]; const a = fileInput.dispatch('change');
    fileInput.files = [{name: 'second.png', type: 'image/png', size: 5}]; const b = fileInput.dispatch('change');
    const callsBefore = t.calls.length; await t.element('local-profile-form').dispatch('submit');
    assert.equal(t.calls.length, callsBefore); assert.equal(t.element('save-local-profile').disabled, true);
    readers[1].result = 'data:image/png;base64,Qg=='; readers[1].onload(); await b;
    readers[0].result = 'data:image/png;base64,QQ=='; readers[0].onload(); await a;
    assert.equal(t.app.model.iconDraft, 'data:image/png;base64,Qg==');
    assert.equal(t.app.model.iconReading, false); assert.equal(t.element('save-local-profile').disabled, false);
  });

  await test('Invalid replacement file cannot leave save permanently disabled', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.openEditor('local_one');
    const readers = []; t.context.FileReader = class {constructor() { readers.push(this); } readAsDataURL() {}};
    const input = t.element('profile-icon-file');
    input.files = [{name: 'first.png', type: 'image/png', size: 5}]; const pending = input.dispatch('change');
    input.files = [{name: 'bad.svg', type: 'image/svg+xml', size: 5}]; await input.dispatch('change');
    readers[0].result = 'data:image/png;base64,QQ=='; readers[0].onload(); await pending;
    assert.equal(t.app.model.iconReading, false); assert.equal(t.element('save-local-profile').disabled, false);
  });

  await test('Empty replacement file selection cannot strand an old read', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.openEditor('local_one');
    const readers = []; t.context.FileReader = class {constructor() { readers.push(this); } readAsDataURL() {}};
    const input = t.element('profile-icon-file');
    input.files = [{name: 'first.png', type: 'image/png', size: 5}]; const pending = input.dispatch('change');
    input.files = []; await input.dispatch('change');
    readers[0].result = 'data:image/png;base64,QQ=='; readers[0].onload(); await pending;
    assert.equal(t.app.model.iconReading, false); assert.equal(t.element('save-local-profile').disabled, false);
  });

  await test('Rejected field validation preserves draft and prior disabled states', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap();
    t.app.model.profiles[0].state = 'running'; t.app.openEditor('local_one');
    t.element('profile-name-input').value = 'Keep this draft';
    t.control.failure = {status: 422, code: 'invalid_profile_configuration', message: 'Invalid profile configuration'};
    await t.element('local-profile-form').dispatch('submit');
    assert.equal(t.element('detail-dialog').open, true);
    assert.equal(t.element('profile-name-input').value, 'Keep this draft');
    assert.equal(t.element('profile-name-input').disabled, false);
    assert.equal(t.element('profile-network-input').disabled, true);
    assert.equal(t.element('save-local-profile').disabled, false);
  });

  await test('Integrated settings do not offer unsupported vertical native-tab layout', async () => {
    const t = desktopScenario(); await t.app.bootstrap();
    const getElement = t.document.getElementById;
    t.document.getElementById = id => ['tab-navigation', 'navigation-form'].includes(id) ? null : getElement(id);
    t.location.hash = '#resources'; t.app.render();
    const content = t.element('view-container').innerHTML;
    assert(!content.includes('id="navigation-form"'));
    assert(content.includes('tab strip is horizontal'));
  });

  await test('Noisy snapshots and unchanged geometry converge without a layout loop', async () => {
    const t = embeddedScenario(); await t.app.activate(t.element('embedded-root'), t.profile); await settle();
    const placed = () => t.commands.filter(x => x.action === 'set_content_bounds').length;
    assert.equal(placed(), 1);
    for (let i = 0; i < 10; i++) { t.emit(structuredClone(t.snapshot)); await t.app.bounds(); }
    assert.equal(placed(), 1);
  });

  await test('Suspended content stays hidden during updates and scroll clipping hides it', async () => {
    const t = embeddedScenario(); await t.app.activate(t.element('embedded-root'), t.profile); await settle();
    await t.app.hide(); const commandCount = t.commands.length;
    t.emit({...t.snapshot, tabs: [{...t.snapshot.tabs[0], title: 'Changed'}]}); await settle();
    assert.equal(t.commands.length, commandCount, 'A hidden browser must not place a native guest');
    t.app.resume(); await settle();
    const hides = t.commands.filter(x => x.action === 'hide_content').length;
    t.setRect({x: 600, y: 50, width: 700, height: 500, right: 1300, bottom: 550});
    await t.app.bounds();
    assert.equal(t.commands.filter(x => x.action === 'hide_content').length, hides + 1);
    await t.app.bounds();
    assert.equal(t.commands.filter(x => x.action === 'hide_content').length, hides + 1);
  });

  console.log(`PASS: ${checks} desktop frontend source contracts. Synthetic DOM/bridge only; no native Electron, rendered layout, focus, proxy, or login acceptance is claimed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
