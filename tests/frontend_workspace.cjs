'use strict';
// Source-level DOM/transport regression. This is deliberately not a browser or
// visual test: no Chromium is executed, no Gmail page or native engine is opened.
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

function managedScenario() {
  const t = scenario();
  vm.runInContext(managedSource, t.context);
  const api = {enabled: true, saving: false, users: [{id: 'user-01', display_name: 'Example One', enabled: true, role: 'member'}, {id: 'user-02', display_name: 'Example Two', enabled: true, role: 'member'}, {id: 'owner', display_name: 'Example Owner', enabled: true, role: 'owner'}]};
  const profiles = [{id: 'DEMO-001', name: 'Synthetic Research', assignedUserId: 'user-01', revision: 1}];
  const data = {policy: {revision: 0, member_create_enabled: false, fixed_profile_cap: 5, proxy_capacity_enabled: false, proxy_reuse_enabled: false}, pools: [{id: 'pool-1', name: 'Shared example', member_ids: ['user-01', 'user-02'], revision: 1}], proxies: [{id: 'proxy-1', name: 'Example direct', country: 'US', assigned_user_id: 'user-01', pool_id: null, max_profiles: 2, enabled: true, bound_profiles: 0, revision: 1, simulated: true}], devices: [{id: 'device-1', name: 'Example offline device', user_id: 'user-01', platform: 'macOS', connectivity: 'offline', last_seen_at: null, synthetic_fixture: true}], commands: [{id: 'command-1', profile_id: 'DEMO-001', device_id: 'device-1', kind: 'setup', generation: 1, status: 'queued', delivery_status: 'offline-pending', acknowledged_at: null, result_code: null}], member: {revision: 0, member_revision: 0, member_create_enabled: false, fixed_profile_cap: 5, proxy_capacity_enabled: false, proxy_reuse_enabled: false, can_create_override: null, fixed_profile_cap_override: null, assigned_profiles: 1, available_proxy_slots: 1}, record: {profile_id: 'DEMO-001', revision: 1, generation: 1, proxy_id: null, shared_member_ids: []}};
  const calls = [], control = {failure: null, pending: false}, notices = [];
  const response = (status, body) => ({ok: status < 400, status, json: async () => structuredClone(body)});
  t.context.fetch = async (url, options) => {
    calls.push({url, options}); assert.equal(options.credentials, 'omit'); assert.equal(options.headers.Authorization, 'Bearer synthetic-demo');
    if (options.method === 'GET') {
      const result = {'/v1/policy': data.policy, '/v1/proxy-pools': data.pools, '/v1/proxies': data.proxies, '/v1/devices': data.devices, '/v1/commands': data.commands, '/v1/users/user-01/policy': data.member, '/v1/profiles/DEMO-001/managed': data.record}[url];
      assert(result, 'Expected managed route ' + url); return response(200, result);
    }
    if (control.pending) return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})), {once: true}));
    if (control.failure) { const failure = control.failure; control.failure = null; return response(failure.status, {detail: failure.detail}); }
    const body = JSON.parse(options.body);
    if (url === '/v1/policy') { assert.equal(body.expected_revision, data.policy.revision); data.policy = {...body, revision: data.policy.revision + 1}; return response(200, data.policy); }
    if (url === '/v1/users/user-01/policy') { assert.equal(body.expected_revision, data.member.member_revision); data.member = {...data.member, can_create_override: body.can_create, fixed_profile_cap_override: body.fixed_profile_cap, member_revision: data.member.member_revision + 1}; return response(200, data.member); }
    if (url === '/v1/proxy-pools') { data.pools.push({...body, id: 'new-pool', revision: 1}); return response(201, data.pools.at(-1)); }
    if (url === '/v1/proxy-pools/pool-1') { assert.equal(body.expected_revision, data.pools[0].revision); data.pools[0] = {...data.pools[0], ...body, revision: data.pools[0].revision + 1}; return response(200, data.pools[0]); }
    if (url === '/v1/proxies/proxy-1') { assert.equal(body.expected_revision, data.proxies[0].revision); data.proxies[0] = {...data.proxies[0], ...body, revision: data.proxies[0].revision + 1}; return response(200, data.proxies[0]); }
    if (url === '/v1/proxies') { data.proxies.push({...body, id: 'new-proxy', revision: 1, bound_profiles: 0}); return response(201, data.proxies.at(-1)); }
    if (url === '/v1/profiles/DEMO-001/sharing') { assert.equal(body.expected_revision, data.record.revision); data.record = {...data.record, shared_member_ids: body.member_ids, revision: data.record.revision + 1, generation: data.record.generation + 1}; return response(200, data.record); }
    if (url === '/v1/profiles/DEMO-001/proxy-binding') { assert.equal(body.expected_revision, data.record.revision); data.record = {...data.record, proxy_id: body.proxy_id, revision: data.record.revision + 1}; return response(200, data.record); }
    throw new Error('Unexpected managed mutation ' + url);
  };
  let app;
  app = t.context.window.ManagedWorkspace.mount({api, profiles, icon: name => `<svg class="icon-${name}"></svg>`, esc: escape, notify: message => notices.push(message), route: () => app.render(), loadApiData: async () => { profiles[0].revision = data.record.revision; }});
  t.location.hash = '#policies';
  return {...t, app, api, profiles, data, calls, control, notices};
}
const settle = () => new Promise(resolve => setTimeout(resolve, 0));

(async () => {
  let checks = 0;
  async function test(name, fn) { await fn(); checks++; console.log('ok', checks, name); }
  await test('First run offers Local without an account and explicit Managed preview', async () => {
    const t = scenario(); await t.app.bootstrap(); assert.equal(t.app.model.mode, 'choose'); assert.equal(t.calls.length, 1); assert(t.element('view-container').innerHTML.includes('No account or team login required'));
    await t.element('choose-local').dispatch('click'); assert.equal(t.app.model.mode, 'local'); assert.equal(t.app.model.profiles.length, 2); assert.equal(t.storage.get('tbm.workspace-mode'), 'local'); assert.equal(t.managed.discoveries, 0);
  });
  await test('Unavailable Local service never silently becomes temporary local data', async () => {
    const t = scenario({configAvailable: false}); await t.app.bootstrap(); await t.app.chooseMode('local'); assert.equal(t.app.model.config, null); assert(t.element('view-container').innerHTML.includes('Profiles are not silently saved'));
  });
  await test('Explicit Managed preview keeps the legacy adapter route available', async () => {
    const t = scenario(); await t.app.bootstrap(); await t.app.chooseMode('managed'); assert.equal(t.managed.routes, 1); assert.equal(t.managed.discoveries, 1); assert.equal(t.app.render(), false);
    const restored = scenario({savedMode: 'managed'}); assert.equal(await restored.app.bootstrap(), false); assert.equal(restored.calls.length, 1); assert.equal(restored.calls[0].url, '/local/config');
  });
  await test('Configured Camoufox setup selects its preset only for a new profile, without choosing networking', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap();
    t.app.model.config.camoufox_setup = {configured: true};
    t.app.model.presets.push({id: 'isolated', name: 'Camoufox', engine_id: 'camoufox'});
    t.app.openEditor(); assert.equal(t.element('profile-preset-input').value, 'isolated'); assert.equal(t.element('profile-network-input').value, 'unconfigured');
    t.app.openEditor('local_one'); assert.equal(t.element('profile-preset-input').value, 'standard');
    t.app.model.config.camoufox_setup.configured = false;
    t.app.openEditor(); assert.equal(t.element('profile-preset-input').value, 'standard');
  });
  await test('Local create, edit, preset, favorite, search and stable selection', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap();
    await t.element('new-profile').dispatch('click'); assert(t.element('detail-dialog').open); t.element('profile-name-input').value = 'Study'; t.element('profile-preset-input').value = 'focused'; t.element('profile-favorite-input').checked = true;
    await t.element('local-profile-form').dispatch('submit'); assert.equal(t.data.profiles.at(-1).name, 'Study'); assert.equal(t.data.profiles.at(-1).favorite, true); assert(!t.element('detail-dialog').open);
    t.app.openEditor('local_new'); t.element('profile-name-input').value = 'Study revised'; await t.element('local-profile-form').dispatch('submit'); assert.equal(t.data.profiles.at(-1).name, 'Study revised');
    await t.app.toggleFavorite('local_one'); assert(t.data.profiles[0].favorite); await t.app.selectProfile('local_one'); assert.equal(t.app.model.selectedId, 'local_one'); assert.equal(t.app.filteredProfiles()[0].id, 'local_one'); assert.equal(t.calls.filter(c => c.options.method === 'POST' && c.url.endsWith('/actions')).length, 1);
    t.app.model.search = 'focused'; assert.equal(t.app.filteredProfiles().length, 2); t.app.model.filter = 'favorites'; assert.equal(t.app.filteredProfiles().length, 2);
  });
  await test('Editor cancel closes with no mutation and preserves original data', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.openEditor('local_one'); t.element('profile-name-input').value = 'Discard me'; const count = t.calls.length; await t.element('cancel-profile-edit').dispatch('click'); assert(!t.element('detail-dialog').open); assert.equal(t.calls.length, count); assert.equal(t.data.profiles[0].name, 'Research');
  });
  await test('Revision conflict refreshes once without retry and rolls back optimistic favorite', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.data.profiles[0].revision = 7; t.control.failure = {code: 'revision_conflict', message: 'Changed elsewhere'};
    await t.app.toggleFavorite('local_one'); assert.equal(t.calls.filter(c => c.options.method === 'PATCH').length, 1); assert.equal(t.app.model.profiles[0].revision, 7); assert(!t.app.model.profiles[0].favorite); assert(t.app.model.error.message.includes('changed elsewhere')); assert(!t.app.model.needsRefresh);
  });
  await test('Aborted mutation is uncertain, prevents double clicks and requires reload', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.control.pending = true; const pending = t.app.toggleFavorite('local_one'); assert(t.app.model.pending); await t.app.toggleFavorite('local_one'); assert.equal(t.calls.filter(c => c.options.method === 'PATCH').length, 1); t.app.cancelPending(); await pending; assert(t.app.model.needsRefresh); assert.equal(t.app.model.error.code, 'request_canceled'); assert(!t.app.model.profiles[0].favorite); await t.app.selectProfile('local_one'); assert.equal(t.calls.filter(c => c.options.method === 'POST').length, 0);
    t.control.pending = false; await t.app.reload(); assert(!t.app.model.needsRefresh);
  });
  await test('Failed refresh after an accepted write never reports verified success', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.control.failRead = true; await t.app.toggleFavorite('local_one'); assert(t.data.profiles[0].favorite); assert(t.app.model.needsRefresh); assert(!t.notices.includes('Favorites saved locally.')); assert(t.notices.at(-1).includes('verification'));
  });
  await test('Typed engine and CSRF errors remain explicit and never silently retry', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.control.failure = {code: 'engine_unavailable', message: 'Runtime verification is required.', blockers: ['Runtime not pinned'], profile: {...t.data.profiles[0], state: 'blocked', revision: 9}};
    await t.app.mutate({label: 'Inspecting engine', path: '/profiles/local_one/actions', body: {action: 'start', expected_revision: 1}}); assert.equal(t.app.model.error.code, 'engine_unavailable'); assert.equal(t.app.model.profiles[0].state, 'blocked'); assert.equal(t.calls.filter(c => c.options.method === 'POST').length, 1);
    t.control.failure = {status: 403, code: 'csrf_rejected', message: 'Refresh before editing'}; await t.app.toggleFavorite('local_one'); assert(t.app.model.needsRefresh);
  });
  await test('Switcher supports keyboard movement, numeric access, Enter and guarded navigation', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap();
    const key = {key: 'k', ctrlKey: true, preventDefault() {}}; t.app.globalKeydown(key); assert(t.element('switcher-dialog').open); assert.equal(t.document.activeElement.key, 'switcher-search'); assert.equal(t.element('switcher-search').attrs['aria-activedescendant'], 'switcher-option-0');
    t.app.switcherKeydown({key: 'ArrowDown', preventDefault() {}}); assert.equal(t.app.model.switcherIndex, 1); t.app.switcherKeydown({key: 'Enter', preventDefault() {}}); await new Promise(resolve => setTimeout(resolve, 0)); assert.equal(t.app.model.selectedId, 'local_two'); assert(!t.element('switcher-dialog').open);
    t.app.globalKeydown({key: '3', altKey: true, target: {tagName: 'INPUT'}, preventDefault() { throw new Error('Typing must not trigger navigation'); }}); assert.equal(t.location.hash, '#profiles');
    t.app.globalKeydown({key: '3', altKey: true, target: {tagName: 'BODY'}, preventDefault() {}}); assert.equal(t.location.hash, '#resources');
    t.app.openSwitcher(); t.app.switcherKeydown({key: '1', altKey: true, preventDefault() {}}); await new Promise(resolve => setTimeout(resolve, 0)); assert.equal(t.app.model.selectedId, 'local_one');
  });
  await test('After profile creation, editing focus guards Alt navigation until a control is focused', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap();
    t.element('new-profile').focus(); await t.element('new-profile').dispatch('click');
    t.element('profile-name-input').value = 'Tablet shortcut fixture';
    await t.element('local-profile-form').dispatch('submit');
    assert(!t.element('detail-dialog').open);
    assert.equal(t.document.activeElement.key, 'local-search');
    t.app.globalKeydown({key: '3', altKey: true, target: t.document.activeElement, preventDefault() { throw new Error('Editing focus must keep navigation shortcuts inactive'); }});
    assert.equal(t.location.hash, '#profiles');
    t.element('quick-switch-button').focus();
    let prevented = false;
    t.app.globalKeydown({key: '3', altKey: true, target: t.document.activeElement, preventDefault() { prevented = true; }});
    assert(prevented); assert.equal(t.location.hash, '#resources');
    t.app.render(); assert(t.element('view-container').innerHTML.includes('id="resource-form"'));
  });
  await test('Inbox defaults to unknown unread, has distinct marked synthetic counts, no global opening', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.location.hash = '#inbox'; t.app.render(); let content = t.element('view-container').innerHTML; assert(content.includes('Unread count unavailable')); assert(!content.includes('synthetic unread threads')); assert(content.includes('UNREAD DATA NOT CONNECTED')); assert(content.includes('Open Gmail')); assert(content.includes('disabled title="Requires a verified native browser'));
    t.element('inbox-examples').checked = true; await t.element('inbox-examples').dispatch('change'); content = t.element('view-container').innerHTML; assert(content.includes('3 synthetic unread threads')); assert(content.includes('10 synthetic unread threads')); assert(content.includes('SYNTHETIC EXAMPLE · NOT LIVE')); assert(!source.includes('window.open('));
  });
  await test('Settings expose real profile counts and save bounded limits without fabricated RAM', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.location.hash = '#resources'; t.app.render(); const content = t.element('view-container').innerHTML; assert(!content.includes('512')); assert(!content.includes('estimated')); assert(!content.includes('Memory budget')); assert(content.includes('max="16"')); assert(content.includes('Execution unavailable')); t.element('warm-limit').value = '2'; await t.element('resource-form').dispatch('submit'); assert.equal(t.data.settings.max_warm_profiles, 2); assert.equal(t.data.settings.revision, 2);
  });
  await test('Synthetic capability never enables native launch or claims a real running browser', async () => {
    const t = scenario({savedMode: 'local', synthetic: true}); await t.app.bootstrap(); t.app.openEditor('local_two'); assert(t.element('profile-start-action').disabled); assert(t.element('drawer-content').innerHTML.includes('Simulation only. No real browser')); const count = t.calls.length; await t.app.lifecycleAction('local_one', 'start'); assert.equal(t.calls.length, count); assert(t.notices.at(-1).includes('unavailable'));
  });
  await test('Managed server metadata validates origin and never sends a network login', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.location.hash = '#connection'; t.app.render(); t.element('managed-server').value = 'https://workspace.example.test/?token=secret'; await t.element('managed-metadata-form').dispatch('submit'); assert.equal(t.calls.filter(c => c.options.method === 'PUT').length, 0);
    t.element('managed-server').value = 'https://workspace.example.test'; await t.element('managed-metadata-form').dispatch('submit'); await new Promise(resolve => setTimeout(resolve, 0)); assert.equal(t.data.managed.server_url, 'https://workspace.example.test'); assert(t.calls.every(c => !c.url.startsWith('https:'))); assert(t.notices.at(-1).includes('No managed connection'));
  });
  await test('Typed local route allowlist, escaped names and strict-CSP source invariants', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); const count = t.calls.length; await assert.rejects(t.app.request('//evil.test/path'), error => error.code === 'invalid_route'); assert.equal(t.calls.length, count); t.app.model.profiles[0].name = '<img src=x onerror=bad()>'; t.app.render(); assert(!t.element('view-container').innerHTML.includes('<img')); assert(t.element('view-container').innerHTML.includes('&lt;img'));
    assert(!/\bstyle=/.test(source + managedSource + legacy + html)); assert(!/\bonclick=/.test(source + managedSource + legacy + html)); assert(html.indexOf('./workspace.js') < html.indexOf('./app.js'));
  });
  await test('Offline mode disables changes and waits for an explicit service reload', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.windowListeners.offline[0](); assert(t.app.model.offline); const count = t.calls.length; await t.app.toggleFavorite('local_one'); assert.equal(t.calls.length, count); t.windowListeners.online[0](); assert(t.app.model.offline); assert(t.notices.at(-1).includes('Reload')); await t.app.reload(); assert(!t.app.model.offline);
  });
  await test('Network policy defaults unconfigured and stays blocked even with a native-capable runtime', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.model.config.launch.actual_process_available = true; t.app.openEditor('local_one'); assert.equal(t.element('profile-network-input').value, 'unconfigured'); assert(t.element('profile-start-action').disabled); assert(t.element('drawer-content').innerHTML.includes('Choose an explicit network policy'));
    t.element('profile-network-input').value = 'local_direct'; await t.element('local-profile-form').dispatch('submit'); assert.equal(t.data.profiles[0].network_policy, 'local_direct'); t.app.openEditor('local_one'); assert(!t.element('profile-start-action').disabled); assert(t.element('drawer-content').innerHTML.includes('no proxy or anonymity guarantee'));
  });
  await test('Managed policy form enforces a creation bound and revision, without real setup', async () => {
    const t = managedScenario(); await t.app.reload(); t.app.openCompanyPolicy(); t.element('company-can-create').checked = true; t.element('company-fixed-cap').value = ''; t.element('company-proxy-capacity').checked = false; await t.element('managed-form').dispatch('submit'); assert(t.element('managed-form-feedback').textContent.includes('cannot be unbounded')); assert.equal(t.calls.filter(c => c.options.method === 'PUT').length, 0);
    t.element('company-fixed-cap').value = '3'; t.element('company-proxy-reuse').checked = true; await t.element('managed-form').dispatch('submit'); await settle(); assert.equal(t.data.policy.fixed_profile_cap, 3); assert(t.data.policy.proxy_reuse_enabled); assert.equal(t.data.policy.revision, 1); assert(t.notices.at(-1).includes('Synthetic'));
  });
  await test('Member overrides round-trip raw inheritance with the member revision', async () => {
    const t = managedScenario(); await t.app.reload(); await t.app.openMemberPolicy('user-01'); assert.equal(t.element('member-can-create').value, 'inherit'); assert.equal(t.element('member-fixed-cap').value, ''); t.element('member-can-create').value = 'allow'; t.element('member-fixed-cap').value = '2'; await t.element('managed-form').dispatch('submit'); await settle(); assert.equal(t.data.member.can_create_override, true); assert.equal(t.data.member.fixed_profile_cap_override, 2); assert.equal(t.data.member.member_revision, 1);
    await t.app.openMemberPolicy('user-01'); assert.equal(t.element('member-can-create').value, 'allow'); t.element('member-can-create').value = 'inherit'; t.element('member-fixed-cap').value = ''; await t.element('managed-form').dispatch('submit'); await settle(); assert.equal(t.data.member.can_create_override, null); assert.equal(t.data.member.fixed_profile_cap_override, null);
  });
  await test('Proxy metadata moves direct versus pool exclusively, with explicit maximum reuse', async () => {
    const t = managedScenario(); await t.app.reload(); t.location.hash = '#providers'; t.app.render(); t.app.openProxy('proxy-1'); assert.equal(t.element('proxy-assignment-kind').value, 'direct'); t.element('proxy-assignment-kind').value = 'pool'; await t.element('proxy-assignment-kind').dispatch('change'); assert(t.element('proxy-direct-field').hidden); assert(!t.element('proxy-pool-field').hidden); t.element('proxy-pool').value = 'pool-1'; t.element('proxy-max-profiles').value = '4'; await t.element('managed-form').dispatch('submit'); await settle(); assert.equal(t.data.proxies[0].assigned_user_id, null); assert.equal(t.data.proxies[0].pool_id, 'pool-1'); assert.equal(t.data.proxies[0].max_profiles, 4); assert(t.notices.at(-1).includes('No traffic'));
  });
  await test('Named pools and sharing submit only explicitly checked member IDs', async () => {
    const t = managedScenario(); await t.app.reload(); t.app.openPool(); t.element('pool-name').value = 'New example pool'; const poolInputs = t.element('detail-dialog').querySelectorAll('.pool-member'); poolInputs.find(input => input.value === 'user-02').checked = true; await t.element('managed-form').dispatch('submit'); await settle(); assert.deepEqual(t.data.pools.at(-1).member_ids, ['user-02']);
    t.location.hash = '#sharing'; t.app.render(); await t.app.openSharing('DEMO-001'); const shares = t.element('detail-dialog').querySelectorAll('.share-member'); assert(!shares.some(input => input.value === 'user-01')); shares.find(input => input.value === 'user-02').checked = true; await t.element('managed-form').dispatch('submit'); await settle(); assert.deepEqual(t.data.record.shared_member_ids, ['user-02']); assert.equal(t.data.record.generation, 2);
    t.app.openBinding(t.profiles[0], t.data.record); t.element('profile-proxy-binding').value = 'proxy-1'; await t.element('managed-form').dispatch('submit'); await settle(); assert.equal(t.data.record.proxy_id, 'proxy-1'); assert(t.notices.at(-1).includes('No network route'));
  });
  await test('Managed conflict refreshes without blind retry; canceled writes block subsequent edits', async () => {
    const t = managedScenario(); await t.app.reload(); t.control.failure = {status: 409, detail: 'Policy changed; reload before editing'}; await t.app.mutate({path: '/v1/policy', body: {expected_revision: 0}, label: 'Saving', success: 'saved'}); assert.equal(t.app.model.error.code, 'revision_conflict'); assert.equal(t.calls.filter(c => c.options.method === 'PUT').length, 1);
    t.control.pending = true; const pending = t.app.mutate({path: '/v1/policy', body: {expected_revision: 0}, label: 'Saving', success: 'saved'}); t.app.cancelPending(); await pending; assert(t.app.model.needsRefresh); const count = t.calls.length; await t.app.mutate({path: '/v1/policy', body: {}, label: 'Retry', success: 'saved'}); assert.equal(t.calls.length, count); assert.equal(t.api.saving, false);
  });
  await test('Device delivery shows offline-pending with no acknowledgement and never submits agent actions', async () => {
    const t = managedScenario(); await t.app.reload(); t.location.hash = '#devices'; t.app.render(); const content = t.element('view-container').innerHTML; assert(content.includes('offline-pending')); assert(content.includes('No acknowledgement received')); assert(content.includes('Never received')); assert(!t.calls.some(c => c.url.includes('/agent/'))); assert(t.calls.every(c => c.options.method === 'GET'));
    t.api.enabled = false; await assert.rejects(t.app.request('/v1/policy'), error => error.code === 'synthetic_only');
  });
  await test('Native Inbox sends only fixed Gmail intent and exact profile revision when all gates pass', async () => {
    const t = scenario({savedMode: 'local'}); await t.app.bootstrap(); t.app.model.config.launch.actual_process_available = true; t.app.model.config.inbox.native_open_available = true; t.app.model.profiles[0].network_policy = 'local_direct';
    t.control.failure = {status: 409, code: 'engine_unavailable', message: 'Native execution intentionally blocked by test fixture'}; await t.app.lifecycleAction('local_one', 'start', 'gmail'); const call = t.calls.find(c => c.options.method === 'POST'); const body = JSON.parse(call.options.body); assert.equal(call.url, '/local/v1/profiles/local_one/actions'); assert.equal(body.action, 'start'); assert.equal(body.intent, 'gmail'); assert.equal(body.expected_revision, 1); assert.equal(body.url, undefined); assert(t.app.model.error); assert(!t.notices.some(n => n.includes('Gmail request processed')));
  });
  await test('Combined static modules boot the persisted account-free local workspace', async () => {
    const t = scenario({savedMode: 'local', autoMount: false}); vm.runInContext(managedSource, t.context); vm.runInContext(legacy, t.context); await settle(); await settle(); assert(t.element('view-container').innerHTML.includes('Your browser profiles')); assert(t.element('view-container').innerHTML.includes('Research')); assert(!t.calls.some(c => c.url.startsWith('/demo/') || c.url.startsWith('/v1/'))); assert(t.windowListeners.hashchange.length);
  });
  await test('Native managed mode never falls through to synthetic records', async () => {
    const t = scenario({nativeSupported: true, savedMode: 'managed'});
    assert.equal(await t.app.bootstrap(), true); await settle();
    assert.equal(t.managed.discoveries, 0); assert.equal(t.managed.routes, 0);
    assert(t.element('view-container').innerHTML.includes('approved managed-service configuration'));
    assert(t.calls.every(c => c.url.startsWith('/local/')));
    assert(t.element('view-container').innerHTML.includes('disabled'));
    t.app.showChoice();
  });
  await test('Native managed data is escaped and only comes from the protected local bridge', async () => {
    const t = scenario({nativeSupported: true}); await t.app.bootstrap();
    Object.assign(t.data.native, {status: 'available', configured: true, records_loaded: true, managed_access_available: true, expires_at: Math.floor(Date.now()/1000)+300, membership: {display_name: '<script>bad</script>', tenant_id: 'org-a', member_id: 'member-a', role: 'member'}, profiles: [{id: 'managed-a', name: '<img onerror=bad>', preset_id: 'preset-a', state: 'unprovisioned'}], presets: [{id: 'preset-a', name: 'Shared'}]});
    await t.app.chooseMode('managed'); await settle();
    const content=t.element('view-container').innerHTML;
    assert(content.includes('&lt;img onerror=bad&gt;')); assert(content.includes('&lt;script&gt;bad&lt;/script&gt;'));
    assert(content.includes('Device setup required')); assert(!content.includes('Synthetic administrator'));
    assert(t.calls.filter(c => c.url === '/local/v1/managed-native').every(c => !c.options.headers.Authorization));
    t.app.showChoice();
  });
  await test('Native sign-out hides records immediately and sends only the fixed action', async () => {
    const t = scenario({nativeSupported: true}); await t.app.bootstrap();
    Object.assign(t.data.native, {status: 'available', configured: true, records_loaded: true, managed_access_available: true, expires_at: Math.floor(Date.now()/1000)+300, capabilities: {can_sign_out: true}, membership: {display_name: 'Private member', tenant_id: 'org-a', member_id: 'member-a', role: 'member'}, profiles: [{id: 'managed-a', name: 'Private record', preset_id: 'preset-a', state: 'unprovisioned'}]});
    await t.app.chooseMode('managed'); await settle();
    const signingOut=t.app.nativeManaged.action('sign_out');
    assert(!t.element('view-container').innerHTML.includes('Private record'));
    await signingOut;
    const sent=t.calls.find(c => c.url === '/local/v1/managed-native/actions');
    assert.deepEqual(JSON.parse(sent.options.body), {action: 'sign_out'});
    assert.equal(sent.options.headers.Authorization, undefined);
    assert.equal(t.app.nativeManaged.state.retiring, false);
    assert(t.element('view-container').innerHTML.includes('Signed out locally'));
    t.app.showChoice();
  });
  await test('Native bridge read failure clears cached identity and records', async () => {
    const t = scenario({nativeSupported: true}); await t.app.bootstrap();
    Object.assign(t.data.native, {status: 'available', configured: true, records_loaded: true, managed_access_available: true, expires_at: Math.floor(Date.now()/1000)+300, membership: {display_name: 'Private member', tenant_id: 'org-a', member_id: 'member-a', role: 'member'}, profiles: [{id: 'managed-a', name: 'Private record', preset_id: 'preset-a', state: 'unprovisioned'}]});
    await t.app.chooseMode('managed'); await settle();
    t.control.failRead=true; await t.app.nativeManaged.poll();
    assert(!t.element('view-container').innerHTML.includes('Private record'));
    assert(!t.element('view-container').innerHTML.includes('Private member'));
    assert(t.app.nativeManaged.state.error);
    t.app.showChoice();
  });
  await test('Activity layout persists while profile order ignores selection and memory estimates are absent', async () => {
    const t = scenario(); await t.app.bootstrap(); await t.app.chooseMode('local');
    assert(t.element('view-container').innerHTML.includes('profile-rail'));
    const before=t.app.filteredProfiles().map(p=>p.id).join(',');
    await t.app.selectProfile('local_two'); await t.app.selectProfile('local_one');
    assert.equal(t.app.filteredProfiles().map(p=>p.id).join(','),before);
    t.location.hash = '#resources'; t.app.render();
    assert(!t.element('view-container').innerHTML.includes('mirror-origin'));
    t.element('tab-navigation').value='side'; await t.element('navigation-form').dispatch('submit'); await settle();
    assert.equal(t.data.settings.tab_navigation,'side');
    const call=t.calls.filter(x=>x.url==='/local/v1/settings'&&x.options.method==='PATCH').at(-1);
    assert(!Object.hasOwn(JSON.parse(call.options.body),'max_warm_profiles'));
  });
  await test('Rapid selections are serialized and coalesced without rebuilding the profile rail', async () => {
    const t = scenario({savedMode:'local'}); await t.app.bootstrap();
    const third={...t.data.profiles[0],id:'local_three',name:'Third',created_at:'2026-10-03T00:00:00Z'};
    t.data.profiles.push(third); await t.app.reload();
    const markup=t.element('view-container').innerHTML;
    const settingsReads=t.calls.filter(c=>c.url==='/local/v1/settings').length;
    t.control.holdSelection=true;
    const one=t.app.selectProfile('local_one'); const two=t.app.selectProfile('local_two'); const three=t.app.selectProfile('local_three');
    assert(t.app.model.selectionPending); assert.equal(t.app.model.selectionTarget,'local_three');
    assert.equal(t.calls.filter(c=>c.options.method==='POST').length,1);
    t.control.releaseSelection(); await Promise.all([one,two,three]);
    const writes=t.calls.filter(c=>c.options.method==='POST'); assert.equal(writes.length,2);
    assert(writes[1].url.includes('local_three')); assert.equal(t.app.model.selectedId,'local_three');
    assert.equal(t.element('view-container').innerHTML,markup,'Selection must not replace the workspace DOM');
    assert.equal(t.calls.filter(c=>c.url==='/local/v1/settings').length,settingsReads);
    assert.equal(t.app.filteredProfiles().map(p=>p.id).join(','),'local_one,local_two,local_three');
  });
  await test('Profile icon, assignment and proxy form submit explicit nonsecret configuration', async () => {
    const t=scenario({savedMode:'local'}); await t.app.bootstrap(); t.app.openEditor('local_one');
    t.element('profile-icon-input').value='facebook'; t.element('profile-assignment-input').value='Marketing / Example';
    t.element('profile-network-input').value='verified_proxy'; t.element('proxy-host-input').value='proxy.example.test'; t.element('proxy-port-input').value='8443'; t.element('proxy-protocol-input').value='https'; t.element('proxy-label-input').value='Example route';
    await t.element('local-profile-form').dispatch('submit');
    assert.equal(t.data.profiles[0].icon_preset,'facebook'); assert.equal(t.data.profiles[0].assignment_label,'Marketing / Example'); assert.equal(t.data.profiles[0].proxy_config.hostname,'proxy.example.test');
    t.app.openEditor('local_one'); t.element('profile-network-input').value='local_direct'; await t.element('local-profile-form').dispatch('submit');
    assert.equal(t.data.profiles[0].proxy_config,null);
    t.app.openEditor(); t.element('profile-icon-input').value='custom'; t.element('profile-name-input').value='Custom'; const count=t.calls.length; await t.element('local-profile-form').dispatch('submit');
    assert.equal(t.calls.length,count); assert(t.element('local-form-feedback').textContent.includes('Choose a custom'));
  });
  await test('Selection verification failure keeps edits blocked without falsely claiming a switch', async () => {
    const t=scenario({savedMode:'local'}); await t.app.bootstrap(); t.control.failRead=true;
    await t.app.selectProfile('local_one'); assert(t.app.model.needsRefresh); assert.equal(t.app.model.selectedId,null);
    const count=t.calls.length; t.app.openEditor('local_one'); await t.app.selectProfile('local_two'); assert.equal(t.calls.length,count);
  });
  console.log(`PASS: ${checks} source-level local and managed workspace scenarios. DOM stubs and synthetic transport only; rendered desktop/mobile, focus trapping, visual layout and native execution remain unverified.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
