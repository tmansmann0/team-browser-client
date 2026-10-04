'use strict';
// Synthetic request/DOM harness only. No installation, browser process, live
// diagnostics, rendered layout, or native acceptance is exercised here.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('src/team_browser/static/camoufox_setup.js', 'utf8');
const workspace = fs.readFileSync('src/team_browser/static/workspace.js', 'utf8');
const html = fs.readFileSync('src/team_browser/static/index.html', 'utf8');
const css = fs.readFileSync('src/team_browser/static/styles.css', 'utf8');
const baseProfile = {id: 'local-one', revision: 4, name: 'Research', engine_id: 'camoufox', network_policy: 'verified_proxy', origin: 'local', state: 'stopped'};
const runtime = (over = {}) => ({configured: true, usable: true, state: 'configured', blockers: [], next_step: 'Select a profile and prepare its stable identity.', ...over});
const snapshot = (p = baseProfile, over = {}) => ({profile_id: p.id, profile_revision: p.revision, revision: 2, state: 'not_prepared', operation_id: null, blockers: [], next_step: 'Prepare this fresh profile.', available_actions: ['prepare'], admission_acknowledged: false, launch_available: false, admission_expires_at: null, network_scope: p.network_policy, ...over});
const admitted = (p = baseProfile, over = {}) => snapshot(p, {state: 'ready', available_actions: ['validate'], admission_acknowledged: true, launch_available: true, admission_expires_at: '2030-01-01T00:10:00Z', ...over});
function setup({profile = baseProfile} = {}) {
  const doc = {activeElement: null};
  class El {
    constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attrs = {}; this.listeners = {}; this.textContent = ''; this.disabled = false; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute(key, value) { this.attrs[key] = String(value); }
    addEventListener(key, fn) { this.listeners[key] = fn; }
    focus() { doc.activeElement = this; }
    async click() { if (!this.disabled) await this.listeners.click?.({target: this}); }
  }
  doc.createElement = tag => new El(tag);
  const root = new El('section'), window = {}, context = {window, document: doc, URL, AbortController, setTimeout, clearTimeout, Date};
  vm.runInNewContext(source, context);
  let currentProfile = profile ? structuredClone(profile) : null, responseProfile = currentProfile, stateResponse = profile ? snapshot(profile) : null, runtimeResponse = runtime();
  let next = null, time = Date.parse('2030-01-01T00:00:00Z'), timerId = 0;
  const timers = new Map(), calls = [], notices = [], launches = [], edits = [], updates = []; let creates = 0;
  const request = async (path, options = {}) => {
    calls.push({path, options});
    if (next) return next(path, options);
    if (path === '/camoufox-setup') return structuredClone(runtimeResponse);
    if (path.endsWith('/camoufox-setup/actions')) return {state: 'ready', admission_acknowledged: true, launch_available: true};
    if (path.endsWith('/camoufox-setup')) return structuredClone(stateResponse);
    if (path === '/profiles/' + responseProfile?.id) return structuredClone(responseProfile);
    throw new Error('Unexpected path ' + path);
  };
  const component = window.TeamCamoufoxSetup.mount({request, document: doc, notify: text => notices.push(text), now: () => time,
    schedule: (fn, ms) => { timers.set(++timerId, {fn, ms}); return timerId; }, cancel: id => timers.delete(id),
    isCurrent: p => Boolean(p.id && currentProfile && p.id === currentProfile.id && p.revision === currentProfile.revision && p.network_policy === currentProfile.network_policy && p.engine_id === currentProfile.engine_id),
    onProfile: (p, old) => { if (old.revision !== currentProfile?.revision || old.id !== currentProfile?.id) return false; updates.push(p); currentProfile = {...p}; return true; },
    onLaunch: id => launches.push(id), onEdit: id => edits.push(id), onCreate: () => { creates++; }
  });
  const all = (el = root) => [el, ...el.children.flatMap(child => all(child))];
  const control = key => all().find(el => el.dataset.setupControl === key);
  return {component, root, doc, context, calls, notices, launches, edits, updates, timers, all, control, get creates() { return creates; }, text: () => all().map(el => el.textContent).join('\n'),
    activate: () => component.activate(root, currentProfile), get profile() { return currentProfile; }, setProfile: p => { currentProfile = p; }, setResponseProfile: p => { responseProfile = p; }, setState: value => { stateResponse = value; }, setRuntime: value => { runtimeResponse = value; }, setNext: fn => { next = fn; }, tick: ms => { time += ms; }, normalize: window.TeamCamoufoxSetup.profileSnapshot};
}
const settle = () => new Promise(resolve => setImmediate(resolve));
const held = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise, resolve}; };
let count = 0;
async function test(name, fn) { await fn(); console.log('ok ' + (++count) + ' ' + name); }
(async () => {
  await test('Unavailable setup gives a concrete native owner action, without browser claims', async () => {
    const t = setup(); t.setRuntime(runtime({configured: false, usable: false, state: 'unavailable', blockers: ['Approved native configuration is absent.'], next_step: 'The device owner must configure the accepted runtime and restart the local service.'}));
    t.setState(snapshot(baseProfile, {state: 'unavailable', available_actions: []})); t.activate(); await settle();
    assert(t.text().includes('device owner')); assert(t.text().includes('restart the local service')); assert(t.control('prepare').disabled); assert(t.control('validate').disabled); assert(t.control('launch').disabled); assert(!t.component.canLaunch(t.profile)); t.component.deactivate();
  });
  await test('Offline preparation can proceed with approved configuration before native qualification', async () => {
    const t = setup(); t.setRuntime(runtime({usable: false, state: 'needs_approval'})); t.activate(); await settle(); assert(!t.control('prepare').disabled); assert(t.control('validate').disabled); await t.component.action('prepare'); assert.equal(t.calls.filter(c => c.options.method === 'POST').length, 1); assert(!t.component.canLaunch(t.profile)); t.component.deactivate();
  });
  await test('An empty workspace only offers profile creation and native runtime status', async () => {
    const t = setup({profile: null}); t.activate(); await settle(); assert(t.text().includes('Create or select a profile')); assert(!t.control('launch')); await t.control('create').click(); assert.equal(t.creates, 1); assert.deepEqual(t.calls.map(c => c.path), ['/camoufox-setup']); t.component.deactivate();
  });
  await test('An existing standard profile gets a concrete Camoufox preset step', async () => {
    const p = {...baseProfile, engine_id: 'chromium'}; const t = setup({profile: p}); t.activate(); await settle(); assert(t.text().includes('choose the Camoufox browser preset')); assert(!t.control('validate')); await t.control('edit').click(); assert.deepEqual(t.edits, [p.id]); assert(!t.calls.some(c => c.path.endsWith('/camoufox-setup') && c.path !== '/camoufox-setup')); t.component.deactivate();
  });
  await test('Prepare submits only enumerated intent and both current revision fences', async () => {
    const t = setup(); t.activate(); await settle(); await t.component.action('prepare'); const write = t.calls.find(c => c.options.method === 'POST'); assert.equal(write.path, '/profiles/local-one/camoufox-setup/actions'); assert.deepEqual(JSON.parse(JSON.stringify(write.options.body)), {action: 'prepare', expected_revision: 4, expected_setup_revision: 2}); assert(t.control('launch').disabled); assert(t.notices[0].includes('Checking')); assert.equal(t.component.state.snapshot.state, 'not_prepared'); t.component.deactivate();
  });
  await test('Prepared identity never implies browser readiness and diagnostics need a click', async () => {
    const t = setup(); t.setState(snapshot(baseProfile, {state: 'prepared', available_actions: ['validate']})); t.activate(); await settle(); assert(!t.control('validate').disabled); assert(t.control('launch').disabled); assert.equal(t.calls.filter(c => c.options.method === 'POST').length, 0); assert(t.text().includes('Native validation is still required')); t.component.deactivate();
  });
  await test('Profile revision is re-read after validation changes lifecycle and generation', async () => {
    const t = setup(); t.setState(snapshot(baseProfile, {state: 'prepared', available_actions: ['validate']})); t.activate(); await settle();
    const latest = {...baseProfile, revision: 6, generation: 1};
    t.setNext(async (path, options) => { if (options.method === 'POST') return admitted(latest); if (path === '/camoufox-setup') return runtime(); if (path.endsWith('/camoufox-setup')) return admitted(latest); return latest; });
    await t.component.action('validate'); assert.equal(t.profile.revision, 6); assert(t.component.canLaunch(t.profile)); await t.control('launch').click(); assert.deepEqual(t.launches, [baseProfile.id]); assert(!t.component.canLaunch(baseProfile)); t.component.deactivate();
  });
  await test('A native lifecycle revision change between GETs is coherently re-read once', async () => {
    const t = setup(), latest = {...baseProfile, revision: 6}; let profileReads = 0;
    t.setNext(async path => path === '/camoufox-setup' ? runtime() : path.endsWith('/camoufox-setup') ? admitted(latest) : ++profileReads === 1 ? baseProfile : latest);
    t.activate(); await settle(); assert.equal(profileReads, 2); assert.equal(t.profile.revision, 6); assert(t.component.canLaunch(t.profile)); assert(!t.calls.some(c => c.options.method === 'POST')); t.component.deactivate();
  });
  await test('Ready requires acknowledged unexpired admission, usable runtime, and launch availability', async () => {
    for (const over of [{admission_acknowledged: false}, {launch_available: false}, {admission_expires_at: null}, {admission_expires_at: '2029-01-01T00:00:00Z'}, {blockers: ['Proxy egress could not be verified.']}]) {
      const t = setup(); t.setState(admitted(baseProfile, over)); t.activate(); await settle(); assert(!t.component.canLaunch(t.profile)); assert(t.control('launch').disabled); t.component.deactivate();
    }
    const t = setup(); t.setState(admitted()); t.setRuntime(runtime({usable: false})); t.activate(); await settle(); assert(!t.component.canLaunch(t.profile)); t.component.deactivate();
  });
  await test('Unconfigured networking never validates or silently becomes local-direct', async () => {
    const p = {...baseProfile, network_policy: 'unconfigured'}, t = setup({profile: p}); t.setState(snapshot(p, {state: 'prepared', available_actions: ['validate']})); t.activate(); await settle(); assert(t.control('validate').disabled); await t.component.action('validate'); assert(!t.calls.some(c => c.options.method === 'POST')); assert(t.text().includes('local-direct must be explicitly selected')); assert.equal(t.profile.network_policy, 'unconfigured'); t.component.deactivate();
  });
  await test('Verified-proxy remains strict and explicit direct mode carries its ordinary-connection warning', async () => {
    const t = setup(); t.activate(); await settle(); assert(t.text().includes('never falls back to a direct connection')); t.component.deactivate();
    const p = {...baseProfile, network_policy: 'local_direct'}, d = setup({profile: p}); d.setState(admitted(p)); d.activate(); await settle(); assert(d.text().includes('ordinary direct connection')); assert(d.text().includes('no proxy or anonymity guarantee')); assert(d.component.canLaunch(d.profile)); d.component.deactivate();
    const m = setup({profile: {...p, origin: 'managed'}}); m.setState(admitted({...p, origin: 'managed'})); m.activate(); await settle(); assert(!m.component.canLaunch(m.profile)); assert(m.control('validate').disabled); m.component.deactivate();
  });
  await test('Cancellation uses the current operation state and remains blocked on uncertain cleanup', async () => {
    const t = setup(); t.setState(snapshot(baseProfile, {state: 'validating', revision: 3, available_actions: ['cancel']})); t.activate(); await settle(); assert(!t.control('cancel').disabled); assert(t.text().includes('Cancellation is complete only when the native host reports it'));
    t.setNext(async (path, options) => options.method === 'POST' ? {state: 'ready'} : path === '/camoufox-setup' ? runtime() : path.endsWith('/camoufox-setup') ? snapshot(baseProfile, {state: 'recovery_required', revision: 4, available_actions: []}) : baseProfile);
    await t.control('cancel').click(); const sent = t.calls.find(c => c.options.method === 'POST'); assert.equal(sent.options.body.action, 'cancel'); assert.equal(sent.options.body.expected_setup_revision, 3); assert(t.text().includes('cleanup is not acknowledged')); assert(t.text().includes('verify native process ownership')); assert(!t.component.canLaunch(t.profile)); t.component.deactivate();
  });
  await test('Duplicate clicks cannot start concurrent native actions', async () => {
    const t = setup(), pending = held(); t.activate(); await settle(); t.setNext(() => pending.promise); const action = t.component.action('prepare'); await t.component.action('prepare'); assert.equal(t.calls.filter(c => c.options.method === 'POST').length, 1); assert(t.control('prepare').disabled); t.component.deactivate(); pending.resolve({}); await action;
  });
  await test('A failed or uncertain write requires explicit refresh, never a blind mutation retry', async () => {
    const t = setup(); t.activate(); await settle(); t.setNext(async () => { throw new Error('private native details'); }); await t.component.action('prepare'); assert(t.text().includes('result is uncertain')); assert(!t.text().includes('private native')); const before = t.calls.length; await t.component.action('prepare'); assert.equal(t.calls.length, before); assert.equal(t.timers.size, 0); t.component.deactivate();
  });
  await test('Stale in-flight ready state cannot enable launch for a newer selected profile', async () => {
    const t = setup(), pending = held(); t.setNext(() => pending.promise); t.activate(); const newProfile = {...baseProfile, id: 'local-two', revision: 1}; t.setProfile(newProfile); t.setResponseProfile(newProfile); t.setState(snapshot(newProfile)); t.setNext(null); t.activate(); await settle(); pending.resolve(runtime()); await settle(); assert.equal(t.component.state.profile.id, 'local-two'); assert.equal(t.component.state.snapshot.state, 'not_prepared'); assert(!t.component.canLaunch(baseProfile)); t.component.deactivate();
  });
  await test('Editing a profile while native work is in flight invalidates old completion', async () => {
    const t = setup(), pending = held(); t.activate(); await settle(); t.setNext(() => pending.promise); const action = t.component.action('prepare'); const changed = {...baseProfile, revision: 5, network_policy: 'local_direct'}; t.setProfile(changed); t.setResponseProfile(changed); t.setState(snapshot(changed)); t.setNext(null); t.activate(); await settle(); pending.resolve(admitted(baseProfile)); await action; assert.equal(t.component.state.profile.revision, 5); assert.equal(t.component.state.snapshot.network_scope, 'local_direct'); assert(t.control('launch').disabled); t.component.deactivate();
  });
  await test('An in-flight refresh immediately disables the former ready controls', async () => {
    const t = setup(), pending = held(); t.setState(admitted()); t.activate(); await settle(); assert(t.component.canLaunch(t.profile)); t.setNext(() => pending.promise); const poll = t.component.poll(); assert(!t.component.canLaunch(t.profile)); assert(t.control('launch').disabled); t.component.deactivate(); pending.resolve(runtime()); await poll;
  });
  await test('Polling timeout retires admission and exposes explicit recovery without a browser retry', async () => {
    const t = setup(), pending = held(); t.setState(admitted()); t.activate(); await settle(); t.setNext(() => pending.promise); const poll = t.component.poll(); const deadline = [...t.timers.values()].find(timer => timer.ms === 8000); assert(deadline); deadline.fn(); await poll; assert(t.text().includes('request timed out')); assert(!t.component.canLaunch(t.profile)); assert(!t.control('refresh').disabled); assert(!t.calls.some(c => c.options.method === 'POST')); pending.resolve(runtime()); await settle(); assert.equal(t.component.state.snapshot, null); t.component.deactivate();
  });
  await test('Read failure removes admission and internal service details are never rendered', async () => {
    const t = setup(); t.setState(admitted()); t.activate(); await settle(); t.setNext(async () => { throw new Error('/secret/runtime/path'); }); await t.component.poll(); assert.equal(t.component.state.snapshot, null); assert(!t.text().includes('/secret/')); assert(!t.component.canLaunch(t.profile)); t.component.deactivate();
  });
  await test('Refresh rejects mismatched profile revisions, malformed actions, and foreign profile IDs', async () => {
    for (const over of [{profile_revision: 3}, {profile_id: 'other'}, {available_actions: ['install']}, {network_scope: 'local_direct'}, {revision: 1.5}, {admission_acknowledged: 'yes'}]) {
      const t = setup(); t.setState(admitted(baseProfile, over)); t.activate(); await settle(); assert.equal(t.component.state.snapshot, null); assert(t.control('launch').disabled); t.component.deactivate();
    }
  });
  await test('Reload and restart require fresh state and never restore stored admission', async () => {
    const t = setup(); t.setState(admitted()); t.activate(); await settle(); assert(t.component.canLaunch(t.profile)); t.component.deactivate(); t.setRuntime(runtime({configured: false, usable: false})); t.setState(snapshot(baseProfile, {state: 'recovery_required', available_actions: []})); t.activate(); assert(!t.component.canLaunch(t.profile)); await settle(); assert(t.text().includes('Recovery needed')); assert(!t.component.canLaunch(t.profile)); assert(!/localStorage|sessionStorage/.test(source)); t.component.deactivate();
  });
  await test('Admission expiry and workspace-offline suspension fail closed', async () => {
    const t = setup(); t.setState(admitted()); t.activate(); await settle(); t.tick(6001); assert(!t.component.canLaunch(t.profile)); const expiry = [...t.timers.values()].find(timer => timer.ms === 6000); expiry.fn(); assert(t.text().includes('information expired')); t.component.activate(t.root, t.profile, {blocked: true}); assert(t.control('refresh').disabled); assert(t.control('launch').disabled); assert.equal(t.timers.size, 0); t.component.deactivate();
  });
  await test('Unknown actions and injected paths or evidence never reach transport', async () => {
    const t = setup(); t.activate(); await settle(); const before = t.calls.length; for (const action of ['install', 'approve', 'https://bad.test', {action: 'validate', admission: true}]) await t.component.action(action); assert.equal(t.calls.length, before); assert(!/innerHTML|window\.open|location\.href/.test(source)); t.component.deactivate();
  });
  await test('Text-only output, accessible live states, real button names and focus continuity', async () => {
    const p = {...baseProfile, name: '<img src=x onerror=bad()>'}, t = setup({profile: p}); t.setState(snapshot(p, {next_step: '<script>not code</script>'})); t.activate(); await settle(); assert(t.text().includes('<img')); assert(t.text().includes('<script>')); assert(!t.all().some(el => el.tagName === 'IMG' || el.tagName === 'SCRIPT')); assert.equal(t.root.attrs['aria-label'], 'Camoufox browser setup'); assert.equal(t.root.attrs['aria-busy'], 'false'); assert(t.all().some(el => el.attrs.role === 'status' && el.attrs['aria-live'] === 'polite')); assert(t.all().filter(el => el.tagName === 'BUTTON').every(el => el.type === 'button' && el.textContent));
    t.control('refresh').focus(); await t.component.poll(); assert.equal(t.doc.activeElement.dataset.setupControl, 'refresh'); t.component.deactivate();
  });
  await test('Fixed-route client enforces loopback CSRF and rejects arbitrary setup routes', async () => {
    const window = {}, calls = []; vm.runInNewContext(workspace, {window, URL, AbortController, setTimeout, clearTimeout});
    let config = {mode: 'local', api_base: '/local/v1', csrf_token: 'native-csrf'};
    const request = window.TeamWorkspace.createClient({getConfig: () => config, fetcher: async (url, options) => { calls.push({url, options}); return {ok: true, status: 200, json: async () => ({})}; }});
    await request('/camoufox-setup'); await request('/profiles/local-one/camoufox-setup'); await request('/profiles/local-one/camoufox-setup/actions', {method: 'POST', body: {action: 'prepare', expected_revision: 4, expected_setup_revision: 2}});
    assert.equal(calls[2].url, '/local/v1/profiles/local-one/camoufox-setup/actions'); assert.equal(calls[2].options.headers['X-Local-CSRF'], 'native-csrf'); assert.equal(calls[2].options.credentials, 'omit'); assert.equal(calls[2].options.cache, 'no-store'); assert.equal(calls[2].options.headers.Authorization, undefined);
    for (const path of ['/camoufox-setup/install', '/profiles/../camoufox-setup', '//bad.test/camoufox-setup', '/profiles/one/camoufox-setup?url=x']) await assert.rejects(request(path), error => error.code === 'invalid_route');
    config = {...config, csrf_token: null}; await assert.rejects(request('/profiles/local-one/camoufox-setup/actions', {method: 'POST', body: {action: 'prepare'}}), error => error.code === 'csrf_missing'); assert.equal(calls.length, 3);
  });
  await test('Actual workspace and setup modules bootstrap together and adopt native profile revisions', async () => {
    const t = setup(), elements = new Map(), doc = t.doc;
    const element = key => { if (!elements.has(key)) { const el = doc.createElement('div'); el.key = key; el.classList = {toggle() {}}; el.querySelectorAll = selector => selector.startsWith('[data-') ? el.children.filter(child => Object.hasOwn(child.attrs, selector.slice(1, -1))) : []; el.close = () => { el.open = false; }; el.showModal = () => { el.open = true; }; el.appendChild = child => el.append(child); let markup = ''; Object.defineProperty(el, 'innerHTML', {get: () => markup, set(value) { markup = value; el.children = []; for (const match of value.matchAll(/<(button|input|select|div|section|p|a)\b([^>]*)>/g)) { const attrs = Object.fromEntries([...match[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)].map(item => [item[1], item[2] || ''])); const child = element(attrs.id || key + '/' + el.children.length); child.attrs = attrs; child.listeners = {}; child.disabled = Object.hasOwn(attrs, 'disabled'); for (const [name, item] of Object.entries(attrs)) if (name.startsWith('data-')) child.dataset[name.slice(5)] = item; el.children.push(child); } }}); elements.set(key, el); } return elements.get(key); };
    doc.getElementById = element; doc.querySelector = selector => element(selector.replace(/^#/, ''));
    t.context.window.addEventListener = () => {}; t.context.location = {hash: '#profiles', protocol: 'http:'}; t.context.localStorage = {getItem: () => 'local', setItem() {}};
    let profile = {...baseProfile, selected: true}, state = snapshot(profile); const requests = [];
    t.context.fetch = async (url, options = {}) => { requests.push({url, options}); let data;
      if (url === '/local/config') data = {mode: 'local', api_base: '/local/v1', account_required: false, csrf_token: 'csrf', selected_profile_id: profile.id, launch: {actual_process_available: true}, inbox: {native_open_available: false}};
      else if (url === '/local/v1/profiles') data = [profile];
      else if (url === '/local/v1/presets') data = [{id: 'isolated', name: 'Camoufox', engine_id: 'camoufox'}];
      else if (url === '/local/v1/settings') data = {revision: 1};
      else if (url === '/local/v1/managed-connection') data = {revision: 1};
      else if (url === '/local/v1/camoufox-setup') data = runtime();
      else if (url.endsWith('/camoufox-setup/actions')) { const body = JSON.parse(options.body); assert.equal(options.headers['X-Local-CSRF'], 'csrf'); if (body.action === 'prepare') state = snapshot(profile, {state: 'prepared', revision: 3, available_actions: ['validate']}); else { profile = {...profile, revision: 6}; state = admitted(profile); } data = {state: 'ready'}; }
      else if (url.endsWith('/camoufox-setup')) data = state;
      else if (url === '/local/v1/profiles/' + profile.id) data = profile;
      else throw new Error('Unexpected integrated request: ' + url);
      return {ok: true, status: 200, json: async () => structuredClone(data)};
    };
    vm.runInNewContext(workspace, t.context);
    const app = t.context.window.TeamWorkspace.mount({icon: () => '', esc: text => String(text), notify: () => {}});
    await app.bootstrap(); await settle(); assert.equal(app.nativeSetup.state.snapshot.state, 'not_prepared'); assert(!app.canLaunch(app.model.profiles[0]));
    await app.nativeSetup.action('prepare'); assert.equal(app.nativeSetup.state.snapshot.state, 'prepared'); assert(!app.canLaunch(app.model.profiles[0]));
    await app.nativeSetup.action('validate'); assert.equal(app.model.profiles[0].revision, 6); assert(app.canLaunch(app.model.profiles[0])); assert.equal(requests.filter(item => item.options.method === 'POST').length, 2);
    app.showChoice(); assert(!app.nativeSetup.state.active); assert(!app.canLaunch(app.model.profiles[0]));
  });
  await test('Integrated shell retains profile rail, top tabs, branding and responsive setup layout', async () => {
    assert(html.includes('./camoufox_setup.js')); assert(html.indexOf('./camoufox_setup.js') < html.indexOf('./workspace.js')); assert(html.includes('TeamBrowser home')); assert(workspace.includes('profile-rail')); assert(workspace.includes('native-tab-workspace')); assert(workspace.includes('camoufox-setup-workspace')); assert(workspace.includes('nativeSetup?.activate')); assert(workspace.includes("p.engine_id === 'camoufox' ? nativeSetup?.canLaunch(p)")); assert(css.includes('.profile-browser-workspace')); assert(css.includes('.camoufox-setup')); assert(css.includes('@media(max-width:700px)')); assert(!/\bstyle=|\bonclick=/.test(source + html));
  });
  console.log(`PASS: ${count} synthetic Camoufox setup UI source/DOM scenarios. Rendered desktop/mobile layout, native diagnostics, installation and real browser acceptance are explicitly unverified.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
