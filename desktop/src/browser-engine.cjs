'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { isIP } = require('node:net');
const { URL, domainToASCII } = require('node:url');

const PROFILE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ACTIONS = new Set(['activate_profile', 'create_tab', 'activate_tab', 'close_tab', 'navigate', 'back', 'forward', 'reload', 'stop', 'close_profile', 'set_content_bounds', 'hide_content']);
const CAPABILITIES = Object.freeze({
  engine_id: 'electron_chromium', embedded: true, proxy_authentication: false,
  google_signin: 'unverified_embedded_agent_restriction', native_acceptance: false,
  isolation: 'separate_persistent_sessions', fingerprint_protection: 'not_claimed',
});
function fail(message) { throw new Error(message); }
function profileId(id) {
  if (typeof id !== 'string' || !PROFILE_ID.test(id)) fail('Invalid profile');
  return id;
}
function partitionFor(id) {
  return 'persist:tbm-' + createHash('sha256').update(profileId(id)).digest('hex');
}
function publicHost(value) {
  let host = value.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host || host === 'localhost' || !host.includes('.') && !host.includes(':') ||
      /\.(localhost|local|internal|test|invalid|onion)$/.test(host)) return false;
  if (isIP(host) === 4) {
    const [a,b] = host.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) || (a === 198 && (b === 18 || b === 19)));
  }
  if (isIP(host) === 6) {
    // Block local/mapped/special IPv6 conservatively. Normal globally routed
    // unicast starts with 2 or 3. No alternate spelling of ::1 can pass.
    return /^[23][a-f0-9]{0,3}:/.test(host);
  }
  return domainToASCII(host) === host && host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
function guestURL(raw, { network = false } = {}) {
  if (raw === 'about:blank' && !network) return raw;
  if (typeof raw !== 'string' || raw.length > 8192 || /[\u0000-\u0020\u007f]/.test(raw)) fail('Enter a full public http or https address');
  let url; try { url = new URL(raw); } catch { fail('Enter a full public http or https address'); }
  if (!(network ? ['http:', 'https:', 'ws:', 'wss:'] : ['http:', 'https:']).includes(url.protocol) ||
      url.username || url.password || !publicHost(url.hostname)) fail('Local, private, credential-bearing, and non-web addresses are blocked');
  return url.href;
}
function routing(profile) {
  if (profile.origin !== 'local' || profile.engine_id !== 'electron_chromium') fail('Choose Built-in Chromium for an integrated browser profile. Other engines cannot be embedded.');
  if (profile.network_policy === 'local_direct' && !profile.proxy_config) return { mode: 'direct' };
  if (profile.network_policy !== 'verified_proxy' || !profile.proxy_config) fail('Choose direct networking or configure a local proxy first');
  const proxy = profile.proxy_config;
  if (Object.keys(proxy).some(key => !['protocol', 'hostname', 'port', 'label'].includes(key)) ||
      !['http', 'https', 'socks5'].includes(proxy.protocol) || !Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535 ||
      typeof proxy.hostname !== 'string' || !publicHost(proxy.hostname) || /[\s\/@?#;=,%]/.test(proxy.hostname)) {
    fail('Use a public proxy endpoint without credentials, bypass rules, or PAC');
  }
  const host = isIP(proxy.hostname) === 6 ? `[${proxy.hostname}]` : proxy.hostname;
  return { mode: 'fixed_servers', proxyRules: `${proxy.protocol}://${host}:${proxy.port}`, proxyBypassRules: '' };
}
function signature(profile) { return JSON.stringify({ engine: profile.engine_id, origin: profile.origin, routing: routing(profile) }); }
function validateCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !ACTIONS.has(value.action)) fail('Unsupported desktop command');
  const allowed = {
    activate_profile: ['profile_id', 'expected_revision'], create_tab: ['profile_id', 'expected_revision', 'url'],
    activate_tab: ['profile_id', 'tab_id'], close_tab: ['profile_id', 'tab_id'], navigate: ['profile_id', 'tab_id', 'url'],
    back: ['profile_id', 'tab_id'], forward: ['profile_id', 'tab_id'], reload: ['profile_id', 'tab_id'], stop: ['profile_id', 'tab_id'],
    close_profile: ['profile_id'], set_content_bounds: ['x', 'y', 'width', 'height', 'visible'], hide_content: [],
  }[value.action];
  if (Object.keys(value).some(key => key !== 'action' && key !== 'expected_revision' && !allowed.includes(key))) fail('Unexpected desktop command field');
  if (allowed.includes('profile_id')) profileId(value.profile_id);
  if (allowed.includes('tab_id') && (typeof value.tab_id !== 'string' || !/^[a-f0-9-]{36}$/.test(value.tab_id))) fail('Invalid tab');
  if ('expected_revision' in value && (!Number.isInteger(value.expected_revision) || value.expected_revision < 1)) fail('Invalid profile revision');
  if (value.action === 'set_content_bounds' && (['x','y','width','height'].some(key => !Number.isInteger(value[key]) || value[key] < 0 || value[key] > 20000) || typeof value.visible !== 'boolean')) fail('Invalid browser bounds');
  return value;
}
class BrowserEngine {
  constructor({ adapter, metadata, emit = () => {} }) {
    this.adapter = adapter; this.metadata = metadata; this.emit = emit;
    this.profiles = new Map(); this.tabs = new Map(); this.activeProfile = null;
    this.bounds = { x: 0, y: 80, width: 0, height: 0, visible: false };
    this.queue = Promise.resolve(); this.disposed = false; this.selectionSequence = 0;
  }
  snapshot() {
    const profile = this.profiles.get(this.activeProfile);
    const tabs = profile ? [...profile.tabs.values()].map(tab => this.tabSnapshot(tab)) : [];
    return {
      profile_id: this.activeProfile, profile: profile ? { ...profile.metadata } : null, profile_revision: profile?.metadata.revision || null,
      engine: this.adapter.versions, capabilities: CAPABILITIES, tabs,
      active_tab_id: profile?.activeTab || null, status: profile ? 'ready' : 'idle', error: null,
      profiles: [...this.profiles.keys()].map(profile_id => ({ profile_id, tab_count: this.profiles.get(profile_id).tabs.size })),
    };
  }
  tabSnapshot(tab) {
    const wc = tab.view.webContents;
    if (wc.isDestroyed()) return { id: tab.id, title: 'Closed tab', url: '', loading: false, can_go_back: false, can_go_forward: false };
    return { id: tab.id, title: String(wc.getTitle() || 'New tab').slice(0, 256), url: wc.getURL() || 'about:blank',
      loading: wc.isLoading(), can_go_back: wc.navigationHistory.canGoBack(), can_go_forward: wc.navigationHistory.canGoForward(),
      error: tab.error || null };
  }
  changed() { this.emit(this.snapshot()); }
  command(value) {
    const command = validateCommand(value);
    if (this.disposed) return Promise.reject(new Error('Browser workspace is closing'));
    if (['hide_content', 'set_content_bounds'].includes(command.action)) return Promise.resolve(this.execute(command)).then(() => this.snapshot());
    if (['activate_profile', 'activate_tab', 'create_tab'].includes(command.action)) command.selectionSequence = ++this.selectionSequence;
    // Serialize ownership/configuration transitions, including interrupted clicks.
    const operation = this.queue.then(() => this.execute(command));
    this.queue = operation.catch(() => {});
    return operation.then(() => this.snapshot(), error => { this.changed(); throw error; });
  }
  async ensureProfile(id, expectedRevision) {
    const fresh = await this.metadata.get(profileId(id));
    if (expectedRevision !== undefined && fresh.revision !== expectedRevision) fail('Profile changed. Refresh before opening it.');
    const fingerprint = signature(fresh);
    if (this.profiles.has(id)) {
      const existing = this.profiles.get(id);
      if (existing.signature !== fingerprint) fail('Close this profile before changing its engine or proxy');
      existing.metadata = fresh;
      return existing;
    }
    const claimed = await this.metadata.claim(id, fresh.revision);
    let session;
    try {
      // Revalidate the metadata returned by the atomic claim, not the earlier read.
      const route = routing(claimed);
      session = this.adapter.session(partitionFor(id));
      const profile = { id, metadata: claimed, signature: signature(claimed), session, tabs: new Map(), activeTab: null, networkEnabled: false };
      this.adapter.secureSession(session, url => {
        if (!profile.networkEnabled) return false;
        try { guestURL(url, { network: true }); return true; } catch { return false; }
      });
      await session.closeAllConnections();
      await session.setProxy(route); // No guest WebContents exists until this completes.
      profile.networkEnabled = true;
      this.profiles.set(id, profile);
      return profile;
    } catch (error) {
      if (session) await session.closeAllConnections();
      await this.metadata.release(id);
      throw error;
    }
  }
  applyBounds() {
    const selected = this.profiles.get(this.activeProfile)?.activeTab;
    for (const tab of this.tabs.values()) this.adapter.show(tab.view, false, this.bounds);
    if (this.bounds.visible && selected && this.tabs.has(selected)) this.adapter.show(this.tabs.get(selected).view, true, this.bounds);
  }
  tab(profile_id, tab_id) {
    const tab = this.tabs.get(tab_id);
    if (!tab || tab.profile_id !== profile_id || tab.view.webContents.isDestroyed()) fail('This tab is no longer available in that profile');
    return tab;
  }
  async newTab(profile, url, selectionSequence) {
    if (profile.tabs.size >= 32 || this.tabs.size >= 128) fail('Close a tab before opening another');
    const target = guestURL(url);
    const view = this.adapter.createView(profile.session);
    const tab = { id: randomUUID(), profile_id: profile.id, view, error: null };
    const wc = view.webContents;
    wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    wc.setWindowOpenHandler(({ url }) => {
      // A hidden profile/tab must never steal foreground through window.open.
      if (this.activeProfile !== profile.id || profile.activeTab !== tab.id) return { action: 'deny' };
      try {
        const target = guestURL(url);
        // A web popup becomes a same-profile tab only, never a privileged window.
        void this.command({ action: 'create_tab', profile_id: profile.id, url: target }).catch(() => {});
      } catch {}
      return { action: 'deny' };
    });
    wc.on('will-navigate', (event, url) => { try { guestURL(url); } catch { event.preventDefault(); } });
    wc.on('will-redirect', (event, url) => { try { guestURL(url); } catch { event.preventDefault(); } });
    wc.on('will-attach-webview', event => event.preventDefault());
    for (const event of ['page-title-updated', 'did-navigate', 'did-navigate-in-page', 'did-start-loading', 'did-stop-loading']) wc.on(event, () => this.changed());
    wc.on('render-process-gone', () => { tab.error = 'This tab stopped unexpectedly. Reload it to retry.'; this.changed(); });
    wc.on('did-fail-load', (_event, code) => { if (code !== -3) { tab.error = 'Page failed to load. Check the address or proxy. No direct fallback was selected.'; this.changed(); } });
    profile.tabs.set(tab.id, tab); this.tabs.set(tab.id, tab);
    profile.activeTab = tab.id; if (selectionSequence === this.selectionSequence) this.activeProfile = profile.id;
    this.adapter.attach(view); this.applyBounds();
    // Do not wait for the website before accepting another UI command. A slow
    // page cannot queue-block switching, closing, Back, or a newer navigation.
    void wc.loadURL(target).catch(() => {});
    return tab;
  }
  async closeProfile(id) {
    const profile = this.profiles.get(id); if (!profile) return;
    profile.networkEnabled = false;
    for (const tab of [...profile.tabs.values()]) {
      if (!(await this.adapter.close(tab.view))) { profile.networkEnabled = true; fail('Tab close was not confirmed. Profile ownership is retained.'); }
      this.adapter.detach(tab.view);
      this.tabs.delete(tab.id); profile.tabs.delete(tab.id);
      if (profile.activeTab === tab.id) profile.activeTab = [...profile.tabs.keys()][0] || null;
    }
    await this.adapter.stopWorkers(profile.session);
    await profile.session.closeAllConnections();
    profile.session.flushStorageData();
    await this.metadata.release(id);
    this.profiles.delete(id);
    if (this.activeProfile === id) this.activeProfile = null;
    this.applyBounds();
  }
  async execute(command) {
    const { action, profile_id, tab_id } = command;
    if (action === 'activate_profile' || action === 'create_tab') {
      const profile = await this.ensureProfile(profile_id, command.expected_revision);
      if (command.selectionSequence === this.selectionSequence) this.activeProfile = profile_id;
      if (action === 'create_tab') await this.newTab(profile, command.url === undefined ? 'about:blank' : command.url, command.selectionSequence);
      this.applyBounds();
    } else if (action === 'set_content_bounds') {
      if (command.visible && (command.y < 80 || command.width < 1 || command.height < 1)) fail('Browser content must remain below the app controls');
      this.bounds = { ...command }; delete this.bounds.action; this.applyBounds(); return;
    } else if (action === 'hide_content') {
      this.bounds.visible = false; this.applyBounds(); return;
    } else if (action === 'close_profile') {
      await this.closeProfile(profile_id);
    } else {
      const tab = this.tab(profile_id, tab_id); const profile = this.profiles.get(profile_id); const wc = tab.view.webContents;
      if (action === 'activate_tab') { profile.activeTab = tab.id; if (command.selectionSequence === this.selectionSequence) this.activeProfile = profile_id; this.applyBounds(); }
      else if (action === 'close_tab') {
        if (!(await this.adapter.close(tab.view))) fail('Tab close was not confirmed');
        this.adapter.detach(tab.view);
        profile.tabs.delete(tab.id); this.tabs.delete(tab.id);
        if (profile.activeTab === tab.id) profile.activeTab = [...profile.tabs.keys()][0] || null;
        this.applyBounds();
      } else if (action === 'navigate') { tab.error = null; void wc.loadURL(guestURL(command.url)).catch(() => {}); }
      else if (action === 'back' && wc.navigationHistory.canGoBack()) wc.navigationHistory.goBack();
      else if (action === 'forward' && wc.navigationHistory.canGoForward()) wc.navigationHistory.goForward();
      else if (action === 'reload') { tab.error = null; wc.reload(); }
      else if (action === 'stop') wc.stop();
    }
    this.changed();
  }
  ownerGone() {
    this.disposed = true;
    for (const profile of this.profiles.values()) profile.networkEnabled = false;
    // Definite sidecar exit means persisted state must stay recovery_required.
    this.metadata.release = async () => {};
  }
  async shutdown() {
    this.disposed = true;
    try {
      await this.queue;
      for (const id of [...this.profiles.keys()]) await this.closeProfile(id);
    } catch (error) { this.disposed = false; throw error; }
  }
}
module.exports = { BrowserEngine, CAPABILITIES, partitionFor, publicHost, guestURL, routing, validateCommand };
