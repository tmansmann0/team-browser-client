'use strict';

// Presentation-only native bridge. Destinations, tokens and vault references
// never cross this interface. This file makes only fixed same-origin requests.
(() => {
  function mount({request, container, esc, icon, notify}) {
    const state = {active: false, view: 'connection', data: null, error: null, pending: false, retiring: false, search: '', epoch: 0, pollSequence: 0, timer: null, expiryTimer: null};
    const byId = id => document.getElementById(id);
    const capability = name => state.data?.capabilities?.[name] === true;
    const available = () => state.data?.managed_access_available === true && !state.retiring && !state.error && Number.isInteger(state.data.expires_at) && state.data.expires_at * 1000 > Date.now();
    const terminalLogout = data => ['signed_out_locally', 'signed_out', 'logged_out', 'ready', 'ready_to_sign_in'].includes(data?.status) && data?.managed_access_available !== true && !data?.native_operations_pending;
    const labels = {preparation_required: 'Prepare sign-in', cancelling: 'Cancelling sign-in', membership_unverified: 'Checking team access', membership_denied: 'Team access unavailable', unavailable: 'Connection unavailable', signed_out_locally: 'Signed out locally', shutting_down: 'Closing connection', unconfigured: 'Not configured', setup_required: 'Prepare sign-in', unprepared: 'Prepare sign-in', preparing: 'Preparing secure storage', ready: 'Ready to sign in', ready_to_sign_in: 'Ready to sign in', signing_in: 'Complete sign-in in your browser', verifying_membership: 'Checking team access', connected: 'Connected', available: 'Connected', refreshing: 'Refreshing profiles', signing_out: 'Signing out', signed_out: 'Signed out', logged_out: 'Signed out', cancelled: 'Sign-in cancelled', expired: 'Session expired', recovery_required: 'Local recovery required', error: 'Connection needs attention', closed: 'Connection closed'};
    function clearRecords() { if (state.data) state.data = {...state.data, membership: null, profiles: [], presets: [], managed_access_available: false}; }
    function expireLocally() {
      if (!state.data || !Number.isInteger(state.data.expires_at) || state.data.expires_at * 1000 > Date.now()) return false;
      clearRecords();
      state.data = {...state.data, status: 'expired', identity_verified: false, company_membership_verified: false, records_loaded: false, capabilities: {...state.data.capabilities, can_sign_in: false, can_refresh_records: false}};
      return true;
    }
    function watchExpiry() {
      clearTimeout(state.expiryTimer); state.expiryTimer = null;
      if (!state.active || !Number.isInteger(state.data?.expires_at)) return;
      if (expireLocally()) return;
      state.expiryTimer = setTimeout(() => { if (state.active && expireLocally()) render(); }, Math.min(2147483647, Math.max(1, state.data.expires_at * 1000 - Date.now())));
    }
    function validate(data) {
      if (!data || typeof data !== 'object' || typeof data.status !== 'string' || !/^[a-z_]{1,50}$/.test(data.status) || typeof data.configured !== 'boolean' || !Array.isArray(data.profiles) || !Array.isArray(data.presets) || data.profiles.length > 500 || data.presets.length > 500 || !data.capabilities || (data.expires_at !== null && (!Number.isInteger(data.expires_at) || data.expires_at < 0))) throw new Error('invalid_native_status');
      for (const row of [...data.profiles, ...data.presets]) if (!row || typeof row.id !== 'string' || typeof row.name !== 'string' || row.name.length > 200) throw new Error('invalid_native_records');
      if (data.managed_access_available === true && (!Number.isInteger(data.expires_at) || !data.membership || !['display_name', 'member_id', 'tenant_id', 'role'].every(name => typeof data.membership[name] === 'string' && data.membership[name].length <= 200))) throw new Error('invalid_native_membership');
      return data;
    }
    function schedule() {
      clearTimeout(state.timer); state.timer = null;
      if (state.active) state.timer = setTimeout(() => poll(), 2000);
    }
    async function poll() {
      if (state.active && expireLocally()) render();
      if (!state.active || state.pending) return schedule();
      const epoch = state.epoch, sequence = ++state.pollSequence, controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 7000);
      try {
        const data = validate(await request('/managed-native', {signal: controller.signal}));
        if (!state.active || epoch !== state.epoch || sequence !== state.pollSequence) return;
        state.data = data; state.error = null; watchExpiry();
        if (state.retiring && terminalLogout(data)) state.retiring = false;
        if (state.retiring) clearRecords();
      } catch {
        if (!state.active || epoch !== state.epoch || sequence !== state.pollSequence) return;
        state.error = 'The local connection status could not be verified. Your account and records are hidden until it responds.';
        clearRecords();
      } finally {
        clearTimeout(timeout);
        if (state.active && epoch === state.epoch && sequence === state.pollSequence) { render(); schedule(); }
      }
    }
    async function action(name) {
      const permitted = {prepare: 'can_prepare', recover: 'can_prepare', sign_in: 'can_sign_in', cancel_sign_in: 'can_cancel_sign_in', refresh_records: 'can_refresh_records', sign_out: 'can_sign_out'};
      if (!Object.hasOwn(permitted, name) || state.pending || !capability(permitted[name]) || (state.retiring && name !== 'sign_out')) return;
      if (name === 'recover' && !window.confirm('Clear this app’s saved managed sign-in record and prepare a new attempt? This does not delete browser profiles or revoke the provider session.')) return;
      const epoch = ++state.epoch;
      state.pending = true; state.error = null;
      if (name === 'sign_out') { state.retiring = true; clearRecords(); }
      render();
      const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 7000);
      try {
        const data = validate(await request('/managed-native/actions', {method: 'POST', body: {action: name}, signal: controller.signal}));
        if (!state.active || epoch !== state.epoch) return;
        state.data = data; watchExpiry();
        if (state.retiring && terminalLogout(data)) state.retiring = false;
        if (state.retiring) clearRecords();
      } catch {
        if (state.active && epoch === state.epoch) {
          state.error = 'The action could not be confirmed. Check the current status before trying again.';
          clearRecords(); notify('Connection action needs verification.');
        }
      } finally {
        clearTimeout(timeout); state.pending = false;
        if (state.active && epoch === state.epoch) { render(); schedule(); }
      }
    }
    function render() {
      if (!state.active) return;
      const data = state.data;
      const connected = available(), member = connected ? data.membership : null;
      const title = state.view === 'profiles' ? 'Your team profiles' : 'Managed connection';
      const status = state.retiring ? 'Confirming sign-out' : labels[data?.status] || (data ? 'Connection needs attention' : 'Checking connection');
      const button = (name, label, capabilityName, primary = false) => `<button class="button${primary ? ' button-primary' : ''}" data-native-action="${name}" ${state.pending || !capability(capabilityName) || (state.retiring && name !== 'sign_out') ? 'disabled' : ''}>${label}</button>`;
      let controls = '';
      if (capability('can_prepare')) controls += button(data?.status === 'recovery_required' ? 'recover' : 'prepare', data?.status === 'recovery_required' ? 'Reset local sign-in' : 'Prepare secure sign-in', 'can_prepare');
      controls += button('sign_in', 'Sign in', 'can_sign_in', true);
      if (capability('can_cancel_sign_in')) controls += button('cancel_sign_in', 'Cancel sign-in', 'can_cancel_sign_in');
      if (connected) controls += button('refresh_records', data?.records_loaded === true ? 'Refresh profiles' : 'Load profiles', 'can_refresh_records');
      if (capability('can_sign_out')) controls += button('sign_out', state.retiring ? 'Check sign-out' : 'Sign out', 'can_sign_out');
      const profiles = connected ? data.profiles.filter(p => `${p.name} ${p.id}`.toLowerCase().includes(state.search.toLowerCase())) : [];
      container.innerHTML = `<div class="page-heading"><div><p class="eyebrow">Managed workspace</p><h1>${title}</h1><p class="page-subtitle">Team access is checked by your managed service. Local profiles remain on this device.</p></div></div>${state.error ? `<div class="workspace-alert error" role="alert"><p>${esc(state.error)}</p><button class="button" id="native-recheck">Check status</button></div>` : ''}<section class="panel settings-panel"><div class="card-topline"><span class="card-icon blue">${icon('users')}</span><span class="status ${connected ? 'active' : 'idle'}" role="status">${esc(status)}</span></div><h2>${member ? esc(member.display_name) : 'Connect to your team'}</h2><p class="field-hint">${data?.configured === false ? 'This installation needs an approved managed-service configuration and native setup before sign-in is available.' : member ? `${esc(member.role)} · ${esc(member.tenant_id)}` : 'Use the system browser to sign in. The app keeps credentials in native secure storage.'}</p><div class="header-actions">${controls}</div><p class="field-hint">Preparing or resetting sign-in clears only this app’s previous managed-login record. Sign-out does not clear browser cookies or revoke your identity-provider session.</p></section>${state.view === 'profiles' && connected && data.records_loaded === true ? `<section class="panel"><div class="panel-heading"><h2>Assigned profiles <span class="subtle-text">${data.profiles.length}</span></h2><label><span class="sr-only">Find a team profile</span><input id="native-profile-search" type="search" value="${esc(state.search)}" placeholder="Find a profile…"></label></div><div class="profile-grid">${profiles.length ? profiles.map(p => `<article class="profile-card"><h3>${esc(p.name)}</h3><p>${esc(data.presets.find(item => item.id === p.preset_id)?.name || 'Managed preset')}</p><span class="status idle">${esc(p.state || 'Unprovisioned')}</span><p class="field-hint">Device enrollment and verified routing are required before this profile can run locally.</p><button class="button" disabled>Device setup required</button></article>`).join('') : '<div class="empty-state"><h3>No matching assigned profiles</h3><p>Ask your administrator to assign a profile, or change the search.</p></div>'}</div></section>` : ''}<div class="info-strip">${icon('shield')}<div><strong>${connected ? 'Team membership verified' : 'Your local workspace remains available'}</strong><p>${connected ? 'This is a read-only view of current team records. Device enrollment, proxy setup and remote execution are separate steps.' : 'No team account is needed for account-free local profile management. Signing in alone does not enroll this device.'}</p></div></div>`;
      container.querySelectorAll('[data-native-action]').forEach(element => element.addEventListener('click', () => action(element.dataset.nativeAction)));
      byId('native-recheck')?.addEventListener('click', () => poll());
      byId('native-profile-search')?.addEventListener('input', event => { state.search = event.target.value; const position = event.target.selectionStart; render(); const input = byId('native-profile-search'); input?.focus(); input?.setSelectionRange?.(position, position); });
    }
    function activate(view = 'connection') {
      const changed = !state.active; state.active = true; state.view = view; watchExpiry(); render();
      if (changed) { state.epoch++; poll(); }
    }
    function deactivate() { state.active = false; state.epoch++; clearTimeout(state.timer); clearTimeout(state.expiryTimer); state.timer = null; state.expiryTimer = null; }
    return {activate, deactivate, poll, action, render, state};
  }
  window.TeamManagedWorkspace = {mount};
})();
