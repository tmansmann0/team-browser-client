'use strict';

// This adapter is activated only by the explicit synthetic /demo/config marker.
// Its public demo marker is not a production credential. No proxy endpoint,
// provider secret, device credential or remote acknowledgement is collected.
(() => {
  class ManagedError extends Error {
    constructor(message, {code = 'request_failed', status = 0, uncertain = false} = {}) {
      super(message); this.name = 'ManagedError'; Object.assign(this, {code, status, uncertain});
    }
  }
  function mount({api, profiles, presets = [], icon, esc, notify, route, loadApiData}) {
    const byId = id => document.getElementById(id);
    const container = byId('view-container'), dialog = byId('detail-dialog');
    const views = {policies: 'Team policies', providers: 'Proxy inventory', sharing: 'Named sharing', devices: 'Devices & delivery'};
    const model = {loaded: false, loading: false, pending: null, error: null, needsRefresh: false, policy: null, proxies: [], pools: [], devices: [], commands: [], view: 'policies', formEpoch: 0};
    const operators = () => api.users.filter(user => user.enabled && user.role !== 'auditor');
    const memberName = id => api.users.find(user => user.id === id)?.display_name || id || 'Unassigned';
    const disabled = () => model.pending || model.loading || model.needsRefresh || api.loading || api.error || api.saving;
    const bind = (id, event, fn) => byId(id)?.addEventListener(event, fn);
    const bindAll = (selector, fn) => container.querySelectorAll(selector).forEach(el => el.addEventListener('click', () => fn(el.dataset)));
    const checkedIds = selector => Array.from(dialog.querySelectorAll(selector)).filter(input => input.checked).map(input => input.value);
    const userOptions = (selected = '') => operators().map(user => `<option value="${esc(user.id)}" ${user.id === selected ? 'selected' : ''}>${esc(user.display_name || user.id)}</option>`).join('');
    const checkboxMembers = (selected = [], className = 'managed-member', excluded = null) => `<fieldset class="named-member-picker"><legend>Named synthetic members</legend>${operators().filter(user => user.id !== excluded).map(user => `<label class="check-field"><input class="${className}" type="checkbox" value="${esc(user.id)}" ${selected.includes(user.id) ? 'checked' : ''}>${esc(user.display_name || user.id)}<small>${esc(user.id)}</small></label>`).join('')}</fieldset>`;
    const heading = (title, subtitle, actions = '') => `<div class="page-heading"><div><p class="eyebrow">Managed simulator · synthetic API</p><h1>${esc(title)}</h1><p class="page-subtitle">${esc(subtitle)}</p></div><div class="header-actions">${actions}</div></div>`;
    const disclosure = () => `<div class="managed-disclosure">${icon('info')}<p><strong>Synthetic control-plane records.</strong> Changes save to the in-memory demo process. No real provider, proxy traffic, team enrollment or device action is connected. Records reset when that process restarts.</p></div>`;

    async function request(path, {method = 'GET', body, signal} = {}) {
      if (!api.enabled || !/^\/v1\/(policy|users\/[^/?]+\/policy|proxy-pools(?:\/[^/?]+)?|proxies(?:\/[^/?]+)?|profiles(?:\/[^/?]+\/(managed|sharing|proxy-binding))?|devices|commands)$/.test(path)) throw new ManagedError('This action requires the explicit synthetic demo API.', {code: 'synthetic_only'});
      let response;
      try { response = await fetch(path, {method, cache: 'no-store', credentials: 'omit', signal, headers: {'Authorization': 'Bearer synthetic-demo', ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, body: body === undefined ? undefined : JSON.stringify(body)}); }
      catch (error) { throw new ManagedError(error.name === 'AbortError' ? 'Waiting was canceled or timed out. Reload records before another change.' : 'The synthetic API could not be reached. Reload after the demo process is available.', {code: error.name === 'AbortError' ? 'request_canceled' : 'offline', uncertain: method !== 'GET'}); }
      let data;
      try { data = response.status === 204 ? null : await response.json(); }
      catch { throw new ManagedError('The synthetic API returned an unreadable response.', {code: 'invalid_response', status: response.status, uncertain: method !== 'GET'}); }
      if (!response.ok) {
        const detail = data?.detail;
        const message = typeof detail === 'string' ? detail : typeof detail?.message === 'string' ? detail.message : response.status === 422 ? 'Check the form values against the shown limits.' : `The synthetic request failed (HTTP ${response.status}).`;
        const code = detail?.code || (response.status === 409 ? /changed|revision|reload before/i.test(message) ? 'revision_conflict' : 'policy_conflict' : response.status === 422 ? 'validation_error' : 'request_failed');
        throw new ManagedError(message, {code, status: response.status, uncertain: response.status >= 500 && method !== 'GET'});
      }
      return data;
    }
    async function read(path) {
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
      try { return await request(path, {signal: controller.signal}); } finally { clearTimeout(timer); }
    }
    function ready() {
      const nav = byId('navigation');
      if (!nav.innerHTML.includes('data-managed-view')) nav.innerHTML += `<div class="nav-caption managed-nav-caption">SIMULATOR CONTROLS</div>${Object.entries(views).filter(([key]) => key !== 'providers').map(([key, title]) => `<a href="#${key}" data-view="${key}" data-managed-view="${key}" class="nav-item">${icon(key === 'policies' ? 'shield' : key === 'sharing' ? 'users' : 'laptop')}<span>${title}</span></a>`).join('')}`;
      const providerLink = Array.from(document.querySelectorAll('[data-view]')).find(el => el.dataset.view === 'providers');
      if (providerLink) providerLink.setAttribute('aria-label', 'Proxy inventory');
    }
    function status() {
      if (model.pending) return `<div class="workspace-alert pending" role="status"><span>${icon('clock')}${esc(model.pending.label)}</span><button class="button" id="managed-cancel-pending">Cancel waiting</button></div>`;
      if (model.error) return `<div class="workspace-alert error" role="alert"><div><strong>${model.needsRefresh ? 'Verify the result before editing' : 'Managed simulator needs attention'}</strong><p>${esc(model.error.message)}</p><span class="error-code">${esc(model.error.code || 'request_failed')}</span></div><button class="button" id="managed-reload">Reload records</button></div>`;
      return '';
    }
    function bindStatus() { bind('managed-reload', 'click', () => reload()); bind('managed-cancel-pending', 'click', cancelPending); }
    async function load() {
      const [policy, pools, proxies, devices, commands] = await Promise.all(['/v1/policy', '/v1/proxy-pools', '/v1/proxies', '/v1/devices', '/v1/commands'].map(read));
      if (!Number.isInteger(policy?.revision) || ![pools, proxies, devices, commands].every(Array.isArray)) throw new ManagedError('The synthetic API returned incomplete managed records.', {code: 'invalid_response'});
      Object.assign(model, {policy, pools, proxies, devices, commands, loaded: true});
    }
    async function reload() {
      if (model.pending || model.loading) return;
      model.loading = true; model.error = null; render();
      try { await loadApiData(); await load(); model.needsRefresh = false; }
      catch (error) { model.error = error; }
      finally { model.loading = false; render(); }
    }
    function cancelPending() { if (model.pending) { model.pending.controller.abort(); model.needsRefresh = true; } }
    async function mutate({path, method = 'PUT', body, label, success}) {
      if (disabled()) return false;
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 10000);
      model.pending = {controller, label}; model.error = null; api.saving = true;
      if (dialog.open) {
        dialog.querySelectorAll('input,select,button').forEach(control => { control.disabled = true; });
        byId('managed-form-feedback').textContent = label + ' Canceling only stops waiting; it cannot undo an accepted request.';
        const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'button'; cancel.textContent = 'Cancel waiting'; cancel.addEventListener('click', cancelPending); byId('managed-form-feedback').appendChild(cancel);
      }
      render(); let accepted = false;
      try {
        await request(path, {method, body, signal: controller.signal}); accepted = true;
        await loadApiData(); await load();
        if (controller.signal.aborted) throw new ManagedError('Waiting was canceled. Reload records to verify the result.', {code: 'request_canceled', uncertain: true});
        model.needsRefresh = false; notify(success); return true;
      } catch (error) {
        model.error = error instanceof ManagedError ? error : new ManagedError('Records could not be refreshed. Reload to verify the result.', {code: 'refresh_failed', uncertain: accepted});
        model.needsRefresh = Boolean(model.error.uncertain || accepted);
        if (model.error.code === 'revision_conflict' && !model.needsRefresh) {
          try { await loadApiData(); await load(); model.error = new ManagedError('This record changed elsewhere. Latest records are loaded; reopen the form and review before saving.', {code: 'revision_conflict', status: 409}); }
          catch { model.needsRefresh = true; }
        }
        notify(model.needsRefresh ? 'The result needs verification. Reload the synthetic records before another change.' : model.error.message); return false;
      } finally {
        clearTimeout(timer); model.pending = null; api.saving = false;
        if (dialog.open) dialog.close(); route();
        byId('managed-page-focus')?.focus();
      }
    }
    function showForm(title, description, form, submit, onSubmit) {
      if (disabled()) { if (model.needsRefresh) notify('Reload the managed simulator records to verify the previous request before editing.'); return; }
      model.formEpoch++;
      byId('drawer-content').innerHTML = `<div class="drawer-head"><p class="eyebrow">Managed simulator · synthetic only</p><button class="close-button" id="close-managed-form" aria-label="Close managed form">${icon('close')}</button></div><div class="drawer-main"><h2 id="drawer-title">${esc(title)}</h2><p id="drawer-description" class="drawer-note">${esc(description)}</p><form id="managed-form">${form}<p id="managed-form-feedback" class="form-feedback" role="status" aria-live="polite"></p><div class="drawer-actions"><button class="button" type="button" id="cancel-managed-form">Cancel</button><button class="button button-primary" type="submit">${esc(submit)}</button></div></form></div>`;
      const close = () => { if (!model.pending) { model.formEpoch++; dialog.close(); } };
      bind('close-managed-form', 'click', close); bind('cancel-managed-form', 'click', close);
      bind('managed-form', 'submit', event => { event.preventDefault(); if (!disabled()) onSubmit(); });
      if (!dialog.open) dialog.showModal(); byId('managed-form').querySelector('input,select')?.focus();
    }
    function formError(message) { byId('managed-form-feedback').textContent = message; }

    function openProfileCreate() {
      showForm('Create a synthetic profile', 'This creates an unassigned control-plane record in the demo. No local browser directory, device session, or provider allocation is created.', `<div class="form-field"><label for="managed-profile-name">Profile name</label><input id="managed-profile-name" required maxlength="120" placeholder="Example research workspace"></div><div class="form-field"><label for="managed-profile-preset">Synthetic preset</label><select id="managed-profile-preset">${presets.map(preset => `<option value="${esc(preset.id)}">${esc(preset.name)}</option>`).join('')}</select><span class="field-hint">Assign a named member afterward, then review sharing and proxy eligibility.</span></div>`, 'Create demo record', () => {
        const name = byId('managed-profile-name').value.trim(), preset_id = byId('managed-profile-preset').value;
        if (!name || !preset_id) { formError('Choose a name and a synthetic preset.'); return; }
        mutate({path: '/v1/profiles', method: 'POST', body: {name, preset_id}, label: 'Creating synthetic profile metadata…', success: 'Unassigned demo profile created. No browser was provisioned.'});
      });
    }

    function renderPolicies() {
      const policy = model.policy;
      container.innerHTML = heading('Team policies', 'Set bounded creation rules, then make explicit exceptions for named demo members.') + disclosure() + status() + `<section class="managed-policy-summary"><article class="panel resource-card"><h2>Member self-creation</h2><span class="status ${policy.member_create_enabled ? 'active' : 'idle'}">${policy.member_create_enabled ? 'Allowed by default' : 'Disabled by default'}</span><p class="field-hint">Default cap: ${policy.fixed_profile_cap === null ? 'Proxy capacity only' : policy.fixed_profile_cap + ' assigned profiles per member'}. Existing profiles count in every lifecycle state.</p><button class="button" id="edit-company-policy" ${disabled() ? 'disabled' : ''}>Edit company rules</button></article><article class="panel resource-card"><h2>Proxy capacity & reuse</h2><dl class="spec-list"><div><dt>Capacity limits</dt><dd>${policy.proxy_capacity_enabled ? 'Required' : 'Not required'}</dd></div><div><dt>Reuse</dt><dd>${policy.proxy_reuse_enabled ? 'Enabled within each proxy cap' : 'One profile per proxy'}</dd></div><div><dt>Policy revision</dt><dd>${policy.revision}</dd></div></dl><p class="field-hint">These are metadata allocation rules. No live proxy is provisioned.</p></article></section><section class="panel"><div class="panel-heading"><h2 id="managed-page-focus" tabindex="-1">Per-member rules</h2><span class="subtle-text">Named synthetic members</span></div>${operators().map(user => `<div class="lifecycle-row"><span><strong>${esc(user.display_name || user.id)}</strong><small class="profile-code">${esc(user.id)} · ${esc(user.role || 'member')}</small></span><span class="subtle-text">${profiles.filter(p => p.assignedUserId === user.id).length} assigned</span><button class="button compact-button" data-member-policy="${esc(user.id)}" ${disabled() ? 'disabled' : ''}>Review cap</button></div>`).join('')}</section>`;
      bind('edit-company-policy', 'click', openCompanyPolicy); bindAll('[data-member-policy]', data => openMemberPolicy(data.memberPolicy)); bindStatus();
    }
    function openCompanyPolicy() {
      const p = model.policy;
      showForm('Company creation rules', 'A fixed cap or proxy-capacity bound is required when member self-creation is enabled. Changes affect only the synthetic organization.', `<label class="check-field"><input id="company-can-create" type="checkbox" ${p.member_create_enabled ? 'checked' : ''}>Allow members to create their own profiles</label><div class="form-field"><label for="company-fixed-cap">Default profile cap per member</label><input id="company-fixed-cap" type="number" min="0" max="10000" value="${p.fixed_profile_cap === null ? '' : p.fixed_profile_cap}" placeholder="Empty only when proxy capacity applies"><span class="field-hint">0 blocks additional assignments. Lowering a cap preserves existing assignments.</span></div><label class="check-field"><input id="company-proxy-capacity" type="checkbox" ${p.proxy_capacity_enabled ? 'checked' : ''}>Bound creation by available proxy slots</label><label class="check-field"><input id="company-proxy-reuse" type="checkbox" ${p.proxy_reuse_enabled ? 'checked' : ''}>Allow proxy reuse within its maximum profiles</label><p class="field-hint">Disabling reuse is rejected while a proxy remains bound to multiple profiles.</p>`, 'Save synthetic rules', () => {
        const fixed = byId('company-fixed-cap').value;
        const body = {expected_revision: p.revision, member_create_enabled: byId('company-can-create').checked, fixed_profile_cap: fixed === '' ? null : Number(fixed), proxy_capacity_enabled: byId('company-proxy-capacity').checked, proxy_reuse_enabled: byId('company-proxy-reuse').checked};
        if (body.member_create_enabled && body.fixed_profile_cap === null && !body.proxy_capacity_enabled) { formError('Choose a fixed profile cap or enable proxy capacity. Creation cannot be unbounded.'); return; }
        mutate({path: '/v1/policy', body, label: 'Saving synthetic company policy…', success: 'Synthetic company policy saved.'});
      });
    }
    async function openMemberPolicy(userId) {
      if (disabled()) return;
      const epoch = ++model.formEpoch;
      try {
        const p = await read('/v1/users/' + encodeURIComponent(userId) + '/policy');
        if (epoch !== model.formEpoch || !['policies'].includes(model.view)) return;
        if (!Object.hasOwn(p, 'can_create_override') || !Object.hasOwn(p, 'fixed_profile_cap_override')) throw new ManagedError('This API cannot expose raw member overrides. Reload with the current simulator before editing inheritance.', {code: 'contract_unavailable'});
        showForm('Rules for ' + memberName(userId), `Currently ${p.assigned_profiles} assigned profiles and ${p.available_proxy_slots} available proxy slots. Shared profiles do not consume the assignment cap.`, `<div class="form-field"><label for="member-can-create">Profile creation</label><select id="member-can-create"><option value="inherit" ${p.can_create_override === null ? 'selected' : ''}>Inherit company rule (${p.member_create_enabled ? 'allowed' : 'disabled'} effective)</option><option value="allow" ${p.can_create_override === true ? 'selected' : ''}>Allow for this member</option><option value="deny" ${p.can_create_override === false ? 'selected' : ''}>Disable for this member</option></select></div><div class="form-field"><label for="member-fixed-cap">Member profile cap override</label><input id="member-fixed-cap" type="number" min="0" max="10000" value="${p.fixed_profile_cap_override === null ? '' : p.fixed_profile_cap_override}" placeholder="Empty inherits the company cap"><span class="field-hint">Effective cap: ${p.fixed_profile_cap === null ? 'proxy capacity' : p.fixed_profile_cap}. Empty clears the override; 0 blocks new assignments.</span></div>`, 'Save member override', () => {
          const choice = byId('member-can-create').value, cap = byId('member-fixed-cap').value;
          mutate({path: '/v1/users/' + encodeURIComponent(userId) + '/policy', body: {expected_revision: p.member_revision, can_create: choice === 'inherit' ? null : choice === 'allow', fixed_profile_cap: cap === '' ? null : Number(cap)}, label: 'Saving synthetic member cap…', success: 'Synthetic member override saved.'});
        });
      } catch (error) { model.error = error; render(); }
    }

    function renderProviders() {
      const poolName = id => model.pools.find(p => p.id === id)?.name || 'Unknown pool';
      container.innerHTML = heading('Proxy inventory', 'Direct member assignments and named-member pools, with explicit reuse limits.', `<button class="button" id="new-proxy-pool" ${disabled() ? 'disabled' : ''}>${icon('plus')}New pool</button><button class="button button-primary" id="new-proxy-metadata" ${disabled() ? 'disabled' : ''}>${icon('plus')}Add proxy metadata</button>`) + disclosure() + status() + `<section class="panel"><div class="panel-heading"><div><h2 id="managed-page-focus" tabindex="-1">Synthetic proxy inventory</h2><p>${model.policy.proxy_reuse_enabled ? 'Reuse enabled within each configured maximum' : 'Reuse disabled: effective capacity is one profile per proxy'}</p></div><span class="status idle">No live endpoints</span></div>${model.proxies.length ? model.proxies.map(p => `<article class="managed-inventory-row"><span class="card-icon blue">${icon('globe')}</span><div><h3>${esc(p.name)}</h3><p class="profile-code">${esc(p.country)} · ${p.assigned_user_id ? 'Direct to ' + esc(memberName(p.assigned_user_id)) : p.pool_id ? 'Pool: ' + esc(poolName(p.pool_id)) : 'Unassigned inventory'}</p><span class="example-label">SIMULATED · METADATA ONLY</span></div><div><span class="status ${p.enabled ? 'active' : 'idle'}">${p.enabled ? 'Enabled metadata' : 'Disabled'}</span><p class="profile-code">${p.bound_profiles} bound / ${model.policy.proxy_reuse_enabled ? p.max_profiles : 1} effective slots</p><p class="profile-code">Configured maximum: ${p.max_profiles}</p></div><button class="button compact-button" data-proxy-edit="${esc(p.id)}" ${disabled() ? 'disabled' : ''}>Edit</button></article>`).join('') : '<div class="empty-state"><h3>No proxy metadata yet</h3><p>Add a synthetic inventory entry. This does not buy, connect, or configure a provider.</p></div>'}</section><section class="panel managed-pools-panel"><div class="panel-heading"><div><h2>Named-member pools</h2><p>Removing access is rejected when a bound profile still depends on it.</p></div></div>${model.pools.length ? model.pools.map(pool => `<div class="lifecycle-row"><span><strong>${esc(pool.name)}</strong><small class="profile-code">${pool.member_ids.length ? pool.member_ids.map(id => esc(memberName(id))).join(', ') : 'No members'} · revision ${pool.revision}</small></span><button class="button compact-button" data-pool-edit="${esc(pool.id)}" ${disabled() ? 'disabled' : ''}>Edit pool</button></div>`).join('') : '<div class="empty-state"><h3>No shared pools</h3><p>Create a pool and grant access to specific synthetic members.</p></div>'}</section>`;
      bind('new-proxy-pool', 'click', () => openPool()); bind('new-proxy-metadata', 'click', () => openProxy()); bindAll('[data-proxy-edit]', data => openProxy(data.proxyEdit)); bindAll('[data-pool-edit]', data => openPool(data.poolEdit)); bindStatus();
    }
    function openPool(id) {
      const pool = model.pools.find(p => p.id === id);
      showForm(pool ? 'Edit synthetic proxy pool' : 'Create synthetic proxy pool', 'Choose named members. Pool membership grants metadata eligibility only; no real proxy connection is created.', `<div class="form-field"><label for="pool-name">Pool name</label><input id="pool-name" maxlength="120" required value="${esc(pool?.name || '')}" placeholder="Example research pool"></div>${checkboxMembers(pool?.member_ids || [], 'pool-member')}`, pool ? 'Save pool metadata' : 'Create pool metadata', () => {
        const name = byId('pool-name').value.trim(); if (!name) { formError('Give this pool a name.'); return; }
        const body = {name, member_ids: checkedIds('.pool-member')}; if (pool) body.expected_revision = pool.revision;
        mutate({path: '/v1/proxy-pools' + (pool ? '/' + encodeURIComponent(pool.id) : ''), method: pool ? 'PUT' : 'POST', body, label: 'Saving synthetic pool metadata…', success: 'Synthetic pool metadata saved. No provider was connected.'});
      });
    }
    function openProxy(id) {
      const p = model.proxies.find(proxy => proxy.id === id);
      showForm(p ? 'Edit synthetic proxy' : 'Add synthetic proxy metadata', 'This form has no endpoint or credential fields. Direct assignment grants one named member access; a pool grants its named members eligibility.', `<div class="form-field"><label for="proxy-name">Inventory name</label><input id="proxy-name" maxlength="120" required value="${esc(p?.name || '')}" placeholder="Example US research proxy"></div><div class="settings-fields"><div class="form-field"><label for="proxy-country">Country code</label><input id="proxy-country" maxlength="2" pattern="[A-Za-z]{2}" required value="${esc(p?.country || 'US')}" autocomplete="off"></div><div class="form-field"><label for="proxy-max-profiles">Maximum profiles when reuse is enabled</label><input id="proxy-max-profiles" type="number" min="1" max="1000" required value="${p?.max_profiles || 1}"></div></div><div class="form-field"><label for="proxy-assignment-kind">Access type</label><select id="proxy-assignment-kind"><option value="unassigned" ${!p?.assigned_user_id && !p?.pool_id ? 'selected' : ''}>Unassigned inventory</option><option value="direct" ${p?.assigned_user_id ? 'selected' : ''}>Direct to one member</option><option value="pool" ${p?.pool_id ? 'selected' : ''}>Shared named-member pool</option></select></div><div class="form-field" id="proxy-direct-field"><label for="proxy-direct-member">Direct member</label><select id="proxy-direct-member"><option value="">Choose a member</option>${userOptions(p?.assigned_user_id)}</select></div><div class="form-field" id="proxy-pool-field"><label for="proxy-pool">Proxy pool</label><select id="proxy-pool"><option value="">Choose a pool</option>${model.pools.map(pool => `<option value="${esc(pool.id)}" ${p?.pool_id === pool.id ? 'selected' : ''}>${esc(pool.name)}</option>`).join('')}</select></div><label class="check-field"><input type="checkbox" id="proxy-enabled" ${!p || p.enabled ? 'checked' : ''}>Enabled in synthetic allocation rules</label><p class="field-hint">Company reuse is ${model.policy.proxy_reuse_enabled ? 'enabled' : 'disabled; effective capacity is currently one'}. Existing bindings must be released before moving or disabling an inventory entry.</p>`, 'Save proxy metadata', () => {
        const kind = byId('proxy-assignment-kind').value, direct = byId('proxy-direct-member').value, pool = byId('proxy-pool').value;
        const name = byId('proxy-name').value.trim(), country = byId('proxy-country').value.trim().toUpperCase();
        if (!name || !/^[A-Z]{2}$/.test(country) || kind === 'direct' && !direct || kind === 'pool' && !pool) { formError('Enter a name, two-letter country code, and a member or pool for the chosen access type.'); return; }
        const body = {name, country, assigned_user_id: kind === 'direct' ? direct : null, pool_id: kind === 'pool' ? pool : null, max_profiles: Number(byId('proxy-max-profiles').value), enabled: byId('proxy-enabled').checked}; if (p) body.expected_revision = p.revision;
        mutate({path: '/v1/proxies' + (p ? '/' + encodeURIComponent(p.id) : ''), method: p ? 'PUT' : 'POST', body, label: 'Saving synthetic proxy inventory…', success: 'Synthetic proxy metadata saved. No traffic or provider setup occurred.'});
      });
      const showKind = () => { byId('proxy-direct-field').hidden = byId('proxy-assignment-kind').value !== 'direct'; byId('proxy-pool-field').hidden = byId('proxy-assignment-kind').value !== 'pool'; };
      bind('proxy-assignment-kind', 'change', showKind); showKind();
    }

    function renderSharing() {
      container.innerHTML = heading('Named profile sharing', 'Review the exact members and proxy binding on each synthetic profile.') + disclosure() + status() + `<section class="panel"><div class="panel-heading"><div><h2 id="managed-page-focus" tabindex="-1">Profile access</h2><p>Reassignment clears prior shares and advances the profile generation.</p></div></div>${profiles.map(p => `<div class="lifecycle-row"><span><strong>${esc(p.name)}</strong><small class="profile-code">${esc(p.id)} · Assigned to ${esc(memberName(p.assignedUserId))}</small></span><button class="button compact-button" data-share-profile="${esc(p.id)}" ${disabled() ? 'disabled' : ''}>Review access</button></div>`).join('')}</section><div class="info-strip">${icon('shield')}<div><strong>Sharing does not merge sessions or move browser data.</strong><p>These rules grant named synthetic members profile access in the control plane. Local session transfer, native device enrollment, and provider verification remain separate gates.</p></div></div>`;
      bindAll('[data-share-profile]', data => openSharing(data.shareProfile)); bindStatus();
    }
    async function openSharing(id) {
      if (disabled()) return;
      const epoch = ++model.formEpoch;
      try {
        const p = profiles.find(profile => profile.id === id), record = await read('/v1/profiles/' + encodeURIComponent(id) + '/managed');
        if (!p || epoch !== model.formEpoch || model.view !== 'sharing') return;
        showForm('Access for ' + p.name, `Assigned to ${memberName(p.assignedUserId)}. Profile revision ${record.revision}; generation ${record.generation}. Review the exact named members before saving.`, `${checkboxMembers(record.shared_member_ids, 'share-member', p.assignedUserId)}<p class="field-hint">The assigned member already has access and is excluded from this list. Saving replaces the complete named-share set.</p><div class="drawer-section"><h3>Current proxy binding</h3><p class="field-hint">${record.proxy_id ? esc(model.proxies.find(proxy => proxy.id === record.proxy_id)?.name || record.proxy_id) : 'No proxy bound'}</p><button class="button" type="button" id="review-proxy-binding" ${!p.assignedUserId ? 'disabled' : ''}>Change proxy binding</button><p class="field-hint">Binding a proxy is a separate revision-checked action and does not save unsaved sharing changes.</p></div>`, 'Save named sharing', () => mutate({path: '/v1/profiles/' + encodeURIComponent(id) + '/sharing', body: {expected_revision: record.revision, member_ids: checkedIds('.share-member')}, label: 'Saving named synthetic sharing…', success: 'Named synthetic sharing saved. No browser sessions were transferred.'}));
        bind('review-proxy-binding', 'click', () => openBinding(p, record));
      } catch (error) { model.error = error; render(); }
    }
    function openBinding(p, record) {
      const eligible = model.proxies.filter(proxy => proxy.enabled && (proxy.assigned_user_id === p.assignedUserId || model.pools.some(pool => pool.id === proxy.pool_id && pool.member_ids.includes(p.assignedUserId))));
      showForm('Proxy binding for ' + p.name, 'Only inventory granted directly to the assigned member or through a named-member pool is offered. The server rechecks capacity and policy on save.', `<div class="form-field"><label for="profile-proxy-binding">Synthetic proxy</label><select id="profile-proxy-binding"><option value="">No proxy binding</option>${eligible.map(proxy => `<option value="${esc(proxy.id)}" ${proxy.id === record.proxy_id ? 'selected' : ''}>${esc(proxy.name)} · ${proxy.bound_profiles} bound</option>`).join('')}</select><span class="field-hint">A required proxy-capacity policy may reject removing the binding. No proxy traffic is initiated.</span></div>`, 'Save proxy binding', () => mutate({path: '/v1/profiles/' + encodeURIComponent(p.id) + '/proxy-binding', body: {expected_revision: record.revision, proxy_id: byId('profile-proxy-binding').value || null}, label: 'Saving synthetic proxy binding…', success: 'Synthetic proxy binding saved. No network route was changed.'}));
    }

    function renderDevices() {
      container.innerHTML = heading('Devices & delivery', 'Read reported connectivity and queued commands without inventing execution results.', `<button class="button" id="refresh-devices" ${disabled() ? 'disabled' : ''}>Refresh status</button>`) + disclosure() + status() + `<section class="panel"><div class="panel-heading"><div><h2 id="managed-page-focus" tabindex="-1">Synthetic device inventory</h2><p>Secure device enrollment is not connected. No device credentials are collected.</p></div></div>${model.devices.length ? model.devices.map(device => `<div class="lifecycle-row"><span><strong>${esc(device.name)}</strong><small class="profile-code">${esc(memberName(device.user_id))} · ${esc(device.platform)} · ${device.synthetic_fixture ? 'Synthetic fixture' : 'Unverified device record'}</small><small class="profile-code">Last report: ${device.last_seen_at ? esc(device.last_seen_at) : 'Never received'}</small></span><span class="status ${device.connectivity === 'online' ? 'active' : 'idle'}">${esc(device.connectivity)}</span></div>`).join('') : '<div class="empty-state"><h3>No approved devices</h3><p>An account login alone is not device enrollment. No remote execution can be claimed.</p></div>'}</section><section class="panel managed-pools-panel"><div class="panel-heading"><div><h2>Command delivery</h2><p>Offline delivery stays pending until a valid device acknowledgement arrives.</p></div></div>${model.commands.length ? model.commands.map(command => `<article class="command-row"><div><strong>${esc(command.kind === 'wipe' ? 'Synthetic local-material removal' : 'Synthetic metadata setup')}</strong><p class="profile-code">Profile ${esc(command.profile_id)} · generation ${command.generation}</p><p class="profile-code">Device ${esc(model.devices.find(device => device.id === command.device_id)?.name || command.device_id)}</p></div><div><span class="status ${command.acknowledged_at ? 'active' : 'setup'}">${esc(command.delivery_status || command.status)}</span><p class="profile-code">${command.acknowledged_at ? 'Acknowledged at ' + esc(command.acknowledged_at) : 'No acknowledgement received'}</p>${command.result_code ? `<p class="profile-code">Reported result: ${esc(command.result_code)}</p>` : ''}</div>${command.wipe_limitation ? `<p class="command-limitation">${esc(command.wipe_limitation)}</p>` : ''}</article>`).join('') : '<div class="empty-state"><h3>No commands queued</h3><p>No setup or removal has been requested through this interface.</p></div>'}</section><div class="info-strip">${icon('lock')}<div><strong>A wipe acknowledgement has a limited meaning.</strong><p>It can describe local profile material removal only. It cannot revoke website sessions or guarantee deletion of copied data. This simulator does not enroll devices, execute agent commands, or fabricate acknowledgements.</p></div></div>`;
      bind('refresh-devices', 'click', () => reload()); bindStatus();
    }
    function render() {
      if (!api.enabled || api.loading || api.error || api.saving && !model.pending) return false;
      ready();
      const view = location.hash.slice(1);
      if (!Object.hasOwn(views, view)) { model.formEpoch++; return false; }
      if (view !== model.view) { model.formEpoch++; if (dialog.open && !model.pending) dialog.close(); }
      model.view = view;
      document.title = `${views[view]} · Managed simulator`;
      byId('breadcrumb').textContent = views[view];
      document.querySelectorAll('[data-view]').forEach(item => { const selected = item.dataset.view === view; item.classList.toggle('active', selected); if (selected) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current'); });
      if (!model.loaded) {
        container.innerHTML = heading(model.loading ? 'Loading synthetic controls…' : 'Managed simulator', 'Reading policy, proxy metadata, device inventory and command records.') + status() + `<section class="panel empty-state" role="status"><p>${model.error ? 'The managed records are unavailable. Reload after checking the demo process.' : 'No real provider or device is being contacted.'}</p></section>`;
        bindStatus(); if (!model.loading && !model.error) reload(); return true;
      }
      ({policies: renderPolicies, providers: renderProviders, sharing: renderSharing, devices: renderDevices}[view])(); return true;
    }
    dialog.addEventListener('close', () => { model.formEpoch++; });
    return {model, request, read, ready, status, bindStatus, render, reload, mutate, cancelPending, openProfileCreate, openCompanyPolicy, openMemberPolicy, openPool, openProxy, openSharing, openBinding};
  }
  window.ManagedWorkspace = {mount, ManagedError};
})();
