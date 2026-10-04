'use strict';

// Public local client. Only same-origin, fixed local routes are used. The CSRF
// capability stays in memory; managed login, provider tokens and cookies do not
// pass through this interface.
(() => {
  class WorkspaceError extends Error {
    constructor(message, {code = 'request_failed', status = 0, blockers = [], profile = null, uncertain = false} = {}) {
      super(message);
      this.name = 'WorkspaceError';
      Object.assign(this, {code, status, blockers, profile, uncertain});
    }
  }

  function createClient({getConfig, fetcher = (...args) => fetch(...args)}) {
    return async function request(path, {method = 'GET', body, signal} = {}) {
      if (typeof path !== 'string' || !/^\/(profiles(?:\/[A-Za-z0-9_-]{1,64})?(?:\/(?:actions|tab-focus|camoufox-setup(?:\/actions)?))?(?:\?expected_revision=\d+)?|camoufox-setup|tabs|presets|settings|managed-connection|managed-native(?:\/actions)?)$/.test(path) || /[\r\n]/.test(path)) {
        throw new WorkspaceError('Unsupported local route.', {code: 'invalid_route'});
      }
      const config = getConfig();
      if (config?.mode !== 'local' || config.api_base !== '/local/v1') {
        throw new WorkspaceError('The local workspace is not connected.', {code: 'local_unavailable'});
      }
      const headers = {'Accept': 'application/json'};
      if (method !== 'GET') {
        if (!config.csrf_token) throw new WorkspaceError('Reload the local workspace before editing.', {code: 'csrf_missing'});
        headers['X-Local-CSRF'] = config.csrf_token;
      }
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      let response;
      try {
        response = await fetcher('/local/v1' + path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal, cache: 'no-store', credentials: 'omit'});
      } catch (error) {
        throw new WorkspaceError(error.name === 'AbortError' ? 'Waiting was canceled or timed out. Reload to verify the result before making another change.' : 'The local service could not be reached. Check that it is running, then reload.', {code: error.name === 'AbortError' ? 'request_canceled' : 'offline', uncertain: method !== 'GET'});
      }
      let data = null;
      if (response.status !== 204) {
        try { data = await response.json(); }
        catch { throw new WorkspaceError('The local service returned an unreadable response. Reload before continuing.', {code: 'invalid_response', status: response.status, uncertain: method !== 'GET'}); }
      }
      if (!response.ok) {
        const detail = data?.detail || data?.error || {};
        const message = typeof detail.message === 'string' ? detail.message : `The local request was rejected (HTTP ${response.status}).`;
        throw new WorkspaceError(message, {code: detail.code || 'request_failed', status: response.status, blockers: Array.isArray(detail.blockers) ? detail.blockers : [], profile: detail.profile || null, uncertain: response.status >= 500 && method !== 'GET'});
      }
      return data;
    };
  }

  function syntheticInboxRows(profiles) {
    return profiles.map((profile, index) => ({
      accountId: 'example-' + profile.id, profileId: profile.id, profileRevision: profile.revision,
      displayName: profile.name, emailHint: `account-${index + 1}@example.test`,
      identityStatus: 'unverified', browserState: profile.state,
      unreadThreads: index * 7 + 3, summarySource: 'synthetic', observedAt: null,
      freshness: 'unknown', nativeOpenAvailable: false, unifiedApiAvailable: false
    }));
  }

  function mount({icon, esc, notify, managedRoute, managedDiscover, isManagedBusy = () => false}) {
    const byId = id => document.getElementById(id);
    const container = byId('view-container');
    const dialog = byId('detail-dialog');
    const switcher = byId('switcher-dialog');
    const savedMode = (() => { try { return localStorage.getItem('tbm.workspace-mode'); } catch { return null; } })();
    const model = {
      mode: ['local', 'managed'].includes(savedMode) ? savedMode : 'choose',
      config: null, profiles: [], presets: [], settings: null, managed: null,
      loading: false, discovering: false, checked: false, error: null, offline: false,
      needsRefresh: false, pending: null, search: '', filter: 'all', sort: 'created',
      selectedId: null, view: 'profiles', switcherQuery: '', switcherIndex: 0, inboxExample: false,
      returnFocus: null, loadSequence: 0, profileSection: 'configuration', selectionPending: false, selectionTarget: null, selectionPromise: null, iconDraft: '', editorEpoch: 0, modalEpoch: 0, iconReadSequence: 0, iconReading: false
    };
    const request = createClient({getConfig: () => model.config});
    const nativeTabs = window.TeamNativeTabs?.mount({request, notify});
    const embeddedBrowser = window.TeamEmbeddedBrowser?.mount({icon, esc, notify, onProfile: profile => { replaceProfile(profile); paintSelection(); }});
    const integrated = () => Boolean(embeddedBrowser && model.config?.desktop_shell);
    const nativeManaged = window.TeamManagedWorkspace?.mount({request, container, esc, icon, notify});
    const nativeSetup = window.TeamCamoufoxSetup?.mount({
      request, notify, onLaunch: id => lifecycleAction(id, 'start'),
      onEdit: id => openEditor(id), onCreate: () => openEditor(),
      isCurrent: profile => {
        const current = model.profiles.find(item => item.id === profile.id);
        return model.mode === 'local' && model.selectedId === profile.id && !blocked() && current?.revision === profile.revision && current?.engine_id === profile.engine_id && current?.network_policy === profile.network_policy;
      },
      onProfile: (profile, previous) => {
        const current = model.profiles.find(item => item.id === profile.id);
        if (model.mode !== 'local' || model.selectedId !== profile.id || blocked() || current?.revision !== previous.revision) return false;
        replaceProfile(profile);
        if (profile.revision !== previous.revision && model.view === 'profiles') {
          refreshRows();
          nativeTabs?.activate(byId('native-tab-workspace'), profile, model.settings?.tab_navigation);
        }
        return true;
      }
    });
    const supportsNativeManaged = () => Boolean(nativeManaged && model.config?.managed_native?.supported === true);
    const initial = {};
    ['#navigation', '.workspace-label', '.sidebar-foot', '.local-card', '.demo-banner', '.page-footer p', '.preview-pill'].forEach(selector => { initial[selector] = document.querySelector(selector)?.innerHTML || ''; });
    const localViews = {profiles: 'Profiles', inbox: 'Inbox', resources: 'App settings', connection: 'Team connection'};
    const stateNames = {cold: 'Stopped', stopped: 'Stopped', idle: 'Stopped', ready: 'Ready', warm: 'Warm', running: 'Running', active: 'Running', starting: 'Starting', stopping: 'Stopping', blocked: 'Blocked', locked: 'Locked', failed: 'Failed', error: 'Error', crashed: 'Crashed', recovery_required: 'Recovery needed', offline: 'Offline'};
    const stateLabel = p => (stateNames[p.state] || (p.state ? p.state.replace(/_/g, ' ') : 'Unknown')) + (model.config?.launch?.execution_kind === 'synthetic' && ['running', 'warm', 'starting', 'stopping'].includes(p.state) ? ' · simulation' : '');
    const blocked = () => Boolean(model.pending || model.selectionPending || model.loading || model.needsRefresh || model.offline || !model.config);
    const canOpenInbox = p => Boolean(model.config?.inbox?.native_open_available && canLaunch(p));
    const canLaunch = p => Boolean(p && (p.engine_id === 'electron_chromium' ? integrated() && p.state !== 'recovery_required' && ['local_direct', 'verified_proxy'].includes(p.network_policy) && (p.network_policy !== 'verified_proxy' || p.proxy_config) : !integrated() && !p.proxy_config && (p.engine_id === 'camoufox' ? nativeSetup?.canLaunch(p) : model.config?.launch?.actual_process_available === true && p.network_policy === 'local_direct' && p.origin !== 'managed' && !(p.blockers?.length))));
    const labelBlocker = value => typeof value === 'string' ? value : value?.message || value?.code || 'Engine verification is pending.';
    const blockersFor = p => (p?.engine_id === 'electron_chromium' ? [!integrated() ? 'Open this profile in the desktop app to use built-in Chromium.' : p.network_policy === 'unconfigured' ? 'Choose a connection in Edit profile before opening tabs.' : 'Profile storage and networking are isolated by the built-in engine. Native proxy and required-site acceptance remain unverified.'] : integrated() ? ['This engine cannot be embedded in the desktop app. Choose Built-in Chromium, or keep this legacy profile stopped.'] : p?.proxy_config ? ['Proxy details are saved, but no trusted route is connected. Launch stays blocked until this exact proxy is verified.'] : p?.engine_id === 'camoufox' ? ['Select this profile and complete its Camoufox setup. Fresh native admission is required before launch.'] : p && (!p.network_policy || p.network_policy === 'unconfigured') ? ['Choose an explicit network policy before launching this profile. Native runtime verification is also required.'] : p?.network_policy === 'verified_proxy' ? ['A trusted per-profile proxy adapter and verified egress are required. No direct fallback is allowed.'] : p?.origin === 'managed' ? ['Managed policy does not allow the local-direct launch path.'] : model.config?.launch?.execution_kind === 'synthetic' ? ['Simulation only. No real browser process is available in this workspace.'] : p?.blockers?.length ? p.blockers : model.config?.launch?.blockers?.length ? model.config.launch.blockers : ['No verified browser engine is available. Browser launch and native Gmail opening remain disabled.']).map(labelBlocker);
    const initials = name => name.split(/[\s·-]+/).filter(Boolean).slice(0, 2).map(word => word[0]).join('').toUpperCase();
    const networkLabel = policy => ({unconfigured: 'Network not configured', local_direct: 'This device’s connection · no proxy', verified_proxy: 'Verified proxy required'}[policy] || 'Network not configured');
    const presetName = id => model.presets.find(p => p.id === id)?.name || id || 'Standard';
    const requestId = () => globalThis.crypto?.randomUUID?.() || 'ui-' + Date.now() + '-' + Math.random().toString(36).slice(2);
    const title = (heading, subtitle, actions = '') => `<div class="page-heading"><div><h1>${esc(heading)}</h1><p class="page-subtitle">${esc(subtitle)}</p></div><div class="header-actions">${actions}</div></div>`;

    function rememberMode(mode) {
      try { localStorage.setItem('tbm.workspace-mode', mode); } catch { /* Storage denial never blocks an account-free workspace. */ }
    }
    function bind(id, event, fn) { byId(id)?.addEventListener(event, fn); }
    function bindAll(selector, fn) { container.querySelectorAll(selector).forEach(el => el.addEventListener('click', () => fn(el.dataset))); }
    function lifecycle(p) {
      const cls = ['running', 'active', 'warm'].includes(p.state) ? 'active' : ['blocked', 'error', 'failed', 'locked', 'crashed', 'recovery_required'].includes(p.state) ? 'setup' : 'idle';
      return `<span class="status ${cls}">${esc(stateLabel(p))}</span>`;
    }
    function paintChrome() {
      document.body?.classList?.toggle('local-app', model.mode !== 'managed');
      if (model.mode === 'managed' && supportsNativeManaged()) {
        document.querySelector('#navigation').innerHTML = `<a href="#profiles" class="nav-item"><span>${icon('profiles')}</span><span>Team profiles</span></a><a href="#connection" class="nav-item"><span>${icon('users')}</span><span>Managed connection</span></a>`;
        document.querySelector('.workspace-label').innerHTML = `<span class="workspace-symbol" aria-hidden="true">M</span><div><strong>Managed workspace</strong><span>Team access · native sign-in</span></div>`;
        document.querySelector('.sidebar-foot').innerHTML = `<span class="avatar">M</span><div><strong>Your team connection</strong><span>Credentials stay in native storage</span></div>`;
        document.querySelector('.local-card').innerHTML = `${icon('laptop')}<strong>Local profiles.<br>Team controls.</strong><p>Managed launch requires device enrollment and verified routing.</p>`;
        document.querySelector('.preview-pill').textContent = 'Managed';
        document.querySelector('.demo-banner').innerHTML = `${icon('shield')}<p>Team identity and device enrollment are separate. Your account-free local workspace remains available.</p>`;
        document.querySelector('.page-footer p').textContent = 'Team records are read through the native client. Signing in does not enroll this device or transfer browser sessions.';
        byId('workspace-mode-button').textContent = 'Managed workspace';
        byId('quick-switch-button').hidden = true;
        return;
      }
      if (model.mode === 'managed') {
        Object.entries(initial).forEach(([selector, html]) => { const el = document.querySelector(selector); if (el) el.innerHTML = html; });
        document.querySelector('.workspace-label strong').textContent = 'Managed preview';
        document.querySelector('.sidebar-foot strong').textContent = 'Synthetic administrator';
      } else {
        document.querySelector('#navigation').innerHTML = Object.entries(localViews).filter(([key]) => !integrated() || key !== 'inbox').map(([key, name], index) => `<a href="#${key}" data-local-view="${key}" class="nav-item${model.view === key ? ' active' : ''}" ${model.view === key ? 'aria-current="page"' : ''}><span>${icon(['profiles', 'mail', 'laptop', 'users'][index])}</span><span>${name}</span><kbd>${index + 1}</kbd></a>`).join('');
        document.querySelector('.workspace-label').innerHTML = `<span class="workspace-symbol" aria-hidden="true">L</span><div><strong>${model.mode === 'choose' ? 'Choose your workspace' : 'My local workspace'}</strong><span>${model.mode === 'choose' ? 'Local first. Managed when needed.' : 'On this device · no account'}</span></div>`;
        document.querySelector('.sidebar-foot').innerHTML = `<span class="avatar">L</span><div><strong>Local workspace</strong><span>No team sign-in required</span></div>`;
        document.querySelector('.local-card').innerHTML = `${icon('laptop')}<strong>Profile manager</strong><p>Browser windows open only when you choose Open browser.</p><span class="outline-chip">⌘ / CTRL + K</span>`;
        document.querySelector('.preview-pill').innerHTML = `<span aria-hidden="true"></span>${model.offline ? 'Service offline' : model.config ? 'Local · saved on device' : 'Workspace setup'}`;
        document.querySelector('.demo-banner').innerHTML = `${icon('info')}<p><strong>Organize now. Launch when verified.</strong> Local profiles and favorites save on this device. Native launch needs current admission for the selected profile. Open its browser setup to see configuration, identity and diagnostic steps. Selecting a profile does not launch it.</p><a href="#resources">View engine status ${icon('chevron')}</a>`;
        document.querySelector('.page-footer p').textContent = 'Local data does not require a managed account. Browser launch, installed-device verification and Google authorization are separate capability gates.';
      }
      byId('workspace-mode-button').textContent = model.mode === 'managed' ? 'Managed preview' : model.mode === 'local' ? 'Local workspace' : 'Choose workspace';
      byId('quick-switch-button').hidden = model.mode !== 'local';
    }

    function statusStrip() {
      if (model.pending) return `<div class="workspace-alert pending" role="status" aria-live="polite"><span>${icon('clock')} ${esc(model.pending.label)}</span><button class="button" id="cancel-pending">Cancel waiting</button></div>`;
      if (model.error || model.needsRefresh || model.offline) {
        const message = model.error?.message || (model.needsRefresh ? 'Reload to verify the last request before making another change.' : 'The local service is offline. Shown records may be out of date.');
        return `<div class="workspace-alert error" role="alert"><div><strong>${model.needsRefresh ? 'Verification needed' : model.offline ? 'Offline' : 'Needs attention'}</strong><p>${esc(message)}</p>${model.error?.code ? `<span class="error-code">${esc(model.error.code)}</span>` : ''}</div><button class="button" id="reload-workspace">Reload</button></div>`;
      }
      return '';
    }
    function bindStrip() {
      bind('cancel-pending', 'click', cancelPending);
      bind('reload-workspace', 'click', () => reload());
    }
    function renderChoice() {
      container.innerHTML = `<section class="workspace-welcome"><p class="eyebrow">A workspace that starts with you</p><h1>Your profiles.<br>Your way to work.</h1><p>Start on this device with no account. Connect to a managed workspace when your team is ready.</p></section><div class="mode-grid"><article class="mode-card recommended"><span class="card-icon">${icon('laptop')}</span><span class="mode-tag">START HERE</span><h2>Local workspace</h2><p>Create profiles, keep favorites, and switch contexts in a few keystrokes. Your profile metadata is saved by the local service.</p><ul><li>No account or team login required</li><li>Separate profile storage on this device</li><li>Honest engine and resource status</li></ul><button class="button button-primary" id="choose-local" ${model.discovering ? 'disabled' : ''}>${model.discovering ? 'Checking local service…' : 'Use local workspace'} ${icon('chevron')}</button><span class="mode-note">${model.config ? 'Local service found · ready for metadata' : model.checked ? 'Start the local service to save profiles' : 'Checking local service availability'}</span></article><article class="mode-card"><span class="card-icon blue">${icon('users')}</span><h2>Managed workspace</h2><p>${supportsNativeManaged() ? 'Sign in through native secure storage to view your assigned team profiles and shared presets.' : 'Explore team assignments, shared presets, and policy controls with clearly labeled synthetic sample data.'}</p><ul><li>Team policies and administrator controls</li><li>${supportsNativeManaged() ? 'Native sign-in and current membership checks' : 'Managed enrollment is not connected'}</li><li>Credentials stay outside the web interface</li></ul><button class="button" id="choose-managed">${supportsNativeManaged() ? 'Open managed workspace' : 'Explore managed preview'} ${icon('chevron')}</button><span class="mode-note">${supportsNativeManaged() ? (model.config.managed_native.configured ? 'Native configuration available · sign-in required' : 'Approved native configuration required') : 'Synthetic data · no production team sign-in'}</span></article></div><div class="info-strip">${icon('shield')}<div><strong>Session separation stays intact.</strong><p>Profile selection never merges browser cookies or accounts. Native browser execution must be verified before a profile can launch.</p></div></div>`;
      bind('choose-local', 'click', () => chooseMode('local'));
      bind('choose-managed', 'click', () => chooseMode('managed'));
    }
    function localUnavailable() {
      container.innerHTML = title('Start your local workspace', 'No account is needed. The local service must be running to save profiles.') + `<section class="panel empty-state"><span class="card-icon">${icon('laptop')}</span><h2>Local service not connected</h2><p>${esc(model.error?.message || 'This page cannot reach the account-free local workspace service at /local/config. Start the local service on this device, then reload.')}</p><div class="empty-actions"><button class="button button-primary" id="retry-local">Reload local service</button><button class="button" id="back-choice">Choose another workspace</button></div><p class="field-hint">Profiles are not silently saved to temporary page memory.</p></section>`;
      bind('retry-local', 'click', () => reload());
      bind('back-choice', 'click', showChoice);
    }

    function filteredProfiles({query = model.search, filter = model.filter, sort = model.sort} = {}) {
      const term = query.trim().toLowerCase();
      return model.profiles.filter(p => (filter !== 'favorites' || p.favorite) && (filter !== 'running' || ['active', 'running', 'warm', 'starting'].includes(p.state)) && `${p.name} ${p.assignment_label || ''} ${p.id} ${presetName(p.preset_id)}`.toLowerCase().includes(term)).sort((a, b) => {
        if (sort === 'name') return a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
        if (sort === 'favorites' && a.favorite !== b.favorite) return Number(b.favorite) - Number(a.favorite);
        // Neither selection timestamps nor lifecycle updates affect a row's place.
        return String(a.created_at || '').localeCompare(String(b.created_at || '')) || a.id.localeCompare(b.id);
      });
    }
    function selectedProfile() { return model.profiles.find(p => p.id === model.selectedId); }
    function profileIcon(p) {
      const type = p?.icon_preset || 'browser';
      const custom = p?.custom_icon_data_url;
      if (type === 'custom' && typeof custom === 'string' && /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(custom) && custom.length < 180000) return `<span class="profile-avatar custom-avatar"><img src="${esc(custom)}" alt="" width="32" height="32"></span>`;
      const symbols = {facebook: '<span class="facebook-glyph">f</span>', google_ads: '<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M18 6 28 23" stroke="#4285f4" stroke-width="9" stroke-linecap="round"/><path d="M18 6 7 24" stroke="#fbbc04" stroke-width="9" stroke-linecap="round"/><circle cx="7" cy="24" r="4.5" fill="#34a853"/></svg>', youtube: '<svg viewBox="0 0 32 32" aria-hidden="true"><rect x="2" y="6" width="28" height="20" rx="6" fill="#ed3039"/><path d="m13 11 8 5-8 5Z" fill="white"/></svg>', browser: icon('globe')};
      return `<span class="profile-avatar profile-icon-${esc(type)}" aria-hidden="true">${symbols[type] || esc(initials(p?.name || 'Profile'))}</span>`;
    }
    function engineLabel(p) { return p?.engine_id === 'electron_chromium' ? 'Built-in Chromium · desktop app' : p?.engine_id === 'camoufox' ? 'Camoufox · Firefox engine' : p?.engine_id === 'chromium' ? 'Installed Chrome · Chromium engine' : 'Engine not configured'; }
    function identityDescription(p) { return p?.engine_id === 'electron_chromium' ? 'This app’s real Chromium identity, with a separate persistent cookie and site-data session per profile. This is not fingerprint camouflage.' : p?.engine_id === 'camoufox' ? 'A persistent, Firefox-compatible identity generated for this profile. Preparation and native validation are required.' : 'Uses the real installed Chrome identity and this device’s platform. Each profile has separate browser storage.'; }
    function renderProfiles() {
      container.innerHTML = `<div class="workspace-title"><div><h1>Your browser profiles</h1><p>Create, configure and assign profiles on this device.</p></div><button class="button button-primary" id="new-profile" ${blocked() ? 'disabled' : ''}>${icon('plus')}New profile</button></div><div id="workspace-status">${statusStrip()}</div><section class="profile-manager" aria-label="Profile manager"><aside class="profile-list-pane"><div class="profile-list-toolbar"><label class="search-field">${icon('search')}<span class="sr-only">Search local profiles</span><input type="search" id="local-search" value="${esc(model.search)}" placeholder="Search profiles…" autocomplete="off"></label><div class="profile-list-filters"><select id="local-filter" aria-label="Filter profiles"><option value="all">All profiles</option><option value="favorites">Favorites</option><option value="running">Open profiles</option></select><select id="local-sort" aria-label="Sort profiles"><option value="created">Created order</option><option value="name">Name A–Z</option><option value="favorites">Favorites first</option></select></div></div><div id="local-results">${profileRows(filteredProfiles())}</div><div class="profile-list-footer"><span>${model.profiles.length} profiles</span><button id="open-switcher" class="text-link">Quick switch <kbd>⌘ K</kbd></button></div></aside><div id="profile-detail" class="profile-detail-pane"></div></section>`;
      bind('new-profile', 'click', () => openEditor()); bind('open-switcher', 'click', openSwitcher);
      byId('local-filter').value = model.filter; byId('local-sort').value = model.sort;
      bind('local-search', 'input', event => { model.search = event.target.value; refreshRows(); });
      bind('local-filter', 'change', event => { model.filter = event.target.value; refreshRows(); });
      bind('local-sort', 'change', event => { model.sort = event.target.value; refreshRows(); });
      bindRows(); bindStrip(); renderProfileDetail();
    }
    function profileRows(rows) {
      if (!rows.length) return `<div class="empty-state compact-empty">${icon(model.profiles.length ? 'search' : 'folder')}<h3>${model.profiles.length ? 'No matching profiles' : 'No profiles yet'}</h3><p>${model.profiles.length ? 'Try another name or filter.' : 'Create your first profile to get started.'}</p><button class="button" id="empty-profile-action" ${blocked() ? 'disabled' : ''}>${model.profiles.length ? 'Clear filters' : 'Create first profile'}</button></div>`;
      return `<nav class="profile-rail" aria-label="Select a profile to configure">${rows.map(p => `<div class="profile-rail-item ${p.id === model.selectedId ? 'selected' : ''}" data-profile-row="${esc(p.id)}"><button data-select="${esc(p.id)}" aria-pressed="${p.id === model.selectedId}" ${model.pending || model.loading || model.needsRefresh || model.offline ? 'disabled' : ''}>${profileIcon(p)}<span class="profile-row-copy"><strong>${esc(p.name)}</strong><small>${esc(p.assignment_label || (p.engine_id === 'electron_chromium' ? 'Built-in Chromium' : p.engine_id === 'camoufox' ? 'Camoufox' : 'Chrome'))}</small></span><span class="profile-state-dot ${['running', 'warm'].includes(p.state) ? 'is-open' : ''}" title="${esc(stateLabel(p))}"></span></button></div>`).join('')}</nav>`;
    }
    function paintSelection() {
      container.querySelectorAll('[data-select]').forEach(button => {
        const selected = button.dataset.select === model.selectedId;
        button.setAttribute('aria-pressed', String(selected));
        button.setAttribute('aria-busy', String(model.selectionPending && button.dataset.select === model.selectionTarget));
        button.parentElement?.classList?.toggle('selected', selected);
        button.parentElement?.classList?.toggle('selecting', model.selectionPending && button.dataset.select === model.selectionTarget);
      });
      if (byId('new-profile')) byId('new-profile').disabled = blocked();
    }
    function renderProfileDetail() {
      const root = byId('profile-detail'), p = selectedProfile();
      nativeSetup?.deactivate(); nativeTabs?.deactivate(); embeddedBrowser?.deactivate();
      if (!p) { root.innerHTML = `<div class="profile-detail-empty">${icon('profiles')}<h2>${model.profiles.length ? 'Select a profile' : 'A separate profile for every account'}</h2><p>${model.profiles.length ? 'Choose a profile from the list to configure its identity, assignment and connection.' : 'Give it a name and icon, choose its browser engine, then set up its connection.'}</p>${!model.profiles.length ? '<button class="button button-primary" id="detail-create-profile">Create profile</button>' : ''}</div>`; bind('detail-create-profile', 'click', () => openEditor()); return; }
      const proxy = p.proxy_config;
      root.innerHTML = `<div class="profile-detail-header"><div class="profile-heading">${profileIcon(p)}<div><h2>${esc(p.name)}</h2><p>${esc(p.assignment_label || 'No local assignment label')}</p></div></div><button class="favorite-button ${p.favorite ? 'is-favorite' : ''}" data-favorite="${esc(p.id)}" aria-label="${p.favorite ? 'Remove from' : 'Add to'} favorites" aria-pressed="${p.favorite}" ${blocked() ? 'disabled' : ''}>${icon('star')}</button>${integrated() && p.engine_id === 'electron_chromium' ? '<button class="button" id="detail-stop-browser">Close profile</button>' : ''}<button class="button" id="detail-edit-profile" ${blocked() ? 'disabled' : ''}>Edit profile</button></div><div class="profile-section-tabs" role="tablist" aria-label="Profile sections"><button id="profile-configuration-tab" role="tab" aria-selected="${model.profileSection === 'configuration'}" tabindex="${model.profileSection === 'configuration' ? '0' : '-1'}">Configuration</button><button id="profile-activity-tab" role="tab" aria-selected="${model.profileSection === 'activity'}" tabindex="${model.profileSection === 'activity' ? '0' : '-1'}">${integrated() ? 'Browser' : 'Browser activity'}</button></div><div id="profile-section-content" class="profile-section-content" role="tabpanel"></div>`;
      bind('detail-edit-profile', 'click', () => openEditor(p.id));
      root.querySelectorAll('[data-favorite]').forEach(button => button.addEventListener('click', () => toggleFavorite(p.id)));
      const section = byId('profile-section-content');
      if (model.profileSection === 'activity' && integrated()) {
        if (p.engine_id === 'electron_chromium') { section.innerHTML = '<div id="embedded-browser-root"></div>'; if (!blocked() && !dialog.open && !switcher.open) void embeddedBrowser.activate(byId('embedded-browser-root'), p); }
        else section.innerHTML = '<div class="engine-blocker"><h3>This profile uses an external engine</h3><p>Built-in tabs require the Built-in Chromium engine. This app does not embed Camoufox or installed Chrome.</p></div>';
      } else if (model.profileSection === 'activity') {
        section.innerHTML = `<div class="activity-summary"><div>${lifecycle(p)}<p>Open tabs belong to this profile’s separate browser window.</p></div><div class="profile-open-actions"><button class="button button-primary" id="detail-open-browser" ${blocked() || !canLaunch(p) || ['starting', 'stopping'].includes(p.state) ? 'disabled' : ''}>${icon('external')}${['running', 'warm'].includes(p.state) ? 'Show browser' : 'Open browser'}</button>${['running', 'warm', 'starting'].includes(p.state) ? '<button class="button" id="detail-stop-browser">Stop browser</button>' : ''}</div></div><section id="native-tab-workspace" aria-label="Selected profile tabs"></section>`;
        if (!blocked()) nativeTabs?.activate(byId('native-tab-workspace'), p, model.settings?.tab_navigation);
        if (!nativeTabs) byId('native-tab-workspace').innerHTML = '<p class="field-hint">Native tab controls are unavailable in this build.</p>';
      } else {
        section.innerHTML = `<section class="configuration-card"><div class="configuration-card-heading">${icon('profiles')}<h3>Browser & identity</h3></div><strong>${esc(engineLabel(p))}</strong><p>${esc(identityDescription(p))}</p><span class="configuration-note">Engine and identity are separate. Safari/WebKit is not supported.${p.engine_id === 'electron_chromium' ? ' Google sign-in compatibility is unverified; embedded-browser restrictions may apply.' : ''}</span></section><section class="configuration-card"><div class="configuration-card-heading">${icon('globe')}<h3>Connection</h3></div><strong>${esc(proxy ? (proxy.label || 'Custom proxy') : networkLabel(p.network_policy))}</strong>${proxy ? `<p>${esc(proxy.protocol.toUpperCase())} · ${esc(proxy.hostname)}:${proxy.port}</p><span class="configuration-note warning">${integrated() && p.engine_id === 'electron_chromium' ? 'Applied before the profile opens · live route not independently verified' : 'Saved configuration · not connected or verified'}</span>` : `<p>${p.network_policy === 'local_direct' ? 'Traffic uses this device’s normal internet connection.' : p.network_policy === 'verified_proxy' ? 'A trusted, profile-bound proxy must be configured and verified.' : 'Choose direct networking or configure a proxy in Edit profile.'}</p>`}</section><section class="configuration-card"><div class="configuration-card-heading">${icon('users')}<h3>Assignment</h3></div><strong>${esc(p.assignment_label || 'Unassigned')}</strong><p>A label for organizing local work. Team access and sharing are managed separately.</p></section><div class="profile-launch-bar"><div>${lifecycle(p)}<span>${canLaunch(p) ? 'Ready to request launch' : 'Setup required before launch'}</span></div><button class="button button-primary" id="detail-open-browser" ${blocked() || !canLaunch(p) || ['starting', 'stopping'].includes(p.state) ? 'disabled' : ''}>${icon('external')}${['running', 'warm'].includes(p.state) ? 'Show browser' : 'Open browser'}</button></div>${!canLaunch(p) ? `<p class="launch-reason">${esc(blockersFor(p)[0])}</p>` : ''}${p.engine_id === 'camoufox' ? '<details class="setup-details"><summary>Runtime setup & diagnostics</summary><section id="camoufox-setup-workspace" aria-label="Camoufox browser setup"></section></details>' : ''}`;
        if (p.engine_id === 'camoufox') nativeSetup?.activate(byId('camoufox-setup-workspace'), p, {blocked: blocked()});
      }
      bind('detail-open-browser', 'click', () => lifecycleAction(p.id, 'start'));
      bind('detail-stop-browser', 'click', () => lifecycleAction(p.id, 'stop'));
      if (integrated() && model.profileSection === 'activity') section.classList?.add?.('embedded-section');
      const chooseSection = name => { model.profileSection = name; renderProfileDetail(); byId('profile-' + name + '-tab')?.focus(); };
      bind('profile-configuration-tab', 'click', () => chooseSection('configuration'));
      bind('profile-activity-tab', 'click', () => chooseSection('activity'));
      for (const name of ['configuration', 'activity']) bind('profile-' + name + '-tab', 'keydown', event => { if (['ArrowLeft', 'ArrowRight'].includes(event.key)) { event.preventDefault(); chooseSection(name === 'configuration' ? 'activity' : 'configuration'); } });
    }
    function refreshRows() { byId('local-results').innerHTML = profileRows(filteredProfiles()); bindRows(); }
    function bindRows() {
      const results = byId('local-results');
      results.querySelectorAll('[data-select]').forEach(button => button.addEventListener('click', () => selectProfile(button.dataset.select)));
      bind('empty-profile-action', 'click', () => { if (model.profiles.length) { model.search = ''; model.filter = 'all'; render(); byId('local-search')?.focus(); } else openEditor(); });
    }

    function restoreFocus(preferred = model.returnFocus) {
      if (preferred?.isConnected) { preferred.focus(); return; }
      const id = model.returnProfileId;
      const row = id ? Array.from(container.querySelectorAll('[data-edit]')).find(el => el.dataset.edit === id) : null;
      (row || byId('local-search') || byId('quick-switch-button'))?.focus();
    }
    function showDialog(body, returnFocus) {
      model.returnFocus = returnFocus || document.activeElement;
      byId('drawer-content').innerHTML = `<div class="drawer-head"><p class="eyebrow">Local profile · saved on device</p><button class="close-button" id="close-local-drawer" aria-label="Close profile editor">${icon('close')}</button></div><div class="drawer-main">${body}</div>`;
      bind('close-local-drawer', 'click', () => { if (!model.pending) dialog.close(); });
      if (!dialog.open) { if (integrated()) { const epoch = ++model.modalEpoch; void embeddedBrowser.hide().then(() => { if (epoch !== model.modalEpoch || model.mode !== 'local') return; dialog.showModal(); byId('profile-name-input')?.focus(); }).catch(() => notify('The browser could not be hidden safely. The editor was not opened.')); } else dialog.showModal(); }
      byId('profile-name-input')?.focus();
    }
    function openEditor(id) {
      if (blocked()) return;
      const profile = model.profiles.find(p => p.id === id);
      if (id && !profile) return;
      model.returnProfileId = profile?.id || null;
      const editorEpoch = ++model.editorEpoch;
      model.iconDraft = profile?.custom_icon_data_url || ''; model.iconReadSequence++; model.iconReading = false;
      const running = profile && ['running', 'warm', 'active', 'starting', 'stopping', 'recovery_required'].includes(profile.state);
      const defaultPreset = profile?.preset_id || (integrated() && model.presets.some(p => p.id === 'desktop') ? 'desktop' : model.config?.camoufox_setup?.configured === true && model.presets.some(p => p.id === 'isolated' && p.engine_id === 'camoufox') ? 'isolated' : 'standard');
      const proxy = profile?.proxy_config;
      const disabled = blocked() || running ? 'disabled' : '';
      showDialog(`<h2 id="drawer-title">${profile ? 'Edit profile' : 'Create profile'}</h2><p id="drawer-description" class="drawer-note">${profile ? 'Configure this profile. Changes save on this device.' : 'Set up a separate browser context. You can finish browser setup after saving.'}</p><form id="local-profile-form"><section class="editor-section"><h3>Profile details</h3><div class="editor-field-grid"><div class="form-field"><label for="profile-name-input">Profile name</label><input id="profile-name-input" name="name" maxlength="120" required autocomplete="off" placeholder="e.g. Acme · Facebook" value="${esc(profile?.name || '')}"></div><div class="form-field"><label for="profile-assignment-input">Assignment label</label><input id="profile-assignment-input" maxlength="120" autocomplete="off" placeholder="e.g. Marketing / Jordan" value="${esc(profile?.assignment_label || '')}"><span class="field-hint">Local organization only. Does not grant team access.</span></div></div><div class="form-field"><label for="profile-icon-input">Profile icon</label><select id="profile-icon-input"><option value="browser">Browser</option><option value="facebook">Facebook</option><option value="google_ads">Google Ads</option><option value="youtube">YouTube</option><option value="custom">Custom image…</option></select></div><div id="custom-icon-field" class="custom-icon-field" ${profile?.icon_preset === 'custom' ? '' : 'hidden'}><label for="profile-icon-file">Choose an icon image</label><input type="file" id="profile-icon-file" accept="image/png,image/jpeg,image/webp"><span class="field-hint">PNG, JPEG or WebP. Up to 128 KB and 1024 × 1024 pixels. Stored only with this local profile.</span><span id="custom-icon-state">${model.iconDraft ? 'Current custom icon saved' : 'No image selected'}</span></div><label class="check-field"><input type="checkbox" id="profile-favorite-input" ${profile?.favorite ? 'checked' : ''}>Keep in favorites</label></section><section class="editor-section"><h3>Browser & identity</h3><div class="form-field"><label for="profile-preset-input">Browser engine</label><select id="profile-preset-input" ${disabled}>${model.presets.map(p => `<option value="${esc(p.id)}" ${p.id === defaultPreset ? 'selected' : ''}>${esc(engineLabel(p))}${integrated() && p.engine_id !== 'electron_chromium' ? ' · external engine, unavailable here' : ''}</option>`).join('')}</select></div><div id="identity-explanation" class="identity-explanation"></div>${running ? '<p class="field-hint">Stop the browser and verify its state before changing engine or connection.</p>' : ''}</section><section class="editor-section"><h3>Connection & proxy</h3><div class="form-field"><label for="profile-network-input">Network policy</label><select id="profile-network-input" ${disabled}><option value="unconfigured" ${!profile?.network_policy || profile.network_policy === 'unconfigured' ? 'selected' : ''}>Configure later</option><option value="local_direct" ${profile?.network_policy === 'local_direct' ? 'selected' : ''} ${profile?.origin === 'managed' ? 'disabled' : ''}>Direct · this device’s connection</option><option value="verified_proxy" ${profile?.network_policy === 'verified_proxy' ? 'selected' : ''}>Custom proxy · verification required</option></select><span class="field-hint">Direct mode uses this device’s normal connection and provides no proxy or anonymity guarantee. Proxy mode never falls back to a direct connection.</span></div><div id="proxy-config-fields" ${profile?.network_policy === 'verified_proxy' ? '' : 'hidden'}><div class="proxy-config-notice">${integrated() ? 'The built-in browser applies this proxy before opening tabs. Authentication is not yet supported; use an unauthenticated or IP-allowlisted proxy. Live route and leak checks remain required.' : 'Proxy details are saved for setup. They are not connected until a trusted adapter verifies this exact configuration.'} Do not enter passwords or tokens here.</div><div class="editor-field-grid"><div class="form-field"><label for="proxy-protocol-input">Protocol</label><select id="proxy-protocol-input" ${disabled}><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5">SOCKS5</option></select></div><div class="form-field"><label for="proxy-label-input">Proxy label</label><input id="proxy-label-input" maxlength="120" value="${esc(proxy?.label || '')}" placeholder="e.g. US West" ${disabled}></div><div class="form-field"><label for="proxy-host-input">Hostname or IP</label><input id="proxy-host-input" maxlength="253" autocomplete="off" value="${esc(proxy?.hostname || '')}" placeholder="proxy.example.com" ${disabled}></div><div class="form-field"><label for="proxy-port-input">Port</label><input type="number" id="proxy-port-input" min="1" max="65535" value="${proxy?.port || ''}" placeholder="8080" ${disabled}></div></div></div></section><p class="form-feedback" id="local-form-feedback" role="status" aria-live="polite"></p><div class="drawer-actions editor-save-actions"><button class="button" type="button" id="cancel-profile-edit">Cancel</button><button class="button button-primary" id="save-local-profile" type="submit">${profile ? 'Save changes' : 'Create profile'}</button></div></form>${profile ? `<details class="editor-advanced"><summary>Browser controls & removal</summary><div class="editor-advanced-body">${lifecycle(profile)}<div class="engine-blocker">${!canLaunch(profile) ? `<strong>Launch unavailable</strong><ul>${blockersFor(profile).map(b => `<li>${esc(b)}</li>`).join('')}</ul>` : ''}</div><div class="drawer-actions">${!integrated() ? `<button class="button" id="profile-start-action" ${!canLaunch(profile) || ['starting', 'stopping'].includes(profile.state) ? 'disabled' : ''}>Open browser</button>` : '<span class="field-hint">Save or cancel this form before using the browser controls.</span>'}${running && !integrated() ? '<button class="button" id="profile-stop-action">Stop browser</button>' : running ? '<span class="field-hint">Save or cancel this form, then use Close profile to change its engine or proxy.</span>' : ''}</div><p class="field-hint">Removing metadata retains browser data. Browser-session deletion is a separate action.</p><button class="button danger-button" id="review-delete" ${running ? 'disabled' : ''}>Remove profile…</button><div id="delete-review" hidden><p class="field-hint">Remove “${esc(profile.name)}” from the local workspace? Browser sessions and files are retained.</p><button class="button danger-button" id="confirm-delete">Remove this profile</button></div></div></details>` : ''}`);
      byId('profile-icon-input').value = profile?.icon_preset || 'browser';
      byId('proxy-protocol-input').value = proxy?.protocol || 'http';
      const updateIdentity = () => { const preset = model.presets.find(p => p.id === byId('profile-preset-input').value); byId('identity-explanation').innerHTML = `<strong>${preset?.engine_id === 'electron_chromium' ? 'Built-in Chromium identity' : preset?.engine_id === 'camoufox' ? 'Firefox-compatible profile identity' : 'Real installed Chrome identity'}</strong><p>${esc(identityDescription(preset))}</p><span>Changing a name or icon does not change the browser engine. Safari/WebKit is not available.</span>`; };
      updateIdentity();
      bind('profile-preset-input', 'change', updateIdentity);
      bind('profile-icon-input', 'change', event => { byId('custom-icon-field').hidden = event.target.value !== 'custom'; });
      bind('profile-network-input', 'change', event => { byId('proxy-config-fields').hidden = event.target.value !== 'verified_proxy'; });
      bind('profile-icon-file', 'change', async event => {
        const sequence = ++model.iconReadSequence;
        const file = event.target.files?.[0]; if (!file) { model.iconReading = false; byId('save-local-profile').disabled = blocked(); byId('custom-icon-state').textContent = model.iconDraft ? 'Current custom icon saved' : 'No image selected'; return; }
        model.iconDraft = ''; model.iconReading = false;
        if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type) || file.size > 131072) { byId('local-form-feedback').textContent = 'Choose a PNG, JPEG or WebP image no larger than 128 KB.'; event.target.value = ''; byId('save-local-profile').disabled = blocked(); byId('custom-icon-state').textContent = 'No image selected'; return; }
        model.iconReading = true; byId('save-local-profile').disabled = true; byId('custom-icon-state').textContent = 'Reading image…';
        try {
          const data = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = reject; reader.readAsDataURL(file); });
          if (!dialog.open || editorEpoch !== model.editorEpoch || sequence !== model.iconReadSequence) return;
          model.iconDraft = data; byId('custom-icon-state').textContent = file.name + ' selected'; byId('local-form-feedback').textContent = '';
        } catch { if (editorEpoch === model.editorEpoch && sequence === model.iconReadSequence) byId('local-form-feedback').textContent = 'The image could not be read. Choose another file.'; }
        finally { if (editorEpoch === model.editorEpoch && sequence === model.iconReadSequence) { model.iconReading = false; byId('save-local-profile').disabled = blocked(); } }
      });
      bind('cancel-profile-edit', 'click', () => { if (!model.pending) dialog.close(); });
      bind('local-profile-form', 'submit', async event => {
        event.preventDefault(); if (blocked()) return;
        if (model.iconReading) { byId('local-form-feedback').textContent = 'Wait for the selected image to finish loading.'; return; }
        const name = byId('profile-name-input').value.trim();
        if (!name) { byId('local-form-feedback').textContent = 'Give this profile a name.'; byId('profile-name-input').focus(); return; }
        const iconPreset = byId('profile-icon-input').value;
        if (iconPreset === 'custom' && !model.iconDraft) { byId('local-form-feedback').textContent = 'Choose a custom icon image, or select a preset icon.'; return; }
        const network = byId('profile-network-input').value;
        const host = byId('proxy-host-input').value.trim(), portText = byId('proxy-port-input').value;
        const proxyConfig = network === 'verified_proxy' && host ? {protocol: byId('proxy-protocol-input').value, hostname: host, port: Number(portText), label: byId('proxy-label-input').value.trim()} : null;
        if (network === 'verified_proxy' && (host || portText) && (!host || !Number.isInteger(Number(portText)) || Number(portText) < 1 || Number(portText) > 65535 || /[\s/@?#]/.test(host))) { byId('local-form-feedback').textContent = 'Use a hostname or IP without credentials or a URL, and a port from 1 to 65535.'; return; }
        const body = {name, preset_id: byId('profile-preset-input').value, network_policy: network, favorite: byId('profile-favorite-input').checked, icon_preset: iconPreset, custom_icon_data_url: iconPreset === 'custom' ? model.iconDraft : '', assignment_label: byId('profile-assignment-input').value.trim(), proxy_config: proxyConfig};
        if (profile) {
          body.expected_revision = profile.revision;
          for (const key of ['preset_id', 'network_policy', 'proxy_config']) if (JSON.stringify(body[key]) === JSON.stringify(profile[key] ?? (key === 'proxy_config' ? null : 'unconfigured'))) delete body[key];
        }
        await mutate({label: profile ? 'Saving profile…' : 'Creating profile…', path: profile ? '/profiles/' + encodeURIComponent(profile.id) : '/profiles', method: profile ? 'PATCH' : 'POST', body, success: profile ? 'Profile changes saved locally.' : 'Profile created. Choose it to finish setup.'});
      });
      bind('profile-start-action', 'click', () => lifecycleAction(profile.id, 'start'));
      bind('profile-stop-action', 'click', () => lifecycleAction(profile.id, 'stop'));
      bind('review-delete', 'click', () => { byId('delete-review').hidden = false; byId('confirm-delete').focus(); });
      bind('confirm-delete', 'click', () => mutate({label: 'Removing profile metadata…', path: '/profiles/' + encodeURIComponent(profile.id) + '?expected_revision=' + profile.revision, method: 'DELETE', success: 'Profile metadata removed.'}));
    }

    const pendingControls = new Map();
    function setDialogPending(pending) {
      if (!pending) {
        for (const [control, disabled] of pendingControls) control.disabled = disabled;
        pendingControls.clear(); return;
      }
      if (!dialog.open) return;
      dialog.querySelectorAll('input,select,button').forEach(control => { if (!pendingControls.has(control)) pendingControls.set(control, control.disabled); control.disabled = true; });
      const feedback = byId('local-form-feedback');
      feedback.textContent = model.pending.label + ' You can cancel waiting below; the service may already have received the request.';
      const cancel = document.createElement('button');
      cancel.type = 'button'; cancel.className = 'button'; cancel.textContent = 'Cancel waiting';
      cancel.addEventListener('click', cancelPending); feedback.appendChild(cancel);
    }
    function cancelPending() {
      if (!model.pending) return;
      model.pending.controller.abort();
      // Abort only stops waiting; it cannot undo an already accepted mutation.
      model.needsRefresh = true;
    }
    async function mutate({label, path, method = 'POST', body, success, optimistic}) {
      if (blocked()) return false;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      const snapshot = model.profiles.map(p => ({...p}));
      const previousFocus = document.activeElement;
      const hadDialog = dialog.open;
      if (optimistic) optimistic();
      model.pending = {label, controller}; model.error = null;
      setDialogPending(true); render();
      let accepted = false, keepDialog = false;
      try {
        const result = await request(path, {method, body, signal: controller.signal});
        accepted = true;
        if (result?.profile && Number.isInteger(result.profile.revision)) replaceProfile(result.profile);
        await loadData();
        if (controller.signal.aborted) throw new WorkspaceError('Waiting was canceled. Reload to verify the result before making another change.', {code: 'request_canceled', uncertain: true});
        model.needsRefresh = false;
        if (dialog.open) dialog.close();
        notify(success || 'Local change saved.');
        return true;
      } catch (error) {
        model.profiles = snapshot;
        const failure = error instanceof WorkspaceError ? error : new WorkspaceError('The latest records could not be loaded. Reload to verify the result.', {code: 'refresh_failed', uncertain: accepted});
        if (failure.profile && typeof failure.profile.id === 'string') replaceProfile(failure.profile);
        model.error = failure;
        model.needsRefresh = failure.uncertain || accepted || failure.code === 'csrf_rejected';
        model.offline = failure.code === 'offline';
        keepDialog = hadDialog && !model.needsRefresh && [400, 422].includes(failure.status);
        if (keepDialog) { byId('local-form-feedback').textContent = failure.message + ' Review the fields and try again.'; }
        else if (dialog.open) dialog.close();
        if (!model.needsRefresh && ['revision_conflict', 'conflict', 'stale_revision'].includes(failure.code)) {
          try { await loadData(); model.error = new WorkspaceError('This profile changed elsewhere. Latest records are loaded; reopen it and review before saving again.', {code: failure.code}); }
          catch { model.needsRefresh = true; }
        }
        notify(failure.uncertain || accepted ? 'The result needs verification. Reload before making another change.' : failure.message);
        return false;
      } finally {
        clearTimeout(timer); model.pending = null; setDialogPending(false); render();
        if (keepDialog) byId('save-local-profile')?.focus();
        else restoreFocus(hadDialog ? model.returnFocus : previousFocus);
      }
    }
    function replaceProfile(profile) { const index = model.profiles.findIndex(p => p.id === profile.id); if (index < 0) model.profiles.push(profile); else model.profiles[index] = profile; }
    function toggleFavorite(id) {
      const p = model.profiles.find(profile => profile.id === id);
      if (!p) return;
      return mutate({label: p.favorite ? 'Removing favorite…' : 'Saving favorite…', path: '/profiles/' + encodeURIComponent(id), method: 'PATCH', body: {expected_revision: p.revision, favorite: !p.favorite}, optimistic: () => { p.favorite = !p.favorite; }, success: 'Favorites saved locally.'});
    }
    function selectProfile(id) {
      if (!model.profiles.some(p => p.id === id) || model.pending || model.loading || model.needsRefresh || model.offline || !model.config) return Promise.resolve(false);
      model.modalEpoch++;
      if (switcher.open) switcher.close();
      if (id === model.selectedId && !model.selectionPending) return Promise.resolve(true);
      model.selectionTarget = id;
      if (model.selectionPromise) { paintSelection(); return model.selectionPromise; }
      const originView = model.view;
      model.selectionPending = true; model.error = null;
      nativeSetup?.deactivate(); nativeTabs?.deactivate(); embeddedBrowser?.deactivate(); paintSelection();
      // Serialize writes, coalescing intermediate clicks. Only the latest accepted
      // selection is painted; no full workspace reload or focus restoration.
      model.selectionPromise = (async () => {
        let accepted = false;
        try {
          while (model.selectionTarget) {
            const target = model.selectionTarget;
            const profile = model.profiles.find(p => p.id === target);
            if (!profile) throw new WorkspaceError('The selected profile is no longer available.', {code: 'not_found'});
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 8000);
            let result;
            try { result = await request('/profiles/' + encodeURIComponent(target) + '/actions', {method: 'POST', body: {action: 'select', expected_revision: profile.revision, idempotency_key: requestId()}, signal: controller.signal}); }
            finally { clearTimeout(timer); }
            accepted = true;
            if (result?.selected_profile_id !== target || result?.profile?.id !== target || !Number.isInteger(result.profile.revision)) throw new WorkspaceError('Selection acknowledgement was incomplete. Reload to verify it.', {code: 'invalid_response', uncertain: true});
            replaceProfile(result.profile);
            // Read only the collection: the previous selected profile may now be
            // warm. Setup/settings polling cannot reset the list or steal focus.
            const readController = new AbortController();
            const readTimer = setTimeout(() => readController.abort(), 8000);
            let profiles;
            try { profiles = await request('/profiles', {signal: readController.signal}); } finally { clearTimeout(readTimer); }
            if (!Array.isArray(profiles) || !profiles.every(p => typeof p.id === 'string' && Number.isInteger(p.revision))) throw new WorkspaceError('Profile state could not be verified.', {code: 'invalid_response', uncertain: true});
            model.profiles = profiles;
            if (model.selectionTarget !== target) continue;
            model.selectedId = target; model.config.selected_profile_id = target;
            model.selectionTarget = null;
          }
          return true;
        } catch (error) {
          model.selectionTarget = null;
          model.error = error instanceof WorkspaceError ? error : new WorkspaceError('Selection could not be verified. Reload before continuing.', {uncertain: accepted});
          model.needsRefresh = accepted || model.error.uncertain || ['csrf_rejected', 'revision_conflict'].includes(model.error.code);
          model.offline = model.error.code === 'offline';
          notify(model.error.message); return false;
        } finally {
          model.selectionPending = false; model.selectionPromise = null;
          if (model.view === 'profiles' && originView === 'profiles' && model.mode === 'local') {
            paintSelection();
            byId('workspace-status').innerHTML = statusStrip(); bindStrip();
            renderProfileDetail();
          } else if (model.mode === 'local') render();
        }
      })();
      return model.selectionPromise;
    }
    function lifecycleAction(id, action, intent) {
      const p = model.profiles.find(profile => profile.id === id);
      if (integrated() && p?.engine_id === 'electron_chromium') {
        if (action === 'start') { if (dialog.open) { notify('Save or cancel the profile form before opening the browser.'); return Promise.resolve(false); } model.profileSection = 'activity'; if (model.selectedId !== id) return selectProfile(id); renderProfileDetail(); return Promise.resolve(true); }
        if (action === 'stop') { model.profileSection = 'configuration'; if (dialog.open) dialog.close(); embeddedBrowser.deactivate(); return window.TeamDesktop.command({action: 'close_profile', profile_id: id, expected_revision: p.revision}).then(() => reload()).catch(error => { notify(error.message); renderProfileDetail(); }); }
      }
      if (!p || action === 'start' && (!canLaunch(p) || intent === 'gmail' && !canOpenInbox(p))) { notify('Browser launch is unavailable: ' + blockersFor(p).join(' ')); return; }
      return mutate({label: `${action === 'start' ? 'Starting' : action === 'stop' ? 'Stopping' : 'Canceling start for'} ${p.name}…`, path: '/profiles/' + encodeURIComponent(id) + '/actions', body: {action, ...(intent ? {intent} : {}), expected_revision: p.revision, idempotency_key: requestId()}, success: action === 'start' ? intent === 'gmail' ? 'Profile-bound Gmail request processed. Check its browser window and reported lifecycle state.' : 'Launch request accepted. Check the reported lifecycle state.' : 'Lifecycle request processed. Check the reported state.'});
    }

    function renderInbox() {
      const examples = syntheticInboxRows(model.profiles);
      container.innerHTML = title('Inbox', 'One Gmail account per isolated profile. Jump between contexts without sharing sessions.') + statusStrip() + `<div class="inbox-disclosure"><span class="card-icon">${icon('mail')}</span><div><h2>Your account switcher, with clear boundaries</h2><p>Native Gmail opens in the browser window bound to its profile. It is never embedded here, and selecting a profile does not verify which Google account is signed in.</p><span class="status ${model.config?.inbox?.native_open_available ? 'active' : 'setup'}">${model.config?.inbox?.native_open_available ? 'Native adapter available · profile gates still apply' : 'Native Gmail launch unavailable'}</span></div></div><div class="inbox-toolbar"><label class="check-field"><input type="checkbox" id="inbox-examples" ${model.inboxExample ? 'checked' : ''}>Show synthetic unread examples</label><span class="subtle-text">Unified message list requires separate Google authorization; not connected.</span></div><div class="inbox-grid">${examples.length ? examples.map(row => { const p = model.profiles.find(profile => profile.id === row.profileId); return `<article class="inbox-card ${p.id === model.selectedId ? 'selected' : ''}"><div class="card-topline"><span class="profile-avatar blue">${esc(initials(row.displayName))}</span><span class="unread-count" aria-label="${model.inboxExample ? row.unreadThreads + ' synthetic unread threads' : 'Unread count unavailable'}">${model.inboxExample ? row.unreadThreads : '—'}</span></div><h3>${esc(row.displayName)}</h3><p class="inbox-account">${model.inboxExample ? esc(row.emailHint) : 'Google account not verified'}</p><span class="example-label">${model.inboxExample ? 'SYNTHETIC EXAMPLE · NOT LIVE' : 'UNREAD DATA NOT CONNECTED'}</span><dl class="spec-list"><div><dt>Bound profile</dt><dd>${esc(p.name)}</dd></div><div><dt>Identity</dt><dd>Unverified label</dd></div><div><dt>Browser</dt><dd>${esc(stateLabel(p))}</dd></div></dl><p class="field-hint">${canOpenInbox(p) ? 'Opens the fixed Gmail Inbox target in this exact profile. Signed-in account identity remains unverified.' : esc(blockersFor(p)[0])}</p><div class="inbox-actions"><button class="button" data-select="${esc(p.id)}" ${blocked() || p.id === model.selectedId ? 'disabled' : ''}>${p.id === model.selectedId ? 'Selected context' : 'Select context'}</button><button class="button button-primary" data-open-gmail="${esc(p.id)}" ${blocked() || !canOpenInbox(p) ? 'disabled' : ''} title="Requires a verified native browser adapter and a fixed Gmail launch target for this profile.">${['running', 'warm'].includes(p.state) && canOpenInbox(p) ? 'Focus Gmail' : 'Open Gmail'} ${icon('external')}</button></div></article>`; }).join('') : '<section class="panel empty-state"><h3>No profiles yet</h3><p>Create a profile first. Each account context stays bound to one profile.</p><a class="button" href="#profiles">Go to profiles</a></section>'}</div><div class="info-strip">${icon('lock')}<div><strong>Drafts and login sessions stay in their own profiles.</strong><p>No cookie merging, shared credentials, message sending, or Google API access occurs in this workspace. Example counts are invented placeholders, and never an indication of unread mail.</p></div></div>`;
      bind('inbox-examples', 'change', event => { model.inboxExample = event.target.checked; renderInbox(); });
      bindAll('[data-select]', data => selectProfile(data.select)); bindAll('[data-open-gmail]', data => lifecycleAction(data.openGmail, 'start', 'gmail')); bindStrip();
    }
    function renderResources() {
      const settings = model.settings || {};
      const resident = model.profiles.filter(p => ['active', 'running', 'warm', 'starting'].includes(p.state)).length;
      const maxWarm = Number(settings.max_warm_profiles) || 3;
      container.innerHTML = title('App settings', 'Browser availability and workspace preferences.') + statusStrip() + `<section class="resource-grid"><article class="panel resource-card"><h2>Open profiles</h2><strong class="resource-value">${resident}</strong><p class="field-hint">Profiles currently reported open or starting by this local service.</p></article><article class="panel resource-card"><h2>Engine verification</h2><span class="status ${model.config?.launch?.actual_process_available ? 'active' : 'setup'}">${model.config?.launch?.actual_process_available ? 'Adapter reports available' : model.config?.launch?.execution_kind === 'synthetic' ? 'Simulation only · no native browser' : 'Execution unavailable'}</span><ul class="blocker-list">${blockersFor().map(b => `<li>${esc(b)}</li>`).join('')}</ul></article></section><section class="panel settings-panel"><h2>Open-profile limit</h2><p class="field-hint">Profiles with unsaved work are never closed automatically. This is a configured limit, not a memory reading.</p><form id="resource-form"><div class="form-field"><label for="warm-limit">Maximum open profiles</label><input type="number" id="warm-limit" min="1" max="16" required value="${maxWarm}" ${blocked() ? 'disabled' : ''}></div><button class="button button-primary" ${blocked() ? 'disabled' : ''}>Save limit</button></form></section>${integrated() ? '<section class="panel settings-panel"><h2>Browser tabs</h2><p class="field-hint">Each profile keeps its own tabs inside this app. The tab strip is horizontal in this version.</p></section>' : `<section class="panel settings-panel"><h2>Browser activity layout</h2><form id="navigation-form"><div class="form-field"><label for="tab-navigation">Open tabs</label><select id="tab-navigation"><option value="top">Horizontal list</option><option value="side">Vertical list</option></select></div><p class="field-hint">Selecting a profile keeps keyboard focus in this app. Only an explicit browser or tab action can bring a browser forward.</p><button class="button" ${blocked() ? 'disabled' : ''}>Save layout</button></form></section>`}`;
      if (!integrated()) byId('tab-navigation').value = settings.tab_navigation || 'top';
      bind('navigation-form', 'submit', event => { event.preventDefault(); return mutate({label: 'Saving navigation…', path: '/settings', method: 'PATCH', body: {expected_revision: settings.revision, tab_navigation: byId('tab-navigation').value}, success: 'Activity layout saved.'}); });
      bind('resource-form', 'submit', event => { event.preventDefault(); return mutate({label: 'Saving profile limit…', path: '/settings', method: 'PATCH', body: {expected_revision: settings.revision, max_warm_profiles: Number(byId('warm-limit').value)}, success: 'Open-profile limit saved.'}); });
      bindStrip();
    }
    function renderConnection() {
      if (supportsNativeManaged()) { nativeManaged.activate('connection'); return; }
      container.innerHTML = title('Managed connection', 'Your local workspace keeps working without a team account.') + statusStrip() + `<section class="panel settings-panel"><span class="card-icon blue">${icon('users')}</span><h2>Connect when your team is ready</h2><p class="field-hint">Managed enrollment is not implemented in this build. Saving a server label does not sign in, grant access, or upload profile data.</p><span class="status idle">Not enrolled</span><form id="managed-metadata-form"><div class="form-field"><label for="managed-server">Managed server URL (optional metadata)</label><input type="url" id="managed-server" placeholder="https://workspace.example.test" value="${esc(model.managed?.server_url || '')}" ${blocked() ? 'disabled' : ''}><span class="field-hint">No connection is made to this URL. Do not include tokens, passwords, or secret query parameters.</span></div><button class="button" ${blocked() ? 'disabled' : ''}>Save server label</button></form></section><div class="info-strip">${icon('shield')}<div><strong>Explicit enrollment will be a separate step.</strong><p>Verified team identity, approved device enrollment, and policy acceptance are required before a managed service can control a local profile. This screen stores metadata only.</p></div></div>`;
      bind('managed-metadata-form', 'submit', event => {
        event.preventDefault();
        const value = byId('managed-server').value.trim();
        if (value) {
          try { const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) throw new Error(); }
          catch { notify('Use an HTTPS server URL with no password, path, query parameters, or fragment.'); return; }
        }
        mutate({label: 'Saving managed server label…', path: '/managed-connection', method: 'PUT', body: {expected_revision: model.managed?.revision || 1, server_url: value || null}, success: 'Server label saved locally. No managed connection was established.'});
      }); bindStrip();
    }

    function switcherRows() {
      return filteredProfiles({query: model.switcherQuery, filter: 'all', sort: model.sort});
    }
    function paintSwitcher() {
      const rows = switcherRows();
      model.switcherIndex = Math.max(0, Math.min(model.switcherIndex, rows.length - 1));
      byId('switcher-results').innerHTML = rows.length ? rows.map((p, index) => `<button type="button" class="switcher-result ${index === model.switcherIndex ? 'highlighted' : ''}" id="switcher-option-${index}" role="option" aria-selected="${index === model.switcherIndex}" data-switch-profile="${esc(p.id)}" tabindex="-1"><span class="profile-avatar ${p.favorite ? 'gold' : 'blue'}">${esc(initials(p.name))}</span><span><strong>${esc(p.name)} ${p.favorite ? '<span aria-label="Favorite">★</span>' : ''}</strong><small>${esc(presetName(p.preset_id))} · ${esc(stateLabel(p))}</small></span><kbd>${index < 9 ? index + 1 : '↵'}</kbd></button>`).join('') : '<p class="switcher-empty" role="status">No matching profiles. Try another name.</p>';
      byId('switcher-search').setAttribute('aria-expanded', 'true');
      if (rows.length) byId('switcher-search').setAttribute('aria-activedescendant', 'switcher-option-' + model.switcherIndex);
      else byId('switcher-search').removeAttribute('aria-activedescendant');
      byId('switcher-results').querySelectorAll('[data-switch-profile]').forEach(el => el.addEventListener('click', () => selectProfile(el.dataset.switchProfile)));
      byId('switcher-announcement').textContent = `${rows.length} matching profiles. ${rows[model.switcherIndex]?.name || ''}`;
    }
    function openSwitcher() {
      if (model.mode !== 'local' || blocked() || dialog.open) return;
      model.returnFocus = document.activeElement;
      const epoch = ++model.modalEpoch;
      const open = () => {
        if (epoch !== model.modalEpoch || model.mode !== 'local' || blocked() || dialog.open) return;
        model.switcherQuery = ''; model.switcherIndex = 0;
        byId('switcher-search').value = ''; paintSwitcher();
        if (!switcher.open) switcher.showModal();
        byId('switcher-search').focus();
      };
      if (integrated()) void embeddedBrowser.hide().then(open).catch(() => notify('The browser could not be hidden safely. The switcher was not opened.'));
      else open();
    }
    function switcherKeydown(event) {
      const rows = switcherRows();
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        if (rows.length) model.switcherIndex = (model.switcherIndex + (event.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
        paintSwitcher(); byId('switcher-option-' + model.switcherIndex)?.scrollIntoView({block: 'nearest'});
      } else if (event.key === 'Enter') { event.preventDefault(); if (rows[model.switcherIndex]) selectProfile(rows[model.switcherIndex].id); }
      else if ((event.altKey || event.metaKey || event.ctrlKey) && /^[1-9]$/.test(event.key)) { event.preventDefault(); const p = rows[Number(event.key) - 1]; if (p) selectProfile(p.id); }
    }
    function globalKeydown(event) {
      if (model.mode !== 'local') return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); if (switcher.open) switcher.close(); else openSwitcher(); return; }
      if (dialog.open || switcher.open || model.pending) return;
      const editing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target?.tagName) || event.target?.isContentEditable;
      if (editing) return;
      if (event.altKey && !event.ctrlKey && !event.metaKey && /^[1-4]$/.test(event.key)) { event.preventDefault(); location.hash = '#' + Object.keys(localViews)[Number(event.key) - 1]; }
      if (event.key === '/' && !event.altKey && !event.ctrlKey && !event.metaKey && model.view === 'profiles') { event.preventDefault(); byId('local-search')?.focus(); }
    }

    async function discoverConfig() {
      if (!['http:', 'https:'].includes(location.protocol)) { model.checked = true; return null; }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      try {
        const response = await fetch('/local/config', {cache: 'no-store', credentials: 'omit', signal: controller.signal});
        if (!response.ok) return null;
        const config = await response.json();
        if (config.mode !== 'local' || config.api_base !== '/local/v1' || typeof config.csrf_token !== 'string' || config.account_required !== false) return null;
        return config;
      } catch { return null; }
      finally { clearTimeout(timer); model.checked = true; }
    }
    async function loadData() {
      nativeSetup?.deactivate();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const [profiles, presets, settings, managed] = await Promise.all(['/profiles', '/presets', '/settings', '/managed-connection'].map(path => request(path, {signal: controller.signal})));
        if (!Array.isArray(profiles) || !profiles.every(p => typeof p.id === 'string' && typeof p.name === 'string' && Number.isInteger(p.revision)) || !Array.isArray(presets) || !presets.every(p => typeof p.id === 'string' && typeof p.name === 'string') || !Number.isInteger(settings?.revision)) throw new WorkspaceError('The service returned incomplete workspace records.', {code: 'invalid_response'});
        model.profiles = profiles; model.presets = presets; model.settings = settings; model.managed = managed;
        model.selectedId = profiles.find(p => p.selected)?.id || model.config.selected_profile_id || null;
        if (!profiles.some(p => p.id === model.selectedId)) model.selectedId = null;
        model.offline = false;
      } finally { clearTimeout(timer); }
    }
    async function reload() {
      if (model.pending || model.selectionPending || model.loading) return;
      const sequence = ++model.loadSequence;
      model.loading = true; model.error = null; render();
      try {
        const config = await discoverConfig();
        if (!config) throw new WorkspaceError('The local workspace service is unavailable. Start it on this device, then reload.', {code: 'local_unavailable'});
        model.config = config;
        await loadData();
        if (sequence === model.loadSequence) model.needsRefresh = false;
      } catch (error) { model.error = error; model.offline = true; }
      finally { if (sequence === model.loadSequence) { model.loading = false; render(); } }
    }
    async function bootstrap() {
      model.discovering = true;
      if (model.mode !== 'managed') render();
      model.config = await discoverConfig();
      model.discovering = false;
      if (model.config?.desktop_shell && model.mode === 'choose') { model.mode = 'local'; rememberMode('local'); }
      if (model.mode === 'managed') {
        if (supportsNativeManaged()) { render(); return true; }
        return false;
      }
      if (model.mode === 'local' && model.config) await reload();
      else render();
      return true;
    }
    async function chooseMode(mode) {
      if (model.pending || model.selectionPending || isManagedBusy()) return;
      if (dialog.open) dialog.close();
      if (switcher.open) switcher.close();
      model.mode = mode; rememberMode(mode); paintChrome();
      nativeTabs?.deactivate();
      nativeSetup?.deactivate();
      if (mode === 'managed') {
        location.hash = '#profiles';
        if (supportsNativeManaged()) render();
        else { managedRoute(); await managedDiscover(); }
      } else { nativeManaged?.deactivate(); location.hash = '#profiles'; await reload(); }
    }
    function showChoice() {
      if (model.pending || model.selectionPending || isManagedBusy()) { notify('Wait for the current request or cancel waiting before switching workspaces.'); return; }
      if (dialog.open) dialog.close();
      if (switcher.open) switcher.close();
      nativeManaged?.deactivate();
      nativeSetup?.deactivate();
      model.mode = 'choose'; model.loadSequence++; model.loading = false; paintChrome(); render();
    }
    function render() {
      model.modalEpoch++;
      embeddedBrowser?.deactivate();
      nativeTabs?.deactivate();
      if (model.mode !== 'local' || !['', '#profiles'].includes(location.hash)) nativeSetup?.deactivate();
      if (model.mode === 'managed') {
        if (!supportsNativeManaged()) return false;
        paintChrome();
        const view = location.hash === '#connection' ? 'connection' : 'profiles';
        document.title = `${view === 'profiles' ? 'Team profiles' : 'Managed connection'} · Team Browser Manager`;
        byId('breadcrumb').textContent = view === 'profiles' ? 'Team profiles' : 'Managed connection';
        nativeManaged.activate(view);
        return true;
      }
      const requested = location.hash.slice(1);
      model.view = Object.hasOwn(localViews, requested) ? requested : 'profiles';
      if (model.view !== 'connection') nativeManaged?.deactivate();
      paintChrome();
      document.title = `${model.mode === 'choose' ? 'Choose workspace' : localViews[model.view]} · Team Browser Manager`;
      byId('breadcrumb').textContent = model.mode === 'choose' ? 'Get started' : localViews[model.view];
      if (model.mode === 'choose') renderChoice();
      else if (model.loading && !model.profiles.length) container.innerHTML = title('Loading your workspace…', 'Reading profiles and resource settings from this device.') + '<section class="panel empty-state" role="status"><h2>Reading local metadata</h2><p>No browser is being launched.</p></section>';
      else if (!model.config) localUnavailable();
      else ({profiles: renderProfiles, inbox: renderInbox, resources: renderResources, connection: renderConnection}[model.view])();
      return true;
    }
    bind('workspace-mode-button', 'click', showChoice);
    bind('quick-switch-button', 'click', openSwitcher);
    bind('close-switcher', 'click', () => switcher.close());
    bind('switcher-search', 'input', event => { model.switcherQuery = event.target.value; model.switcherIndex = 0; paintSwitcher(); });
    bind('switcher-search', 'keydown', switcherKeydown);
    switcher.addEventListener('close', () => { byId('switcher-search').setAttribute('aria-expanded', 'false'); model.returnFocus?.focus(); if (integrated()) embeddedBrowser.resume(); });
    dialog.addEventListener('cancel', event => { if (model.pending) event.preventDefault(); });
    dialog.addEventListener('close', () => { model.editorEpoch++; if (model.mode !== 'managed') restoreFocus(); if (integrated()) embeddedBrowser.resume(); });
    window.addEventListener('keydown', globalKeydown);
    window.addEventListener('hashchange', () => { if (model.mode !== 'managed' && !model.pending) { if (dialog.open) dialog.close(); if (switcher.open) switcher.close(); } });
    window.addEventListener('offline', () => { if (model.mode === 'local') { model.offline = true; render(); } });
    window.addEventListener('online', () => { if (model.mode === 'local' && model.offline) notify('Connectivity changed. Reload to verify the local service.'); });
    return {bootstrap, render, renderProfileDetail, chooseMode, showChoice, reload, model, request, filteredProfiles, toggleFavorite, selectProfile, lifecycleAction, canLaunch, canOpenInbox, openEditor, openSwitcher, switcherKeydown, globalKeydown, cancelPending, mutate, nativeManaged, nativeTabs, nativeSetup, embeddedBrowser};
  }
  window.TeamWorkspace = {mount, createClient, WorkspaceError, syntheticInboxRows};
})();
