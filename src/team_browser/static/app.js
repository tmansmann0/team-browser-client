'use strict';

// All data in this UI is synthetic. By default it runs as a standalone preview.
// A same-origin /demo/config opt-in enables the local, synthetic-only demo API.
// No real credential, browser launch, provider connection, or production login is used.
(() => {
  const iconPaths = {
    mail: '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m4 6 8 7 8-7"/>',
    star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9L12 3Z"/>',
    external: '<path d="M14 3h7v7M21 3l-9 9M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
    profiles: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 16l9 5 9-5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>',
    chart: '<path d="M4 3v17h17M8 15v-4M13 15V6M18 15V9"/>',
    checklist: '<rect x="5" y="4" width="15" height="17" rx="2"/><path d="M9 4V2h7v2M8 10l1.5 1.5L12 9M14 10h3M8 16l1.5 1.5L12 15M14 16h3"/>',
    laptop: '<rect x="4" y="3" width="16" height="13" rx="2"/><path d="m4 16-2 4h20l-2-4M10 17h4"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.5v.1"/>',
    chevron: '<path d="m9 5 7 7-7 7"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
    users: '<circle cx="9" cy="8" r="3"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M16 5a3 3 0 0 1 0 6M18 15a5 5 0 0 1 3 5"/>',
    shield: '<path d="m12 3 8 3v6c0 4-5 8-8 9-3-1-8-5-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
    plug: '<path d="m8 3 5 5M3 8l5 5M7 5l-3 3 6 6 4-4M13 11l3 3M12 16l4-4 4 4-4 4-4-4ZM18 18l3 3"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v9H3V7Z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
    check: '<path d="m5 12 4 4L19 6"/>'
  };
  const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${iconPaths[name] || iconPaths.profiles}</svg>`;
  const esc = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  document.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); });

  const profiles = [
    {id:'DEMO-001',name:'Acquisition · North',initials:'AN',color:'',seat:'01',preset:'Everyday work',status:'Ready',region:'US · East',activity:'12 min ago',group:'Campaign operations'},
    {id:'DEMO-002',name:'Studio · Editorial',initials:'SE',color:'blue',seat:'02',preset:'Creative review',status:'In use',region:'US · West',activity:'Now',group:'Content production'},
    {id:'DEMO-003',name:'Client · Sandbox',initials:'CS',color:'lilac',seat:'03',preset:'Client workspace',status:'Ready',region:'Direct connection',activity:'34 min ago',group:'Demo client work'},
    {id:'DEMO-004',name:'Acquisition · Europe',initials:'AE',color:'gold',seat:'04',preset:'Everyday work',status:'Needs setup',region:'Europe · West',activity:'Not started',group:'Campaign operations'},
    {id:'DEMO-005',name:'Studio · Production',initials:'SP',color:'rose',seat:'05',preset:'Creative review',status:'In use',region:'Direct connection',activity:'Now',group:'Content production'},
    {id:'DEMO-006',name:'Client · Research',initials:'CR',color:'blue',seat:'06',preset:'Client workspace',status:'Ready',region:'US · East',activity:'1 hr ago',group:'Demo client work'},
    {id:'DEMO-007',name:'Operations · Daily',initials:'OD',color:'',seat:'01',preset:'Everyday work',status:'Ready',region:'Direct connection',activity:'2 hrs ago',group:'Internal operations'},
    {id:'DEMO-008',name:'Review · Reserve',initials:'RR',color:'lilac',seat:'',preset:'Creative review',status:'Unassigned',region:'Not configured',activity:'Not started',group:'Content production'}
  ];
  const presets = [
    {name:'Everyday work',description:'A consistent starting point for day-to-day team operations.',icon:'profiles',color:'',profiles:3,permissions:'Standard',proxy:'Optional',download:'Ask every time'},
    {name:'Creative review',description:'A focused workspace for reviewing content and creative work.',icon:'layers',color:'blue',profiles:3,permissions:'Restricted',proxy:'Direct by default',download:'Ask every time'},
    {name:'Client workspace',description:'Keep each client workflow in its own browser profile.',icon:'folder',color:'gold',profiles:2,permissions:'Standard',proxy:'Per workspace',download:'Dedicated folder'}
  ];
  const state = {view:'profiles',search:'',status:'all',detailId:null};
  const api = {enabled:false,loading:false,error:'',saving:false,users:[]};
  const container = document.getElementById('view-container');
  const dialog = document.getElementById('detail-dialog');
  document.querySelector('.skip-link').addEventListener('click', event => {
    event.preventDefault();
    const main = document.getElementById('main');
    main.focus();
    main.scrollIntoView({block:'start'});
  });
  const titles = {profiles:'Browser profiles',presets:'Presets',providers:'Proxy providers',usage:'Usage overview',readiness:'Pilot readiness'};
  let toastTimer;

  function notify(message) {
    const toast = document.getElementById('toast');
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.hidden = false;
    toastTimer = setTimeout(() => { toast.hidden = true; }, 5000);
  }
  function statusBadge(status) {
    const cls = {'Ready':'ready','In use':'active','Needs setup':'setup','Unassigned':'idle'}[status] || 'idle';
    return `<span class="status ${cls}" title="Synthetic demo status; no browser is running">${esc(status)}</span>`;
  }
  function pageHeading(title, subtitle, button = '') {
    return `<div class="page-heading"><div><p class="eyebrow">Your team, in sync</p><h1>${title}</h1><p class="page-subtitle">${subtitle}</p></div>${button ? `<div class="header-actions">${button}</div>` : ''}</div>`;
  }
  function metric(label,value,note,iconName,badge='') {
    return `<article class="metric"><div class="metric-label">${label}${icon(iconName)}</div><div class="metric-value">${value}${badge ? `<span class="small-badge">${badge}</span>` : ''}</div><div class="metric-bottom">${note}</div></article>`;
  }
  function metrics() {
    const assignedSeats = new Set(profiles.filter(p=>p.seat).map(p=>p.seat)).size;
    const groups = new Set(profiles.map(p=>p.group)).size;
    return `<section class="metrics" aria-label="Synthetic workspace summary">${metric('Browser profiles',profiles.length,`<span class="green-text">All demo records</span> · ${groups} workgroup${groups===1?'':'s'}`,'profiles')}${metric('Assigned seats',assignedSeats,`${profiles.filter(p=>p.seat).length} profiles assigned in this preview`,'users')}${metric('Shared presets',presets.length,'Consistent defaults for every workflow','layers')}${metric('Browser connections',0,'Browser & provider integrations pending','plug','NOT CONNECTED')}</section>`;
  }
  function renderProfiles() {
    container.innerHTML = (api.enabled && managed ? managed.status() : '') + pageHeading('Browser profiles',api.enabled ? 'Synthetic profiles and assignments from the local demo API.' : 'One place to organize your team’s local browser workspaces.',`<button class="button button-primary" id="managed-new-profile" ${api.enabled && managed && !managed.model.needsRefresh && !managed.model.loading && !managed.model.pending ? '' : 'disabled'} title="${api.enabled && managed ? 'Create an unassigned synthetic profile record only.' : 'Profile provisioning requires the local agent and an authenticated control plane.'}">${icon('plus')}${api.enabled && managed ? 'New demo profile' : 'New profile'}</button>`) + metrics() + `
      <section class="panel" aria-labelledby="profile-list-title">
        <div class="panel-heading"><div><h2 id="profile-list-title">All profiles <span class="count-pill">${profiles.length}</span></h2><p>Central assignments. Separate local workspaces.</p></div><span class="subtle-text">Synthetic sample · no live activity</span></div>
        <div class="table-toolbar"><label class="search-field">${icon('search')}<span class="sr-only">Search demo profiles</span><input id="profile-search" type="search" placeholder="Search profiles, seats, or presets…" value="${esc(state.search)}" autocomplete="off"></label><div class="toolbar-right"><label class="select-wrap"><span>Status</span><select id="status-filter" aria-label="Filter profiles by status"><option value="all">All statuses</option>${api.enabled ? '' : '<option value="Ready">Ready</option><option value="In use">In use</option>'}<option value="Needs setup">Needs setup</option><option value="Unassigned">Unassigned</option></select></label></div></div>
        <div id="profile-results"></div>
      </section>
      <section class="support-grid" aria-label="Architecture and rollout notes"><article class="support-card">${icon('laptop')}<div><h3>Work locally. Organize together.</h3><p>Browser sessions are intended to run on each teammate’s Mac.<br>Assignments and preset definitions belong in the shared control plane.</p></div></article><article class="support-card secondary">${icon('shield')}<div><h3>A clear path to your first pilot</h3><p>Four integration gates remain before real team use.</p><a class="text-link" href="#readiness">Review pilot readiness${icon('chevron')}</a></div></article></section>`;
    managed?.bindStatus();
    document.getElementById('managed-new-profile')?.addEventListener('click', () => managed?.openProfileCreate());
    const search = document.getElementById('profile-search');
    search.addEventListener('input', () => { state.search = search.value; renderRows(); });
    const filter = document.getElementById('status-filter');
    filter.value = state.status;
    filter.addEventListener('change', () => { state.status = filter.value; renderRows(); });
    renderRows();
  }
  function renderRows() {
    const term = state.search.trim().toLowerCase();
    const rows = profiles.filter(p => (state.status === 'all' || p.status === state.status) && `${p.name} ${p.id} ${p.seat ? 'Seat '+p.seat : 'Unassigned'} ${p.preset} ${p.group} ${p.region}`.toLowerCase().includes(term));
    const result = document.getElementById('profile-results');
    result.innerHTML = rows.length ? `<div class="table-scroll"><table aria-label="Synthetic browser profiles"><thead><tr><th scope="col">Browser profile</th><th class="seat-column" scope="col">Assigned seat</th><th class="preset-column" scope="col">Preset</th><th scope="col">Demo status</th><th class="activity-column" scope="col">Sample activity</th><th scope="col"><span class="sr-only">Profile details</span></th></tr></thead><tbody>${rows.map(p=>`<tr><td><div class="profile-cell"><span class="profile-avatar ${p.color}" aria-hidden="true">${esc(p.initials)}</span><div><button class="profile-name" data-profile="${esc(p.id)}">${esc(p.name)}</button><span class="profile-code">${esc(p.id)} · ${esc(p.region)}</span></div></div></td><td class="seat-column">${p.seat ? `<span class="seat-label"><span class="seat-icon" aria-hidden="true">${esc(p.seat)}</span>Seat ${esc(p.seat)}</span>` : '<span class="unassigned">Unassigned</span>'}</td><td class="preset-column"><span class="preset-tag">${esc(p.preset)}</span></td><td>${statusBadge(p.status)}</td><td class="activity-column">${p.activity}</td><td><button class="row-action" data-profile="${esc(p.id)}" aria-label="View ${esc(p.name)} details">${icon('chevron')}</button></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty-state">${icon('search')}<h3>No matching profiles</h3><p>Try another profile name, seat, preset, or status.</p><button class="button" id="clear-filters">Clear filters</button></div>`;
    result.innerHTML += `<div class="table-footer"><span id="result-count" aria-live="polite">Showing ${rows.length} of ${profiles.length} demo profiles</span><span class="legend">${icon('info')}Statuses and activity are simulated.</span></div>`;
    result.querySelectorAll('[data-profile]').forEach(button => button.addEventListener('click', () => openProfile(button.dataset.profile)));
    document.getElementById('clear-filters')?.addEventListener('click', () => {state.search='';state.status='all';renderProfiles();document.getElementById('profile-search').focus();});
  }
  function renderPresets() {
    container.innerHTML = pageHeading('Shared presets','A familiar starting point, no matter who’s doing the work.',`<button class="button button-primary" disabled title="Creating real shared presets requires team login and the control plane.">${icon('plus')}New preset</button>`) + `
      <div class="card-grid">${presets.map((p,i)=>`<article class="preset-card"><div class="card-topline"><span class="card-icon ${p.color}">${icon(p.icon)}</span><span class="preset-tag">${p.profiles} demo profiles</span></div><h3>${esc(p.name)}</h3><p class="card-description">${esc(p.description)}</p><dl class="spec-list"><div><dt>Browser</dt><dd>${esc(p.engine || 'Chromium · planned')}</dd></div><div><dt>Permissions</dt><dd>${esc(p.permissions)}</dd></div><div><dt>Proxy policy</dt><dd>${esc(p.proxy)}</dd></div><div><dt>Downloads</dt><dd>${esc(p.download)}</dd></div></dl><button class="button" data-preset="${i}">Explore demo preset</button></article>`).join('')}</div>
      <div class="info-strip">${icon('layers')}<div><strong>Defaults with a clear owner.</strong><p>Presets describe intended settings for isolated local profiles. The current preview shows sample definitions only; nothing is applied to a Mac or synced to a team.</p></div></div>`;
    container.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => openPreset(Number(button.dataset.preset))));
  }
  function renderProviders() {
    const data = [
      {name:'North America pool',desc:'Example provider slot for region-specific campaign work.',icon:'globe',color:'blue',type:'Provider A · fictional',region:'US · East / West',count:'3 demo profiles'},
      {name:'Europe pool',desc:'An example regional pool awaiting provider setup.',icon:'globe',color:'gold',type:'Provider B · fictional',region:'Europe · West',count:'1 demo profile'},
      {name:'Bring your own proxy',desc:'A planned option for a team-managed HTTP or SOCKS proxy.',icon:'plug',color:'',type:'Team-managed · planned',region:'No endpoint configured',count:'0 demo profiles'}
    ];
    container.innerHTML = pageHeading('Proxy providers','Keep provider configuration visible without exposing credentials.') + `<section class="metrics" aria-label="Provider preview summary">${metric('Example provider slots',3,'Fictional provider configurations','globe')}${metric('Live providers',0,'No integration has been connected','plug')}${metric('Credentials stored',0,'This preview never collects secrets','lock')}${metric('Live traffic',0,'No traffic is sent through a proxy','chart')}</section><section class="provider-list" aria-label="Fictional proxy provider slots">${data.map(p=>`<article class="provider-card"><span class="card-icon ${p.color}">${icon(p.icon)}</span><div><h3>${esc(p.name)}</h3><p>${p.desc}</p><div class="provider-meta"><span>${p.type}</span><span>${p.region}</span><span>${api.enabled ? 'Illustrative slot, not linked to API' : p.count}</span></div></div><div class="provider-state"><span class="status idle">Not connected</span><button class="button" disabled title="Provider setup requires an approved integration and secure credential storage.">Connect provider</button></div></article>`).join('')}</section><div class="info-strip">${icon('lock')}<div><strong>Credential handling is a pilot gate.</strong><p>Real integrations need an approved provider, secure secret storage, health checks, and a verified egress test. No credentials, real endpoints, or provider accounts are present here.</p></div></div>`;
  }
  function renderUsage() {
    const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    const sessions = [9,14,11,18,16,6,4];
    container.innerHTML = pageHeading('Usage overview','An example of how a shared team activity view could look.') + `<section class="metrics" aria-label="Synthetic usage summary">${metric('Sample sessions',78,'Fictional seven-day example','profiles')}${metric('Sample active time','42.5h','Illustrative duration, not measured','clock')}${metric('Demo seats',6,'Synthetic labels only','users')}${metric('Live telemetry',0,'No usage has been collected','chart')}</section><section class="usage-grid"><article class="panel chart-panel"><div class="chart-title"><h2>Sample sessions</h2><span>Illustrative week · 78 total</span></div><div class="bar-chart" role="img" aria-label="Fictional sessions by weekday: Monday 9, Tuesday 14, Wednesday 11, Thursday 18, Friday 16, Saturday 6, Sunday 4.">${sessions.map((n,i)=>`<div class="bar-column"><div class="bar-fill bar-height-${n} ${i===3?'highlight':''}"><span class="bar-number">${n}</span></div><span>${days[i]}</span></div>`).join('')}</div><p class="chart-foot">Static sample data. No activity tracking or telemetry is connected.</p></article><article class="panel chart-panel"><div class="chart-title"><h2>By workflow</h2><span>Demo share</span></div><div class="usage-breakdown"><div><div class="breakdown-title"><span>Everyday work</span><strong>40 sessions · 51%</strong></div><div class="track"><span class="track-workflow-a"></span></div></div><div><div class="breakdown-title"><span>Creative review</span><strong>26 sessions · 33%</strong></div><div class="track"><span class="track-workflow-b"></span></div></div><div><div class="breakdown-title"><span>Client workspace</span><strong>12 sessions · 16%</strong></div><div class="track"><span class="track-workflow-c"></span></div></div></div><p class="chart-foot">Planned reporting: session counts and duration. Team visibility and retention rules must be agreed before collecting real activity.</p></article></section><div class="info-strip">${icon('shield')}<div><strong>Measure only what the team agrees to.</strong><p>This sample does not represent employee activity. Browsing history, page contents, and credentials are not collected by this preview.</p></div></div>`;
  }
  function renderReadiness() {
    const gates = [
      {name:'Local browser launch',desc:'Connect a Mac agent, validate isolated browser data directories, and confirm launch and cleanup behavior on a pilot device.',facts:['Mac agent handshake','Profile isolation test','Launch / close validation']},
      {name:'Team login & permissions',desc:'Choose an identity provider and verify administrator, team-member, and profile-assignment access before allowing team use.',facts:['Authenticated sessions','Role enforcement','Assignment access checks']},
      {name:'Provider integrations',desc:'Approve a real provider, keep secrets out of the browser UI, and verify connection health, egress location, and failure handling.',facts:['Secure credential storage','Provider health checks','Network validation']},
      {name:'Install & update packages',desc:'Build and test signed, notarized Mac packages with a documented installation, update, and uninstall path for the pilot team.',facts:['Signed packages','Notarization','Install / uninstall test']}
    ];
    container.innerHTML = pageHeading('Pilot readiness','A small, deliberate path from preview to real team use.') + `<section class="readiness-summary"><span class="readiness-icon">${icon('checklist')}</span><div><h2>Preview ready. Integrations pending.</h2><p>You can explore profiles, filter the list, inspect presets, and edit demo assignments.<br>The four gates below must be verified before any live pilot.</p></div><span class="button" aria-label="Four open pilot gates">4 open gates</span></section><section class="panel" aria-labelledby="gate-title"><div class="panel-heading"><div><h2 id="gate-title">Before the first real session</h2><p>Product requirements, not completed integration checks.</p></div><span class="subtle-text">0 of 4 gates verified</span></div><div class="gate-list">${gates.map((g,i)=>`<article class="gate"><span class="gate-number">0${i+1}</span><div class="gate-body"><h3>${g.name}</h3><p>${g.desc}</p><div class="gate-facts">${g.facts.map(f=>`<span>${f}</span>`).join('')}</div></div><span class="status setup">Not verified</span></article>`).join('')}</div></section><div class="info-strip">${icon('info')}<div><strong>Nothing here claims production readiness.</strong><p>All profile states, activity timestamps, seats, provider slots, and usage figures are synthetic examples. ${api.enabled ? 'This mode uses a local synthetic demo API for seat assignments only. It does not provision real profiles, launch browsers, or store secrets.' : 'The standalone preview does not provision profiles, launch browsers, or store secrets.'}</p></div></div>`;
  }
  function drawerFrame(body) {
    return `<div class="drawer-head"><p class="eyebrow">Interactive preview · synthetic data</p><button class="close-button" id="close-drawer" aria-label="Close details">${icon('close')}</button></div><div class="drawer-main">${body}</div>`;
  }
  function showDrawer(html) {
    document.getElementById('drawer-content').innerHTML = drawerFrame(html);
    document.getElementById('close-drawer').addEventListener('click', () => { if (!api.saving) dialog.close(); });
    if (!dialog.open) dialog.showModal();
    dialog.scrollTop = 0;
    document.getElementById('close-drawer').focus();
  }
  function openProfile(id) {
    if (api.enabled && managed?.model.needsRefresh) { notify('Reload the managed simulator records to verify the previous request before editing.'); return; }
    const p = profiles.find(profile=>profile.id===id);
    if (!p) return;
    state.detailId = id;
    showDrawer(`<div class="drawer-profile"><span class="profile-avatar ${p.color}" aria-hidden="true">${esc(p.initials)}</span><div><h2 id="drawer-title">${esc(p.name)}</h2><span class="profile-code">${esc(p.id)} · Synthetic profile</span></div></div>${statusBadge(p.status)}<p id="drawer-description" class="drawer-note">Explore this sample profile. ${api.enabled ? 'Assignments save to this local, in-memory synthetic demo API. Data resets when the demo process restarts.' : 'Assignment changes affect only the preview and reset when this page reloads.'}</p><section class="drawer-section"><h3>Workspace details</h3><dl class="spec-list"><div><dt>Workgroup</dt><dd>${esc(p.group)}</dd></div><div><dt>Intended device</dt><dd>macOS · local Mac</dd></div><div><dt>Region label</dt><dd>${esc(p.region)}</dd></div><div><dt>Browser engine</dt><dd>Chromium · planned</dd></div><div><dt>Browser connection</dt><dd>None</dd></div></dl></section><section class="drawer-section"><h3>Try a demo assignment</h3><form id="assignment-form"><div class="form-field"><label for="seat-select">Assigned demo seat</label><select id="seat-select"><option value="">Unassigned</option>${seatOptions(p)}</select></div><div class="form-field"><label for="preset-select">Shared demo preset</label><select id="preset-select" ${api.enabled ? 'disabled aria-describedby="preset-scope"' : ''}>${presets.map(pr=>`<option ${pr.name===p.preset?'selected':''}>${esc(pr.name)}</option>`).join('')}</select></div><p class="field-hint" id="preset-scope">${api.enabled ? 'The demo API supports seat assignments only. Preset changes are disabled. No real teammate or browser is affected.' : 'No real teammate is assigned and no browser settings are changed.'}</p><p class="form-feedback" id="assignment-feedback" role="status" aria-live="polite"></p><div class="drawer-actions"><button class="button" type="button" id="cancel-assignment">Cancel</button><button class="button button-primary" type="submit">${api.enabled ? 'Save demo assignment' : 'Apply to preview'}</button></div></form></section><section class="drawer-section"><h3>Browser launch is unavailable</h3><p class="field-hint">Requires a connected Mac agent, authenticated team access, and verified installation. No local process will be started.</p><button class="button" disabled>${icon('laptop')}Launch browser</button></section>`);
    document.getElementById('cancel-assignment').addEventListener('click', () => dialog.close());
    document.getElementById('assignment-form').addEventListener('submit', async event => {
      event.preventDefault();
      if (api.saving) return;
      if (api.enabled) {
        await saveApiAssignment(p, document.getElementById('seat-select').value);
        return;
      }
      p.seat = document.getElementById('seat-select').value;
      p.preset = document.getElementById('preset-select').value;
      if (!p.seat) p.status = 'Unassigned';
      else if (p.status === 'Unassigned') p.status = 'Needs setup';
      // Counts reflect current in-memory preview assignments, never a real service.
      presets.forEach(pr => {pr.profiles = profiles.filter(profile=>profile.preset===pr.name).length;});
      renderProfiles();
      dialog.close();
      notify(`Preview updated for ${p.name}. No real assignment was changed.`);
    });
  }
  function openPreset(index) {
    const p = presets[index];
    state.detailId = null;
    showDrawer(`<div class="drawer-profile"><span class="card-icon ${p.color}">${icon(p.icon)}</span><div><h2 id="drawer-title">${esc(p.name)}</h2><span class="profile-code">Synthetic shared preset</span></div></div><p id="drawer-description" class="drawer-note">${esc(p.description)} This is a sample definition; no settings are applied to any browser.</p><section class="drawer-section"><h3>Sample defaults</h3><dl class="spec-list"><div><dt>Browser engine</dt><dd>${esc(p.engine || 'Chromium · planned')}</dd></div><div><dt>Platform</dt><dd>macOS · Mac-first</dd></div><div><dt>Permissions</dt><dd>${esc(p.permissions)}</dd></div><div><dt>Proxy policy</dt><dd>${esc(p.proxy)}</dd></div><div><dt>Downloads</dt><dd>${esc(p.download)}</dd></div><div><dt>Sample profiles</dt><dd>${p.profiles}</dd></div>${api.enabled ? `<div><dt>Locale</dt><dd>${esc(p.locale)}</dd></div><div><dt>Timezone</dt><dd>${esc(p.timezone)}</dd></div><div><dt>Revision</dt><dd>${p.revision}</dd></div>` : ''}</dl></section><section class="drawer-section"><h3>Profiles with this demo preset</h3>${profiles.filter(profile=>profile.preset===p.name).map(profile=>`<p class="field-hint">${esc(profile.name)} <span class="profile-code">${esc(profile.id)}</span></p>`).join('')}</section><section class="drawer-section"><h3>Sync is unavailable</h3><p class="field-hint">A team identity service and connected Mac agent are required before preset changes can be synchronized.</p><button class="button" disabled>Publish preset</button></section>`);
  }
  dialog.addEventListener('cancel', event => { if (api.saving) event.preventDefault(); });
  dialog.addEventListener('click', event => { if (!api.saving && !workspace?.model.pending && event.target === dialog) { const rect=dialog.getBoundingClientRect(); if (event.clientX<rect.left || event.clientX>rect.right || event.clientY<rect.top || event.clientY>rect.bottom) dialog.close(); }});
  // Native dialog handles Escape and traps keyboard focus; close returns focus.
  dialog.addEventListener('close', () => {
    if (state.detailId) {
      const returnTarget = Array.from(document.querySelectorAll('.profile-name[data-profile]')).find(button => button.dataset.profile === state.detailId) || document.getElementById('profile-search');
      returnTarget?.focus();
    }
    state.detailId = null;
    if (api.error) renderApiState();
  });
  function seatOptions(profile) {
    if (!api.enabled) return ['01','02','03','04','05','06'].map(seat => `<option value="${seat}" ${profile.seat===seat?'selected':''}>Seat ${seat}</option>`).join('');
    return api.users.filter(user=>user.enabled && user.id!=='demo-owner').map(user => `<option value="${esc(user.id)}" ${profile.assignedUserId===user.id?'selected':''}>${esc(user.display_name || user.id)}</option>`).join('');
  }
  function updateModeCopy() {
    const banner = document.querySelector('.demo-banner p');
    banner.innerHTML = '<strong>Connected to the local demo API.</strong> Data is synthetic and kept in memory. Assignment changes save only to this demo; no real browser or provider is connected.';
    document.querySelector('.preview-pill').innerHTML = '<span aria-hidden="true"></span>Local API demo';
    document.querySelector('.sidebar-foot div>span').textContent = 'Synthetic API · no team login';
    document.querySelector('.page-footer p').textContent = 'Local browser launch, team login, provider integrations, and install packages remain pilot gates. No live browser or provider is connected. Demo data resets when the demo process restarts.';
    document.querySelector('.workspace-label div>span').textContent = `Synthetic team · ${api.users.filter(user=>user.enabled && user.id!=='demo-owner').length} seats`;
    document.querySelector('.nav-count').textContent = String(profiles.length);
    managed?.ready();
  }
  async function requestApi(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(()=>controller.abort(),8000);
    try {
      const response = await fetch(path, {...options, cache:'no-store', credentials:'omit', signal:controller.signal, headers:{'Authorization':'Bearer synthetic-demo', ...(options.body ? {'Content-Type':'application/json'} : {}), ...options.headers}});
      if (!response.ok) {
        let detail; try { detail = typeof response.json === 'function' ? (await response.json())?.detail : null; } catch { /* Preserve the HTTP failure when no JSON detail exists. */ }
        const message = typeof detail === 'string' ? detail : detail?.message;
        const error = new Error(message || `Demo API request failed (${response.status}).`);
        error.status = response.status;
        error.code = detail?.code || (response.status === 409 && message && !/changed|revision|reload before/i.test(message) ? 'policy_conflict' : response.status === 409 ? 'revision_conflict' : 'request_failed');
        throw error;
      }
      return response.status===204 ? null : await response.json();
    } finally { clearTimeout(timer); }
  }
  function collection(data, name) {
    const values = Array.isArray(data) ? data : data?.items || data?.[name];
    if (!Array.isArray(values)) throw new Error('The demo API returned an unexpected data format.');
    return values;
  }
  async function loadApiData() {
    const [userData,presetData,profileData] = await Promise.all([requestApi('/v1/users'),requestApi('/v1/presets'),requestApi('/v1/profiles')]);
    const users = collection(userData,'users');
    const loadedPresets = collection(presetData,'presets');
    const loadedProfiles = collection(profileData,'profiles');
    if (!users.every(u=>typeof u.id==='string') || !loadedPresets.every(p=>typeof p.id==='string' && typeof p.name==='string') || !loadedProfiles.every(p=>typeof p.id==='string' && typeof p.name==='string' && Number.isInteger(p.revision))) throw new Error('The demo API returned incomplete records.');
    api.users = users;
    presets.splice(0,presets.length,...loadedPresets.map((preset,index)=>({id:preset.id,name:preset.name,description:'Synthetic defaults loaded from the local demo API.',icon:['profiles','layers','folder'][index%3],color:['','blue','gold'][index%3],profiles:loadedProfiles.filter(p=>p.preset_id===preset.id).length,permissions:'Demo defaults',proxy:preset.proxy_required?'Required · demo':'Optional · demo',download:'Not configured',engine:preset.engine,locale:preset.locale,timezone:preset.timezone,revision:preset.revision})));
    profiles.splice(0,profiles.length,...loadedProfiles.map((profile,index)=>{
      const assigned=users.find(user=>user.id===profile.assigned_user_id);
      const seat=assigned?.id.startsWith('user-') ? assigned.id.slice(5) : assigned ? assigned.id : '';
      return {id:profile.id,name:profile.name,initials:profile.name.split(/[\s·-]+/).filter(Boolean).slice(0,2).map(word=>word[0]).join('').toUpperCase(),color:['','blue','lilac','gold','rose'][index%5],seat,assignedUserId:profile.assigned_user_id || '',preset:loadedPresets.find(preset=>preset.id===profile.preset_id)?.name || 'Unknown preset',status:profile.assigned_user_id?'Needs setup':'Unassigned',region:'Not connected',activity:'No live activity',group:'Demo workspace',revision:profile.revision};
    }));
    updateModeCopy();
  }
  function renderApiState() {
    container.innerHTML = pageHeading(api.loading?'Loading demo workspace…':'Demo API needs attention',api.loading?'Reading synthetic profiles, presets, and seats from the local demo API.':'Your browser has not changed any real account, browser, or provider.') + `<section class="panel empty-state" role="status">${icon(api.loading?'clock':'info')}<h2>${api.loading?'Loading synthetic records':'Unable to load demo records'}</h2><p>${api.loading?'This should only take a moment.':esc(api.error)}</p>${api.loading?'':'<button class="button" id="retry-api">Reload demo records</button>'}</section>`;
    document.getElementById('retry-api')?.addEventListener('click',reloadApiWorkspace);
  }
  async function reloadApiWorkspace() {
    api.loading=true; api.error=''; route();
    try { await loadApiData(); }
    catch { api.error='The local demo API could not be reached or returned invalid records. Check that the demo process is running, then reload.'; }
    finally { api.loading=false; route(); }
  }
  async function discoverDemoApi() {
    if (workspace && await workspace.bootstrap()) return;
    if (!['http:','https:'].includes(location.protocol)) return;
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),4000);
    try {
      const response=await fetch('/demo/config',{cache:'no-store',credentials:'omit',signal:controller.signal});
      if (!response.ok) return;
      const config=await response.json();
      if (config.mode!=='synthetic' || config.token!=='synthetic-demo') return;
      api.enabled=true;
      state.status='all'; state.search='';
      await reloadApiWorkspace();
    } catch { /* Missing config is the normal standalone-preview path. */ }
    finally {clearTimeout(timer);}
  }
  async function saveApiAssignment(profile,userId) {
    api.saving=true;
    const form=document.getElementById('assignment-form');
    const feedback=document.getElementById('assignment-feedback');
    const submit=form.querySelector('[type="submit"]');
    form.querySelectorAll('button,select').forEach(control=>{control.disabled=true;});
    document.getElementById('close-drawer').disabled=true;
    feedback.textContent='Saving this synthetic assignment to the local demo API…';
    submit.textContent='Saving…';
    let saved=false;
    try {
      await requestApi(`/v1/profiles/${encodeURIComponent(profile.id)}/assignment`,{method:'PUT',body:JSON.stringify({user_id:userId || null,expected_revision:profile.revision})});
      saved=true;
      await loadApiData();
      api.saving=false;
      dialog.close(); route();
      notify('Demo assignment saved to the local API. No real team or browser was changed.');
    } catch (error) {
      api.saving=false;
      if (error.status===409 && error.code !== 'policy_conflict' || saved) {
        dialog.close();
        if (saved) {
          api.error='The demo assignment was saved, but refreshed records could not be loaded. Reload demo records before editing again.';
          route();
        } else {
          await reloadApiWorkspace();
          notify('This demo profile changed elsewhere. Records were reloaded; reopen it and review before saving again.');
        }
      } else {
        feedback.textContent=error.code==='policy_conflict' ? `${error.message} Close this panel and reload records before reviewing the assignment again.` : error.name==='AbortError' ? 'The request timed out. The save outcome is uncertain. Close this panel and reload demo records before trying again.' : `The demo assignment could not be saved${error.status ? ' (HTTP '+error.status+')' : ''}. Close this panel and reload demo records before trying again.`;
        submit.textContent='Save unavailable until reload';
        document.getElementById('close-drawer').disabled=false;
        document.getElementById('cancel-assignment').disabled=false;
        // Do not blindly repeat an uncertain mutation. A reload is required.
        api.error='The previous save did not finish cleanly. Reload demo records to verify the current assignment before editing again.';
      }
    }
  }
  function route() {
    if (workspace?.render()) return;
    if (managed?.render()) return;
    if (api.saving) return;
    const requested = location.hash.slice(1);
    const view = Object.hasOwn(titles,requested) ? requested : 'profiles';
    if (dialog.open) dialog.close();
    state.view = view;
    document.querySelectorAll('[data-view]').forEach(item => {
      const selected = item.dataset.view === view;
      item.classList.toggle('active',selected);
      if (selected) item.setAttribute('aria-current','page'); else item.removeAttribute('aria-current');
    });
    document.getElementById('breadcrumb').textContent = titles[view];
    document.title = `${titles[view]} · Team Browser Manager Preview`;
    if (api.loading || api.error) { renderApiState(); return; }
    ({profiles:renderProfiles,presets:renderPresets,providers:renderProviders,usage:renderUsage,readiness:renderReadiness}[view])();
  }
  const managed = window.ManagedWorkspace?.mount({api, profiles, presets, icon, esc, notify, route, loadApiData});
  const workspace = window.TeamWorkspace?.mount({icon, esc, notify, managedRoute: route, managedDiscover: discoverDemoApi, isManagedBusy: () => api.saving});
  window.addEventListener('hashchange', route);
  route();
  discoverDemoApi();
})();
