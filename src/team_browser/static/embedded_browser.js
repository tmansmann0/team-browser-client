'use strict';
// Trusted app chrome only. Website content is a main-owned WebContentsView;
// it never receives this script, a preload bridge or the local API capability.
(() => {
  function mount({icon, esc, notify, onProfile = () => {}, document: doc = document, bridge = window.TeamDesktop}) {
    if (!bridge || typeof bridge.command !== 'function' || typeof bridge.subscribe !== 'function') return null;
    const state = {active: false, root: null, profile: null, snapshot: null, epoch: 0, sequence: 0, pending: false, error: null, suspended: true};
    let observer = null, boundsSequence = 0, lastBounds = null, lastSemantic = null;
    function normalize(value, profile) {
      if (!value || value.profile_id !== profile.id || !Array.isArray(value.tabs) || value.tabs.length > 128 || value.capabilities?.engine_id !== 'electron_chromium') throw new Error('The browser returned a different profile context.');
      const ids = new Set();
      for (const tab of value.tabs) {
        if (!tab || typeof tab.id !== 'string' || ids.has(tab.id) || typeof tab.url !== 'string' || typeof tab.title !== 'string' || tab.url.length > 8192 || tab.title.length > 4096) throw new Error('The browser returned an invalid tab.');
        ids.add(tab.id);
      }
      if (value.active_tab_id && !ids.has(value.active_tab_id)) throw new Error('The active tab is not in this profile.');
      return value;
    }
    async function hide() {
      state.suspended = true;
      lastBounds = null;
      boundsSequence++;
      observer?.disconnect(); observer = null;
      await bridge.command({action: 'hide_content'});
    }
    function deactivate() { lastSemantic = null; state.epoch++; state.active = false; state.root = null; state.profile = null; state.snapshot = null; state.pending = false; void hide().catch(() => { notify?.('The browser content could not be hidden. Close the app before changing profiles.'); }); }
    async function bounds() {
      const area = doc.getElementById('embedded-browser-viewport');
      if (!state.active || state.suspended || !area || doc.querySelector('dialog[open]')) return;
      const rect = area.getBoundingClientRect(), seq = ++boundsSequence;
      const pane = area.closest?.('.profile-detail-pane')?.getBoundingClientRect();
      const visible = rect.x >= 0 && rect.y >= Math.max(80, pane?.top || 0) && rect.right <= window.innerWidth && rect.bottom <= Math.min(window.innerHeight, pane?.bottom || window.innerHeight) && rect.width > 0 && rect.height > 0 && Boolean(state.snapshot?.active_tab_id);
      if (!visible) { if (lastBounds === 'hidden') return; lastBounds = 'hidden'; try { await bridge.command({action: 'hide_content'}); } catch { state.error = 'Browser content could not be hidden safely.'; drawStatus(); } return; }
      const nextBounds = {action: 'set_content_bounds', x: Math.round(rect.x), y: Math.round(rect.y), width: Math.max(0, Math.floor(rect.width)), height: Math.max(0, Math.floor(rect.height)), visible};
      const key = JSON.stringify([state.profile.id, nextBounds]);
      if (lastBounds === key) return;
      lastBounds = key;
      try { await bridge.command(nextBounds); }
      catch { if (seq === boundsSequence && state.active) { lastBounds = null; state.error = 'Browser content could not be placed safely. Switch back to Configuration and retry.'; drawStatus(); } }
    }
    function drawStatus() {
      const status = doc.getElementById('embedded-browser-status');
      if (status) { status.textContent = state.error || (state.pending ? 'Updating browser…' : state.snapshot?.tabs.find(t => t.id === state.snapshot.active_tab_id)?.error || ''); status.hidden = !status.textContent; }
    }
    function draw() {
      if (!state.active || !state.root) return;
      const focusedAddress = doc.activeElement?.id === 'embedded-browser-address';
      const priorDraft = focusedAddress ? doc.activeElement.value : null;
      const priorSelection = focusedAddress ? [doc.activeElement.selectionStart, doc.activeElement.selectionEnd, doc.activeElement.selectionDirection] : null;
      const snapshot = state.snapshot, tabs = snapshot?.tabs || [];
      const current = tabs.find(t => t.id === snapshot.active_tab_id);
      const statusText = state.error || (state.pending ? 'Updating browser…' : current?.error || '');
      state.root.innerHTML = `<div class="embedded-browser"><div class="embedded-tab-strip" role="tablist" aria-label="Tabs in this profile">${tabs.map(tab => `<div class="embedded-tab ${tab.id === snapshot.active_tab_id ? 'selected' : ''}"><button role="tab" data-embedded-tab="${esc(tab.id)}" aria-selected="${tab.id === snapshot.active_tab_id}">${esc(tab.title || (tab.url === 'about:blank' ? 'New tab' : 'Loading…'))}</button><button data-close-tab="${esc(tab.id)}" aria-label="Close ${esc(tab.title || 'tab')}">×</button></div>`).join('')}<button id="embedded-new-tab" class="embedded-new-tab" aria-label="New tab" ${state.pending ? 'disabled' : ''}>+</button></div><form id="embedded-navigation" class="embedded-navigation"><button type="button" id="embedded-back" aria-label="Back" ${!current?.can_go_back || state.pending ? 'disabled' : ''}>←</button><button type="button" id="embedded-forward" aria-label="Forward" ${!current?.can_go_forward || state.pending ? 'disabled' : ''}>→</button><button type="button" id="embedded-reload" aria-label="${current?.loading ? 'Stop loading' : 'Reload'}" ${!current || state.pending ? 'disabled' : ''}>${current?.loading ? '×' : '↻'}</button><label class="embedded-address-label"><span class="sr-only">Website address</span><input id="embedded-browser-address" type="text" spellcheck="false" autocomplete="off" value="${esc(priorDraft ?? current?.url ?? '')}" placeholder="Enter a website address" ${state.pending ? 'disabled' : ''}></label><button type="submit" class="button compact-button" ${state.pending ? 'disabled' : ''}>Go</button></form><p id="embedded-browser-status" class="embedded-status" role="status" ${!statusText ? 'hidden' : ''}>${esc(statusText)}</p><div class="embedded-runtime-note">Built-in Chromium${snapshot?.engine?.chromium ? ' ' + esc(snapshot.engine.chromium) : ''} · Profile storage is separate. Fingerprint protection and Google sign-in are not verified.</div><div id="embedded-browser-viewport" class="embedded-browser-viewport">${!tabs.length ? '<div class="embedded-empty"><h3>Ready for a new tab</h3><p>Enter an address above, or create a blank tab.</p><button class="button" id="embedded-empty-new-tab">New tab</button></div>' : ''}</div></div>`;
      const byId = id => doc.getElementById(id);
      const bind = (id, event, fn) => byId(id)?.addEventListener(event, fn);
      state.root.querySelectorAll('[data-embedded-tab]').forEach(button => button.addEventListener('click', () => command('activate_tab', {tab_id: button.dataset.embeddedTab})));
      state.root.querySelectorAll('[data-close-tab]').forEach(button => button.addEventListener('click', () => command('close_tab', {tab_id: button.dataset.closeTab})));
      const newTab = () => command('create_tab', {url: 'about:blank'});
      bind('embedded-new-tab', 'click', newTab); bind('embedded-empty-new-tab', 'click', newTab);
      bind('embedded-navigation', 'submit', event => { event.preventDefault(); const input = byId('embedded-browser-address').value.trim(); if (!input) return; const url = /^[a-z][a-z0-9+.-]*:/i.test(input) ? input : 'https://' + input; command(current ? 'navigate' : 'create_tab', {...(current ? {tab_id: current.id} : {}), url}); });
      for (const action of ['back', 'forward']) bind('embedded-' + action, 'click', () => current && command(action, {tab_id: current.id}));
      bind('embedded-reload', 'click', () => current && command(current.loading ? 'stop' : 'reload', {tab_id: current.id}));
      if (focusedAddress) { const address = byId('embedded-browser-address'); address?.focus(); if (Number.isInteger(priorSelection?.[0]) && Number.isInteger(priorSelection?.[1])) address?.setSelectionRange?.(...priorSelection); }
      observer?.disconnect();
      if (typeof ResizeObserver !== 'undefined') { observer = new ResizeObserver(() => void bounds()); observer.observe(byId('embedded-browser-viewport')); }
      void bounds();
    }
    async function command(action, extra = {}) {
      if (!state.active || state.pending || !state.profile) return false;
      const epoch = state.epoch, sequence = ++state.sequence, profile = state.profile;
      state.pending = true; state.error = null; drawStatus();
      try {
        const result = await bridge.command({action, profile_id: profile.id, expected_revision: profile.revision, ...extra});
        if (!state.active || epoch !== state.epoch || sequence !== state.sequence) return false;
        state.snapshot = normalize(result, profile);
        if (Number.isInteger(result.profile_revision)) state.profile.revision = result.profile_revision;
        if (result.profile && result.profile.id === profile.id && Number.isInteger(result.profile.revision)) { state.profile = {...result.profile}; onProfile(result.profile); }
        state.error = null; return true;
      } catch (error) { if (state.active && epoch === state.epoch) { state.error = typeof error.message === 'string' ? error.message : 'The browser operation was rejected.'; notify?.(state.error); } return false; }
      finally { if (state.active && epoch === state.epoch && sequence === state.sequence) { state.pending = false; draw(); } }
    }
    async function activate(root, profile) {
      deactivate();
      if (!root || !profile || profile.engine_id !== 'electron_chromium') return;
      Object.assign(state, {active: true, root, profile: {...profile}, error: null, suspended: false}); draw();
      await command('activate_profile');
    }
    bridge.subscribe(value => {
      if (!state.active || state.pending || value?.profile_id !== state.profile?.id) return;
      try { const normalized = normalize(value, state.profile); const semantic = JSON.stringify([normalized.profile_id, normalized.profile_revision, normalized.active_tab_id, normalized.tabs, normalized.status, normalized.error]); if (semantic === lastSemantic) return; lastSemantic = semantic; state.snapshot = normalized; if (Number.isInteger(value.profile_revision)) state.profile.revision = value.profile_revision; if (value.profile && Number.isInteger(value.profile.revision)) { state.profile = {...value.profile}; onProfile(value.profile); } draw(); }
      catch { state.snapshot = null; state.error = 'The profile context changed. Reopen this profile to verify its tabs.'; void hide().catch(() => {}); drawStatus(); }
    });
    function resume() { if (state.active) { state.suspended = false; void bounds(); } }
    window.addEventListener('scroll', () => { if (state.active) void bounds(); }, true);
    window.addEventListener('resize', () => { if (state.active) void bounds(); });
    return {activate, deactivate, hide, resume, bounds, command, state};
  }
  window.TeamEmbeddedBrowser = {mount};
})();
