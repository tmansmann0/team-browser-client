'use strict';
// Local native-window controls only. No website embedding, navigation, cookies,
// remote telemetry, or URL input is exposed by this component.
(() => {
  const statuses = new Set(['ready', 'limited', 'changed', 'busy', 'not_ready', 'unsupported', 'unavailable', 'superseded', 'no_selection']);
  const focusStatuses = new Set(['queued', 'pending', 'focused', 'stale_tab', 'not_ready', 'empty', 'superseded', 'unavailable', 'idle']);
  const tabId = /^tab_[a-f0-9]{32}$/;
  function normalize(value, profile) {
    if (!value || value.profile_id !== profile.id || !statuses.has(value.status) || !Array.isArray(value.tabs) || value.tabs.length > 128) throw new Error('Tab context changed.');
    const ready = value.status === 'ready';
    if (ready && (value.truncated !== false || !Number.isSafeInteger(value.generation) || value.generation < 1 || (Number.isSafeInteger(profile.generation) && value.generation !== profile.generation))) throw new Error('Tab generation changed.');
    const ids = new Set();
    const tabs = value.tabs.map(tab => {
      if (!tab || typeof tab.id !== 'string' || tab.id.length !== 36 || !tabId.test(tab.id) || ids.has(tab.id) || typeof tab.title !== 'string' || tab.title.length > 160 || typeof tab.active !== 'boolean') throw new Error('Invalid tab response.');
      ids.add(tab.id);
      let origin = null;
      if (tab.origin !== null) {
        if (typeof tab.origin !== 'string' || tab.origin.length > 2048) throw new Error('Invalid origin.');
        const url = new URL(tab.origin);
        if (url.protocol !== 'https:' || url.origin !== tab.origin || url.username || url.password || url.search || url.hash) throw new Error('Invalid origin.');
        origin = tab.origin;
      }
      return {id: tab.id, title: tab.title, origin, active: tab.active};
    });
    if (!ready && value.status !== 'limited' && tabs.length) throw new Error('Incomplete context returned tabs.');
    return {status: value.status, generation: value.generation, tabs: ready ? tabs : [], activeEvidence: value.active_evidence === 'dom_visibility_hint', focus: focusStatuses.has(value.focus?.status) ? value.focus.status : 'unavailable'};
  }
  function mount({request, notify, document: doc = document, schedule = setTimeout, cancel = clearTimeout}) {
    const state = {epoch: 0, sequence: 0, active: false, root: null, profile: null, layout: 'top', snapshot: null, error: null, sending: false};
    let timer = null, expiry = null, controller = null;
    const later = (fn, ms) => { const t = schedule(fn, ms); t?.unref?.(); return t; };
    function clearTimers() { cancel(timer); cancel(expiry); timer = expiry = null; }
    function deactivate() { state.epoch++; state.sequence++; state.active = false; state.snapshot = null; state.sending = false; clearTimers(); controller?.abort(); controller = null; if (state.root) state.root.replaceChildren(); state.root = null; state.profile = null; }
    function node(tag, text, cls) { const el = doc.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; }
    function draw() {
      const root = state.root;
      if (!state.active || !root) return;
      const previouslyFocused = doc.activeElement?.dataset?.nativeTab;
      root.replaceChildren();
      root.className = 'native-tabs panel ' + (state.layout === 'side' ? 'native-tabs-side' : 'native-tabs-top');
      const heading = node('div', undefined, 'native-tabs-heading');
      heading.append(node('h2', 'Open tabs'), node('p', 'Controls for this profile’s existing browser window.'));
      const refresh = node('button', 'Refresh tabs', 'button compact-button'); refresh.type = 'button'; refresh.addEventListener('click', poll); heading.append(refresh); root.append(heading);
      const snap = state.snapshot;
      if (!snap || snap.status !== 'ready') {
        const labels = {not_ready: 'Start this profile with a verified native engine to see its tabs.', unsupported: 'This runtime does not expose owned native tabs.', no_selection: 'Select a profile to see its tabs.', limited: 'Too many tabs to show a complete, safe selection. Use the native browser.', busy: 'The browser is reading its tabs. Waiting for a fresh snapshot.', changed: 'The browser context changed. Refreshing tabs.', superseded: 'Profile selection changed. Refreshing tabs.', unavailable: 'Native tabs are unavailable. No cached tabs are shown.'};
        root.append(node('p', state.error || labels[snap?.status] || 'Reading this profile’s native tabs…', 'native-tabs-empty')); return;
      }
      const status = node('p', state.sending ? 'Requesting tab focus…' : ({queued: 'Focus requested; waiting for the browser.', pending: 'Focus requested; waiting for the browser.', focused: 'The browser acknowledged the focus request.', stale_tab: 'That tab closed or changed. Choose a current tab.', unavailable: 'Focus acknowledgement is unavailable.'}[snap.focus] || 'Choose an existing tab to bring it forward.'), 'native-tabs-status');
      status.setAttribute('role', 'status'); root.append(status);
      if (!snap.tabs.length) root.append(node('p', 'No open tabs. Create tabs in the native browser.', 'native-tabs-empty'));
      const list = node('div', undefined, 'native-tab-list'); list.setAttribute('role', 'group'); list.setAttribute('aria-label', 'Native browser tabs');
      for (const tab of snap.tabs) {
        const button = node('button', undefined, 'native-tab' + (tab.active && snap.activeEvidence ? ' is-visible' : '')); button.type = 'button'; button.dataset.nativeTab = tab.id; button.disabled = state.sending;
        button.append(node('strong', tab.title || 'Untitled tab'), node('span', tab.origin || 'Non-web page'));
        if (tab.active && snap.activeEvidence) button.append(node('small', 'Visible page hint'));
        button.addEventListener('click', () => focus(tab.id)); list.append(button);
      }
      root.append(list, node('p', 'Page visibility is a hint, not verified browser selection or account identity. Tabs stay in their own profile.', 'field-hint'));
      if (previouslyFocused) { const match = [...list.children].find(el => el.dataset.nativeTab === previouslyFocused); if (match && !match.disabled) match.focus(); }
    }
    async function poll() {
      if (!state.active || state.sending) return;
      const epoch = state.epoch, sequence = ++state.sequence, profile = state.profile;
      cancel(timer); timer = null; controller?.abort(); const current = new AbortController(); controller = current;
      const timeout = later(() => current.abort(), 4500);
      try {
        const raw = await request('/tabs', {signal: current.signal});
        if (!state.active || epoch !== state.epoch || sequence !== state.sequence) return;
        state.snapshot = normalize(raw, profile); state.error = null; draw();
        const observed = state.snapshot;
        cancel(expiry); expiry = later(() => { if (state.active && epoch === state.epoch && state.snapshot === observed) { state.snapshot = null; state.error = 'Tab information expired. Waiting for a fresh browser response.'; draw(); } }, 5000);
      } catch {
        if (!state.active || epoch !== state.epoch || sequence !== state.sequence) return;
        state.snapshot = null; state.error = 'Native tabs could not be verified. Refresh to try again.'; cancel(expiry); draw();
      } finally { cancel(timeout); if (controller === current) controller = null; if (state.active && epoch === state.epoch && sequence === state.sequence) timer = later(poll, 3000); }
    }
    async function focus(id) {
      if (!state.active || state.sending || !state.snapshot?.tabs.some(tab => tab.id === id) || state.snapshot.status !== 'ready') return;
      const epoch = state.epoch, profile = state.profile, generation = state.snapshot.generation;
      state.sending = true; state.sequence++; clearTimers(); controller?.abort(); const current = new AbortController(); controller = current;
      const timeout = later(() => current.abort(), 8000); draw();
      try {
        const result = await request('/profiles/' + encodeURIComponent(profile.id) + '/tab-focus', {method: 'POST', body: {tab_id: id, generation, expected_revision: profile.revision}, signal: current.signal});
        if (!state.active || epoch !== state.epoch) return;
        if (result?.outcome !== 'queued' || result.profile_id !== profile.id || result.generation !== generation || result.tab_id !== id) throw new Error('Invalid focus acknowledgement');
        state.snapshot = null; state.error = 'Focus requested. Waiting for a fresh browser acknowledgement.';
      } catch { if (state.active && epoch === state.epoch) { state.snapshot = null; state.error = 'Focus result is uncertain or rejected. Refresh before choosing another tab.'; notify?.(state.error); } }
      finally { cancel(timeout); if (controller === current) controller = null; if (state.active && epoch === state.epoch) { state.sending = false; draw(); await poll(); } }
    }
    function activate(root, profile, layout = 'top') {
      deactivate(); if (!root || !profile || !Number.isSafeInteger(profile.revision)) return;
      Object.assign(state, {active: true, root, profile: {...profile}, layout: layout === 'side' ? 'side' : 'top', error: null}); draw(); void poll();
    }
    return {activate, deactivate, poll, focus, state};
  }
  window.TeamNativeTabs = {mount, normalize};
})();
