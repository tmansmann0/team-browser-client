'use strict';
// The native host owns runtime configuration, identity artifacts, diagnostics and
// admission. This view sends fixed intents only; it never manufactures evidence.
(() => {
  const profileId = /^[A-Za-z0-9_-]{1,64}$/;
  const states = new Set(['unavailable', 'needs_approval', 'not_prepared', 'preparing', 'prepared', 'validating', 'ready', 'recovery_required']);
  const actions = new Set(['prepare', 'validate', 'cancel']);
  const networks = new Set(['unconfigured', 'local_direct', 'verified_proxy']);
  const activeStates = new Set(['preparing', 'validating']);
  const strings = value => Array.isArray(value) && value.length <= 32 && value.every(item => typeof item === 'string' && item.length <= 2000);
  function runtimeSnapshot(value) {
    if (!value || typeof value.configured !== 'boolean' || typeof value.usable !== 'boolean' || typeof value.state !== 'string' || !strings(value.blockers) || typeof value.next_step !== 'string') throw new Error('Invalid setup status.');
    return {configured: value.configured, usable: value.usable, state: value.state, blockers: [...value.blockers], next_step: value.next_step};
  }
  function profileSnapshot(value, profile) {
    if (!value || value.profile_id !== profile.id || value.profile_revision !== profile.revision || !Number.isSafeInteger(value.revision) || value.revision < 1 || !states.has(value.state) || !networks.has(value.network_scope) || value.network_scope !== (profile.network_policy || 'unconfigured') || !strings(value.blockers) || typeof value.next_step !== 'string' || !Array.isArray(value.available_actions) || value.available_actions.some(action => !actions.has(action)) || typeof value.admission_acknowledged !== 'boolean' || typeof value.launch_available !== 'boolean') throw new Error('Setup or profile revision changed.');
    const expiry = typeof value.admission_expires_at === 'string' ? Date.parse(value.admission_expires_at) : NaN;
    return {profile_id: profile.id, profile_revision: profile.revision, revision: value.revision, state: value.state, network_scope: value.network_scope, blockers: [...value.blockers], next_step: value.next_step, available_actions: [...new Set(value.available_actions)], admission_acknowledged: value.admission_acknowledged, launch_available: value.launch_available, expires: expiry};
  }
  function normalizeProfile(value, id) {
    if (!value || value.id !== id || !profileId.test(id) || !Number.isSafeInteger(value.revision) || value.revision < 1 || typeof value.name !== 'string' || !networks.has(value.network_policy || 'unconfigured') || typeof value.engine_id !== 'string') throw new Error('Profile changed or is unavailable.');
    return {...value};
  }
  function mount({request, notify, onProfile = () => true, onLaunch, onEdit, onCreate, isCurrent = () => true, document: doc = document, schedule = setTimeout, cancel = clearTimeout, now = Date.now}) {
    const state = {epoch: 0, sequence: 0, active: false, root: null, profile: null, runtime: null, snapshot: null, error: null, reading: false, sending: false, blocked: false, checkedAt: 0};
    let timer = null, expiry = null, readController = null, writeController = null;
    const later = (fn, ms) => { const handle = schedule(fn, ms); handle?.unref?.(); return handle; };
    const same = (a, b) => a?.id === b?.id && a?.revision === b?.revision && a?.network_policy === b?.network_policy && a?.engine_id === b?.engine_id;
    function clearTimers() { cancel(timer); cancel(expiry); timer = expiry = null; }
    function retire() { state.epoch++; state.sequence++; clearTimers(); readController?.abort(); writeController?.abort(); readController = writeController = null; state.snapshot = null; state.runtime = null; state.reading = state.sending = false; state.checkedAt = 0; }
    function deactivate() { retire(); state.active = false; state.root = null; state.profile = null; state.error = null; }
    function node(tag, text, cls) { const el = doc.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; }
    function button(text, key, handler, disabled = false, primary = false) { const el = node('button', text, 'button compact-button' + (primary ? ' button-primary' : '')); el.type = 'button'; el.dataset.setupControl = key; el.disabled = disabled; el.addEventListener('click', handler); return el; }
    function fresh() { return state.active && !state.blocked && !state.reading && !state.sending && now() - state.checkedAt < 6000 && state.checkedAt > 0; }
    function canLaunch(profile) {
      const snap = state.snapshot;
      return Boolean(profile && state.profile && fresh() && same(profile, state.profile) && isCurrent(state.profile) && state.runtime?.configured && state.runtime.usable && profile?.engine_id === 'camoufox' && snap?.state === 'ready' && snap.profile_revision === profile.revision && snap.admission_acknowledged && snap.launch_available && snap.expires > now() && !snap.blockers.length && ['local_direct', 'verified_proxy'].includes(snap.network_scope) && !(profile.origin === 'managed' && snap.network_scope !== 'verified_proxy'));
    }
    function allows(action) {
      const snap = state.snapshot;
      return Boolean(actions.has(action) && fresh() && state.profile?.engine_id === 'camoufox' && isCurrent(state.profile) && snap?.available_actions.includes(action) && (action === 'cancel' || state.runtime?.configured && (action === 'prepare' || state.runtime.usable)) && (action !== 'validate' || ['local_direct', 'verified_proxy'].includes(snap.network_scope) && !(state.profile.origin === 'managed' && snap.network_scope !== 'verified_proxy')));
    }
    function draw() {
      const root = state.root;
      if (!state.active || !root) return;
      const focused = doc.activeElement?.dataset?.setupControl;
      root.replaceChildren(); root.className = 'camoufox-setup panel';
      root.setAttribute('aria-label', 'Camoufox browser setup'); root.setAttribute('aria-busy', String(state.reading || state.sending));
      const heading = node('div', undefined, 'setup-heading');
      const intro = node('div'); intro.append(node('p', 'BROWSER SETUP', 'eyebrow'), node('h2', 'Make this profile launch-ready'));
      heading.append(intro, button('Refresh setup', 'refresh', () => poll(), state.blocked || state.sending || state.reading)); root.append(heading);
      const profile = state.profile, runtime = state.runtime, snap = state.snapshot;
      root.append(node('p', profile ? 'Camoufox setup for ' + profile.name + '. Identity stays with this profile.' : 'Create or select a profile to prepare its own stable browser identity.', 'field-hint'));
      const status = node('p', state.error || (state.blocked ? 'Workspace is changing or offline. Reload the local service before continuing.' : state.sending ? 'Sending your setup request. Waiting for the native host.' : state.reading ? 'Checking the native host and current profile…' : ({unavailable: 'Setup unavailable', needs_approval: 'Native owner approval required', not_prepared: 'Identity has not been prepared', preparing: 'Preparing this profile’s stable identity…', prepared: 'Identity prepared. Native validation is still required.', validating: 'Native diagnostics are running. Browser launch remains blocked.', ready: canLaunch(profile) ? 'Native admission acknowledged. This profile can request launch.' : 'Admission is not current. Refresh setup before launching.', recovery_required: 'Recovery needed. Native cleanup is not acknowledged.'}[snap?.state] || (runtime?.configured ? 'Trusted runtime configuration is present.' : 'Trusted runtime configuration is missing.'))), 'setup-status');
      status.setAttribute('role', state.error ? 'alert' : 'status'); status.setAttribute('aria-live', state.error ? 'assertive' : 'polite'); status.setAttribute('aria-atomic', 'true'); root.append(status);
      const steps = node('ol', undefined, 'setup-steps');
      function step(label, description, complete) { const item = node('li'); const content = node('div'); const badge = node('span', complete ? 'Verified' : 'Required', 'setup-step-label' + (complete ? ' complete' : '')); content.append(node('h3', label), node('p', description), badge); item.append(content); steps.append(item); }
      step('Trusted runtime', runtime?.configured ? runtime.usable ? 'The native host has trusted runtime configuration. Each profile still needs validation.' : 'Configuration is present but is not usable. Follow the owner action below.' : 'The device owner must configure an independently accepted, pinned Camoufox runtime in the native host, then restart the local service.', runtime?.configured && runtime.usable && !state.error);
      step('Stable profile identity', !profile ? 'Create a profile and choose the Camoufox browser preset.' : profile.engine_id !== 'camoufox' ? 'Edit this profile and choose the Camoufox browser preset.' : 'Prepare once for this profile. Preparation does not launch a browser or grant admission.', Boolean(snap && ['prepared', 'validating', 'ready'].includes(snap.state) && !state.error));
      step('Explicit network & diagnostics', profile?.network_policy === 'local_direct' ? 'You selected this device’s ordinary direct connection. Validation uses that connection; it provides no proxy or anonymity guarantee.' : profile?.network_policy === 'verified_proxy' ? 'A native, verified per-profile proxy is required. Validation never falls back to a direct connection.' : 'Choose a network policy in Edit profile. Managed profiles require a verified proxy; local-direct must be explicitly selected.', canLaunch(profile));
      root.append(steps);
      const blockers = [...new Set([...(runtime?.blockers || []), ...(snap?.blockers || [])])];
      if (blockers.length) { const list = node('ul', undefined, 'blocker-list'); for (const text of blockers) list.append(node('li', text)); root.append(list); }
      const next = snap?.next_step || runtime?.next_step;
      if (next) root.append(node('p', 'Next step: ' + next, 'setup-next-step'));
      if (snap?.state === 'recovery_required') root.append(node('p', 'Ask the device owner to verify native process ownership and cleanup before retrying. Refresh only checks status; it does not force cleanup or remove this profile’s identity.', 'setup-warning'));
      if (snap && activeStates.has(snap.state)) root.append(node('p', 'You can request cancellation below. Cancellation is complete only when the native host reports it; an uncertain cleanup keeps launch blocked.', 'field-hint'));
      const controls = node('div', undefined, 'setup-actions');
      if (!profile) controls.append(button('Create profile', 'create', () => onCreate?.(), state.blocked));
      else {
        controls.append(button('Edit profile', 'edit', () => onEdit?.(profile.id), state.blocked || state.sending));
        if (profile.engine_id === 'camoufox') {
          controls.append(button('Prepare stable identity', 'prepare', () => action('prepare'), !allows('prepare')));
          controls.append(button('Run native diagnostics', 'validate', () => action('validate'), !allows('validate')));
          if (snap?.available_actions.includes('cancel') || activeStates.has(snap?.state)) controls.append(button('Request cancellation', 'cancel', () => action('cancel'), !allows('cancel')));
          controls.append(button('Launch browser', 'launch', () => { if (canLaunch(state.profile)) onLaunch?.(state.profile.id); }, !canLaunch(profile), true));
        }
      }
      root.append(controls, node('p', 'Diagnostics may open a native browser for fixed checks. This page cannot install a runtime, grant approval or submit diagnostic results. A successful request alone never makes the browser ready.', 'field-hint'));
      if (focused) { const control = controls.children && [...controls.children].find(el => el.dataset.setupControl === focused) || [...heading.children].find(el => el.dataset?.setupControl === focused); if (control && !control.disabled) control.focus(); else if (focused === 'cancel' || focused === 'validate' || focused === 'prepare') { status.tabIndex = -1; status.focus(); } }
    }
    async function bounded(path, options, controller, ms = 8000) {
      let timeout;
      try { return await Promise.race([request(path, {...options, signal: controller.signal}), new Promise((_, reject) => { timeout = later(() => { controller.abort(); reject(new Error('Setup request timed out.')); }, ms); })]); }
      finally { cancel(timeout); }
    }
    async function poll() {
      if (!state.active || state.blocked || state.sending) return;
      cancel(timer); timer = null; cancel(expiry); expiry = null; readController?.abort();
      const epoch = state.epoch, sequence = ++state.sequence, previous = state.profile;
      const controller = new AbortController(); readController = controller; state.reading = true; state.error = null; draw();
      const current = () => state.active && epoch === state.epoch && sequence === state.sequence && !controller.signal.aborted && (!previous || isCurrent(previous));
      try {
        const runtime = runtimeSnapshot(await bounded('/camoufox-setup', {}, controller));
        let profile = previous, snap = null;
        if (profile) {
          profile = normalizeProfile(await bounded('/profiles/' + encodeURIComponent(profile.id), {}, controller), profile.id);
          if (profile.revision < previous.revision) throw new Error('Profile revision moved backwards.');
          if (profile.engine_id === 'camoufox') {
            let raw = await bounded('/profiles/' + encodeURIComponent(profile.id) + '/camoufox-setup', {}, controller);
            // Native validation can advance lifecycle between these two reads.
            // Re-read once for a coherent pair; never patch a revision in JS.
            if (raw?.profile_id === profile.id && Number.isSafeInteger(raw.profile_revision) && raw.profile_revision > profile.revision) {
              profile = normalizeProfile(await bounded('/profiles/' + encodeURIComponent(profile.id), {}, controller), profile.id);
              raw = await bounded('/profiles/' + encodeURIComponent(profile.id) + '/camoufox-setup', {}, controller);
            }
            snap = profileSnapshot(raw, profile);
          }
        }
        if (!current()) return;
        if (profile && onProfile(profile, previous) === false) throw new Error('The profile changed while setup was loading.');
        state.profile = profile; state.runtime = runtime; state.snapshot = snap; state.checkedAt = now(); state.error = null;
        const observed = snap;
        expiry = later(() => { if (state.active && epoch === state.epoch && state.snapshot === observed) { state.snapshot = null; state.error = 'Setup information expired. Refresh to verify current admission before launching.'; draw(); } }, Math.max(1, Math.min(6000, snap?.expires > now() ? snap.expires - now() : 6000)));
      } catch {
        if (state.active && epoch === state.epoch && sequence === state.sequence) { state.snapshot = null; state.runtime = null; state.checkedAt = 0; state.error = 'Setup could not be verified or the request timed out. Refresh setup, or reload the local service. Any native operation may still be running; launch stays blocked.'; }
      } finally {
        if (readController === controller) readController = null;
        if (state.active && epoch === state.epoch && sequence === state.sequence) { state.reading = false; draw(); if (!state.error) timer = later(poll, 3000); }
      }
    }
    async function action(name) {
      if (!allows(name)) return false;
      const epoch = state.epoch, profile = {...state.profile}, snap = state.snapshot;
      state.sequence++; clearTimers(); readController?.abort(); state.sending = true; state.error = null; state.snapshot = null;
      const controller = new AbortController(); writeController = controller; draw();
      try {
        // Deliberately ignore the response as evidence. Only a subsequent GET of
        // the current profile and setup state can authorize a launch control.
        await bounded('/profiles/' + encodeURIComponent(profile.id) + '/camoufox-setup/actions', {method: 'POST', body: {action: name, expected_revision: profile.revision, expected_setup_revision: snap.revision}}, controller);
        if (!state.active || epoch !== state.epoch || !isCurrent(profile)) return false;
        notify?.(name === 'cancel' ? 'Cancellation requested. Checking native cleanup status.' : name === 'prepare' ? 'Preparation requested. Checking this profile’s identity status.' : 'Native diagnostics requested. Waiting for verified admission.');
      } catch {
        if (state.active && epoch === state.epoch) { state.error = 'The setup request was rejected or its result is uncertain. Refresh setup before another action. Native work may still be running; no cleanup or admission is assumed.'; notify?.(state.error); }
        return false;
      } finally {
        if (writeController === controller) writeController = null;
        if (state.active && epoch === state.epoch) { state.sending = false; draw(); }
      }
      await poll(); return true;
    }
    function activate(root, profile = null, {blocked = false} = {}) {
      if (!root || profile && (!profileId.test(profile.id) || !Number.isSafeInteger(profile.revision))) { deactivate(); return; }
      const changed = !state.active || !same(profile, state.profile) || blocked !== state.blocked;
      if (changed) retire();
      Object.assign(state, {active: true, root, profile: profile ? {...profile} : null, blocked});
      if (changed) state.error = null;
      draw(); if (changed && !blocked) void poll();
    }
    return {activate, deactivate, poll, action, canLaunch, state};
  }
  window.TeamCamoufoxSetup = {mount, runtimeSnapshot, profileSnapshot};
})();
