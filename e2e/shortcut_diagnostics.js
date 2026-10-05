() => {
  // Synthetic local CI only. No input values, text, HTML, URLs, or app records.
  const events = [];
  let truncated = false;
  const element = node => node ? {
    id: String(node.id || '').slice(0, 64),
    tag: String(node.tagName || '').slice(0, 16),
    connected: Boolean(node.isConnected),
    editable: Boolean(node.isContentEditable),
  } : null;
  const record = (stage, event = null) => {
    if (events.length >= 96) { events.shift(); truncated = true; }
    events.push({
      at: Math.round(performance.now() * 1000) / 1000,
      stage,
      hash: ['', '#profiles', '#inbox', '#resources', '#connection'].includes(location.hash) ? location.hash : 'other',
      documentFocused: document.hasFocus(),
      quickSwitch: {
        hidden: Boolean(document.getElementById('quick-switch-button')?.hidden),
        disabled: Boolean(document.getElementById('quick-switch-button')?.disabled),
        inert: Boolean(document.getElementById('quick-switch-button')?.inert),
      },
      active: element(document.activeElement),
      target: element(event?.target),
      related: element(event?.relatedTarget),
      detailOpen: Boolean(document.getElementById('detail-dialog')?.open),
      switcherOpen: Boolean(document.getElementById('switcher-dialog')?.open),
      pendingIndicator: Boolean(document.querySelector('.workspace-alert.pending')),
      resourceFormPresent: Boolean(document.getElementById('resource-form')),
      key: event?.key?.slice(0, 16),
      code: event?.code?.slice(0, 16),
      alt: Boolean(event?.altKey),
      control: Boolean(event?.ctrlKey),
      meta: Boolean(event?.metaKey),
      shift: Boolean(event?.shiftKey),
      defaultPrevented: Boolean(event?.defaultPrevented),
      trusted: Boolean(event?.isTrusted),
      phase: event?.eventPhase,
    });
  };
  for (const type of ['keydown', 'keyup']) {
    for (const capture of [true, false]) {
      window.addEventListener(type, event => {
        if (event.key === 'Alt' || event.key === '3' || event.code === 'Digit3' || event.altKey) {
          record(type + (capture ? ':capture' : ':bubble'), event);
        }
      }, capture);
    }
  }
  for (const type of ['focusin', 'focusout', 'close', 'cancel', 'beforetoggle', 'toggle']) {
    window.addEventListener(type, event => record(type, event), true);
  }
  window.addEventListener('hashchange', event => record('hashchange', event));
  window.__tbmShortcutDiagnostics = {
    record,
    read: () => ({schemaVersion: 1, events, truncated}),
  };
  record('diagnostics-started');
}
