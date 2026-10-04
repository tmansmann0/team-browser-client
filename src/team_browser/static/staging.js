'use strict';
(() => {
  document.addEventListener('submit', event => {
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
  document.addEventListener('DOMContentLoaded', () => {
    const detail = document.getElementById('detail-dialog');
    const switcher = document.getElementById('switcher-dialog');
    const search = document.getElementById('switcher-search');
    const results = document.getElementById('switcher-results');
    const button = document.getElementById('quick-switch-button');
    const announce = document.getElementById('switcher-announcement');
    const entries = __STAGING_FIXTURES__;
    let matches = [], selected = 0, opener = button, pendingSelection = null;
    const readOnly = () => {
      const form = document.getElementById('assignment-form');
      if (!form || form.dataset.readOnly === 'true') return;
      form.dataset.readOnly = 'true';
      form.querySelectorAll('select, input, button[type="submit"]').forEach(el => {
        el.disabled = true;
      });
      const submit = form.querySelector('button[type="submit"]');
      if (submit) submit.textContent = 'Read-only preview';
      const note = document.getElementById('drawer-description');
      if (note) note.textContent = 'Fixed synthetic record. Assignments cannot be changed in this hosted preview. No browser is running.';
      const feedback = document.getElementById('assignment-feedback');
      if (feedback) feedback.textContent = 'Read-only: assignment changes are disabled.';
    };
    new MutationObserver(readOnly).observe(document.getElementById('drawer-content'), {childList:true, subtree:true});
    new MutationObserver(() => {
      const input = document.getElementById('profile-search');
      if (input) { input.maxLength = 120; input.autocomplete = 'off'; }
    }).observe(document.getElementById('view-container'), {childList:true, subtree:true});
    function inspectProfile(id) {
      const profileSearch = document.getElementById('profile-search');
      if (profileSearch) { profileSearch.value = ''; profileSearch.dispatchEvent(new Event('input')); }
      const filter = document.getElementById('status-filter');
      if (filter) { filter.value = 'all'; filter.dispatchEvent(new Event('change')); }
      document.querySelector(`.profile-name[data-profile="${id}"]`)?.click();
      readOnly();
    }
    function selectEntry(id) {
      switcher.close();
      if (location.hash !== '#profiles') {
        pendingSelection = id;
        location.hash = 'profiles';
      } else {
        setTimeout(() => inspectProfile(id), 0);
      }
    }
    function render() {
      const term = search.value.toLowerCase().slice(0, 120);
      matches = entries.filter(entry => `${entry.name} ${entry.id}`.toLowerCase().includes(term));
      selected = Math.min(selected, Math.max(matches.length - 1, 0));
      results.replaceChildren();
      matches.forEach((entry, index) => {
        const item = document.createElement('button');
        item.className = 'switcher-item'; item.type = 'button';
        item.id = `staging-option-${index}`;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', String(index === selected));
        item.textContent = `${entry.name} · ${entry.id}`;
        item.addEventListener('click', () => selectEntry(entry.id));
        results.append(item);
      });
      search.setAttribute('aria-expanded', String(switcher.open));
      if (matches.length) search.setAttribute('aria-activedescendant', `staging-option-${selected}`);
      else search.removeAttribute('aria-activedescendant');
      announce.textContent = `${matches.length} synthetic profiles. Selection only; launch is disabled.`;
    }
    function openSwitcher() {
      if (detail.open) detail.close();
      opener = document.activeElement;
      selected = 0; search.value = '';
      switcher.showModal(); render(); search.focus();
    }
    button.hidden = false;
    button.addEventListener('click', openSwitcher);
    document.getElementById('close-switcher').addEventListener('click', () => switcher.close());
    switcher.addEventListener('close', () => {
      search.value = ''; search.setAttribute('aria-expanded', 'false');
      search.removeAttribute('aria-activedescendant'); opener?.focus();
    });
    window.addEventListener('hashchange', () => {
      if (switcher.open) switcher.close();
      if (pendingSelection && location.hash === '#profiles') {
        const id = pendingSelection; pendingSelection = null;
        setTimeout(() => inspectProfile(id), 0);
      } else pendingSelection = null;
    });
    search.maxLength = 120; search.autocomplete = 'off';
    search.addEventListener('input', () => { selected = 0; render(); });
    search.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        if (matches.length) selected = (selected + (event.key === 'ArrowDown' ? 1 : matches.length - 1)) % matches.length;
        render();
      } else if (event.key === 'Enter' && matches.length) {
        event.preventDefault(); selectEntry(matches[selected].id);
      }
    });
    document.addEventListener('keydown', event => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault(); if (!switcher.open) openSwitcher();
      }
    });
    document.getElementById('switcher-title').textContent = 'Select a synthetic profile';
    document.getElementById('switcher-help').textContent = '↑ ↓ to choose · Enter to inspect · Esc to close · No browser will launch';
    const profileSearch = document.getElementById('profile-search');
    if (profileSearch) profileSearch.maxLength = 120;
  });
})();
