'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { allowedRequest, allowedNavigation, authenticatedHeaders, webPreferences, secureContents, secureSession, localOrigin } = require('../src/security.cjs');
const { EventEmitter } = require('node:events');
const origin = localOrigin(48216);

test('only exact loopback workspace/API requests are eligible', () => {
  for (const path of ['/app/', '/app/workspace.js', '/app/brand/logo.svg', '/local/config', '/local/v1/profiles', '/healthz']) assert.equal(allowedRequest(origin + path, origin), true);
  for (const url of ['https://example.com', 'file:///etc/passwd', 'http://localhost:48216/app/', 'http://127.0.0.1:48217/app/', 'http://127.0.0.1.evil.test:48216/app/', 'http://x@127.0.0.1:48216/app/', origin + '/demo/config', origin + '/app/../../secret', origin + '/preview/', 'javascript:alert(1)', 'not a URL']) assert.equal(allowedRequest(url, origin), false, url);
});
test('navigation only allows root workspace document and its local hash', () => {
  assert.equal(allowedNavigation(origin + '/app/#profiles', origin), true);
  for (const path of ['/app/?target=https://evil.test', '/app/workspace.js', '/local/config']) assert.equal(allowedNavigation(origin + path, origin), false);
});
test('header injection is restricted and replaces all case variants', () => {
  assert.equal(authenticatedHeaders('https://evil.test/', origin, {}, 'secret'), null);
  assert.deepEqual(authenticatedHeaders(origin + '/local/config', origin, {
    'x-tbm-desktop-token': 'renderer-value', 'X-TBM-DESKTOP-TOKEN': 'other', Accept: 'application/json',
  }, 'secret'), { Accept: 'application/json', 'X-TBM-Desktop-Token': 'secret' });
});
test('renderer has no native bridge, Node integration, downloads, or permission grants', () => {
  const prefs = webPreferences('session-fixture');
  assert.equal(prefs.sandbox, true); assert.equal(prefs.contextIsolation, true);
  assert.equal(prefs.nodeIntegration, false); assert.equal(prefs.webviewTag, false);
  assert.equal(prefs.webSecurity, true); assert.equal(prefs.preload, undefined);
  const session = new EventEmitter();
  for (const method of ['setPermissionRequestHandler', 'setPermissionCheckHandler', 'setDevicePermissionHandler']) session[method] = fn => { session[method + 'Callback'] = fn; };
  session.webRequest = { onBeforeRequest: fn => { session.beforeRequest = fn; }, onBeforeSendHeaders: fn => { session.beforeHeaders = fn; } };
  secureSession(session, origin, 'secret');
  session.setPermissionRequestHandlerCallback(null, 'camera', answer => assert.equal(answer, false));
  assert.equal(session.setPermissionCheckHandlerCallback(), false);
  assert.equal(session.setDevicePermissionHandlerCallback(), false);
  let prevented = false; session.emit('will-download', { preventDefault() { prevented = true; } }); assert.equal(prevented, true);
  session.beforeRequest({ url: 'https://evil.test/' }, answer => assert.equal(answer.cancel, true));
});
test('new windows, webviews, redirects and external navigation are denied', () => {
  const contents = new EventEmitter(); contents.setWindowOpenHandler = fn => { contents.open = fn; };
  secureContents(contents, origin);
  assert.deepEqual(contents.open({ url: 'https://evil.test' }), { action: 'deny' });
  for (const name of ['will-navigate', 'will-redirect', 'will-attach-webview']) {
    let prevented = false; contents.emit(name, { preventDefault() { prevented = true; } }, 'https://evil.test'); assert.equal(prevented, true);
  }
});
