'use strict';
const { URL } = require('node:url');
const TOKEN_HEADER = 'X-TBM-Desktop-Token';

function localOrigin(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid sidecar port');
  return `http://127.0.0.1:${port}`;
}
function allowedRequest(raw, origin) {
  try {
    const url = new URL(raw);
    return url.origin === origin && !url.username && !url.password &&
      (url.pathname.startsWith('/app/') || url.pathname.startsWith('/local/v1/') ||
       url.pathname === '/local/config' || url.pathname === '/healthz');
  } catch { return false; }
}
function allowedNavigation(raw, origin) {
  try {
    const url = new URL(raw);
    return url.origin === origin && !url.username && !url.password &&
      url.pathname === '/app/' && url.search === '';
  } catch { return false; }
}
function authenticatedHeaders(raw, origin, original, token) {
  if (!allowedRequest(raw, origin)) return null;
  const result = Object.fromEntries(Object.entries(original)
    .filter(([key]) => key.toLowerCase() !== TOKEN_HEADER.toLowerCase()));
  result[TOKEN_HEADER] = token;
  return result;
}
function webPreferences(session) {
  return {
    session, sandbox: true, contextIsolation: true, nodeIntegration: false,
    nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
    webviewTag: false, webSecurity: true, allowRunningInsecureContent: false,
    navigateOnDragDrop: false, safeDialogs: true, devTools: false,
  };
}
function secureSession(session, origin, token) {
  session.setPermissionRequestHandler((_contents, _permission, answer) => answer(false));
  session.setPermissionCheckHandler(() => false);
  session.setDevicePermissionHandler(() => false);
  session.on('will-download', event => event.preventDefault());
  session.webRequest.onBeforeRequest((details, answer) => {
    answer({ cancel: !allowedRequest(details.url, origin) });
  });
  session.webRequest.onBeforeSendHeaders((details, answer) => {
    const headers = authenticatedHeaders(details.url, origin, details.requestHeaders, token);
    answer(headers ? { requestHeaders: headers } : { cancel: true });
  });
}
function secureContents(contents, origin) {
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-navigate', (event, url) => {
    if (!allowedNavigation(url, origin)) event.preventDefault();
  });
  contents.on('will-redirect', (event, url) => {
    if (!allowedNavigation(url, origin)) event.preventDefault();
  });
  contents.on('will-attach-webview', event => event.preventDefault());
}
module.exports = {
  TOKEN_HEADER, localOrigin, allowedRequest, allowedNavigation,
  authenticatedHeaders, webPreferences, secureSession, secureContents,
};
