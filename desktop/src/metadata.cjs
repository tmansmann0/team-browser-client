'use strict';
const http = require('node:http');
const { TOKEN_HEADER } = require('./security.cjs');
function metadataClient(origin, token, ownerToken) {
  let csrf;
  function request(path, { method = 'GET', body, owner = false } = {}) {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request(origin + path, {
        method, headers: {
          [TOKEN_HEADER]: owner ? ownerToken : token,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-Local-CSRF': csrf } : {}),
        }, timeout: 5000,
      }, response => {
        let raw = '';
        response.on('data', chunk => {
          raw += chunk.toString('utf8');
          if (Buffer.byteLength(raw) > 1024 * 1024) req.destroy(new Error('Workspace response too large'));
        });
        response.on('end', () => {
          if (response.statusCode < 200 || response.statusCode >= 300) { reject(new Error('Workspace ownership or profile revision changed. Refresh the profile.')); return; }
          try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid local workspace response')); }
        });
      });
      req.on('error', () => reject(new Error('Local workspace request could not be confirmed')));
      req.on('timeout', () => req.destroy(new Error('Local workspace request timed out')));
      req.end(payload);
    });
  }
  const id = value => { if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)) throw new Error('Invalid profile'); return value; };
  return {
    async initialize() { csrf = (await request('/local/config')).csrf_token; if (typeof csrf !== 'string') throw new Error('Invalid workspace token'); },
    get(profileId) { return request(`/local/v1/profiles/${id(profileId)}`); },
    claim(profileId, revision) { return request(`/desktop/v1/profiles/${id(profileId)}/claim`, { method: 'POST', owner: true, body: { expected_revision: revision } }); },
    release(profileId) { return request(`/desktop/v1/profiles/${id(profileId)}/release`, { method: 'POST', owner: true, body: {} }); },
  };
}
module.exports = { metadataClient };
