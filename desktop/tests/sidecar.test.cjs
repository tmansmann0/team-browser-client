'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { Sidecar, childEnvironment, sidecarCommand, parseReady } = require('../src/sidecar.cjs');
function fixture() {
  const child = new EventEmitter(); child.pid = 4321;
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  let invocation;
  const controller = new Sidecar({ command: { executable: '/bundle/sidecar', args: [] }, workspace: '/private/workspace',
    environment: { HOME: '/home/fixture', PYTHONPATH: '/evil', NODE_OPTIONS: '--inspect', HTTPS_PROXY: 'secret' },
    spawnProcess: (...args) => { invocation = args; return child; }, startupMs: 50 });
  const ready = () => child.stdout.write(JSON.stringify({ kind: 'tbm-desktop-ready', protocol: 1, pid: 4321, port: 48216 }) + '\n');
  return { controller, child, ready, invocation: () => invocation };
}
test('fixed bundled command never searches runtime Python or launches a shell', () => {
  assert.deepEqual(sidecarCommand({ packaged: true, resourcesPath: '/App/Resources', developmentPython: '/evil' }), { executable: '/App/Resources/tbm-sidecar/tbm-desktop-sidecar', args: [] });
  assert.throws(() => sidecarCommand({ packaged: false, developmentPython: 'python', sourceRoot: '/source' }));
  assert.deepEqual(childEnvironment({ HOME: '/home', PYTHONPATH: '/evil', NODE_OPTIONS: 'evil', LD_PRELOAD: '/evil', HTTPS_PROXY: 'credential' }), { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'en_US.UTF-8', TZ: 'UTC', HOME: '/home' });
});
test('handshake binds the actual owned child PID and exact loopback port', () => {
  assert.equal(parseReady('{"kind":"tbm-desktop-ready","protocol":1,"pid":4321,"port":48216}', 4321), 'http://127.0.0.1:48216');
  for (const bad of [{ kind: 'tbm-desktop-ready', protocol: 1, pid: 999, port: 48216 }, { kind: 'tbm-desktop-ready', protocol: 1, pid: 4321, port: 0 }, { kind: 'tbm-desktop-ready', protocol: 1, pid: 4321, port: 48216, url: 'https://evil.test' }]) assert.throws(() => parseReady(JSON.stringify(bad), 4321));
});
test('secret goes only through owned stdin, not arguments or environment', async () => {
  const f = fixture(); const starting = f.controller.start(); f.ready();
  assert.equal(await starting, 'http://127.0.0.1:48216');
  const [binary, args, options] = f.invocation();
  assert.equal(binary, '/bundle/sidecar'); assert.equal(options.shell, false);
  assert.equal(JSON.stringify([args, options]).includes(f.controller.token), false);
  assert.equal(JSON.parse(f.child.stdin.read().toString()).token, f.controller.token);
  assert.throws(() => f.controller.start());
  const stop = f.controller.stop(); f.child.emit('exit', 0, null); assert.equal(await stop, true);
});
test('shutdown timeout does not kill any process or pretend it stopped', async () => {
  const f = fixture(); const starting = f.controller.start(); f.ready(); await starting;
  f.child.kill = () => { throw new Error('Must not force-kill'); };
  assert.equal(await f.controller.stop(2), false); assert.equal(f.controller.exited, false);
  f.child.emit('exit', 0, null); assert.equal(await f.controller.stop(), true);
});
test('bad startup and early exit fail closed without a fallback URL', async () => {
  for (const mode of ['malformed', 'exit', 'timeout', 'oversized']) {
    const f = fixture(); const starting = f.controller.start();
    if (mode === 'malformed') f.child.stdout.write('https://evil.test\n');
    if (mode === 'oversized') f.child.stdout.write('x'.repeat(513));
    if (mode === 'exit') f.child.emit('exit', 1, null);
    await assert.rejects(starting); assert.equal(f.controller.stopping, true);
    f.child.emit('exit', 1, null);
  }
});
