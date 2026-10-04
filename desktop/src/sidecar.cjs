'use strict';
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { isAbsolute, join } = require('node:path');
const { localOrigin } = require('./security.cjs');

// No PATH-based interpreter search and no inherited Python, loader, proxy, or Node overrides.
function childEnvironment(parent) {
  const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'en_US.UTF-8', TZ: 'UTC' };
  for (const key of ['HOME', 'TMPDIR', 'USER', 'LOGNAME', 'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR']) {
    if (typeof parent[key] === 'string') env[key] = parent[key];
  }
  return env;
}
function sidecarCommand({ packaged, resourcesPath, developmentPython, sourceRoot }) {
  if (packaged) return { executable: join(resourcesPath, 'tbm-sidecar', 'tbm-desktop-sidecar'), args: [] };
  if (!developmentPython || !isAbsolute(developmentPython) || !isAbsolute(sourceRoot)) {
    throw new Error('Development needs an explicit absolute interpreter and source root');
  }
  return { executable: developmentPython, args: ['-m', 'team_browser.desktop_sidecar'], cwd: sourceRoot };
}
function parseReady(line, pid) {
  const value = JSON.parse(line);
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'kind,pid,port,protocol' ||
      value.kind !== 'tbm-desktop-ready' || value.protocol !== 1 || value.pid !== pid) {
    throw new Error('Invalid sidecar handshake');
  }
  return localOrigin(value.port);
}
class Sidecar extends EventEmitter {
  constructor({ command, workspace, spawnProcess = spawn, environment = process.env,
    startupMs = 20000 }) {
    super();
    this.command = command;
    this.workspace = workspace;
    this.spawnProcess = spawnProcess;
    this.environment = environment;
    this.startupMs = startupMs;
    this.token = randomBytes(32).toString('hex');
    this.ownerToken = randomBytes(32).toString('hex');
    this.child = null;
    this.stopping = false;
    this.exited = false;
  }
  start() {
    if (this.child) throw new Error('Sidecar already started');
    if (!isAbsolute(this.workspace)) throw new Error('Invalid workspace');
    const args = [...this.command.args, '--workspace', this.workspace];
    this.child = this.spawnProcess(this.command.executable, args, {
      shell: false, detached: false, windowsHide: true,
      cwd: this.command.cwd || '/', env: childEnvironment(this.environment),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const child = this.child;
    child.stdin.on('error', () => {}); // A dead child is handled through exit/error, never an unhandled pipe error.
    child.stderr.on('data', () => {}); // No raw Python/profile diagnostics in user logs.
    this.exitPromise = new Promise(resolve => {
      child.once('exit', (code, signal) => {
        this.exited = true;
        resolve({ code, signal });
        this.emit('exit', { expected: this.stopping, code, signal });
      });
      child.once('error', () => {
        this.exited = true;
        resolve({ code: null, signal: null });
      });
    });
    return new Promise((resolve, reject) => {
      let received = '';
      let settled = false;
      const finish = (error, origin) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdout.removeListener('data', onData);
        // Continue draining the private pipe, but never print unexpected output.
        child.stdout.resume();
        if (error) { this.requestStop(); reject(error); } else resolve(origin);
      };
      const onData = chunk => {
        received += chunk.toString('utf8');
        if (Buffer.byteLength(received) > 512) return finish(new Error('Invalid sidecar handshake'));
        if (!received.includes('\n')) return;
        try {
          const lines = received.split('\n');
          if (lines.length !== 2 || lines[1] !== '') throw new Error('Invalid sidecar handshake');
          finish(null, parseReady(lines[0], child.pid));
        } catch { finish(new Error('Invalid sidecar handshake')); }
      };
      const timer = setTimeout(() => finish(new Error('Workspace startup timed out')), this.startupMs);
      child.stdout.on('data', onData);
      child.once('error', () => finish(new Error('Workspace process could not start')));
      child.once('exit', () => finish(new Error('Workspace stopped before it was ready')));
      child.stdin.write(JSON.stringify({ protocol: 1, token: this.token, owner_token: this.ownerToken }) + '\n');
    });
  }
  requestStop() {
    this.stopping = true;
    if (this.child && !this.exited && !this.child.stdin.writableEnded) this.child.stdin.end('stop\n');
  }
  async stop(timeoutMs = 20000) {
    this.requestStop();
    if (!this.child || this.exited) return true;
    let timer;
    const completed = await Promise.race([
      this.exitPromise.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); }),
    ]);
    clearTimeout(timer);
    return completed;
  }
}
module.exports = { Sidecar, childEnvironment, sidecarCommand, parseReady };
