'use strict';
const { app, BrowserWindow, Menu, dialog, session, ipcMain } = require('electron');
const { join, resolve } = require('node:path');
const { randomBytes } = require('node:crypto');
const { Sidecar, sidecarCommand } = require('./sidecar.cjs');
const { secureSession, secureContents, webPreferences, allowedNavigation } = require('./security.cjs');
const { metadataClient } = require('./metadata.cjs');
const { BrowserEngine } = require('./browser-engine.cjs');
const { electronAdapter } = require('./electron-adapter.cjs');

app.enableSandbox();
app.setName('TeamBrowser');
let window, sidecar, engine, origin;
let quitting = false, quitApproved = false, fatalShown = false;
function fatal(message) {
  if (fatalShown) return;
  fatalShown = true;
  dialog.showErrorBox('TeamBrowser could not continue', message);
  app.quit();
}
function trusted(event) {
  if (!window || window.isDestroyed() || event.sender !== window.webContents ||
      event.senderFrame !== window.webContents.mainFrame || !allowedNavigation(event.senderFrame.url, origin)) {
    throw new Error('Only the bundled browser controls may call desktop actions');
  }
}
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  // Guests cannot invoke credential dialogs, external protocols, or TLS bypasses.
  app.on('login', (event, _contents, _details, _auth, callback) => { event.preventDefault(); callback(); });
  app.on('certificate-error', (event, _contents, _url, _error, _certificate, callback) => { event.preventDefault(); callback(false); });
  app.on('second-instance', () => {
    if (window && !window.isDestroyed()) {
      if (window.isMinimized()) window.restore();
      window.show(); window.focus();
    }
  });
  app.on('before-quit', event => {
    if (quitApproved) return;
    event.preventDefault();
    if (quitting) return;
    quitting = true;
    void (async () => {
      try {
        if (engine) await engine.shutdown();
        if (sidecar && !(await sidecar.stop())) throw new Error('The local workspace has not confirmed shutdown');
        quitApproved = true; app.quit();
      } catch {
        quitting = false;
        await dialog.showMessageBox(window && !window.isDestroyed() ? window : undefined, {
          type: 'warning', title: 'TeamBrowser is still open', buttons: ['Keep open'],
          message: 'A tab or workspace has not confirmed that it closed.',
          detail: 'Save your work or close the affected tabs, then try quitting again. Profile ownership has been retained.',
        });
      }
    })();
  });
  app.on('window-all-closed', () => app.quit());
  app.on('activate', () => { if (window && !window.isDestroyed()) { window.show(); window.focus(); } });
  void app.whenReady().then(async () => {
    if (!app.isPackaged && !process.argv.includes('--development')) throw new Error('Explicit development launch required');
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { label: 'TeamBrowser', submenu: [{ role: 'about' }, { type: 'separator' }, { role: 'quit' }] },
      { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
      { label: 'Window', submenu: [{ role: 'minimize' }, { role: 'zoom' }] },
    ]));
    const command = sidecarCommand({ packaged: app.isPackaged, resourcesPath: process.resourcesPath,
      developmentPython: process.env.TBM_DEV_PYTHON, sourceRoot: resolve(__dirname, '../..') });
    sidecar = new Sidecar({ command, workspace: join(app.getPath('home'), '.team-browser-client') });
    sidecar.on('exit', ({ expected }) => {
      if (!expected) {
        if (engine) engine.ownerGone();
        fatal('The local workspace stopped unexpectedly. Restart TeamBrowser to check recovery. No profile has been marked safely stopped.');
      }
    });
    origin = await sidecar.start();
    if (quitting || sidecar.exited) return;
    const metadata = metadataClient(origin, sidecar.token, sidecar.ownerToken);
    await metadata.initialize();
    const workspaceSession = session.fromPartition(`tbm-ui-${randomBytes(16).toString('hex')}`, { cache: false });
    secureSession(workspaceSession, origin, sidecar.token);
    window = new BrowserWindow({
      width: 1440, height: 960, minWidth: 1000, minHeight: 700,
      title: 'TeamBrowser', show: false, backgroundColor: '#f6f7f9', autoHideMenuBar: true,
      webPreferences: { ...webPreferences(workspaceSession), preload: join(__dirname, 'preload.cjs') },
    });
    secureContents(window.webContents, origin);
    engine = new BrowserEngine({ adapter: electronAdapter(window), metadata, emit: snapshot => {
      if (window && !window.isDestroyed() && !window.webContents.isDestroyed()) window.webContents.send('tbm:changed', snapshot);
    } });
    ipcMain.handle('tbm:command', (event, command) => { trusted(event); return engine.command(command); });
    ipcMain.handle('tbm:snapshot', event => { trusted(event); return engine.snapshot(); });
    window.on('resize', () => engine.applyBounds());
    window.on('close', event => { if (!quitApproved) { event.preventDefault(); app.quit(); } });
    window.webContents.on('render-process-gone', () => fatal('The browser controls stopped unexpectedly. TeamBrowser will close its tabs carefully before restarting.'));
    window.once('ready-to-show', () => { if (window && !window.isDestroyed()) window.show(); });
    await window.loadURL(`${origin}/app/`);
  }).catch(() => fatal('The packaged workspace could not start. No browser or dependency was installed. Check the release package and its platform requirements.'));
}
