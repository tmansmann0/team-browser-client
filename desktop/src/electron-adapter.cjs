'use strict';
const { WebContentsView, session, dialog } = require('electron');
function electronAdapter(window) {
  return {
    versions: { electron: process.versions.electron, chromium: process.versions.chrome },
    session: partition => session.fromPartition(partition),
    secureSession(ses, permitted) {
      ses.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
      ses.setPermissionCheckHandler(() => false);
      ses.setDevicePermissionHandler(() => false);
      ses.on('will-download', event => event.preventDefault());
      ses.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !permitted(details.url) }));
    },
    createView(ses) {
      const view = new WebContentsView({ webPreferences: {
        session: ses, sandbox: true, contextIsolation: true, nodeIntegration: false,
        nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
        webviewTag: false, webSecurity: true, allowRunningInsecureContent: false,
        navigateOnDragDrop: false, safeDialogs: true, devTools: false,
      } });
      view.webContents.on('will-prevent-unload', event => {
        const result = dialog.showMessageBoxSync(window, {
          type: 'warning', buttons: ['Keep tab open', 'Leave page'], defaultId: 0, cancelId: 0,
          message: 'This page has changes that may not be saved.',
          detail: 'Leave the page and close this tab?',
        });
        if (result === 1) event.preventDefault();
      });
      return view;
    },
    attach(view) { window.contentView.addChildView(view); view.setVisible(false); },
    detach(view) { window.contentView.removeChildView(view); },
    show(view, visible, bounds) {
      const [width, height] = window.getContentSize();
      const x = Math.min(bounds.x, width), y = Math.max(80, Math.min(bounds.y, height));
      const w = Math.max(0, Math.min(bounds.width, width - x));
      const h = Math.max(0, Math.min(bounds.height, height - y));
      view.setBounds({ x, y, width: w, height: h });
      view.setVisible(Boolean(visible && w > 0 && h > 0));
    },
    close(view) {
      const wc = view.webContents;
      if (wc.isDestroyed()) return Promise.resolve(true);
      return new Promise(resolve => {
        let timer;
        const done = result => { clearTimeout(timer); wc.removeListener('destroyed', closed); resolve(result); };
        const closed = () => done(true);
        wc.once('destroyed', closed);
        timer = setTimeout(() => done(false), 5000);
        wc.close({ waitForBeforeUnload: true });
      });
    },
    async stopWorkers(ses) {
      // Electron exposes worker observation, not a documented force-stop API.
      // Do not clear registrations/site storage to manufacture shutdown.
      const deadline = Date.now() + 35000;
      while (Object.keys(ses.serviceWorkers.getAllRunning()).length) {
        if (Date.now() >= deadline) throw new Error('Background worker shutdown is unconfirmed; restart the app before changing this profile route');
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    },
  };
}
module.exports = { electronAdapter };
