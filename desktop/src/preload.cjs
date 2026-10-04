'use strict';
const { contextBridge, ipcRenderer } = require('electron');
// This preload belongs exclusively to bundled app chrome. Guests have no preload.
// No token, URL loader, filesystem, credential, generic channel, or ipcRenderer is exposed.
contextBridge.exposeInMainWorld('TeamDesktop', Object.freeze({
  command: value => ipcRenderer.invoke('tbm:command', value),
  snapshot: () => ipcRenderer.invoke('tbm:snapshot'),
  subscribe: callback => {
    if (typeof callback !== 'function') throw new TypeError('Expected a callback');
    const listener = (_event, snapshot) => callback(snapshot);
    ipcRenderer.on('tbm:changed', listener);
    return () => ipcRenderer.removeListener('tbm:changed', listener);
  },
}));
