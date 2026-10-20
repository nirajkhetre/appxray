const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  run: (cmd) => ipcRenderer.invoke('run-command', cmd),
  open: (url) => ipcRenderer.send('open-link', url),
});
