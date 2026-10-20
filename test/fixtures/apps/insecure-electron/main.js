const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { exec } = require('child_process');
function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadURL('https://example.com/app');
  const safe = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js') } });
  safe.loadFile('index.html');
}
ipcMain.handle('run-command', (_event, cmd) => new Promise((r) => exec(cmd, (e, out) => r(out))));
ipcMain.on('open-link', (_event, url) => shell.openExternal(url));
app.whenReady().then(createWindow);
