Deliberately insecure Electron app source used as a test fixture. It is never run; tests pack
it into an `app.asar` and analyze it statically (with REA) to check that appxray finds:

- a window with `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`, `sandbox: false`
- remote content loaded with `loadURL('https://example.com/app')`
- the path `window.api.run` -> IPC `run-command` -> `child_process.exec` in the main process
