# appxray

**X-ray the desktop apps on your computer: find outdated Chromium, and use
[REA](https://github.com/morluto/rea) to find dangerous Electron code inside them.**

Slack, Discord, Teams, VS Code, Notion and hundreds of other desktop apps are built on
[Electron](https://www.electronjs.org/) or another embedded Chromium. Each one carries its
own copy of the browser engine, and **updating Chrome does not update them**. Many also
give web pages far more power than a browser would. appxray checks both, without running
the apps.

**Runtime check (fast, every app on the machine).** appxray reads the exact Electron and Chromium versions from each app's binaries and reports:

- **Actively exploited Chromium bugs**: entries in CISA's
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog that the app's Chromium has not fixed, after accounting for Electron's backported fixes.
- **Unsupported Electron lines** and **missed patch releases**.
- **Electron security advisories** from the GitHub Advisory Database.
- **Risky Electron fuses**, such as `RunAsNode`, which lets malware run code inside a trusted, signed app.

**Code check with `--deep`, powered by REA.** appxray picks out the code that defines each app's security boundary, then has [REA](https://github.com/morluto/rea) statically analyze it. REA
reverse-engineers Electron apps without their source code. Together they find:

- **Web content that can reach command execution.** For example, a function the preload exposes to web pages (`window.api.run`) sends an IPC message to a main-process handler that calls `child_process.exec`. Each finding shows the exact file and line of every hop.
- **Insecure window settings** such as `nodeIntegration: true`, `contextIsolation: false`,
  `webSecurity: false` or `sandbox: false`. Defaults that were insecure in the app's Electron version are flagged too.
- **Preload bridges that forward caller-chosen IPC channels**, **IPC handlers that never check
  the sender**, and **remote content loaded over plain HTTP**.
- An inventory of exposed functions, IPC handlers, remote URLs and native add-ons.

**Release diff.** `appxray diff old new` shows what an update changed: runtime, fuses,
findings, and with `--deep` the attack surface found by REA. You get a verdict of safer, riskier, mixed or unchanged.

```text
SEVERITY  APP        VERSION  RUNTIME                          TOP ISSUE
CRITICAL  Probe App  1.2.3    Electron 22.3.14 · Chromium 108  Web content can reach command execution through an IPC handler
CRITICAL  VS Code    1.80.0   Electron 22.3.14 · Chromium 108  24 actively exploited Chromium vulnerabilities not fixed
MEDIUM    VS Code    1.142.0  Electron 43.7.7 · Chromium 150   5 newer Electron 43 patch releases available

  CRITICAL Web content can reach command execution through an IPC handler
           window.api.run (exposed by the preload) sends IPC "run-command" to the handler at
           main.js:20, which calls child_process.exec at main.js:20. The app loads remote
           content (https://example.com/app). REA evidence ev_a663ccc1…
```

## Safe by design

- **Read-only.** appxray and REA read files. They never run, load, attach to or modify the
  apps they inspect.
- **Offline scans.** A scan uses a vulnerability database stored on disk and makes no network
  requests. Only `appxray db update` goes online, and only to fetch public vulnerability data.
- **Honest confidence levels.** Every finding states how sure it is and why. When a backport
  might exist, the finding says "not ruled out". When REA could only partly analyze an app,
  for example minified bundles, the report says so instead of calling the app clean.
- **Minimal, pinned dependencies.** The runtime check needs only
  [`semver`](https://www.npmjs.com/package/semver). REA is an exact-pinned optional dependency.
  Lockfile committed, GitHub Actions pinned to commit SHAs.

## Install

Requires [Node.js](https://nodejs.org/) 22.19+ (or 24.11+).

The project is not on npm yet, so install it from source:

```powershell
git clone https://github.com/nirajkhetre/appxray.git
cd appxray
npm ci
npm run build
node dist/cli.js scan
```

`npm ci` also installs the pinned REA version. If REA cannot be installed on a machine,
everything except `--deep` still works.

On Windows, use PowerShell or Windows Terminal. Run it as administrator with `--all-users`
to include other people's profiles.

## Usage

```text
appxray [scan]                 Scan this computer's installed apps (Windows, Linux)
appxray inspect <path>...      Check app folders, build outputs or binaries
appxray diff <old> <new>       Compare two builds of an app
appxray db update              Refresh the vulnerability database
appxray db info                Show which database is used and how fresh it is
```

| Option                                 | Purpose                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------- |
| `--deep`                               | Analyze each Electron app's code with REA (about 5 to 60 seconds per app).  |
| `--deep-timeout <seconds>`             | Time limit for REA per app (default 300).                                   |
| `-f, --format text\|json\|sarif\|html` | Report format. HTML is a single self-contained file.                        |
| `-o, --output <file>`                  | Write the report to a file.                                                 |
| `--min-severity <level>`               | Hide findings below `critical`, `high`, `medium`, `low` or `info`.          |
| `--fail-on <level>`                    | Exit with code 1 when a finding (or, for `diff`, a new finding) reaches it. |
| `--all-users`                          | Also scan other users' profiles (needs admin or root).                      |
| `--root <dir>`                         | Search an extra folder; `--no-default-roots` searches only those.           |
| `--redact-paths`                       | Replace your home folder with `~`, for sharing reports.                     |

Examples:

```powershell
# Full audit of this machine, as a shareable HTML report
node dist/cli.js scan --deep --format html --output report.html --redact-paths

# Electron developers: fail the build on a vulnerable Electron or a dangerous IPC path
node dist/cli.js inspect .\dist\win-unpacked --deep --fail-on high --format sarif --output appxray.sarif

# Did this update make the app riskier? Fail CI if it introduced a high or critical finding.
node dist/cli.js diff .\release-1.2\win-unpacked .\release-1.3\win-unpacked --deep --fail-on high
```

Exit codes: `0` OK, `1` findings at the `--fail-on` level, `2` usage error, `3` runtime error.

## How REA is used, and why REA updates cannot break appxray

REA is the engine behind `--deep` and `diff`. appxray does the parts that need to be fast and
broad: finding apps, reading versions and fuses, choosing which of an app's files matter.
REA does the hard part: semantic analysis of an Electron app's JavaScript, including windows,
preload bridges, IPC and process creation.

REA is a young, fast-moving project, with dozens of breaking releases a month, so it is used
under a contract:

1. **Pinned exactly.** appxray installs `rea-agents@6.7.0`, never "latest". A new REA release
   changes nothing for appxray users until appxray itself is updated.
2. **One gateway.** Every REA call goes through `src/rea/`, which validates REA's output
   before anything uses it. Malformed output becomes an error message, never a silent
   "no findings".
3. **Version gate.** A REA version outside the tested range (`REA_TESTED_RANGE`) is refused
   unless you pass `--rea-allow-untested`.
4. **Real contract tests.** CI runs the real pinned REA on a deliberately insecure test app on
   Windows and Linux and checks the exact attack path. Dependabot proposes REA upgrades as pull
   requests, and they merge only if those tests pass.
5. **Graceful degradation.** If REA is missing or fails on one app, that app's report says
   so and every other check still runs.

## What it detects

| Runtime            | How it is found                                                 | What is checked                                                                     |
| ------------------ | --------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Electron           | `resources/app.asar` (or `app/`) next to Chromium runtime files | Versions, fuses, app name and version; with `--deep`, the app's security code (REA) |
| Qt WebEngine       | `Qt5/Qt6WebEngineCore` library                                  | Chromium base version and the Chromium version its security patches reach           |
| CEF (experimental) | `libcef.dll` / `libcef.so`                                      | Chromium version                                                                    |

Where it looks:

- **Windows:** Program Files (both), `%LOCALAPPDATA%` (including `Programs` and Squirrel
  installs such as `app-1.2.3` folders), `%APPDATA%`, `%ProgramData%`, plus every location
  registered under "Apps & features". Names and versions come from the registry.
- **Linux:** `/opt`, `/usr/lib`, `/usr/share`, `/usr/local`, `~/.local`, snaps and flatpaks.
  Names come from `.desktop` launchers. AppImages are listed but not opened.

See [docs/how-it-works.md](docs/how-it-works.md) for the detection, matching and REA logic, and
[docs/findings.md](docs/findings.md) for every rule.

## Keeping the data fresh

The database ships with each release and can be refreshed at any time:

```powershell
$env:GITHUB_TOKEN = "<any token>"   # optional; avoids GitHub API rate limits
node dist/cli.js db update
```

`db update` collects:

- Electron releases from npm
- Electron advisories from the GitHub Advisory Database, through npm's advisory API
- CISA's KEV catalog
- fixed Chrome versions from the CVE List
- Electron release notes, which list backported Chromium fixes

Scans warn when the data is more than 14 days old. In this repository, a scheduled workflow
rebuilds `data/appxray-db.json` daily and opens a pull request. Behind a corporate proxy, set
`NODE_USE_ENV_PROXY=1` along with `HTTPS_PROXY`.

## Limitations

- An outdated Chromium means **exposure**, not compromise. Exploiting it usually needs the
  app to load attacker-controlled web content.
- REA's analysis is static. It reports what the code can do, not what users trigger.
  Minified or heavily bundled apps may be only partly resolved; this is reported as
  `deep/limited-coverage`.
- Fixes a vendor backports without Electron are invisible. CEF and Qt results without a
  security-patch level are reported as "not ruled out".
- Windows Store (MSIX) apps under `WindowsApps` and AppImages are not inspected yet.
- macOS support is planned; `inspect` already works on macOS for explicit paths.

## Contributing

Bug reports with a sample report (`--redact-paths`) are very welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in
[SECURITY.md](SECURITY.md).

## Credits

Deep analysis is powered by [REA (Reverse Engineer Anything)](https://github.com/morluto/rea), MIT licensed.

## License

[MIT](LICENSE)
