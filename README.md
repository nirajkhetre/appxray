# appxray

**Find the desktop apps on your computer that ship an outdated or vulnerable Chromium.**

Slack, Discord, Teams, VS Code, Notion and hundreds of other desktop apps are built on
[Electron](https://www.electronjs.org/) or another embedded Chromium. Each one carries
its own copy of the browser engine, and **updating Chrome does not update them**. When a
Chromium bug is exploited in the wild, every app with an old copy stays exposed until its
vendor ships an update.

appxray finds those apps on Windows and Linux, reads the exact Electron and Chromium
versions from their binaries, and checks them against public vulnerability data:

- **Actively exploited Chromium bugs**: entries in CISA's
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog that are not fixed in the app's Chromium, after accounting for Electron's backported fixes.
- **Unsupported Electron lines**: apps on an Electron major version that no longer gets security fixes.
- **Missed patch releases** in a supported Electron line.
- **Electron security advisories** from the GitHub Advisory Database.
- **Risky Electron fuses**, such as `RunAsNode`, which lets malware run code inside a trusted, signed app.

```text
SEVERITY  APP                 VERSION  RUNTIME                           TOP ISSUE
CRITICAL  Visual Studio Code  1.80.0   Electron 22.3.14 · Chromium 108   24 actively exploited Chromium vulnerabilities not fixed
HIGH      Qt6                 -        Qt WebEngine · Chromium 130 (p…   8 actively exploited Chromium vulnerabilities not fixed
MEDIUM    Visual Studio Code  1.142.0  Electron 43.7.7 · Chromium 150    5 newer Electron 43 patch releases available
```

## Safe by design

- **Read-only.** appxray reads files. It never runs, loads, attaches to or modifies the apps it inspects.
- **Offline scans.** A scan uses a vulnerability database stored on disk and makes no network requests.
  Only `appxray db update` goes online, and only to fetch public vulnerability data.
- **One runtime dependency** ([`semver`](https://www.npmjs.com/package/semver)), with exact versions
  pinned and GitHub Actions pinned to commit SHAs.
- **Honest confidence levels.** Every finding states how sure it is and why. When a vendor might have
  backported a fix that appxray cannot see, the finding says "not ruled out" instead of claiming exposure.

## Install

Requires [Node.js](https://nodejs.org/) 22.12 or newer.

The project is not on npm yet, so install it from source:

```powershell
git clone https://github.com/<you>/appxray.git
cd appxray
npm ci
npm run build
node dist/cli.js scan
```

On Windows, use PowerShell or Windows Terminal. Run it as administrator with `--all-users`
to include other people's profiles.

## Usage

```text
appxray [scan]               Scan this computer's installed apps (Windows, Linux)
appxray inspect <path>...    Check app folders, build outputs or binaries
appxray db update            Refresh the vulnerability database
appxray db info              Show which database is used and how fresh it is
```

Common options:

| Option                                 | Purpose                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `-f, --format text\|json\|sarif\|html` | Report format. HTML is a single self-contained file.                      |
| `-o, --output <file>`                  | Write the report to a file.                                               |
| `--min-severity <level>`               | Hide findings below `critical`, `high`, `medium`, `low` or `info`.        |
| `--fail-on <level>`                    | Exit with code 1 when any finding is at or above the level. Useful in CI. |
| `--all-users`                          | Also scan other users' profiles (needs admin or root).                    |
| `--root <dir>`                         | Search an extra folder; `--no-default-roots` searches only those.         |
| `--redact-paths`                       | Replace your home folder with `~`, for sharing reports.                   |
| `--deep`                               | Cross-check fuse readings with [REA](#optional-deep-mode-with-rea).       |

Examples:

```powershell
# Shareable HTML report of this machine
node dist/cli.js scan --format html --output report.html --redact-paths

# Electron developers: fail the build if your packaged app ships a vulnerable Electron
node dist/cli.js inspect .\dist\win-unpacked --fail-on high --format sarif --output appxray.sarif
```

Exit codes: `0` OK, `1` findings at the `--fail-on` level, `2` usage error, `3` runtime error.

## What it detects

| Runtime            | How it is found                                                 | What is checked                                                                     |
| ------------------ | --------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Electron           | `resources/app.asar` (or `app/`) next to Chromium runtime files | Electron version, Chromium version, fuses, app name and version from `package.json` |
| Qt WebEngine       | `Qt5/Qt6WebEngineCore` library                                  | Chromium base version and the Chromium version its security patches reach           |
| CEF (experimental) | `libcef.dll` / `libcef.so`                                      | Chromium version                                                                    |

Where it looks:

- **Windows:** Program Files (both), `%LOCALAPPDATA%` (including `Programs` and Squirrel
  installs such as `app-1.2.3` folders), `%APPDATA%`, `%ProgramData%`, plus every location
  registered under "Apps & features". Names and versions come from the registry.
- **Linux:** `/opt`, `/usr/lib`, `/usr/share`, `/usr/local`, `~/.local`, snaps and flatpaks.
  Names come from `.desktop` launchers. AppImages are listed but not opened.

See [docs/how-it-works.md](docs/how-it-works.md) for the detection and matching logic, and
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

It saves the result to your user cache folder. Scans warn when the data is more than 14 days old. In this repository, a scheduled workflow
rebuilds `data/appxray-db.json` daily and opens a pull request.

Behind a corporate proxy, set `NODE_USE_ENV_PROXY=1` along with `HTTPS_PROXY`.

## Optional deep mode with REA

`--deep` asks [REA](https://github.com/morluto/rea) to independently read each Electron
app's fuses and attaches its evidence ID to the report. REA is never installed or required by
appxray. Only the version range covered by appxray's contract tests (currently `6.7.x`) is
used unless you pass `--rea-allow-untested`. A change in REA cannot silently alter appxray's results.

```powershell
npm install --global rea-agents@6.7
node dist/cli.js scan --deep
```

## Limitations

- An outdated Chromium means **exposure**, not compromise. Exploiting it usually needs the
  app to load attacker-controlled web content.
- Fixes a vendor backports without Electron are invisible. CEF and Qt results without a
  security-patch level are reported as "not ruled out".
- Windows Store (MSIX) apps under `WindowsApps` and AppImages are not inspected yet.
- macOS support is planned; `inspect` already works on macOS for explicit paths.

## Contributing

Bug reports with a sample report (`--redact-paths`) are very welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
