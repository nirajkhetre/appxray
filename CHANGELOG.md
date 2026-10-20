# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## 0.2.0 (unreleased)

Deep analysis powered by [REA](https://github.com/morluto/rea).

- `--deep` analyzes each Electron app's code with REA. appxray selects the security-relevant
  files (main entry, preload scripts, window and IPC code) straight from `app.asar`, and REA
  reconstructs windows, preload bridges, IPC handlers, process creation and loaded content.
- New findings: web content that can reach command execution (with every hop's file and line),
  insecure `webPreferences` including insecure defaults of old Electron versions, preload bridges
  with caller-chosen IPC channels, IPC handlers without sender checks, plain-HTTP content, and
  explicit partial-coverage reporting.
- `appxray diff <old> <new>` compares two builds: runtime, fuses, findings and the REA attack
  surface, with a safer / riskier / mixed / unchanged verdict and `--fail-on` for release gates.
- REA is bundled as an exact-pinned optional dependency (6.7.0), guarded by a version gate and by
  a CI contract test that runs the real REA on Windows and Linux.
- Node.js 22.19+ or 24.11+ is now required (REA's requirement).

## 0.1.0

First release.

- `scan` discovers installed apps with embedded Chromium on Windows (Program Files,
  per-user installs, Squirrel, registry locations) and Linux (system and user folders,
  snaps, flatpaks, `.desktop` names).
- `inspect` checks explicit app folders, build outputs or binaries on any OS.
- Reads Electron and Chromium versions, Electron fuses and Qt WebEngine security-patch levels
  directly from binaries, without running them.
- Findings for known exploited Chromium vulnerabilities (CISA KEV, with Electron backport
  awareness), end-of-life Electron lines, missed patch releases, Electron security advisories
  and risky fuses, each with a confidence level.
- Text, JSON, SARIF 2.1.0 and self-contained HTML reports; `--fail-on` for CI.
- `db update` rebuilds the vulnerability database from public sources; a scheduled workflow
  keeps the bundled copy fresh.
- Optional `--deep` cross-check of fuses with REA 6.7.x.
