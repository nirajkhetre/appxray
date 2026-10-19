# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## 0.1.0 (unreleased)

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
