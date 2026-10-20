# How appxray works

A scan has four stages: **discover** install folders, **inspect** their runtime binaries,
**match** the versions against the vulnerability database, and **report**.

## 1. Discover

appxray walks a fixed set of install locations breadth-first
(`src/discovery/windows.ts`, `src/discovery/linux.ts`). Each folder is classified from its
directory listing alone (`src/detect/classify.ts`):

- **Electron:** Chromium runtime files (`icudtl.dat`, `v8_context_snapshot.bin`,
  `snapshot_blob.bin`, `chrome_100_percent.pak` or `resources.pak`) next to a `resources/`
  folder that holds `app.asar`, `app/` or `default_app.asar`. A plain Chromium browser has the
  runtime files but no app bundle, so it is not counted.
- **CEF:** `libcef.dll` or `libcef.so`.
- **Qt WebEngine:** `Qt5WebEngineCore.dll`, `Qt6WebEngineCore.dll` or `libQt*WebEngineCore.so*`.

The walk is bounded: each root has a depth limit, there is a global budget of directories
(`--max-dirs`), and cache and data folders such as `node_modules`, `GPUCache` and
`Service Worker` are skipped. It never descends into a detected app. Symlinks and junctions are
followed once. Permission errors are counted, not fatal.

Squirrel.Windows keeps older versions beside the current one (`app-1.0.1`, `app-1.0.2`).
Only the newest is launched, so only that one is scanned and the others are listed.

Names and versions come from, in order: the Windows uninstall registry or Linux `.desktop`
launchers, the app's `package.json` (read directly from `app.asar` without extracting it),
and finally the folder name.

## 2. Inspect

For an Electron app the main executable is the largest executable in the folder, since
Electron links Chromium into it statically. appxray streams the file once
(`src/binary/scan.ts`) and records:

- `Electron/<version>` and `Chrome/<version>` strings. Electron builds its user agent from these.
- The **fuse wire**: the sentinel `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`, a wire version, a
  length, then one byte per fuse (`0` off, `1` on, `r` removed). The order is fixed by Electron
  (see `@electron/fuses`).
- For Qt WebEngine, the Chromium version that its security patches reach, stored after the
  `QtWebEngineProcess` string.
- A SHA-256 of the binary, computed in the same pass, so results can be tied to an exact file.

Chunks overlap so a marker that spans a read boundary is found exactly once; this is covered by
a test that places markers at every offset around a boundary. Files are only read, never
executed or memory-mapped.

## 3. Match

The database (`data/appxray-db.json`, schema in `src/db/schema.ts`) is built by
`appxray db update` from public sources:

| Data                                | Source                                                        |
| ----------------------------------- | ------------------------------------------------------------- |
| Electron versions and release dates | npm registry (`electron` package)                             |
| Electron security advisories        | GitHub Advisory Database via npm's bulk advisory API          |
| Known exploited Chromium CVEs       | CISA KEV catalog (GitHub mirror as fallback)                  |
| First fixed Chrome version per CVE  | CVE List V5 records (`affected[].versions[].lessThan`)        |
| Backported Chromium fixes           | Electron release notes ("Security: backported fix for CVE-…") |

Rules (`src/analysis/analyze.ts`):

- **End of life.** Electron supports the newest three major lines. A line is out of support once
  the line three versions newer ships, or after its last release if it was patched past that
  point. Electron 22, for example, was extended for Windows 7.
- **Outdated patch.** For supported lines, appxray counts the newer patch releases and the
  backported CVE fixes they contain.
- **Advisories.** The Electron version is matched against each advisory's affected semver range.
- **Known exploited Chromium bugs.** For each KEV entry with a known fixed Chrome version:
  1. If the embedded Chromium is at or past the fix, it is fixed. A fix listed for several
     branches counts on the branch the build is on.
  2. If an Electron release in the same line, at or before the app's version, lists the CVE as a
     backported fix, it is fixed.
  3. If release notes were collected for that line and none mention the CVE, the app is
     **exposed (high confidence)**.
  4. Without release notes, if the CVE was published after the app's Electron version was
     released, the fix cannot be in it: **exposed (medium confidence)**.
  5. Otherwise the result is **not ruled out (low confidence)**. A backport may exist.

  Qt WebEngine is compared at its security-patch level, and CEF at its Chromium version, both
  with medium confidence. Qt builds without a patch level are only reported as "not ruled out".

- **Fuses.** `RunAsNode`, `EnableNodeOptionsEnvironmentVariable` and
  `EnableNodeCliInspectArguments` are reported when enabled. Disabled ASAR integrity, which only
  exists for Windows and macOS builds, and `OnlyLoadAppFromAsar` are informational.

## 4. Report

Reports are available as text, JSON (`docs/report-format.md`), SARIF 2.1.0 (for CI and GitHub
code scanning) and a self-contained HTML file with a strict Content-Security-Policy and no
scripts. `--redact-paths` replaces the home folder with `~` for sharing.

## 5. Deep analysis with REA (`--deep`)

For each Electron app, appxray hands the code that defines its security boundary to
[REA](https://github.com/morluto/rea) and turns REA's evidence into findings.

1. **Select** (`src/deep/select.ts`). appxray opens `app.asar` (or `resources/app/`) without
   extracting it, scores every JavaScript file outside `node_modules`, and keeps the
   `package.json` main entry plus files with Electron boundary code (`webPreferences`,
   `contextBridge`, `ipcMain`, `new BrowserWindow`). VS Code, for example, ships about 1,500
   JavaScript files; this step picks about 5 of them. That makes a full REA run of several
   minutes into seconds.
2. **Analyze.** `rea analyze-javascript-application <app> --source-path <file>...` statically
   reconstructs windows and their `webPreferences`, renderer content (`loadURL`/`loadFile`),
   `contextBridge` APIs, IPC channels and handlers, process creation, endpoints and native add-ons,
   with a source location for each.
3. **Model** (`src/deep/posture.ts`). REA's evidence is parsed defensively into an Electron
   posture. Attack paths are linked: an exposed bridge function → its literal IPC channel → the
   main-process handler for that channel → a `child_process` call inside that handler's body.
4. **Judge** (`src/analysis/deep.ts`). Insecure settings are flagged when set explicitly, or
   when omitted while the app's Electron version still had an insecure default and every option
   was visible: `nodeIntegration` before 5, `contextIsolation` before 12, `sandbox` before 20.
   Severity rises when the app loads remote `http(s)` content, because that is when a page can be
   hostile. Gaps such as minified bundles, parse failures, the time limit or unresolved window
   options become a `deep/limited-coverage` finding.

`appxray diff` runs the same pipeline on two builds and compares versions, fuses, findings and
the REA attack surface (exposed functions, IPC handlers, remote content, native add-ons, command
execution paths, insecure settings). A severity-weighted risk score gives the verdict.

### The REA contract

All REA calls go through `src/rea/`. REA is an exact-pinned optional dependency, versions
outside `REA_TESTED_RANGE` are refused by default, and output is validated before use.
`test/integration/rea-real.test.ts` runs the real pinned REA in CI against
`test/fixtures/apps/insecure-electron`. `test/unit/rea.test.ts` and `test/unit/deep.test.ts`
pin parsers to recorded REA 6.7.0 output. A REA upgrade that changes behavior fails these tests
instead of silently changing results.
