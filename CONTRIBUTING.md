# Contributing

Thanks for helping. Bug reports, detection improvements and new data sources are all welcome.

## Development setup

```sh
git clone https://github.com/saurabhkhetre/appxray.git
cd appxray
npm ci
npm run check      # typecheck, lint, formatting and tests
npm run build
node dist/cli.js scan
```

Node.js 22.12 or newer is required. Development works on Windows, Linux and macOS.

## Project layout

| Path                            | Purpose                                                                                        |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| `src/discovery/`                | Where to look on each platform (registry, roots, `.desktop` files) and the bounded folder walk |
| `src/detect/`                   | Classifying a folder as Electron/CEF/Qt and inspecting it                                      |
| `src/binary/`                   | Streaming binary scanner, fuse decoder, ASAR manifest reader                                   |
| `src/db/`                       | Vulnerability database schema, builder (`db update`) and loader                                |
| `src/analysis/`                 | Rules that turn runtime versions into findings                                                 |
| `src/report/`                   | Text, JSON, SARIF and HTML output                                                              |
| `src/rea/`                      | Optional, version-pinned REA cross-check                                                       |
| `test/unit`, `test/integration` | Fast tests with synthetic fixtures                                                             |
| `test/real`                     | Opt-in tests against real Electron/Qt builds (`APPXRAY_REAL_FIXTURES`)                         |

## Guidelines

- **Accuracy over alarm.** A finding must state its confidence. If a backport might exist, use
  the "not ruled out" rule instead of claiming exposure. Add a test that pins the expected outcome.
- **Never execute inspected apps.** Detection reads files only.
- **Keep scans offline.** Network access belongs in `src/db/build.ts` only.
- **Dependencies:** adding a runtime dependency needs a strong reason; pin exact versions.
- **Windows paths:** use `path.win32` / the `platform` parameters so Windows logic is testable on any OS.
- Run `npm run check` before opening a pull request. CI runs on Windows and Linux with Node 22 and 24.

## Reporting detection problems

Please include the output of `appxray inspect "<app folder>" --format json --redact-paths`, the
app's name and version, and what you expected. Do not attach the app's binaries.

## Releasing (maintainers)

1. Update `CHANGELOG.md` and bump `version` in `package.json`.
2. Merge the latest data-refresh pull request.
3. Tag `vX.Y.Z` and push the tag; the release workflow publishes to npm with provenance.
