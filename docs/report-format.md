# JSON report format

`appxray scan --format json` prints one object (`schemaVersion: 1`). Fields are only
added in minor releases; removals or meaning changes bump `schemaVersion`.

```jsonc
{
  "schemaVersion": 1,
  "tool": { "name": "appxray", "version": "0.1.0" },
  "mode": "scan", // or "inspect"
  "scannedAt": "2026-10-19T19:00:00.000Z",
  "durationMs": 4120,
  "host": { "platform": "win32", "arch": "x64", "osRelease": "10.0.26100" },
  "database": {
    "generatedAt": "2026-10-19T05:17:00.000Z",
    "ageDays": 0,
    "stale": false,
    "origin": "bundled", // "bundled" | "cache" | "explicit"
    "releaseNoteMajors": [44, 43, 42, 41, 40, 39],
  },
  "minSeverity": "info",
  "directoriesVisited": 18234,
  "apps": [
    {
      "id": "d5ab3727d24d", // stable per install folder
      "name": "Visual Studio Code",
      "appVersion": "1.80.0",
      "publisher": "Microsoft Corporation",
      "root": "C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code",
      "binary": "C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "binarySize": 182345728,
      "binarySha256": "…",
      "kind": "electron", // "electron" | "cef" | "qtwebengine"
      "source": "registry", // "registry" | "filesystem" | "snap" | "flatpak" | "explicit"
      "runtime": { "electron": "22.3.14", "chromium": "108.0.5359.215" },
      "fuses": {
        "offset": 35991408,
        "wireVersion": 1,
        "fuses": [{ "index": 0, "name": "RunAsNode", "state": "enabled" }],
      },
      "otherCopies": [],
      "notes": [],
      "evidence": [], // e.g. REA cross-check results with --deep
      "maxSeverity": "critical",
      "findings": [
        {
          "ruleId": "chromium/known-exploited",
          "severity": "critical",
          "confidence": "medium",
          "title": "24 actively exploited Chromium vulnerabilities not fixed",
          "detail": "…",
          "references": ["https://www.cve.org/CVERecord?id=CVE-2026-87491"],
          "data": {
            "cves": [
              {
                "cve": "CVE-2026-87491",
                "fixedIn": ["153.0.8010.36"],
                "confidence": "medium",
                "reason": "…",
              },
            ],
          },
        },
      ],
    },
  ],
  "skipped": [
    { "path": "C:\\Program Files\\WindowsApps", "reason": "cannot list directory (EPERM)" },
  ],
  "summary": {
    "apps": 12,
    "appsWithFindings": 5,
    "appsBySeverity": { "critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0 },
  },
}
```

The `data` object of each finding is rule-specific and documented by example in
`test/unit/analyze.test.ts`.
