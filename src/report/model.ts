import os from 'node:os';

import {
  SEVERITIES,
  severityRank,
  type AnalyzedApp,
  type Finding,
  type Severity,
} from '../analysis/types.js';
import type { LoadedDb } from '../db/load.js';
import { dbAgeDays, STALE_AFTER_DAYS } from '../db/load.js';
import type { SkippedPath } from '../detect/types.js';
import { packageInfo, TOOL_NAME } from '../util/pkg.js';

export const REPORT_SCHEMA_VERSION = 1;

export interface ScanReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  tool: { name: string; version: string };
  mode: 'scan' | 'inspect';
  scannedAt: string;
  durationMs: number;
  host: { platform: NodeJS.Platform; arch: string; osRelease: string };
  database: {
    generatedAt: string;
    ageDays: number;
    stale: boolean;
    origin: LoadedDb['origin'];
    releaseNoteMajors: number[];
  };
  /** Findings below this severity were left out. */
  minSeverity: Severity;
  directoriesVisited: number;
  apps: AnalyzedApp[];
  skipped: SkippedPath[];
  summary: {
    apps: number;
    appsWithFindings: number;
    /** Number of apps whose most severe finding has each severity. */
    appsBySeverity: Record<Severity, number>;
  };
}

export interface BuildReportInput {
  mode: ScanReport['mode'];
  startedAt: Date;
  finishedAt: Date;
  loadedDb: LoadedDb;
  apps: AnalyzedApp[];
  skipped: SkippedPath[];
  directoriesVisited: number;
  minSeverity: Severity;
  redactPaths?: boolean;
}

function redact(value: string, home: string): string {
  if (!home) return value;
  const pattern = new RegExp(
    home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    process.platform === 'win32' ? 'gi' : 'g',
  );
  return value.replace(pattern, '~');
}

function redactApp(app: AnalyzedApp, home: string): AnalyzedApp {
  return {
    ...app,
    root: redact(app.root, home),
    binary: redact(app.binary, home),
    otherCopies: app.otherCopies.map((copy) => redact(copy, home)),
    notes: app.notes.map((note) => redact(note, home)),
  };
}

export function buildReport(input: BuildReportInput): ScanReport {
  const threshold = severityRank(input.minSeverity);
  const keep = (finding: Finding) => severityRank(finding.severity) >= threshold;
  const home = os.homedir();

  let apps = input.apps
    .map((app) => {
      const findings = app.findings.filter(keep);
      return { ...app, findings, maxSeverity: findings[0] ? app.maxSeverity : null };
    })
    .map((app) => ({
      ...app,
      findings: [...app.findings].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity),
      ),
    }))
    .sort(
      (a, b) =>
        (b.maxSeverity ? severityRank(b.maxSeverity) : 0) -
          (a.maxSeverity ? severityRank(a.maxSeverity) : 0) || a.name.localeCompare(b.name),
    );
  let skipped = input.skipped;
  if (input.redactPaths) {
    apps = apps.map((app) => redactApp(app, home));
    skipped = skipped.map((item) => ({ ...item, path: redact(item.path, home) }));
  }

  const appsBySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    Severity,
    number
  >;
  for (const app of apps) {
    if (app.maxSeverity) appsBySeverity[app.maxSeverity]++;
  }
  const ageDays = dbAgeDays(input.loadedDb.db, input.finishedAt);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: packageInfo().version },
    mode: input.mode,
    scannedAt: input.startedAt.toISOString(),
    durationMs: input.finishedAt.getTime() - input.startedAt.getTime(),
    host: { platform: process.platform, arch: process.arch, osRelease: os.release() },
    database: {
      generatedAt: input.loadedDb.db.generatedAt,
      ageDays,
      stale: ageDays > STALE_AFTER_DAYS,
      origin: input.loadedDb.origin,
      releaseNoteMajors: input.loadedDb.db.coverage.releaseNoteMajors,
    },
    minSeverity: input.minSeverity,
    directoriesVisited: input.directoriesVisited,
    apps,
    skipped,
    summary: {
      apps: apps.length,
      appsWithFindings: apps.filter((app) => app.findings.length > 0).length,
      appsBySeverity,
    },
  };
}

/** Describes the runtime in a short human-readable form, e.g. "Electron 43.7.7 · Chromium 150". */
export function runtimeLabel(app: AnalyzedApp): string {
  const chromiumMajor = app.runtime.chromium?.split('.')[0];
  const patchMajor = app.runtime.chromiumSecurityPatch?.split('.')[0];
  const chromium = chromiumMajor
    ? ` · Chromium ${chromiumMajor}${patchMajor && patchMajor !== chromiumMajor ? ` (patched ${patchMajor})` : ''}`
    : '';
  switch (app.kind) {
    case 'electron':
      return `Electron ${app.runtime.electron ?? '?'}${chromium}`;
    case 'cef':
      return `CEF${chromium}`;
    case 'qtwebengine':
      return `Qt WebEngine${chromium}`;
  }
}
