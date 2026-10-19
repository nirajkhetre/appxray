import { describe, expect, it } from 'vitest';

import { analyzeApp } from '../../src/analysis/analyze.js';
import type { InspectedApp } from '../../src/detect/types.js';
import { formatHtml } from '../../src/report/html.js';
import { buildReport, runtimeLabel } from '../../src/report/model.js';
import { formatSarif } from '../../src/report/sarif.js';
import { formatText } from '../../src/report/text.js';
import { fixtureDb, NOW } from '../fixtures/db.js';

function inspected(name: string, electron: string, chromium: string): InspectedApp {
  return {
    id: name,
    name,
    appVersion: '1.0.0',
    root: `/opt/${name}`,
    binary: `/opt/${name}/${name}`,
    binarySize: 1,
    kind: 'electron',
    source: 'filesystem',
    runtime: { electron, chromium },
    otherCopies: [],
    notes: [],
    evidence: [],
  };
}

function report(minSeverity: 'info' | 'medium' = 'info') {
  const db = fixtureDb();
  const apps = [
    inspected('Fresh', '44.9.0', '154.0.8100.1'),
    inspected('Ancient <script>alert(1)</script>', '22.3.14', '108.0.5359.215'),
  ].map((app) => analyzeApp(app, db, { now: NOW }));
  return buildReport({
    mode: 'scan',
    startedAt: NOW,
    finishedAt: new Date(NOW.getTime() + 1500),
    loadedDb: { db, path: '/tmp/db.json', origin: 'bundled' },
    apps,
    skipped: [{ path: '/opt/broken', reason: 'cannot list directory (EACCES)' }],
    directoriesVisited: 10,
    minSeverity,
  });
}

describe('report model', () => {
  it('orders apps by severity and counts them', () => {
    const result = report();
    expect(result.apps.map((app) => app.name)).toEqual([
      'Ancient <script>alert(1)</script>',
      'Fresh',
    ]);
    expect(result.summary).toMatchObject({ apps: 2, appsWithFindings: 1 });
    expect(result.summary.appsBySeverity.critical).toBe(1);
    expect(result.durationMs).toBe(1500);
  });

  it('filters findings below the minimum severity', () => {
    const result = report('medium');
    const severities = result.apps.flatMap((app) =>
      app.findings.map((finding) => finding.severity),
    );
    expect(severities).not.toContain('low');
    expect(severities).not.toContain('info');
  });

  it('labels runtimes compactly', () => {
    expect(runtimeLabel(report().apps[1]!)).toBe('Electron 44.9.0 · Chromium 154');
  });
});

describe('formatters', () => {
  it('renders plain text without color codes when color is off', () => {
    const text = formatText(report(), { color: false, width: 120 });
    expect(text).not.toContain('\u001b[');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('Electron 22 reached end of life');
    expect(text).toContain('/opt/broken: cannot list directory (EACCES)');
  });

  it('escapes app names in HTML and loads nothing external', () => {
    const html = formatHtml(report());
    expect(html).not.toContain('<script>');
    expect(html).toContain('Ancient &lt;script&gt;');
    expect(html).not.toMatch(/<(script|link|img)\b/);
    expect(html).toContain("default-src 'none'");
  });

  it('produces SARIF 2.1.0 with rule metadata and severities', () => {
    const sarif = JSON.parse(formatSarif(report())) as {
      version: string;
      runs: {
        tool: { driver: { rules: { id: string }[] } };
        results: {
          ruleId: string;
          ruleIndex: number;
          level: string;
          locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
        }[];
      }[];
    };
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0]!;
    expect(run.results.length).toBeGreaterThan(0);
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
      expect(['error', 'warning', 'note']).toContain(result.level);
      expect(result.locations[0]?.physicalLocation.artifactLocation.uri).toMatch(/^file:\/\//);
    }
  });
});
