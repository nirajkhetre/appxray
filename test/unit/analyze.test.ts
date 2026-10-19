import { describe, expect, it } from 'vitest';

import { analyzeApp, chromiumHasFix } from '../../src/analysis/analyze.js';
import type { Finding } from '../../src/analysis/types.js';
import { decodeFuseWire } from '../../src/binary/fuses.js';
import type { InspectedApp } from '../../src/detect/types.js';
import { fixtureDb, NOW } from '../fixtures/db.js';

function app(overrides: Partial<InspectedApp> = {}): InspectedApp {
  return {
    id: 'test',
    name: 'Test App',
    root: '/opt/test',
    binary: '/opt/test/test',
    binarySize: 1,
    kind: 'electron',
    source: 'explicit',
    runtime: { electron: '43.7.7', chromium: '150.0.7871.250' },
    otherCopies: [],
    notes: [],
    evidence: [],
    ...overrides,
  };
}

const byRule = (findings: Finding[], ruleId: Finding['ruleId']) =>
  findings.find((finding) => finding.ruleId === ruleId);
const cves = (finding: Finding | undefined) =>
  ((finding?.data?.['cves'] ?? []) as { cve: string }[]).map((item) => item.cve);

describe('chromiumHasFix', () => {
  it.each([
    ['153.0.8010.36', ['153.0.8010.36'], true],
    ['154.0.1.1', ['153.0.8010.36'], true],
    ['153.0.8010.35', ['153.0.8010.36'], false],
    // Fixed on the extended-stable branch the build is on.
    ['110.0.5481.210', ['112.0.5615.121', '110.0.5481.200'], true],
    ['110.0.5481.100', ['112.0.5615.121', '110.0.5481.200'], false],
    ['111.0.1.1', ['112.0.5615.121', '110.0.5481.200'], false],
    ['150.0.1.1', [], false],
  ])('%s with fixes %j -> %s', (version, fixedIn, expected) => {
    expect(chromiumHasFix(version, fixedIn)).toBe(expected);
  });
});

describe('analyzeApp: Electron', () => {
  it('flags an end-of-life Electron line with its advisories and exploited bugs', () => {
    const result = analyzeApp(
      app({ runtime: { electron: '22.3.14', chromium: '108.0.5359.215' } }),
      fixtureDb(),
      { now: NOW },
    );
    expect(result.maxSeverity).toBe('critical');
    expect(byRule(result.findings, 'electron/end-of-life')?.severity).toBe('high');
    expect(byRule(result.findings, 'electron/advisories')?.data?.['advisories']).toHaveLength(1);
    const kev = byRule(result.findings, 'chromium/known-exploited');
    // All three 2026 CVEs were disclosed after 22.3.14 was released, so none can be fixed.
    expect(cves(kev).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']);
    expect(kev?.confidence).toBe('medium');
    expect(kev?.detail).toContain('ransomware');
    // CVE-2023-0004 predates the release and could have been backported.
    expect(cves(byRule(result.findings, 'chromium/known-exploited-unverified'))).toEqual([
      'CVE-2023-0004',
    ]);
  });

  it('reports a supported line that is behind on patches, including missed backports', () => {
    const result = analyzeApp(app(), fixtureDb(), { now: NOW });
    const outdated = byRule(result.findings, 'electron/outdated');
    expect(outdated?.data).toMatchObject({
      latest: '43.8.0',
      releasesBehind: 2,
      missedBackports: ['CVE-2026-0001'],
    });
    expect(byRule(result.findings, 'electron/end-of-life')).toBeUndefined();
    expect(byRule(result.findings, 'electron/advisories')).toBeDefined();
  });

  it('without release notes, confirms only bugs disclosed after the release', () => {
    const result = analyzeApp(app(), fixtureDb(), { now: NOW });
    // 0001 was disclosed after 43.7.7 shipped, so 43.7.7 cannot contain its fix.
    const kev = byRule(result.findings, 'chromium/known-exploited');
    expect(cves(kev)).toEqual(['CVE-2026-0001']);
    expect(kev?.confidence).toBe('medium');
    // 0002 predates the release and may have been backported; 0003 was backported in a beta.
    expect(cves(byRule(result.findings, 'chromium/known-exploited-unverified'))).toEqual([
      'CVE-2026-0002',
    ]);
  });

  it('with release notes, confirms missing backports and accepts recorded ones', () => {
    const db = fixtureDb({ coverage: { releaseNoteMajors: [44, 43] } });
    const result = analyzeApp(app(), db, { now: NOW });
    const kev = byRule(result.findings, 'chromium/known-exploited');
    expect(cves(kev).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    expect(kev?.confidence).toBe('high');
    expect(byRule(result.findings, 'chromium/known-exploited-unverified')).toBeUndefined();

    const patched = analyzeApp(
      app({ runtime: { electron: '43.7.8', chromium: '150.0.7871.260' } }),
      db,
      { now: NOW },
    );
    expect(cves(byRule(patched.findings, 'chromium/known-exploited'))).toEqual(['CVE-2026-0002']);
    expect(byRule(patched.findings, 'electron/advisories')).toBeUndefined();
  });

  it('is clean for the latest release of a supported line', () => {
    const result = analyzeApp(
      app({ runtime: { electron: '44.9.0', chromium: '154.0.8100.1' } }),
      fixtureDb(),
      { now: NOW },
    );
    expect(result.findings).toEqual([]);
    expect(result.maxSeverity).toBeNull();
  });

  it('notes versions missing from the database', () => {
    const result = analyzeApp(
      app({ runtime: { electron: '45.0.0', chromium: '155.0.1.1' } }),
      fixtureDb(),
      { now: NOW },
    );
    expect(byRule(result.findings, 'electron/unknown-version')?.detail).toContain(
      'newer than the database',
    );
  });

  it('reports an unreadable version instead of guessing', () => {
    const result = analyzeApp(app({ runtime: {} }), fixtureDb(), { now: NOW });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'runtime/version-unreadable',
    ]);
  });

  it('reports hardening fuses, and ASAR integrity only for Windows binaries', () => {
    const fuses = decodeFuseWire(Buffer.from([1, 6, ...Buffer.from('111100')]), 0) ?? undefined;
    const linux = analyzeApp(
      app({
        runtime: { electron: '44.9.0', chromium: '154.0.8100.1' },
        ...(fuses ? { fuses } : {}),
      }),
      fixtureDb(),
      { now: NOW },
    );
    expect(linux.findings.map((finding) => finding.ruleId).sort()).toEqual([
      'fuse/inspect-arguments',
      'fuse/load-outside-asar',
      'fuse/node-options',
      'fuse/run-as-node',
    ]);
    const windows = analyzeApp(
      app({
        binary: 'C:\\App\\app.exe',
        runtime: { electron: '44.9.0', chromium: '154.0.8100.1' },
        ...(fuses ? { fuses } : {}),
      }),
      fixtureDb(),
      { now: NOW },
    );
    expect(byRule(windows.findings, 'fuse/asar-integrity-disabled')).toBeDefined();
  });
});

describe('analyzeApp: other Chromium embedders', () => {
  it('compares Qt WebEngine against its security patch level', () => {
    const result = analyzeApp(
      app({
        kind: 'qtwebengine',
        runtime: { chromium: '130.0.6723.192', chromiumSecurityPatch: '150.0.7871.1' },
      }),
      fixtureDb(),
      { now: NOW },
    );
    const kev = byRule(result.findings, 'chromium/known-exploited');
    expect(kev?.severity).toBe('high');
    expect(cves(kev).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    expect(kev?.detail).toContain('security patches up to Chromium 150.0.7871.1');
  });

  it('does not claim exposure for Qt builds without a known patch level', () => {
    const result = analyzeApp(
      app({ kind: 'qtwebengine', runtime: { chromium: '130.0.6723.192' } }),
      fixtureDb(),
      { now: NOW },
    );
    expect(byRule(result.findings, 'chromium/known-exploited')).toBeUndefined();
    expect(byRule(result.findings, 'chromium/known-exploited-unverified')).toBeDefined();
  });

  it('treats CEF as tracking upstream Chromium', () => {
    const result = analyzeApp(
      app({ kind: 'cef', runtime: { chromium: '149.0.7700.1' } }),
      fixtureDb(),
      { now: NOW },
    );
    expect(cves(byRule(result.findings, 'chromium/known-exploited')).sort()).toEqual([
      'CVE-2026-0001',
      'CVE-2026-0002',
    ]);
  });
});
