import { DB_SCHEMA_VERSION, type VulnDb } from '../../src/db/schema.js';

/**
 * A small, hand-written database with known answers. Dates are chosen around
 * NOW = 2026-10-19 so that each rule has a clear expected outcome.
 */
export const NOW = new Date('2026-10-19T12:00:00Z');

export function fixtureDb(overrides: Partial<VulnDb> = {}): VulnDb {
  return {
    schemaVersion: DB_SCHEMA_VERSION,
    generatedAt: '2026-10-18T00:00:00.000Z',
    generator: 'test',
    sources: [],
    coverage: { releaseNoteMajors: [] },
    electron: {
      latestMajor: 44,
      supportedMajors: [44, 43, 42],
      majors: [
        { major: 22, firstStable: '22.0.0', firstStableDate: '2022-11-30T00:00:00Z', latest: '22.3.27', latestDate: '2023-10-09T00:00:00Z', eolDate: '2023-10-09T00:00:00Z' },
        { major: 43, firstStable: '43.0.0', firstStableDate: '2026-06-30T00:00:00Z', latest: '43.8.0', latestDate: '2026-10-16T00:00:00Z', eolDate: null },
        { major: 44, firstStable: '44.0.0', firstStableDate: '2026-09-01T00:00:00Z', latest: '44.9.0', latestDate: '2026-10-17T00:00:00Z', eolDate: null },
      ],
      releases: [
        { version: '22.3.14', date: '2023-06-20T00:00:00Z' },
        { version: '22.3.27', date: '2023-10-09T00:00:00Z' },
        { version: '43.0.0-beta.2', date: '2026-06-01T00:00:00Z', backports: ['CVE-2026-0003'] },
        { version: '43.0.0', date: '2026-06-30T00:00:00Z' },
        { version: '43.7.7', date: '2026-10-01T00:00:00Z' },
        { version: '43.7.8', date: '2026-10-08T00:00:00Z', backports: ['CVE-2026-0001'] },
        { version: '43.8.0', date: '2026-10-16T00:00:00Z' },
        { version: '44.0.0', date: '2026-09-01T00:00:00Z' },
        { version: '44.9.0', date: '2026-10-17T00:00:00Z' },
      ],
      advisories: [
        { id: 'GHSA-aaaa-bbbb-cccc', url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', title: 'Old bug', severity: 'high', vulnerableVersions: '<22.3.20' },
        { id: 'GHSA-dddd-eeee-ffff', url: 'https://github.com/advisories/GHSA-dddd-eeee-ffff', title: 'New bug', severity: 'moderate', vulnerableVersions: '>=43.0.0-alpha.1 <43.7.8' },
      ],
    },
    chromiumKev: [
      // Fixed in Chrome 153; disclosed after Electron 43.7.7 shipped and backported in 43.7.8.
      { cve: 'CVE-2026-0001', product: 'Chromium V8', name: 'V8 bug', dateAdded: '2026-10-05', knownRansomwareUse: false, fixedIn: ['153.0.8010.36'], published: '2026-10-03T00:00:00Z' },
      // Fixed in Chrome 151; disclosed before 43.7.7 shipped, no backport recorded.
      { cve: 'CVE-2026-0002', product: 'Chromium', name: 'Blink bug', dateAdded: '2026-09-01', knownRansomwareUse: true, fixedIn: ['151.0.7900.10'], published: '2026-08-20T00:00:00Z' },
      // Backported during the 43 beta.
      { cve: 'CVE-2026-0003', product: 'Chromium Skia', name: 'Skia bug', dateAdded: '2026-05-20', knownRansomwareUse: false, fixedIn: ['149.0.7700.1'], published: '2026-05-15T00:00:00Z' },
      // Fixed long ago on both a stable and an extended branch.
      { cve: 'CVE-2023-0004', product: 'Chromium V8', name: 'Old V8 bug', dateAdded: '2023-04-20', knownRansomwareUse: false, fixedIn: ['112.0.5615.121', '110.0.5481.200'], published: '2023-04-14T00:00:00Z' },
      // No fixed version known: never evaluated.
      { cve: 'CVE-2016-0005', product: 'Chromium', name: 'Ancient', dateAdded: '2022-01-01', knownRansomwareUse: false, fixedIn: [], published: null },
    ],
    ...overrides,
  };
}
