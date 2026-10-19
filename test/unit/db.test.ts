import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  backportedCves,
  buildDb,
  chromiumKev,
  electronMajors,
  electronReleases,
  fixedFromCveRecord,
  SOURCES,
} from '../../src/db/build.js';
import { fetchJson, fetchText, HttpError, type FetchLike } from '../../src/db/http.js';
import { dbAgeDays, loadDb, readDbFile, saveDb } from '../../src/db/load.js';
import { DbValidationError, validateDb } from '../../src/db/schema.js';
import { fixtureDb } from '../fixtures/db.js';
import { tempDir } from '../helpers.js';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const packument = {
  versions: Object.fromEntries(
    [
      '40.0.0',
      '40.1.0',
      '41.0.0',
      '42.0.0',
      '42.1.0',
      '43.0.0-beta.1',
      '43.0.0',
      '43.1.0',
      'not-semver',
    ].map((v) => [v, {}]),
  ),
  time: {
    created: '2015-01-01T00:00:00Z',
    '40.0.0': '2026-01-01T00:00:00Z',
    '40.1.0': '2026-04-20T00:00:00Z',
    '41.0.0': '2026-03-01T00:00:00Z',
    '42.0.0': '2026-05-01T00:00:00Z',
    '42.1.0': '2026-06-01T00:00:00Z',
    '43.0.0-beta.1': '2026-06-02T00:00:00Z',
    '43.0.0': '2026-07-01T00:00:00Z',
    '43.1.0': '2026-08-01T00:00:00Z',
  },
};

const kevFeed = {
  vulnerabilities: [
    {
      cveID: 'CVE-2026-1111',
      vendorProject: 'Google',
      product: 'Chromium V8',
      vulnerabilityName: 'V8 bug',
      dateAdded: '2026-08-10',
      knownRansomwareCampaignUse: 'Known',
    },
    {
      cveID: 'CVE-2026-2222',
      vendorProject: 'Google',
      product: 'Chromium Mojo',
      vulnerabilityName: 'Mojo bug',
      dateAdded: '2026-07-10',
      knownRansomwareCampaignUse: 'Unknown',
    },
    {
      cveID: 'CVE-2026-3333',
      vendorProject: 'Microsoft',
      product: 'Windows',
      vulnerabilityName: 'Not Chromium',
      dateAdded: '2026-07-10',
    },
    {
      cveID: 'CVE-2026-4444',
      vendorProject: 'Google',
      product: 'Android',
      vulnerabilityName: 'Not Chromium',
      dateAdded: '2026-07-10',
    },
  ],
};

const cveRecord = (lessThan: string[]) => ({
  cveMetadata: { datePublished: '2026-08-01T00:00:00.000Z' },
  containers: {
    cna: {
      affected: [
        {
          vendor: 'Google',
          product: 'Chrome',
          versions: lessThan.map((v) => ({ version: v, status: 'affected', lessThan: v })),
        },
      ],
    },
  },
});

function mockFetch(
  overrides: Record<string, () => Response> = {},
): FetchLike & { calls: string[] } {
  const calls: string[] = [];
  const impl = vi.fn((url: string, init?: RequestInit) => {
    calls.push(url);
    if (overrides[url]) return Promise.resolve(overrides[url]());
    if (url === SOURCES.npmElectron) return Promise.resolve(json(packument));
    if (url === SOURCES.npmAdvisories) {
      const body = JSON.parse(init?.body as string) as { electron: string[] };
      expect(body.electron).toContain('43.1.0');
      return Promise.resolve(
        json({
          electron: [
            {
              url: 'https://github.com/advisories/GHSA-mpjm-v997-c4h4',
              title: 'A bug',
              severity: 'high',
              vulnerable_versions: '<43.1.0',
              cvss: { score: 7.5 },
            },
            {
              url: 'https://example.com/no-ghsa',
              title: 'Dropped',
              severity: 'low',
              vulnerable_versions: '<1.0.0',
            },
            {
              url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
              title: 'Bad range',
              severity: 'low',
              vulnerable_versions: 'nonsense',
            },
          ],
        }),
      );
    }
    if (url === SOURCES.kev) return Promise.resolve(json(kevFeed));
    if (url === SOURCES.cveRecord('CVE-2026-1111'))
      return Promise.resolve(json(cveRecord(['152.0.1.1'])));
    if (url === SOURCES.cveRecord('CVE-2026-2222'))
      return Promise.resolve(json(cveRecord(['151.0.1.1', '150.0.9.9'])));
    if (url === SOURCES.electronReleases(1)) {
      return Promise.resolve(
        json([
          {
            tag_name: 'v43.1.0',
            body: '* Security: backported fix for CVE-2026-1111. [#1]\n* Fixed CVE-2020-0000 docs typo',
          },
          { tag_name: 'v42.1.0', body: '* Security: backported fix for CVE-2026-1111.' },
          {
            tag_name: 'v43.0.0-beta.1',
            body: 'Security: backported fixes for CVE-2026-2222 and CVE-2026-1112',
          },
        ]),
      );
    }
    if (url === SOURCES.electronReleases(2))
      return Promise.resolve(json([{ tag_name: 'v39.0.0', body: '' }]));
    return Promise.resolve(new Response('not found', { status: 404 }));
  }) as unknown as FetchLike & { calls: string[] };
  impl.calls = calls;
  return impl;
}

describe('buildDb', () => {
  it('assembles a valid database from all sources', async () => {
    const db = await buildDb({
      fetchImpl: mockFetch(),
      now: () => new Date('2026-10-19T00:00:00Z'),
      releaseNoteMajors: 2,
    });
    expect(db.electron.releases.map((release) => release.version)).toEqual([
      '40.0.0',
      '40.1.0',
      '41.0.0',
      '42.0.0',
      '42.1.0',
      '43.0.0-beta.1',
      '43.0.0',
      '43.1.0',
    ]);
    expect(db.electron.latestMajor).toBe(43);
    expect(db.electron.supportedMajors).toEqual([43, 42, 41]);
    // 40 ended when 43 shipped, but it was still patched later than that.
    expect(db.electron.majors.find((major) => major.major === 40)?.eolDate).toBe(
      '2026-07-01T00:00:00Z',
    );
    expect(db.electron.advisories).toEqual([
      {
        id: 'GHSA-mpjm-v997-c4h4',
        url: 'https://github.com/advisories/GHSA-mpjm-v997-c4h4',
        title: 'A bug',
        severity: 'high',
        vulnerableVersions: '<43.1.0',
        cvss: 7.5,
      },
    ]);
    expect(
      db.chromiumKev.map((entry) => [entry.cve, entry.fixedIn, entry.knownRansomwareUse]),
    ).toEqual([
      ['CVE-2026-1111', ['152.0.1.1'], true],
      ['CVE-2026-2222', ['151.0.1.1', '150.0.9.9'], false],
    ]);
    expect(db.coverage.releaseNoteMajors).toEqual([43, 42]);
    const backports = Object.fromEntries(
      db.electron.releases.filter((r) => r.backports).map((r) => [r.version, r.backports]),
    );
    expect(backports).toEqual({
      '42.1.0': ['CVE-2026-1111'],
      '43.0.0-beta.1': ['CVE-2026-1112', 'CVE-2026-2222'],
      '43.1.0': ['CVE-2026-1111'],
    });
    expect(db.sources.every((source) => source.ok)).toBe(true);
  });

  it('falls back to the CISA GitHub mirror and degrades without release notes', async () => {
    const fetchImpl = mockFetch({
      [SOURCES.kev]: () => new Response('gone', { status: 404 }),
      [SOURCES.kevMirror]: () => json(kevFeed),
      [SOURCES.electronReleases(1)]: () => new Response('rate limited', { status: 403 }),
    });
    const db = await buildDb({ fetchImpl });
    expect(db.chromiumKev).toHaveLength(2);
    expect(db.coverage.releaseNoteMajors).toEqual([]);
    expect(db.sources.find((source) => source.name.includes('release notes'))?.ok).toBe(false);
    expect(db.sources.find((source) => source.name.includes('KEV'))?.url).toBe(SOURCES.kevMirror);
  });

  it('fails when a required source is unavailable', async () => {
    const fetchImpl = mockFetch({
      [SOURCES.npmElectron]: () => new Response('nope', { status: 404 }),
    });
    await expect(buildDb({ fetchImpl })).rejects.toThrow(/HTTP 404/);
  });

  it('sends the GitHub token only to the GitHub API', async () => {
    const fetchImpl = vi.fn(mockFetch());
    await buildDb({ fetchImpl, githubToken: 'secret-token', releaseNoteMajors: 2 });
    for (const [url, init] of fetchImpl.mock.calls) {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      expect(Boolean(headers['authorization'])).toBe(url.startsWith('https://api.github.com/'));
    }
  });
});

describe('database helpers', () => {
  it('only accepts versions that are both listed and dated', () => {
    expect(
      electronReleases({ versions: { '1.0.0': {}, '2.0.0': {} }, time: { '1.0.0': '2020-01-01' } }),
    ).toEqual([{ version: '1.0.0', date: '2020-01-01' }]);
  });

  it('marks the newest three majors as supported (no EOL date)', () => {
    const majors = electronMajors(electronReleases(packument));
    expect(majors.filter((major) => major.eolDate === null).map((major) => major.major)).toEqual([
      41, 42, 43,
    ]);
  });

  it('keeps only Google Chromium/Chrome KEV entries', () => {
    expect(chromiumKev(kevFeed).map((entry) => entry.cve)).toEqual([
      'CVE-2026-1111',
      'CVE-2026-2222',
    ]);
  });

  it('ignores non-Chrome products and malformed versions in CVE records', () => {
    expect(
      fixedFromCveRecord({
        containers: {
          cna: {
            affected: [
              {
                product: 'Chrome',
                versions: [{ lessThan: '125.0.6422.60' }, { lessThan: 'unspecified' }],
              },
              { product: 'Android', versions: [{ lessThan: '14.0.0.1' }] },
            ],
          },
        },
      }),
    ).toEqual({ fixedIn: ['125.0.6422.60'], published: null });
  });

  it('extracts CVEs only from security/backport lines', () => {
    expect(
      backportedCves(
        '* Security: backported fix for CVE-2024-1234.\n* Fixed crash (CVE-2024-9999 related docs)\n* backported fix for CVE-2024-5678',
      ),
    ).toEqual(['CVE-2024-1234', 'CVE-2024-5678']);
  });
});

describe('fetchText', () => {
  it('retries transient failures', async () => {
    let attempts = 0;
    const fetchImpl: FetchLike = () =>
      Promise.resolve(++attempts < 2 ? new Response('busy', { status: 503 }) : new Response('ok'));
    await expect(fetchText('https://example.test/', { retries: 2 }, fetchImpl)).resolves.toBe('ok');
    expect(attempts).toBe(2);
  });

  it('does not retry client errors', async () => {
    let attempts = 0;
    const fetchImpl: FetchLike = () => {
      attempts++;
      return Promise.resolve(new Response('missing', { status: 404 }));
    };
    await expect(
      fetchText('https://example.test/', { retries: 3 }, fetchImpl),
    ).rejects.toBeInstanceOf(HttpError);
    expect(attempts).toBe(1);
  });

  it('enforces the size limit', async () => {
    const fetchImpl: FetchLike = () => Promise.resolve(new Response('x'.repeat(2048)));
    await expect(fetchText('https://example.test/', { maxBytes: 1024 }, fetchImpl)).rejects.toThrow(
      /exceeded/,
    );
  });

  it('rejects invalid JSON with a clear error', async () => {
    const fetchImpl: FetchLike = () => Promise.resolve(new Response('<html>'));
    await expect(fetchJson('https://example.test/', {}, fetchImpl)).rejects.toThrow(/valid JSON/);
  });
});

describe('validateDb', () => {
  it('accepts a well-formed database', () => {
    expect(validateDb(JSON.parse(JSON.stringify(fixtureDb())))).toBeTruthy();
  });

  it.each([
    ['a newer schema', { schemaVersion: 99 }],
    ['no releases', { electron: { ...fixtureDb().electron, releases: [] } }],
    ['bad date', { generatedAt: 'yesterday' }],
    ['bad advisory', { electron: { ...fixtureDb().electron, advisories: [{ id: 'x' }] } }],
  ])('rejects %s', (_label, override) => {
    expect(() => validateDb({ ...fixtureDb(), ...override })).toThrow(DbValidationError);
  });
});

describe('loading and saving', () => {
  let dir: string;
  let cleanup: () => Promise<void>;
  const saved = {
    XDG_CACHE_HOME: process.env['XDG_CACHE_HOME'],
    LOCALAPPDATA: process.env['LOCALAPPDATA'],
  };
  beforeEach(async () => {
    ({ dir, cleanup } = await tempDir());
    process.env['XDG_CACHE_HOME'] = dir;
    process.env['LOCALAPPDATA'] = dir;
  });
  afterEach(async () => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) Reflect.deleteProperty(process.env, key);
      else process.env[key] = value;
    }
    await cleanup();
  });

  it('round-trips a database file', async () => {
    const file = path.join(dir, 'nested', 'db.json');
    await saveDb(fixtureDb(), file);
    expect((await readDbFile(file)).generatedAt).toBe(fixtureDb().generatedAt);
  });

  it('reports corrupt files clearly', async () => {
    const file = path.join(dir, 'db.json');
    await writeFile(file, '{"schemaVersion": 1, "generatedAt"');
    await expect(readDbFile(file)).rejects.toThrow(/not valid JSON/);
  });

  it('uses the per-user cache when it is newer than the bundled copy', async () => {
    const { cachedDbPath, BUNDLED_DB_PATH } = await import('../../src/db/load.js');
    const bundled = JSON.parse(await readFile(BUNDLED_DB_PATH, 'utf8')) as { generatedAt: string };
    await saveDb(fixtureDb({ generatedAt: '2999-01-01T00:00:00.000Z' }), cachedDbPath());
    expect((await loadDb()).origin).toBe('cache');
    await saveDb(fixtureDb({ generatedAt: '2000-01-01T00:00:00.000Z' }), cachedDbPath());
    const loaded = await loadDb();
    expect(loaded.origin).toBe('bundled');
    expect(loaded.db.generatedAt).toBe(bundled.generatedAt);
  });

  it('computes age in whole days', () => {
    expect(
      dbAgeDays(
        fixtureDb({ generatedAt: '2026-10-01T00:00:00Z' }),
        new Date('2026-10-15T12:00:00Z'),
      ),
    ).toBe(14);
  });
});
