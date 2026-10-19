import semver from 'semver';

import type { Logger } from '../util/log.js';
import { silentLogger } from '../util/log.js';
import { mapLimit } from '../util/concurrency.js';
import { packageInfo } from '../util/pkg.js';
import { parseDotted } from '../util/version.js';
import { fetchJson, fetchText, type FetchLike } from './http.js';
import {
  DB_SCHEMA_VERSION,
  validateDb,
  type AdvisorySeverity,
  type DbAdvisory,
  type DbElectronMajor,
  type DbElectronRelease,
  type DbKevEntry,
  type DbSource,
  type VulnDb,
} from './schema.js';

export const SOURCES = {
  npmElectron: 'https://registry.npmjs.org/electron',
  npmAdvisories: 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  kevMirror:
    'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
  cveRecord: (cve: string) => {
    const [, year, number] = cve.split('-');
    const bucket = `${Math.floor(Number(number) / 1000)}xxx`;
    return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${cve}.json`;
  },
  electronReleases: (page: number) =>
    `https://api.github.com/repos/electron/electron/releases?per_page=100&page=${page}`,
} as const;

/** Electron supports the latest three stable major lines. */
export const SUPPORTED_MAJOR_COUNT = 3;

export interface BuildOptions {
  fetchImpl?: FetchLike;
  githubToken?: string;
  /** How many of the newest majors to collect release notes for. */
  releaseNoteMajors?: number;
  logger?: Logger;
  now?: () => Date;
}

interface NpmPackument {
  versions?: Record<string, unknown>;
  time?: Record<string, string>;
}

interface NpmAdvisory {
  url?: string;
  title?: string;
  severity?: string;
  vulnerable_versions?: string;
  cvss?: { score?: number };
}

interface KevFeed {
  vulnerabilities?: {
    cveID?: string;
    vendorProject?: string;
    product?: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    knownRansomwareCampaignUse?: string;
  }[];
}

interface CveRecord {
  cveMetadata?: { datePublished?: string };
  containers?: {
    cna?: {
      affected?: {
        vendor?: string;
        product?: string;
        versions?: { lessThan?: string; status?: string }[];
      }[];
    };
  };
}

interface GithubRelease {
  tag_name?: string;
  body?: string | null;
  draft?: boolean;
}

/** Rebuilds the database from public sources. Throws if a required source is unavailable. */
export async function buildDb(options: BuildOptions = {}): Promise<VulnDb> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const logger = options.logger ?? silentLogger;
  const now = options.now ?? (() => new Date());
  const sources: DbSource[] = [];
  const record = (name: string, url: string, ok: boolean, detail?: string) => {
    const source: DbSource = { name, url, retrievedAt: now().toISOString(), ok };
    if (detail) source.detail = detail;
    sources.push(source);
  };

  logger.info('Fetching Electron release history from npm...');
  const packument = await fetchJson<NpmPackument>(
    SOURCES.npmElectron,
    { maxBytes: 256 * 1024 * 1024, timeoutMs: 120_000 },
    fetchImpl,
  );
  const releases = electronReleases(packument);
  if (releases.length === 0) throw new Error('npm returned no Electron releases');
  record('npm: electron versions', SOURCES.npmElectron, true, `${releases.length} versions`);

  const majors = electronMajors(releases);
  const latestMajor = Math.max(...majors.map((major) => major.major));
  const supportedMajors = majors
    .map((major) => major.major)
    .sort((a, b) => b - a)
    .slice(0, SUPPORTED_MAJOR_COUNT);

  logger.info('Fetching Electron security advisories...');
  const advisories = await fetchAdvisories(
    releases.map((release) => release.version),
    fetchImpl,
  );
  record(
    'GitHub Advisory Database via npm',
    SOURCES.npmAdvisories,
    true,
    `${advisories.length} advisories`,
  );

  logger.info('Fetching CISA Known Exploited Vulnerabilities...');
  const { feed, url: kevUrl } = await fetchKev(fetchImpl, logger);
  const kevBase = chromiumKev(feed);
  record('CISA KEV catalog', kevUrl, true, `${kevBase.length} Chromium entries`);

  logger.info(`Resolving fixed Chrome versions for ${kevBase.length} CVEs...`);
  let unresolved = 0;
  const chromiumKevEntries = await mapLimit(kevBase, 8, async (entry) => {
    try {
      const cve = await fetchJson<CveRecord>(
        SOURCES.cveRecord(entry.cve),
        { maxBytes: 4 * 1024 * 1024 },
        fetchImpl,
      );
      const resolved = { ...entry, ...fixedFromCveRecord(cve) };
      if (resolved.fixedIn.length === 0) unresolved++;
      return resolved;
    } catch (error) {
      unresolved++;
      logger.debug(`${entry.cve}: ${(error as Error).message}`);
      return entry;
    }
  });
  record(
    'CVE List V5 (CVE Program)',
    'https://github.com/CVEProject/cvelistV5',
    unresolved < kevBase.length,
    `${kevBase.length - unresolved}/${kevBase.length} CVEs with fixed versions`,
  );

  const noteMajors = majors
    .map((major) => major.major)
    .sort((a, b) => b - a)
    .slice(0, options.releaseNoteMajors ?? 6);
  logger.info(`Collecting Electron release notes for majors ${noteMajors.join(', ')}...`);
  let coveredMajors: number[] = [];
  try {
    const backports = await fetchBackports(Math.min(...noteMajors), fetchImpl, options.githubToken);
    for (const release of releases) {
      const cves = backports.get(release.version);
      if (cves && cves.length > 0) release.backports = cves;
    }
    coveredMajors = noteMajors;
    record(
      'Electron release notes (GitHub)',
      SOURCES.electronReleases(1),
      true,
      `${backports.size} releases`,
    );
  } catch (error) {
    const message = (error as Error).message;
    logger.warn(
      `Could not collect Electron release notes (${message}). Backported fixes will be unknown; ` +
        'set GITHUB_TOKEN to avoid GitHub API rate limits.',
    );
    record('Electron release notes (GitHub)', SOURCES.electronReleases(1), false, message);
  }

  const db: VulnDb = {
    schemaVersion: DB_SCHEMA_VERSION,
    generatedAt: now().toISOString(),
    generator: `appxray ${packageInfo().version}`,
    sources,
    coverage: { releaseNoteMajors: coveredMajors },
    electron: { latestMajor, supportedMajors, majors, releases, advisories },
    chromiumKev: chromiumKevEntries.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded)),
  };
  return validateDb(JSON.parse(JSON.stringify(db)));
}

/** All published, non-deprecated-by-unpublish versions with their publish dates. */
export function electronReleases(packument: NpmPackument): DbElectronRelease[] {
  const versions = packument.versions ?? {};
  const time = packument.time ?? {};
  return Object.keys(versions)
    .filter((version) => semver.valid(version) && typeof time[version] === 'string')
    .map((version) => ({ version, date: time[version] as string }))
    .sort((a, b) => semver.compare(a.version, b.version));
}

export function electronMajors(releases: readonly DbElectronRelease[]): DbElectronMajor[] {
  const stable = releases.filter((release) => !semver.prerelease(release.version));
  const byMajor = new Map<number, DbElectronRelease[]>();
  for (const release of stable) {
    const major = semver.major(release.version);
    const list = byMajor.get(major) ?? [];
    list.push(release);
    byMajor.set(major, list);
  }
  const majors: DbElectronMajor[] = [];
  for (const [major, list] of byMajor) {
    list.sort((a, b) => semver.compare(a.version, b.version));
    const first = list[0] as DbElectronRelease;
    const last = list[list.length - 1] as DbElectronRelease;
    majors.push({
      major,
      firstStable: first.version,
      firstStableDate: first.date,
      latest: last.version,
      latestDate: last.date,
      eolDate: null,
    });
  }
  majors.sort((a, b) => a.major - b.major);
  for (const entry of majors) {
    const successor = majors.find((other) => other.major === entry.major + SUPPORTED_MAJOR_COUNT);
    // A line is out of support once major+3 ships, unless it kept receiving releases after
    // that (Electron 22 was extended for Windows 7); its last release then marks the end.
    entry.eolDate = successor
      ? ([successor.firstStableDate, entry.latestDate].sort().at(-1) ?? null)
      : null;
  }
  return majors;
}

const SEVERITIES: readonly AdvisorySeverity[] = ['critical', 'high', 'moderate', 'low'];

async function fetchAdvisories(
  versions: readonly string[],
  fetchImpl: FetchLike,
): Promise<DbAdvisory[]> {
  const response = await fetchJson<Record<string, NpmAdvisory[] | undefined>>(
    SOURCES.npmAdvisories,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ electron: versions }),
    },
    fetchImpl,
  );
  const advisories: DbAdvisory[] = [];
  for (const raw of response['electron'] ?? []) {
    const id = /GHSA(-[23456789cfghjmpqrvwx]{4}){3}/.exec(raw.url ?? '')?.[0];
    const range = raw.vulnerable_versions;
    if (!id || !raw.url || !range || !semver.validRange(range)) continue;
    const severity = SEVERITIES.find((value) => value === raw.severity) ?? 'moderate';
    const advisory: DbAdvisory = {
      id,
      url: raw.url,
      title: raw.title ?? id,
      severity,
      vulnerableVersions: range,
    };
    if (typeof raw.cvss?.score === 'number' && raw.cvss.score > 0) advisory.cvss = raw.cvss.score;
    advisories.push(advisory);
  }
  return advisories.sort((a, b) => a.id.localeCompare(b.id));
}

async function fetchKev(
  fetchImpl: FetchLike,
  logger: Logger,
): Promise<{ feed: KevFeed; url: string }> {
  try {
    return { feed: await fetchJson<KevFeed>(SOURCES.kev, {}, fetchImpl), url: SOURCES.kev };
  } catch (error) {
    logger.warn(`CISA feed unavailable (${(error as Error).message}); using CISA's GitHub mirror.`);
    return {
      feed: await fetchJson<KevFeed>(SOURCES.kevMirror, {}, fetchImpl),
      url: SOURCES.kevMirror,
    };
  }
}

export function chromiumKev(feed: KevFeed): DbKevEntry[] {
  const entries: DbKevEntry[] = [];
  for (const item of feed.vulnerabilities ?? []) {
    if (!item.cveID || !/^CVE-\d{4}-\d{4,}$/.test(item.cveID)) continue;
    if (item.vendorProject?.toLowerCase() !== 'google') continue;
    if (!/^(chromium|chrome)\b/i.test(item.product ?? '')) continue;
    entries.push({
      cve: item.cveID,
      product: item.product ?? 'Chromium',
      name: item.vulnerabilityName ?? item.cveID,
      dateAdded: item.dateAdded ?? '',
      knownRansomwareUse: item.knownRansomwareCampaignUse?.toLowerCase() === 'known',
      fixedIn: [],
      published: null,
    });
  }
  return entries;
}

export function fixedFromCveRecord(record: CveRecord): Pick<DbKevEntry, 'fixedIn' | 'published'> {
  const fixed = new Set<string>();
  for (const affected of record.containers?.cna?.affected ?? []) {
    if (!/chrome|chromium/i.test(affected.product ?? '')) continue;
    for (const version of affected.versions ?? []) {
      if (version.lessThan && parseDotted(version.lessThan)) fixed.add(version.lessThan);
    }
  }
  const published = record.cveMetadata?.datePublished;
  return {
    fixedIn: [...fixed],
    published: published && !Number.isNaN(Date.parse(published)) ? published : null,
  };
}

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/g;

/** Extracts CVE ids from release-note lines that describe security backports. */
export function backportedCves(body: string): string[] {
  const cves = new Set<string>();
  for (const line of body.split(/\r?\n/)) {
    if (!/backport|security/i.test(line)) continue;
    for (const match of line.matchAll(CVE_PATTERN)) cves.add(match[0]);
  }
  return [...cves].sort();
}

async function fetchBackports(
  minMajor: number,
  fetchImpl: FetchLike,
  token?: string,
): Promise<Map<string, string[]>> {
  const headers: Record<string, string> = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
  };
  if (token) headers['authorization'] = `Bearer ${token}`;
  const result = new Map<string, string[]>();
  for (let page = 1; page <= 50; page++) {
    const text = await fetchText(
      SOURCES.electronReleases(page),
      { headers, retries: 2 },
      fetchImpl,
    );
    const releases = JSON.parse(text) as GithubRelease[];
    if (!Array.isArray(releases) || releases.length === 0) return result;
    let relevant = 0;
    for (const release of releases) {
      const version = semver.valid(release.tag_name ?? '');
      if (!version || release.draft) continue;
      if (semver.major(version) < minMajor) continue;
      relevant++;
      result.set(version, backportedCves(release.body ?? ''));
    }
    // Releases are newest first; once a full page predates the window we are done.
    if (relevant === 0) return result;
  }
  throw new Error('release history is longer than expected; refusing to report partial coverage');
}
