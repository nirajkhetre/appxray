/**
 * The vulnerability database is a single JSON document built from public sources by
 * `appxray db update` (see src/db/build.ts) and shipped with each release. Scans never
 * touch the network; they read this file.
 */
export const DB_SCHEMA_VERSION = 1;

export interface DbSource {
  name: string;
  url: string;
  retrievedAt: string;
  ok: boolean;
  detail?: string;
}

export interface DbElectronRelease {
  version: string;
  /** npm publish time (ISO 8601). */
  date: string;
  /** CVE ids listed as "backported fix" in the release notes, when notes were collected. */
  backports?: string[];
}

export interface DbElectronMajor {
  major: number;
  firstStable: string;
  firstStableDate: string;
  latest: string;
  latestDate: string;
  /** When the line stopped receiving fixes (release of major + 3), or null while supported. */
  eolDate: string | null;
}

export type AdvisorySeverity = 'critical' | 'high' | 'moderate' | 'low';

export interface DbAdvisory {
  /** GHSA id. */
  id: string;
  url: string;
  title: string;
  severity: AdvisorySeverity;
  /** npm semver range of affected Electron versions. */
  vulnerableVersions: string;
  cvss?: number;
}

export interface DbKevEntry {
  cve: string;
  product: string;
  name: string;
  dateAdded: string;
  knownRansomwareUse: boolean;
  /**
   * First fixed Chrome versions from the CVE record ("lessThan" bounds). Usually one; several
   * when the fix also shipped on another branch. Empty when the record has none.
   */
  fixedIn: string[];
  /** CVE publication date, used to bound what a release could have fixed. */
  published: string | null;
}

export interface VulnDb {
  schemaVersion: typeof DB_SCHEMA_VERSION;
  generatedAt: string;
  generator: string;
  sources: DbSource[];
  coverage: {
    /** Majors whose release notes (and therefore backport lists) were collected. */
    releaseNoteMajors: number[];
  };
  electron: {
    latestMajor: number;
    supportedMajors: number[];
    majors: DbElectronMajor[];
    releases: DbElectronRelease[];
    advisories: DbAdvisory[];
  };
  chromiumKev: DbKevEntry[];
}

export class DbValidationError extends Error {
  constructor(message: string) {
    super(`Invalid vulnerability database: ${message}`);
    this.name = 'DbValidationError';
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function requireArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new DbValidationError(`${label} must be an array`);
  return value;
}

/**
 * Structural validation of a parsed database. It checks the shape the scanner relies on so a
 * truncated or tampered file fails loudly instead of producing a clean-looking report.
 */
export function validateDb(raw: unknown): VulnDb {
  if (!isObject(raw)) throw new DbValidationError('root must be an object');
  if (raw['schemaVersion'] !== DB_SCHEMA_VERSION) {
    throw new DbValidationError(
      `unsupported schemaVersion ${String(raw['schemaVersion'])} (expected ${DB_SCHEMA_VERSION}); update appxray`,
    );
  }
  if (typeof raw['generatedAt'] !== 'string' || Number.isNaN(Date.parse(raw['generatedAt']))) {
    throw new DbValidationError('generatedAt must be an ISO date');
  }
  const electron = raw['electron'];
  if (!isObject(electron)) throw new DbValidationError('electron must be an object');
  if (typeof electron['latestMajor'] !== 'number') {
    throw new DbValidationError('electron.latestMajor must be a number');
  }
  const releases = requireArray(electron['releases'], 'electron.releases');
  if (releases.length === 0) throw new DbValidationError('electron.releases is empty');
  for (const release of releases) {
    if (
      !isObject(release) ||
      typeof release['version'] !== 'string' ||
      typeof release['date'] !== 'string'
    ) {
      throw new DbValidationError('electron.releases entries need version and date');
    }
  }
  requireArray(electron['majors'], 'electron.majors');
  requireArray(electron['supportedMajors'], 'electron.supportedMajors');
  for (const advisory of requireArray(electron['advisories'], 'electron.advisories')) {
    if (!isObject(advisory) || typeof advisory['vulnerableVersions'] !== 'string') {
      throw new DbValidationError('electron.advisories entries need vulnerableVersions');
    }
  }
  for (const entry of requireArray(raw['chromiumKev'], 'chromiumKev')) {
    if (!isObject(entry) || typeof entry['cve'] !== 'string') {
      throw new DbValidationError('chromiumKev entries need a cve');
    }
  }
  const coverage = raw['coverage'];
  if (!isObject(coverage)) throw new DbValidationError('coverage must be an object');
  requireArray(coverage['releaseNoteMajors'], 'coverage.releaseNoteMajors');
  requireArray(raw['sources'], 'sources');
  return raw as unknown as VulnDb;
}
