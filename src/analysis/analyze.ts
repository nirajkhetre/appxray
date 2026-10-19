import semver from 'semver';

import { fuseState } from '../binary/fuses.js';
import type { DbAdvisory, DbKevEntry, VulnDb } from '../db/schema.js';
import type { InspectedApp } from '../detect/types.js';
import { compareDotted, parseDotted } from '../util/version.js';
import {
  maxSeverity,
  type AnalyzedApp,
  type Confidence,
  type Finding,
  type Severity,
} from './types.js';

export interface AnalyzeOptions {
  now?: Date;
}

const ELECTRON_SUPPORT_DOCS = 'https://www.electronjs.org/docs/latest/tutorial/electron-timelines';
const FUSES_DOCS = 'https://www.electronjs.org/docs/latest/tutorial/fuses';
const kevUrl = (cve: string) => `https://www.cve.org/CVERecord?id=${cve}`;

const ADVISORY_SEVERITY: Record<DbAdvisory['severity'], Severity> = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
};

const day = (iso: string) => iso.slice(0, 10);
const daysBetween = (from: string, to: Date) =>
  Math.max(0, Math.floor((to.getTime() - Date.parse(from)) / 86_400_000));

/**
 * True when Chromium build `version` contains the fix. A fix may be listed for several
 * branches; a build on one of those branches is fixed from that branch's bound onwards.
 */
export function chromiumHasFix(version: string, fixedIn: readonly string[]): boolean {
  const own = parseDotted(version)?.[0];
  let highest: string | undefined;
  for (const bound of fixedIn) {
    if (!parseDotted(bound)) continue;
    if (parseDotted(bound)?.[0] === own && compareDotted(version, bound) >= 0) return true;
    if (!highest || compareDotted(bound, highest) > 0) highest = bound;
  }
  return highest !== undefined && compareDotted(version, highest) >= 0;
}

interface KevAssessment {
  exposed: { entry: DbKevEntry; confidence: Confidence; reason: string }[];
  unverified: DbKevEntry[];
}

/** Compares the app's Chromium against each known exploited Chromium vulnerability. */
function assessKev(
  db: VulnDb,
  chromium: string | undefined,
  decide: (entry: DbKevEntry) => { confidence: Confidence; reason: string } | 'fixed' | 'unknown',
): KevAssessment {
  const result: KevAssessment = { exposed: [], unverified: [] };
  for (const entry of db.chromiumKev) {
    if (entry.fixedIn.length === 0) continue;
    if (chromium && chromiumHasFix(chromium, entry.fixedIn)) continue;
    if (!chromium) {
      result.unverified.push(entry);
      continue;
    }
    const verdict = decide(entry);
    if (verdict === 'fixed') continue;
    if (verdict === 'unknown') result.unverified.push(entry);
    else result.exposed.push({ entry, ...verdict });
  }
  return result;
}

/**
 * @param runtime Sentence fragment naming what was found, e.g. "Electron 22.3.14 embeds
 *   Chromium 108.0.5359.215"; it is completed with "which predates the fix for ...".
 */
function kevFindings(
  assessment: KevAssessment,
  chromium: string | undefined,
  runtime: string,
): Finding[] {
  const findings: Finding[] = [];
  const { exposed, unverified } = assessment;
  if (exposed.length > 0) {
    const confident = exposed.some((item) => item.confidence === 'high');
    const ransomware = exposed.filter((item) => item.entry.knownRansomwareUse).length;
    findings.push({
      ruleId: 'chromium/known-exploited',
      severity: 'critical',
      confidence: confident ? 'high' : 'medium',
      title: `${exposed.length} actively exploited Chromium ${exposed.length === 1 ? 'vulnerability' : 'vulnerabilities'} not fixed`,
      detail:
        `${runtime}, which predates the fix for ` +
        `${exposed.length} ${exposed.length === 1 ? 'vulnerability' : 'vulnerabilities'} in CISA's Known Exploited Vulnerabilities catalog` +
        (ransomware > 0 ? `, ${ransomware} of them known to be used in ransomware campaigns` : '') +
        '. Newest: ' +
        exposed
          .slice(0, 3)
          .map((item) => `${item.entry.cve} (${item.entry.name})`)
          .join('; ') +
        '.',
      references: exposed.slice(0, 10).map((item) => kevUrl(item.entry.cve)),
      data: {
        cves: exposed.map((item) => ({
          cve: item.entry.cve,
          name: item.entry.name,
          fixedIn: item.entry.fixedIn,
          dateAdded: item.entry.dateAdded,
          knownRansomwareUse: item.entry.knownRansomwareUse,
          confidence: item.confidence,
          reason: item.reason,
        })),
      },
    });
  }
  if (unverified.length > 0) {
    findings.push({
      ruleId: 'chromium/known-exploited-unverified',
      severity: 'medium',
      confidence: 'low',
      title: `${unverified.length} actively exploited Chromium ${unverified.length === 1 ? 'vulnerability' : 'vulnerabilities'} not ruled out`,
      detail:
        `The embedded Chromium${chromium ? ` ${chromium}` : ''} is older than the fixed versions of ` +
        `${unverified.length} known exploited ${unverified.length === 1 ? 'vulnerability' : 'vulnerabilities'}, ` +
        'but the vendor may have backported the fixes. Check the vendor release notes or update the app.',
      references: unverified.slice(0, 10).map((entry) => kevUrl(entry.cve)),
      data: { cves: unverified.map((entry) => ({ cve: entry.cve, fixedIn: entry.fixedIn })) },
    });
  }
  return findings;
}

function electronFindings(app: InspectedApp, db: VulnDb, now: Date): Finding[] {
  const version = app.runtime.electron ? semver.valid(app.runtime.electron) : null;
  if (!version) {
    return [
      {
        ruleId: 'runtime/version-unreadable',
        severity: 'info',
        confidence: 'high',
        title: 'Electron version could not be read',
        detail: 'An Electron runtime was detected but no version string was found in its binary.',
        references: [],
      },
    ];
  }

  const findings: Finding[] = [];
  const major = semver.major(version);
  const majorInfo = db.electron.majors.find((entry) => entry.major === major);
  const release = db.electron.releases.find((entry) => entry.version === version);
  if (!release) {
    findings.push({
      ruleId: 'electron/unknown-version',
      severity: 'info',
      confidence: 'high',
      title: `Electron ${version} is not in the database`,
      detail:
        major > db.electron.latestMajor
          ? `Electron ${major} is newer than the database (latest known: ${db.electron.latestMajor}). Run "appxray db update".`
          : 'This may be a custom or unpublished build; release-based checks were skipped.',
      references: [],
    });
  }

  const supported = db.electron.supportedMajors.includes(major);
  if (!supported && majorInfo?.eolDate) {
    const days = daysBetween(majorInfo.eolDate, now);
    findings.push({
      ruleId: 'electron/end-of-life',
      severity: 'high',
      confidence: 'high',
      title: `Electron ${major} reached end of life ${days} days ago`,
      detail:
        `Electron ${major} stopped receiving security fixes on ${day(majorInfo.eolDate)}. ` +
        `Supported lines today: ${db.electron.supportedMajors.join(', ')}.`,
      references: [ELECTRON_SUPPORT_DOCS],
      data: { major, eolDate: majorInfo.eolDate, supportedMajors: db.electron.supportedMajors },
    });
  } else if (supported && majorInfo && semver.lt(version, majorInfo.latest)) {
    const newer = db.electron.releases.filter(
      (entry) =>
        !semver.prerelease(entry.version) &&
        semver.major(entry.version) === major &&
        semver.gt(entry.version, version),
    );
    const missedBackports = [...new Set(newer.flatMap((entry) => entry.backports ?? []))].sort();
    findings.push({
      ruleId: 'electron/outdated',
      severity: 'medium',
      confidence: 'high',
      title: `${newer.length} newer Electron ${major} patch ${newer.length === 1 ? 'release' : 'releases'} available (latest ${majorInfo.latest})`,
      detail:
        `The app uses Electron ${version}; Electron ${majorInfo.latest} was released on ${day(majorInfo.latestDate)}.` +
        (missedBackports.length > 0
          ? ` Newer releases include backported fixes for ${missedBackports.length} CVEs.`
          : ''),
      references: [`https://releases.electronjs.org/release/v${majorInfo.latest}`],
      data: {
        current: version,
        latest: majorInfo.latest,
        releasesBehind: newer.length,
        missedBackports,
      },
    });
  }

  const advisories = db.electron.advisories.filter((advisory) =>
    semver.satisfies(version, advisory.vulnerableVersions, { includePrerelease: true }),
  );
  if (advisories.length > 0) {
    const severity =
      maxSeverity(advisories.map((advisory) => ADVISORY_SEVERITY[advisory.severity])) ?? 'medium';
    const ordered = [...advisories].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
    findings.push({
      ruleId: 'electron/advisories',
      severity,
      confidence: 'high',
      title: `${advisories.length} Electron security ${advisories.length === 1 ? 'advisory' : 'advisories'} apply`,
      detail:
        `Electron ${version} is in the affected range of: ` +
        ordered
          .slice(0, 3)
          .map((advisory) => `${advisory.title} (${advisory.severity})`)
          .join('; ') +
        (ordered.length > 3 ? `; and ${ordered.length - 3} more.` : '.'),
      references: ordered.slice(0, 10).map((advisory) => advisory.url),
      data: {
        advisories: ordered.map((advisory) => ({
          id: advisory.id,
          title: advisory.title,
          severity: advisory.severity,
          vulnerableVersions: advisory.vulnerableVersions,
          url: advisory.url,
        })),
      },
    });
  }

  const covered = db.coverage.releaseNoteMajors.includes(major);
  const backported = new Set(
    db.electron.releases
      .filter(
        (entry) => semver.major(entry.version) === major && semver.lte(entry.version, version),
      )
      .flatMap((entry) => entry.backports ?? []),
  );
  const assessment = assessKev(db, app.runtime.chromium, (entry) => {
    if (backported.has(entry.cve)) return 'fixed';
    if (covered && release) {
      return {
        confidence: 'high',
        reason: 'no backported fix in this Electron line up to this release',
      };
    }
    if (release && entry.published && Date.parse(entry.published) > Date.parse(release.date)) {
      return {
        confidence: 'medium',
        reason: `the vulnerability was disclosed after Electron ${version} was released (${day(release.date)})`,
      };
    }
    return 'unknown';
  });
  findings.push(
    ...kevFindings(
      assessment,
      app.runtime.chromium,
      `Electron ${version} embeds Chromium ${app.runtime.chromium ?? 'of unknown version'}`,
    ),
  );
  findings.push(...fuseFindings(app));
  return findings;
}

const SEVERITY_ORDER: readonly DbAdvisory['severity'][] = ['critical', 'high', 'moderate', 'low'];

function fuseFindings(app: InspectedApp): Finding[] {
  const wire = app.fuses;
  if (!wire) return [];
  const findings: Finding[] = [];
  const enabled = (name: Parameters<typeof fuseState>[1]) => fuseState(wire, name) === 'enabled';
  const disabled = (name: Parameters<typeof fuseState>[1]) => fuseState(wire, name) === 'disabled';
  const fuse = (ruleId: Finding['ruleId'], severity: Severity, title: string, detail: string) =>
    findings.push({
      ruleId,
      severity,
      confidence: 'high',
      title,
      detail,
      references: [FUSES_DOCS],
    });

  if (enabled('RunAsNode')) {
    fuse(
      'fuse/run-as-node',
      'low',
      'ELECTRON_RUN_AS_NODE is honored',
      'Anyone who can set environment variables for this app can make its signed executable run arbitrary Node.js code. Some apps (for example code editors) rely on this; most do not.',
    );
  }
  if (enabled('EnableNodeOptionsEnvironmentVariable')) {
    fuse(
      'fuse/node-options',
      'low',
      'NODE_OPTIONS is honored',
      'NODE_OPTIONS can preload code into the app.',
    );
  }
  if (enabled('EnableNodeCliInspectArguments')) {
    fuse(
      'fuse/inspect-arguments',
      'low',
      'Debugger flags are honored',
      'Launching the app with --inspect attaches a debugger that can run code in its main process.',
    );
  }
  // Embedded ASAR integrity is implemented for Windows and macOS builds only.
  if (disabled('EnableEmbeddedAsarIntegrityValidation') && /\.exe$/i.test(app.binary)) {
    fuse(
      'fuse/asar-integrity-disabled',
      'info',
      'ASAR integrity validation is off',
      'Modified application code in app.asar is loaded without verification.',
    );
  }
  if (disabled('OnlyLoadAppFromAsar')) {
    fuse(
      'fuse/load-outside-asar',
      'info',
      'App code may load from outside app.asar',
      'Electron also searches other locations for the app entry point.',
    );
  }
  return findings;
}

function embeddedChromiumFindings(app: InspectedApp, db: VulnDb): Finding[] {
  const label = app.kind === 'qtwebengine' ? 'Qt WebEngine' : 'CEF';
  const base = app.runtime.chromium;
  // Qt WebEngine states the Chromium version its security patches reach; that is the
  // level to compare. Without it we only know the base, which vendors patch on top of.
  const patchLevel = app.runtime.chromiumSecurityPatch;
  const effective = patchLevel ?? base;
  if (!effective) {
    return [
      {
        ruleId: 'runtime/version-unreadable',
        severity: 'info',
        confidence: 'high',
        title: `${label} Chromium version could not be read`,
        detail: `A ${label} runtime was detected but its Chromium version string was not found.`,
        references: [],
      },
    ];
  }
  const knowsPatchLevel = app.kind === 'cef' || patchLevel !== undefined;
  const assessment = assessKev(db, effective, () =>
    knowsPatchLevel
      ? {
          confidence: 'medium',
          reason:
            app.kind === 'cef'
              ? 'CEF tracks Chromium releases; the bundled version predates the fix'
              : `Qt WebEngine security patches only reach Chromium ${effective}`,
        }
      : 'unknown',
  );
  const runtime = patchLevel
    ? `${label} is based on Chromium ${base ?? 'of unknown version'} with security patches up to Chromium ${patchLevel}`
    : `${label} embeds Chromium ${effective}`;
  return kevFindings(assessment, effective, runtime).map((finding) =>
    finding.ruleId === 'chromium/known-exploited' ? { ...finding, severity: 'high' } : finding,
  );
}

export function analyzeApp(
  app: InspectedApp,
  db: VulnDb,
  options: AnalyzeOptions = {},
): AnalyzedApp {
  const now = options.now ?? new Date();
  const findings =
    app.kind === 'electron' ? electronFindings(app, db, now) : embeddedChromiumFindings(app, db);
  return {
    ...app,
    findings,
    maxSeverity: maxSeverity(findings.map((finding) => finding.severity)),
  };
}
