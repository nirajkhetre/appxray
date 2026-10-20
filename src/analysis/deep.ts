import semver from 'semver';

import type { PreferenceValue, SourceLocation, WindowConfig } from '../deep/posture.js';
import type { InspectedApp } from '../detect/types.js';
import type { Finding, Severity } from './types.js';

const SECURITY_DOCS = 'https://www.electronjs.org/docs/latest/tutorial/security';

export const where = (location: SourceLocation | undefined) =>
  location ? `${location.file}:${location.line}` : 'unknown location';

const isLiteral = (value: PreferenceValue | undefined, expected: unknown) =>
  value?.status === 'literal' && value.value === expected;

interface RiskySetting {
  setting: string;
  /** Severity before considering whether the app loads remote content. */
  base: Severity;
  test: (window: WindowConfig, electronMajor: number | undefined) => 'set' | 'default' | false;
}

/**
 * Settings that remove an Electron security boundary. Electron changed several defaults over
 * time (nodeIntegration off in 5, contextIsolation on in 12, sandbox on in 20), so an omitted
 * option is only flagged when the app's Electron version still had the insecure default and
 * every option of the window was visible to the analysis.
 */
const RISKY_SETTINGS: readonly RiskySetting[] = [
  {
    setting: 'nodeIntegration: true',
    base: 'high',
    test: (w, major) =>
      isLiteral(w.preferences['nodeIntegration'], true)
        ? 'set'
        : w.fullyKnown && !('nodeIntegration' in w.preferences) && major !== undefined && major < 5
          ? 'default'
          : false,
  },
  {
    setting: 'contextIsolation: false',
    base: 'high',
    test: (w, major) =>
      isLiteral(w.preferences['contextIsolation'], false)
        ? 'set'
        : w.fullyKnown &&
            !('contextIsolation' in w.preferences) &&
            major !== undefined &&
            major < 12
          ? 'default'
          : false,
  },
  {
    setting: 'webSecurity: false',
    base: 'high',
    test: (w) => (isLiteral(w.preferences['webSecurity'], false) ? 'set' : false),
  },
  {
    setting: 'allowRunningInsecureContent: true',
    base: 'high',
    test: (w) => (isLiteral(w.preferences['allowRunningInsecureContent'], true) ? 'set' : false),
  },
  {
    setting: 'nodeIntegrationInSubFrames: true',
    base: 'high',
    test: (w) => (isLiteral(w.preferences['nodeIntegrationInSubFrames'], true) ? 'set' : false),
  },
  {
    setting: 'enableRemoteModule: true',
    base: 'medium',
    test: (w) => (isLiteral(w.preferences['enableRemoteModule'], true) ? 'set' : false),
  },
  {
    setting: 'sandbox: false',
    base: 'medium',
    test: (w, major) =>
      isLiteral(w.preferences['sandbox'], false)
        ? 'set'
        : w.fullyKnown && !('sandbox' in w.preferences) && major !== undefined && major < 20
          ? 'default'
          : false,
  },
  {
    setting: 'nodeIntegrationInWorker: true',
    base: 'medium',
    test: (w) => (isLiteral(w.preferences['nodeIntegrationInWorker'], true) ? 'set' : false),
  },
];

const RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const raise = (severity: Severity): Severity =>
  severity === 'high' ? 'critical' : severity === 'medium' ? 'high' : severity;

/** Findings from REA's static analysis of the app's code (requires --deep). */
export function deepFindings(app: InspectedApp): Finding[] {
  const deep = app.deep;
  if (!deep) return [];
  const findings: Finding[] = [];
  const evidence = deep.posture?.evidenceId ? ` REA evidence ${deep.posture.evidenceId}.` : '';
  const limitedCoverage = (detail: string): Finding => ({
    ruleId: 'deep/limited-coverage',
    severity: 'info',
    confidence: 'high',
    title: 'Code analysis was partial',
    detail,
    references: [],
  });

  const posture = deep.posture;
  if (!posture) {
    return [limitedCoverage(`REA analysis did not complete: ${deep.error ?? 'unknown error'}.`)];
  }

  const remote = posture.content.filter((content) => content.remote);
  const remoteNote =
    remote.length > 0
      ? ` The app loads remote content (${remote
          .slice(0, 3)
          .map((content) => content.url)
          .join(', ')}${remote.length > 3 ? ', …' : ''}).`
      : '';
  const major = app.runtime.electron
    ? (semver.coerce(app.runtime.electron)?.major ?? undefined)
    : undefined;

  // 1. Exposed bridge function → IPC → handler → child_process.
  if (posture.attackPaths.length > 0) {
    const first = posture.attackPaths[0];
    findings.push({
      ruleId: 'electron/renderer-command-execution',
      severity: remote.length > 0 ? 'critical' : 'high',
      confidence: 'high',
      title: `Web content can reach command execution through ${posture.attackPaths.length === 1 ? 'an IPC handler' : `${posture.attackPaths.length} IPC paths`}`,
      detail:
        (first
          ? `window.${first.entry} (exposed by the preload) sends IPC "${first.channel}" to the handler at ` +
            `${where(first.handler)}, which calls child_process.${first.sink.method} at ${where(first.sink.location)}.`
          : '') +
        remoteNote +
        ' Confirm that the handler validates the sender and never passes page-controlled data to the command.' +
        evidence,
      references: [`${SECURITY_DOCS}#17-validate-the-sender-of-all-ipc-messages`],
      data: { paths: posture.attackPaths },
    });
  }

  // 2. Insecure window settings.
  const risky: {
    setting: string;
    how: 'set' | 'default';
    location?: SourceLocation;
    severity: Severity;
  }[] = [];
  for (const window of posture.windows) {
    for (const rule of RISKY_SETTINGS) {
      const how = rule.test(window, major);
      if (!how) continue;
      const item: (typeof risky)[number] = {
        setting: rule.setting,
        how,
        severity: remote.length > 0 ? raise(rule.base) : rule.base,
      };
      if (window.location) item.location = window.location;
      risky.push(item);
    }
  }
  if (risky.length > 0) {
    const severity = risky.reduce<Severity>(
      (max, item) => (RANK[item.severity] > RANK[max] ? item.severity : max),
      'info',
    );
    const settings = [...new Set(risky.map((item) => item.setting))];
    findings.push({
      ruleId: 'electron/insecure-web-preferences',
      severity,
      confidence: 'high',
      title: `Insecure window settings: ${settings.join(', ')}`,
      detail:
        risky
          .slice(0, 4)
          .map(
            (item) =>
              `${item.setting} ${item.how === 'default' ? `(Electron ${major ?? '?'} default)` : 'set'} at ${where(item.location)}`,
          )
          .join('; ') +
        (risky.length > 4 ? `; and ${risky.length - 4} more` : '') +
        '.' +
        remoteNote +
        evidence,
      references: [SECURITY_DOCS],
      data: { settings: risky },
    });
  }

  // 3. Preload forwarding caller-chosen channels.
  const raw = posture.bridgeCalls.filter((call) => call.channel === null);
  if (raw.length > 0) {
    findings.push({
      ruleId: 'electron/raw-ipc-bridge',
      severity: remote.length > 0 ? 'high' : 'medium',
      confidence: 'medium',
      title: `Preload lets pages pick IPC channels (${raw
        .slice(0, 3)
        .map((call) => `window.${call.entry}`)
        .join(', ')})`,
      detail:
        `${raw.length} exposed bridge ${raw.length === 1 ? 'function forwards' : 'functions forward'} IPC messages on a channel supplied by the caller, so page code is not limited to an allowlist of channels.` +
        remoteNote +
        evidence,
      references: [`${SECURITY_DOCS}#20-do-not-expose-electron-apis-to-untrusted-web-content`],
      data: { entries: raw.map((call) => call.entry) },
    });
  }

  // 4. Remote content + IPC handlers + no sender checks.
  if (
    remote.length > 0 &&
    posture.mainHandlers.length > 0 &&
    posture.senderValidationCandidates === 0
  ) {
    findings.push({
      ruleId: 'electron/ipc-sender-not-validated',
      severity: 'medium',
      confidence: 'medium',
      title: `${posture.mainHandlers.length} IPC ${posture.mainHandlers.length === 1 ? 'handler' : 'handlers'} with no sender check found`,
      detail:
        `Handlers for ${posture.mainHandlers
          .slice(0, 4)
          .map((handler) => `"${handler.channel ?? '(dynamic)'}"`)
          .join(', ')} were found, but no comparison of the IPC sender in the analyzed code.` +
        remoteNote +
        evidence,
      references: [`${SECURITY_DOCS}#17-validate-the-sender-of-all-ipc-messages`],
      data: { channels: posture.mainHandlers.map((handler) => handler.channel) },
    });
  }

  // 5. Plain HTTP content.
  const insecure = posture.content.filter((content) => content.insecureTransport);
  if (insecure.length > 0) {
    findings.push({
      ruleId: 'electron/insecure-remote-content',
      severity: 'medium',
      confidence: 'high',
      title: `Loads content over plain HTTP (${insecure[0]?.url ?? ''})`,
      detail: `${insecure.length} URL${insecure.length === 1 ? '' : 's'} loaded into the app use http://.${evidence}`,
      references: [`${SECURITY_DOCS}#1-only-load-secure-content`],
      data: { urls: insecure.map((content) => content.url) },
    });
  }

  // 6. Coverage.
  const gaps: string[] = [];
  if (!posture.coverage.complete) gaps.push('REA reported partial coverage');
  if (posture.coverage.parseFailures > 0)
    gaps.push(`${posture.coverage.parseFailures} files could not be parsed`);
  if (deep.omittedFiles > 0)
    gaps.push(`${deep.omittedFiles} relevant files exceeded the analysis budget`);
  const selectedWindowCode = Object.values(deep.analyzedFiles).some((labels) =>
    labels.includes('webPreferences'),
  );
  if (selectedWindowCode && posture.windows.length === 0) {
    gaps.push(
      'window creation code was found but its settings could not be resolved (often minified or bundled code)',
    );
  }
  if (gaps.length > 0)
    findings.push(limitedCoverage(`${gaps.join('; ')}. Missing findings do not prove absence.`));
  return findings;
}
