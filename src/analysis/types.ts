import type { InspectedApp } from '../detect/types.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** How sure the rule is that the finding applies, given what could be observed. */
export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  confidence: Confidence;
  title: string;
  detail: string;
  references: string[];
  data?: Record<string, unknown>;
}

export interface AnalyzedApp extends InspectedApp {
  findings: Finding[];
  /** Highest severity among findings, or null when there are none. */
  maxSeverity: Severity | null;
}

export const RULES = {
  'electron/end-of-life': {
    name: 'Electron version no longer supported',
    help: 'The app ships an Electron major version that no longer receives security fixes. Update the app; if it is current, ask the vendor to move to a supported Electron line.',
  },
  'electron/outdated': {
    name: 'Electron patch releases missed',
    help: 'Newer patch releases of the same Electron line exist. They usually carry Chromium security fixes.',
  },
  'electron/advisories': {
    name: 'Electron security advisories',
    help: 'The Electron version is in the affected range of published Electron security advisories (GitHub Advisory Database).',
  },
  'chromium/known-exploited': {
    name: 'Actively exploited Chromium vulnerabilities',
    help: 'The embedded Chromium predates the fix for vulnerabilities in the CISA Known Exploited Vulnerabilities catalog, and no backported fix was found.',
  },
  'chromium/known-exploited-unverified': {
    name: 'Actively exploited Chromium vulnerabilities not ruled out',
    help: 'The embedded Chromium predates fixes for known exploited vulnerabilities, but a backported fix cannot be confirmed or excluded with the available data.',
  },
  'electron/unknown-version': {
    name: 'Unrecognized Electron version',
    help: 'The Electron version is not in the vulnerability database. It may be a custom build or newer than the database.',
  },
  'runtime/version-unreadable': {
    name: 'Runtime version not found',
    help: 'An embedded Chromium runtime was detected but its version string could not be read.',
  },
  'fuse/run-as-node': {
    name: 'ELECTRON_RUN_AS_NODE honored',
    help: 'The RunAsNode fuse is enabled, so setting ELECTRON_RUN_AS_NODE makes the app run arbitrary Node.js code under its own signed executable. Attackers use this to bypass application allowlisting. Apps that do not rely on it should disable the fuse.',
  },
  'fuse/node-options': {
    name: 'NODE_OPTIONS honored',
    help: 'The EnableNodeOptionsEnvironmentVariable fuse is enabled, so NODE_OPTIONS can inject code or flags into the app.',
  },
  'fuse/inspect-arguments': {
    name: 'Debugger arguments honored',
    help: 'The EnableNodeCliInspectArguments fuse is enabled, so --inspect flags can attach a debugger to the main process and run code in it.',
  },
  'fuse/asar-integrity-disabled': {
    name: 'ASAR integrity validation disabled',
    help: 'The app does not verify its app.asar at startup, so modified application code is loaded without complaint.',
  },
  'fuse/load-outside-asar': {
    name: 'App code may load from outside app.asar',
    help: 'The OnlyLoadAppFromAsar fuse is disabled, so Electron also looks for app code in other locations that may be easier to tamper with.',
  },
} as const;

export type RuleId = keyof typeof RULES;

export function severityRank(severity: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(severity);
}

export function maxSeverity(severities: readonly Severity[]): Severity | null {
  let best: Severity | null = null;
  for (const severity of severities) {
    if (!best || severityRank(severity) > severityRank(best)) best = severity;
  }
  return best;
}

export function parseSeverity(value: string): Severity | null {
  const normalized = value.toLowerCase();
  return (SEVERITIES as readonly string[]).includes(normalized) ? (normalized as Severity) : null;
}
