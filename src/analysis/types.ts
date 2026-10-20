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
  'electron/renderer-command-execution': {
    name: 'Web content can reach command execution',
    help: 'REA traced a function that the preload script exposes to web pages through an IPC channel to a main-process handler that starts a process (child_process). If anything a page sends reaches that command, page content can run programs on the computer. Validate the sender and the arguments, or remove the capability.',
  },
  'electron/insecure-web-preferences': {
    name: 'Insecure BrowserWindow settings',
    help: 'Windows are created with settings that remove Electron security boundaries (for example nodeIntegration enabled, contextIsolation or webSecurity disabled). A bug or injected script in the page then gets far more power. This is most dangerous when the app loads remote content.',
  },
  'electron/raw-ipc-bridge': {
    name: 'Preload exposes IPC with caller-chosen channels',
    help: 'The preload bridge forwards IPC messages on channels chosen by the page, so page code can talk to any main-process handler instead of a fixed allowlist.',
  },
  'electron/ipc-sender-not-validated': {
    name: 'IPC handlers without sender checks',
    help: 'The app loads remote content and handles IPC messages, but no check of the message sender (event.senderFrame or webContents id) was found. Any frame that can send IPC can then use those handlers.',
  },
  'electron/insecure-remote-content': {
    name: 'Remote content over plain HTTP',
    help: 'The app loads content over unencrypted http://, so anyone on the network path can replace it with their own script.',
  },
  'deep/limited-coverage': {
    name: 'Code analysis was partial',
    help: 'REA could not analyze all of the selected code (minified bundles, dynamic code, parse failures or time limits). Missing findings do not prove absence.',
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
