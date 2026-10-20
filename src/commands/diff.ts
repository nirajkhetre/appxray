import type { AnalyzedApp, Finding, Severity } from '../analysis/types.js';
import { runtimeLabel } from '../report/model.js';
import { runAudit, type AuditOptions } from './audit.js';

/**
 * Compares two builds of the same app, typically an installed version and its update, or the
 * previous and current build output in CI. It reports what changed in the runtime, the fuses,
 * the findings and, with REA's code analysis, the app's Electron attack surface.
 */
export interface SetChange {
  added: string[];
  removed: string[];
}

export interface AppDiff {
  schemaVersion: 1;
  old: AppIdentity;
  new: AppIdentity;
  runtime: {
    electron?: [string | undefined, string | undefined];
    chromium?: [string | undefined, string | undefined];
  };
  fuses: { name: string; from: string; to: string }[];
  findings: { added: Finding[]; resolved: Finding[]; changed: { from: Finding; to: Finding }[] };
  /** Present when both builds were analyzed with REA. */
  surface?: {
    exposedFunctions: SetChange;
    ipcHandlers: SetChange;
    remoteContent: SetChange;
    nativeAddons: SetChange;
    commandExecutionPaths: SetChange;
    insecureSettings: SetChange;
  };
  verdict: 'riskier' | 'safer' | 'mixed' | 'unchanged';
}

interface AppIdentity {
  name: string;
  version?: string;
  runtime: string;
  path: string;
  maxSeverity: Severity | null;
}

function identity(app: AnalyzedApp): AppIdentity {
  const result: AppIdentity = {
    name: app.name,
    runtime: runtimeLabel(app),
    path: app.root,
    maxSeverity: app.maxSeverity,
  };
  if (app.appVersion) result.version = app.appVersion;
  return result;
}

function setChange(before: Iterable<string>, after: Iterable<string>): SetChange {
  const a = new Set(before);
  const b = new Set(after);
  return {
    added: [...b].filter((item) => !a.has(item)).sort(),
    removed: [...a].filter((item) => !b.has(item)).sort(),
  };
}

function surfaceOf(app: AnalyzedApp) {
  const posture = app.deep?.posture;
  if (!posture) return undefined;
  const settings = app.findings.find(
    (finding) => finding.ruleId === 'electron/insecure-web-preferences',
  );
  const insecure = ((settings?.data?.['settings'] ?? []) as { setting: string }[]).map(
    (item) => item.setting,
  );
  return {
    exposedFunctions: posture.bridges.flatMap((bridge) =>
      bridge.members.map((member) => `${bridge.apiKey}.${member}`),
    ),
    ipcHandlers: posture.mainHandlers.map(
      (handler) => `${handler.mode}:${handler.channel ?? '(dynamic)'}`,
    ),
    remoteContent: posture.content
      .filter((content) => content.remote)
      .map((content) => content.url),
    nativeAddons: posture.nativeAddons.map((addon) => addon.path),
    commandExecutionPaths: posture.attackPaths.map(
      (path) => `window.${path.entry} -> ${path.channel} -> ${path.sink.method}`,
    ),
    insecureSettings: insecure,
  };
}

export function diffApps(before: AnalyzedApp, after: AnalyzedApp): AppDiff {
  const runtime: AppDiff['runtime'] = {};
  if (before.runtime.electron !== after.runtime.electron)
    runtime.electron = [before.runtime.electron, after.runtime.electron];
  if (before.runtime.chromium !== after.runtime.chromium)
    runtime.chromium = [before.runtime.chromium, after.runtime.chromium];

  const fuses: AppDiff['fuses'] = [];
  const oldFuses = new Map(before.fuses?.fuses.map((fuse) => [fuse.name, fuse.state]) ?? []);
  for (const fuse of after.fuses?.fuses ?? []) {
    const previous = oldFuses.get(fuse.name) ?? 'absent';
    if (previous !== fuse.state) fuses.push({ name: fuse.name, from: previous, to: fuse.state });
  }

  const oldByRule = new Map(before.findings.map((finding) => [finding.ruleId, finding]));
  const newByRule = new Map(after.findings.map((finding) => [finding.ruleId, finding]));
  const findings: AppDiff['findings'] = { added: [], resolved: [], changed: [] };
  for (const [rule, finding] of newByRule) {
    const previous = oldByRule.get(rule);
    if (!previous) findings.added.push(finding);
    else if (previous.title !== finding.title || previous.severity !== finding.severity) {
      findings.changed.push({ from: previous, to: finding });
    }
  }
  for (const [rule, finding] of oldByRule)
    if (!newByRule.has(rule)) findings.resolved.push(finding);

  const diff: AppDiff = {
    schemaVersion: 1,
    old: identity(before),
    new: identity(after),
    runtime,
    fuses,
    findings,
    verdict: 'unchanged',
  };

  const a = surfaceOf(before);
  const b = surfaceOf(after);
  if (a && b) {
    diff.surface = {
      exposedFunctions: setChange(a.exposedFunctions, b.exposedFunctions),
      ipcHandlers: setChange(a.ipcHandlers, b.ipcHandlers),
      remoteContent: setChange(a.remoteContent, b.remoteContent),
      nativeAddons: setChange(a.nativeAddons, b.nativeAddons),
      commandExecutionPaths: setChange(a.commandExecutionPaths, b.commandExecutionPaths),
      insecureSettings: setChange(a.insecureSettings, b.insecureSettings),
    };
  }

  // Weighted so one critical outweighs several medium findings.
  const weight: Record<Severity, number> = { critical: 100, high: 30, medium: 8, low: 1, info: 0 };
  const risk = (app: AnalyzedApp) =>
    app.findings.reduce((sum, finding) => sum + weight[finding.severity], 0);
  const delta = risk(after) - risk(before);
  const moved =
    findings.added.length + findings.resolved.length + findings.changed.length > 0 ||
    Object.values(diff.surface ?? {}).some(
      (change) => change.added.length + change.removed.length > 0,
    );
  diff.verdict = delta > 0 ? 'riskier' : delta < 0 ? 'safer' : moved ? 'mixed' : 'unchanged';
  return diff;
}

export async function runDiff(
  oldPath: string,
  newPath: string,
  options: Omit<AuditOptions, 'mode' | 'paths' | 'minSeverity'>,
): Promise<AppDiff> {
  const pick = async (target: string) => {
    const report = await runAudit({
      ...options,
      mode: 'inspect',
      paths: [target],
      minSeverity: 'info',
    });
    if (report.apps.length !== 1) {
      throw new Error(
        `expected one app in ${target}, found ${report.apps.length}; point at a single app folder or binary`,
      );
    }
    return report.apps[0] as AnalyzedApp;
  };
  return diffApps(await pick(oldPath), await pick(newPath));
}

export function formatDiffText(diff: AppDiff): string {
  const out: string[] = [];
  const label = (app: AppIdentity) =>
    `${app.name}${app.version ? ` ${app.version}` : ''} (${app.runtime})`;
  out.push(
    `${label(diff.old)}  ->  ${label(diff.new)}`,
    `Verdict: ${diff.verdict.toUpperCase()}`,
    '',
  );
  if (diff.runtime.electron)
    out.push(`Electron: ${diff.runtime.electron[0] ?? '?'} -> ${diff.runtime.electron[1] ?? '?'}`);
  if (diff.runtime.chromium)
    out.push(`Chromium: ${diff.runtime.chromium[0] ?? '?'} -> ${diff.runtime.chromium[1] ?? '?'}`);
  for (const fuse of diff.fuses) out.push(`Fuse ${fuse.name}: ${fuse.from} -> ${fuse.to}`);

  const section = (title: string, items: string[]) => {
    if (items.length === 0) return;
    out.push('', title);
    for (const item of items) out.push(`  ${item}`);
  };
  section(
    'New findings:',
    diff.findings.added.map((f) => `+ [${f.severity}] ${f.title}`),
  );
  section(
    'Resolved findings:',
    diff.findings.resolved.map((f) => `- [${f.severity}] ${f.title}`),
  );
  section(
    'Changed findings:',
    diff.findings.changed.map(
      (c) => `~ [${c.from.severity} -> ${c.to.severity}] ${c.from.title}  =>  ${c.to.title}`,
    ),
  );
  if (diff.surface) {
    const s = diff.surface;
    const change = (name: string, value: SetChange) => [
      ...value.added.map((item) => `+ ${name}: ${item}`),
      ...value.removed.map((item) => `- ${name}: ${item}`),
    ];
    section('Attack surface (REA code analysis):', [
      ...change('command execution path', s.commandExecutionPaths),
      ...change('insecure setting', s.insecureSettings),
      ...change('exposed function', s.exposedFunctions),
      ...change('IPC handler', s.ipcHandlers),
      ...change('remote content', s.remoteContent),
      ...change('native add-on', s.nativeAddons),
    ]);
  } else {
    out.push('', 'Run with --deep to compare the attack surface with REA as well.');
  }
  return `${out.join('\n')}\n`;
}
