import type { Severity } from '../analysis/types.js';
import { runtimeLabel, type ScanReport } from './model.js';

export interface TextOptions {
  color: boolean;
  /** Terminal width; long cells are truncated to fit. */
  width?: number;
}

const CODES: Record<Severity | 'dim' | 'bold', [number, number]> = {
  critical: [91, 39],
  high: [31, 39],
  medium: [33, 39],
  low: [36, 39],
  info: [90, 39],
  dim: [2, 22],
  bold: [1, 22],
};

function painter(color: boolean) {
  return (style: keyof typeof CODES, text: string) =>
    color ? `\u001b[${CODES[style][0]}m${text}\u001b[${CODES[style][1]}m` : text;
}

function truncate(text: string, width: number): string {
  if (width <= 1) return text.slice(0, Math.max(0, width));
  return text.length > width ? `${text.slice(0, width - 1)}…` : text;
}

const pad = (text: string, width: number) => truncate(text, width).padEnd(width);

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    if (line && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((item) => indent + item).join('\n');
}

export function formatText(report: ScanReport, options: TextOptions): string {
  const paint = painter(options.color);
  const width = Math.max(80, Math.min(options.width ?? 120, 160));
  const out: string[] = [];
  const seconds = (report.durationMs / 1000).toFixed(1);
  const db = report.database;

  out.push(
    `${paint('bold', `${report.tool.name} ${report.tool.version}`)} · ` +
      `${report.summary.apps} ${report.summary.apps === 1 ? 'app' : 'apps'} with embedded Chromium found in ${seconds}s · ` +
      `database ${db.generatedAt.slice(0, 10)} (${db.ageDays} ${db.ageDays === 1 ? 'day' : 'days'} old)`,
  );
  if (db.stale) {
    out.push(
      paint(
        'medium',
        `! The vulnerability database is ${db.ageDays} days old. Run "appxray db update".`,
      ),
    );
  }
  if (db.releaseNoteMajors.length === 0) {
    out.push(
      paint(
        'dim',
        'Note: this database has no Electron release notes, so backported fixes cannot be confirmed. ' +
          'Run "appxray db update" with GITHUB_TOKEN set for the most precise results.',
      ),
    );
  }
  out.push('');

  if (report.apps.length === 0) {
    out.push('No apps with an embedded Chromium runtime were found.');
  } else {
    // Size columns to their content, within limits, and give the rest to the issue.
    const fit = (values: string[], header: string, max: number) =>
      Math.min(max, Math.max(header.length, ...values.map((value) => value.length)));
    const nameWidth = fit(
      report.apps.map((app) => app.name),
      'APP',
      28,
    );
    const versionWidth = fit(
      report.apps.map((app) => app.appVersion ?? '-'),
      'VERSION',
      14,
    );
    const runtimeWidth = fit(report.apps.map(runtimeLabel), 'RUNTIME', 44);
    const issueWidth = Math.max(20, width - (10 + nameWidth + versionWidth + runtimeWidth + 4));
    out.push(
      paint(
        'dim',
        `${pad('SEVERITY', 10)}${pad('APP', nameWidth)} ${pad('VERSION', versionWidth)} ${pad('RUNTIME', runtimeWidth)} TOP ISSUE`,
      ),
    );
    for (const app of report.apps) {
      const severity = app.maxSeverity;
      const label = severity
        ? paint(severity, pad(severity.toUpperCase(), 10))
        : paint('dim', pad('ok', 10));
      const top = app.findings[0]?.title ?? 'no findings at this severity';
      out.push(
        `${label}${pad(app.name, nameWidth)} ${pad(app.appVersion ?? '-', versionWidth)} ` +
          `${pad(runtimeLabel(app), runtimeWidth)} ${truncate(top, issueWidth)}`,
      );
    }

    const detailed = report.apps.filter((app) => app.findings.length > 0);
    if (detailed.length > 0) {
      out.push('', paint('bold', 'Details'));
      for (const app of detailed) {
        out.push(
          '',
          `${paint('bold', app.name)}${app.appVersion ? ` ${app.appVersion}` : ''} · ${runtimeLabel(app)}`,
        );
        out.push(paint('dim', `  ${app.binary}`));
        for (const finding of app.findings) {
          out.push(
            `  ${paint(finding.severity, pad(finding.severity.toUpperCase(), 9))}${finding.title}` +
              paint('dim', ` [${finding.ruleId}, confidence ${finding.confidence}]`),
          );
          out.push(paint('dim', wrap(finding.detail, width - 11, '           ')));
        }
        for (const note of app.notes) out.push(paint('dim', `  note: ${note}`));
        for (const item of app.evidence) {
          out.push(
            paint('dim', `  ${item.provider} ${item.providerVersion ?? ''}: ${item.summary}`),
          );
        }
        if (app.otherCopies.length > 0) {
          out.push(
            paint('dim', `  ${app.otherCopies.length} older side-by-side copies were not scanned.`),
          );
        }
      }
    }
  }

  if (report.skipped.length > 0) {
    out.push('', paint('dim', `Skipped ${report.skipped.length}:`));
    for (const item of report.skipped.slice(0, 20))
      out.push(paint('dim', `  ${item.path}: ${item.reason}`));
    if (report.skipped.length > 20)
      out.push(paint('dim', `  … and ${report.skipped.length - 20} more`));
  }

  const counts = report.summary.appsBySeverity;
  const parts = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((severity) => counts[severity] > 0)
    .map((severity) => paint(severity, `${counts[severity]} ${severity}`));
  out.push(
    '',
    `Summary: ${parts.length > 0 ? parts.join(', ') : 'no findings'}` +
      paint('dim', ` (apps by highest severity; showing ${report.minSeverity} and above)`),
  );
  return `${out.join('\n')}\n`;
}
