import { deepSummary, runtimeLabel, type ScanReport } from './model.js';

const escapeHtml = (value: string) =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

/** Only http(s) links are rendered as anchors; anything else is shown as text. */
function link(url: string): string {
  return /^https?:\/\//i.test(url)
    ? `<a href="${escapeHtml(url)}" rel="noreferrer noopener" target="_blank">${escapeHtml(url)}</a>`
    : escapeHtml(url);
}

const STYLE = `
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;--card:#fff;
--critical:#b3261e;--high:#d1453b;--medium:#a86500;--low:#1f6f8b;--info:#6b6b70}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececee;--muted:#9a9aa2;--line:#2c2c30;--card:#1c1c1f;
--critical:#ff6b61;--high:#ff8a80;--medium:#f0b44c;--low:#6cc4e0;--info:#9a9aa2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:13px}
.notice{border-left:3px solid var(--medium);padding:8px 12px;background:var(--card);margin:12px 0;font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.sev{font-weight:700;font-size:12px;text-transform:uppercase}
.sev.critical{color:var(--critical)}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}
.sev.low{color:var(--low)}.sev.info,.sev.ok{color:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:10px 14px}
summary{cursor:pointer;font-weight:600}
.finding{border-top:1px solid var(--line);padding:10px 0}.finding:first-of-type{border-top:0}
.path,code{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--muted);word-break:break-all}
ul{margin:6px 0;padding-left:18px}a{color:inherit}
.table-wrap{overflow-x:auto}
`;

/** Self-contained HTML report: no scripts, no external resources. */
export function formatHtml(report: ScanReport): string {
  const counts = report.summary.appsBySeverity;
  const card = (value: number | string, label: string) =>
    `<div class="card"><b>${escapeHtml(String(value))}</b><span>${escapeHtml(label)}</span></div>`;

  const rows = report.apps
    .map((app) => {
      const severity = app.maxSeverity ?? 'ok';
      return `<tr><td class="sev ${severity}">${severity}</td><td>${escapeHtml(app.name)}</td>
<td>${escapeHtml(app.appVersion ?? '-')}</td><td>${escapeHtml(runtimeLabel(app))}</td>
<td>${escapeHtml(app.findings[0]?.title ?? 'No findings at this severity')}</td></tr>`;
    })
    .join('\n');

  const details = report.apps
    .filter((app) => app.findings.length > 0)
    .map((app) => {
      const findings = app.findings
        .map(
          (
            finding,
          ) => `<div class="finding"><span class="sev ${finding.severity}">${finding.severity}</span>
<strong>${escapeHtml(finding.title)}</strong>
<div class="meta">${escapeHtml(finding.ruleId)} · confidence ${finding.confidence}</div>
<p>${escapeHtml(finding.detail)}</p>
${finding.references.length > 0 ? `<ul>${finding.references.map((ref) => `<li>${link(ref)}</li>`).join('')}</ul>` : ''}</div>`,
        )
        .join('\n');
      return `<details${app.maxSeverity === 'critical' || app.maxSeverity === 'high' ? ' open' : ''}>
<summary>${escapeHtml(app.name)}${app.appVersion ? ` ${escapeHtml(app.appVersion)}` : ''} — ${escapeHtml(runtimeLabel(app))}</summary>
<div class="path">${escapeHtml(app.binary)}${app.binarySha256 ? `<br>sha256 ${app.binarySha256}` : ''}</div>
${findings}
${app.notes.map((note) => `<p class="meta">Note: ${escapeHtml(note)}</p>`).join('')}
${deepSummary(app) ? `<p class="meta">${escapeHtml(deepSummary(app) ?? '')}</p>` : ''}
${app.evidence.map((item) => `<p class="meta">${escapeHtml(`${item.provider} ${item.providerVersion ?? ''}: ${item.summary}`)}</p>`).join('')}
</details>`;
    })
    .join('\n');

  const notices: string[] = [];
  if (report.database.stale) {
    notices.push(
      `The vulnerability database is ${report.database.ageDays} days old. Run <code>appxray db update</code>.`,
    );
  }
  if (report.database.releaseNoteMajors.length === 0) {
    notices.push(
      'This database has no Electron release notes, so backported fixes could not be confirmed.',
    );
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>appxray report</title>
<style>${STYLE}</style>
</head>
<body><main>
<h1>Embedded Chromium report</h1>
<div class="meta">${escapeHtml(report.tool.name)} ${escapeHtml(report.tool.version)} · ${escapeHtml(report.scannedAt)} ·
${escapeHtml(report.host.platform)} ${escapeHtml(report.host.arch)} · database ${escapeHtml(report.database.generatedAt.slice(0, 10))}</div>
${notices.map((notice) => `<div class="notice">${notice}</div>`).join('\n')}
<div class="cards">
${card(report.summary.apps, 'apps found')}
${card(counts.critical, 'critical')}
${card(counts.high, 'high')}
${card(counts.medium, 'medium')}
${card(counts.low + counts.info, 'low / info')}
</div>
<h2>Apps</h2>
<div class="table-wrap"><table>
<thead><tr><th>Severity</th><th>App</th><th>Version</th><th>Runtime</th><th>Top issue</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5">No apps with an embedded Chromium runtime were found.</td></tr>'}</tbody>
</table></div>
${details ? `<h2>Details</h2>\n${details}` : ''}
${
  report.skipped.length > 0
    ? `<h2>Skipped</h2><ul>${report.skipped.map((item) => `<li><span class="path">${escapeHtml(item.path)}</span> — ${escapeHtml(item.reason)}</li>`).join('')}</ul>`
    : ''
}
<p class="meta">Findings at ${escapeHtml(report.minSeverity)} severity and above. Results describe the files on disk; they are evidence for follow-up, not proof of compromise.</p>
</main></body></html>
`;
}
