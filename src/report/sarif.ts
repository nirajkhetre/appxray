import { pathToFileURL } from 'node:url';

import { RULES, type RuleId, type Severity } from '../analysis/types.js';
import { packageInfo } from '../util/pkg.js';
import type { ScanReport } from './model.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub code scanning reads `security-severity` (0-10) to rank alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

/** SARIF 2.1.0 output for CI systems and GitHub code scanning. */
export function formatSarif(report: ScanReport): string {
  const ruleIds = Object.keys(RULES) as RuleId[];
  const results = report.apps.flatMap((app) =>
    app.findings.map((finding) => ({
      ruleId: finding.ruleId,
      ruleIndex: ruleIds.indexOf(finding.ruleId),
      level: LEVEL[finding.severity],
      message: { text: `${app.name}: ${finding.title}. ${finding.detail}` },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri: pathToFileURL(app.binary).href } },
        },
      ],
      partialFingerprints: { appxrayFinding: `${app.id}/${finding.ruleId}` },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        'security-severity': SECURITY_SEVERITY[finding.severity],
        app: { name: app.name, version: app.appVersion ?? null, runtime: app.runtime },
        references: finding.references,
      },
    })),
  );
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            version: report.tool.version,
            ...(packageInfo().homepage ? { informationUri: packageInfo().homepage } : {}),
            rules: ruleIds.map((id) => ({
              id,
              name: RULES[id].name,
              shortDescription: { text: RULES[id].name },
              fullDescription: { text: RULES[id].help },
              help: { text: RULES[id].help },
            })),
          },
        },
        invocations: [{ executionSuccessful: true, startTimeUtc: report.scannedAt }],
        results,
        properties: { database: report.database },
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}
