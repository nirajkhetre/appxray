/**
 * Programmatic API. The CLI (src/cli.ts) is a thin layer over these functions.
 */
export { runAudit, type AuditOptions } from './commands/audit.js';
export { analyzeApp, chromiumHasFix } from './analysis/analyze.js';
export {
  RULES,
  SEVERITIES,
  type AnalyzedApp,
  type Finding,
  type RuleId,
  type Severity,
} from './analysis/types.js';
export { scanBinary, type BinaryScanResult } from './binary/scan.js';
export { decodeFuseWire, FUSE_V1_NAMES, type FuseWire } from './binary/fuses.js';
export { buildDb } from './db/build.js';
export { loadDb, saveDb, readDbFile } from './db/load.js';
export { validateDb, type VulnDb } from './db/schema.js';
export { inspectCandidate } from './detect/inspect.js';
export type { AppCandidate, InspectedApp, RuntimeKind } from './detect/types.js';
export { candidatesForPaths, discoverApps } from './discovery/index.js';
export { buildReport, type ScanReport } from './report/model.js';
export { formatHtml } from './report/html.js';
export { formatSarif } from './report/sarif.js';
export { formatText } from './report/text.js';
