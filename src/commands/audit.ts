import { analyzeApp } from '../analysis/analyze.js';
import type { AnalyzedApp, Severity } from '../analysis/types.js';
import { loadDb } from '../db/load.js';
import { inspectCandidate } from '../detect/inspect.js';
import type { InspectedApp, SkippedPath } from '../detect/types.js';
import { candidatesForPaths, discoverApps, type DiscoveryResult } from '../discovery/index.js';
import { locateRea, reaFuseEvidence, ReaUnavailableError } from '../rea/adapter.js';
import { buildReport, type ScanReport } from '../report/model.js';
import { mapLimit } from '../util/concurrency.js';
import type { Logger } from '../util/log.js';
import { silentLogger } from '../util/log.js';

export interface AuditOptions {
  mode: 'scan' | 'inspect';
  /** For inspect mode: files or folders to check. */
  paths?: string[];
  /** For scan mode. */
  allUsers?: boolean;
  extraRoots?: string[];
  defaultRoots?: boolean;
  maxDirectories?: number;
  dbPath?: string;
  minSeverity: Severity;
  hash?: boolean;
  concurrency?: number;
  redactPaths?: boolean;
  deep?: { reaPath?: string; allowUntested?: boolean };
  logger?: Logger;
  signal?: AbortSignal;
  now?: () => Date;
}

export async function runAudit(options: AuditOptions): Promise<ScanReport> {
  const logger = options.logger ?? silentLogger;
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const loadedDb = await loadDb(options.dbPath);
  logger.debug(`using ${loadedDb.origin} database ${loadedDb.path}`);

  const signalOption = options.signal ? { signal: options.signal } : {};
  let discovery: DiscoveryResult;
  if (options.mode === 'inspect') {
    discovery = await candidatesForPaths(options.paths ?? [], { logger, ...signalOption });
  } else {
    logger.info('Searching for installed apps...');
    discovery = await discoverApps({
      allUsers: options.allUsers ?? false,
      extraRoots: options.extraRoots ?? [],
      defaultRoots: options.defaultRoots ?? true,
      logger,
      ...(options.maxDirectories ? { maxDirectories: options.maxDirectories } : {}),
      ...signalOption,
    });
  }
  logger.info(
    `Inspecting ${discovery.candidates.length} ${discovery.candidates.length === 1 ? 'app' : 'apps'}...`,
  );

  const skipped: SkippedPath[] = [...discovery.skipped];
  const inspected: InspectedApp[] = [];
  const outcomes = await mapLimit(discovery.candidates, options.concurrency ?? 2, (candidate) =>
    inspectCandidate(candidate, { hash: options.hash ?? true, ...signalOption }),
  );
  for (const outcome of outcomes) {
    if (outcome.ok) inspected.push(outcome.app);
    else skipped.push({ path: outcome.path, reason: outcome.reason });
  }

  if (options.deep) await addReaEvidence(inspected, options.deep, logger);

  const analyzed: AnalyzedApp[] = inspected.map((app) =>
    analyzeApp(app, loadedDb.db, { now: now() }),
  );
  return buildReport({
    mode: options.mode,
    startedAt,
    finishedAt: now(),
    loadedDb,
    apps: analyzed,
    skipped,
    directoriesVisited: discovery.directoriesVisited,
    minSeverity: options.minSeverity,
    redactPaths: options.redactPaths ?? false,
  });
}

async function addReaEvidence(
  apps: InspectedApp[],
  deep: NonNullable<AuditOptions['deep']>,
  logger: Logger,
): Promise<void> {
  let runner;
  try {
    runner = await locateRea({
      ...(deep.reaPath ? { explicitPath: deep.reaPath } : {}),
      allowUntested: deep.allowUntested ?? false,
    });
  } catch (error) {
    if (error instanceof ReaUnavailableError) {
      logger.warn(`--deep skipped: ${error.message}`);
      return;
    }
    throw error;
  }
  const electronApps = apps.filter((app) => app.kind === 'electron');
  logger.info(`Cross-checking ${electronApps.length} Electron apps with REA ${runner.version}...`);
  for (const app of electronApps) {
    const evidence = await reaFuseEvidence(runner, app.binary, app.fuses);
    app.evidence.push(evidence);
    if (evidence.agrees === false) app.notes.push(evidence.summary);
  }
}
