import { analyzeApp } from '../analysis/analyze.js';
import type { AnalyzedApp, Severity } from '../analysis/types.js';
import { loadDb } from '../db/load.js';
import { inspectCandidate } from '../detect/inspect.js';
import type { InspectedApp, SkippedPath } from '../detect/types.js';
import { candidatesForPaths, discoverApps, type DiscoveryResult } from '../discovery/index.js';
import { deepAnalyze } from '../deep/analyze.js';
import { reaFuseEvidence } from '../rea/fuses.js';
import { locateRea, ReaUnavailableError } from '../rea/runner.js';
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
  deep?: {
    reaPath?: string;
    allowUntested?: boolean;
    /** Upper bound for REA's code analysis of one app. */
    timeoutMs?: number;
    /** Apps analyzed by REA in parallel. Default 1: REA itself uses several cores. */
    concurrency?: number;
  };
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

  if (options.deep) await addDeepAnalysis(inspected, options.deep, logger);

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

/**
 * REA-powered deep analysis: an independent fuse reading, and static analysis of the app's
 * security-relevant JavaScript (windows, preload bridges, IPC, command execution).
 */
async function addDeepAnalysis(
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
  logger.info(
    `Analyzing ${electronApps.length} Electron ${electronApps.length === 1 ? 'app' : 'apps'} with REA ${runner.version} (${runner.origin})...`,
  );
  await mapLimit(electronApps, deep.concurrency ?? 1, async (app) => {
    const evidence = await reaFuseEvidence(runner, app.binary, app.fuses);
    app.evidence.push(evidence);
    if (evidence.agrees === false) app.notes.push(evidence.summary);
    if (!app.appBundle) return;
    logger.info(`  ${app.name}: analyzing code...`);
    app.deep = await deepAnalyze(
      app.appBundle,
      runner,
      deep.timeoutMs ? { timeoutMs: deep.timeoutMs } : {},
    );
    if (app.deep.error) logger.warn(`${app.name}: deep analysis incomplete: ${app.deep.error}`);
    else
      logger.debug(
        `${app.name}: REA analyzed ${Object.keys(app.deep.analyzedFiles).length} files in ${app.deep.durationMs} ms`,
      );
  });
}
