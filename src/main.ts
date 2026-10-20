import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs, type ParseArgsConfig } from 'node:util';

import { parseSeverity, severityRank, type Severity } from './analysis/types.js';
import { runAudit } from './commands/audit.js';
import { formatDiffText, runDiff } from './commands/diff.js';
import { buildDb } from './db/build.js';
import { cachedDbPath, dbAgeDays, loadDb, saveDb, STALE_AFTER_DAYS } from './db/load.js';
import { UnsupportedPlatformError } from './discovery/index.js';
import { formatHtml } from './report/html.js';
import type { ScanReport } from './report/model.js';
import { formatSarif } from './report/sarif.js';
import { formatText } from './report/text.js';
import { createLogger, type Logger, type LogLevel } from './util/log.js';
import { packageInfo } from './util/pkg.js';

export const EXIT = { ok: 0, findings: 1, usage: 2, error: 3, interrupted: 130 } as const;

const FORMATS = ['text', 'json', 'sarif', 'html'] as const;
type Format = (typeof FORMATS)[number];

class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const HELP = `appxray - find desktop apps that ship outdated or vulnerable embedded Chromium

Usage:
  appxray [scan] [options]          Scan this computer's installed apps (Windows, Linux)
  appxray inspect <path>... [opts]  Check specific app folders, build outputs or binaries
  appxray diff <old> <new> [opts]   Compare two builds of an app: runtime, fuses, findings and,
                                    with --deep, the attack surface found by REA
  appxray db update [--output f]    Rebuild the vulnerability database from public sources
  appxray db info [--db f]          Show which database is used and how fresh it is

Output:
  -f, --format <text|json|sarif|html>  Report format (default: text)
  -o, --output <file>                  Write the report to a file instead of stdout
      --min-severity <level>           Hide findings below critical|high|medium|low|info
                                       (default: medium for text, info otherwise)
      --fail-on <level>                Exit with code 1 if any finding is at or above level
      --redact-paths                   Replace your home folder with ~ in the report
      --no-color                       Disable colors in text output

Scan options:
      --all-users                      Also search other users' profiles (needs admin/root)
      --root <dir>                     Extra folder to search (repeatable)
      --no-default-roots               Only search --root folders
      --max-dirs <n>                   Directory budget for the search (default 250000)

General:
      --db <file>                      Use this database file
      --no-hash                        Skip SHA-256 hashing of runtime binaries
      --concurrency <n>                Binaries inspected in parallel (default 2)
      --deep                           Analyze each Electron app's code with REA: window settings,
                                       preload bridges, IPC handlers, command execution paths
      --deep-timeout <seconds>         Time limit for REA per app (default 300)
      --rea <path>                     Use this REA executable or rea.mjs instead of the bundled one
      --rea-allow-untested             Use a REA version outside the tested range
  -q, --quiet                          Only print the report and errors
  -v, --verbose                        Print debug information
  -h, --help                           Show this help
      --version                        Show the version

Exit codes: 0 ok, 1 findings at --fail-on level, 2 usage error, 3 runtime error.
Scans read files only; they never run the apps and never use the network.
Behind a proxy, set NODE_USE_ENV_PROXY=1 for "db update".`;

const OPTIONS = {
  format: { type: 'string', short: 'f' },
  output: { type: 'string', short: 'o' },
  'min-severity': { type: 'string' },
  'fail-on': { type: 'string' },
  'redact-paths': { type: 'boolean' },
  color: { type: 'boolean' },
  'all-users': { type: 'boolean' },
  root: { type: 'string', multiple: true },
  'default-roots': { type: 'boolean' },
  'max-dirs': { type: 'string' },
  db: { type: 'string' },
  hash: { type: 'boolean' },
  concurrency: { type: 'string' },
  deep: { type: 'boolean' },
  'deep-timeout': { type: 'string' },
  rea: { type: 'string' },
  'rea-allow-untested': { type: 'boolean' },
  quiet: { type: 'boolean', short: 'q' },
  verbose: { type: 'boolean', short: 'v' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
} as const satisfies ParseArgsConfig['options'];

type Values = ReturnType<typeof parse>['values'];

function parse(argv: string[]) {
  return parseArgs({
    args: argv,
    options: OPTIONS,
    allowPositionals: true,
    allowNegative: true,
    strict: true,
  });
}

function severityOption(value: string | undefined, flag: string): Severity | undefined {
  if (value === undefined) return undefined;
  const severity = parseSeverity(value);
  if (!severity) throw new UsageError(`${flag} must be one of critical, high, medium, low, info`);
  return severity;
}

function positiveInt(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1)
    throw new UsageError(`${flag} must be a positive integer`);
  return number;
}

function render(report: ScanReport, format: Format, color: boolean): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(report, null, 2)}\n`;
    case 'sarif':
      return formatSarif(report);
    case 'html':
      return formatHtml(report);
    case 'text':
      return formatText(report, {
        color,
        width: process.stdout.isTTY ? process.stdout.columns : 120,
      });
  }
}

function meetsFailOn(report: ScanReport, failOn: Severity | undefined): boolean {
  if (!failOn) return false;
  return report.apps.some((app) =>
    app.findings.some((finding) => severityRank(finding.severity) >= severityRank(failOn)),
  );
}

async function emit(text: string, output: string | undefined): Promise<void> {
  if (output) await writeFile(path.resolve(output), text, 'utf8');
  else process.stdout.write(text);
}

/** Options shared by scan, inspect and diff. */
function commonAuditOptions(values: Values, logger: Logger, signal: AbortSignal) {
  return {
    allUsers: values['all-users'] ?? false,
    extraRoots: values.root ?? [],
    defaultRoots: values['default-roots'] ?? true,
    ...(values['max-dirs']
      ? { maxDirectories: positiveInt(values['max-dirs'], '--max-dirs') as number }
      : {}),
    ...(values.db ? { dbPath: values.db } : {}),
    hash: values.hash ?? true,
    concurrency: positiveInt(values.concurrency, '--concurrency') ?? 2,
    redactPaths: values['redact-paths'] ?? false,
    ...(values.deep
      ? {
          deep: {
            ...(values.rea ? { reaPath: values.rea } : {}),
            allowUntested: values['rea-allow-untested'] ?? false,
            timeoutMs: (positiveInt(values['deep-timeout'], '--deep-timeout') ?? 300) * 1000,
          },
        }
      : {}),
    logger,
    signal,
  };
}

async function diffCommand(paths: string[], values: Values, logger: Logger, signal: AbortSignal) {
  if (paths.length !== 2) throw new UsageError('diff needs exactly two paths: <old> <new>');
  const format = values.format ?? 'text';
  if (format !== 'text' && format !== 'json')
    throw new UsageError('diff supports --format text or json');
  const failOn = severityOption(values['fail-on'], '--fail-on');
  const diff = await runDiff(
    paths[0] as string,
    paths[1] as string,
    commonAuditOptions(values, logger, signal),
  );
  await emit(
    format === 'json' ? `${JSON.stringify(diff, null, 2)}\n` : formatDiffText(diff),
    values.output,
  );
  const introduced = [...diff.findings.added, ...diff.findings.changed.map((change) => change.to)];
  return failOn &&
    introduced.some((finding) => severityRank(finding.severity) >= severityRank(failOn))
    ? EXIT.findings
    : EXIT.ok;
}

async function auditCommand(
  mode: 'scan' | 'inspect',
  paths: string[],
  values: Values,
  logger: Logger,
  signal: AbortSignal,
) {
  const format = (values.format ?? 'text') as Format;
  if (!FORMATS.includes(format))
    throw new UsageError(`--format must be one of ${FORMATS.join(', ')}`);
  if (mode === 'inspect' && paths.length === 0)
    throw new UsageError('inspect needs at least one path');
  const failOn = severityOption(values['fail-on'], '--fail-on');
  const explicitMin = severityOption(values['min-severity'], '--min-severity');
  // --fail-on must see every finding it could fail on, so it lowers the display threshold.
  let minSeverity: Severity = explicitMin ?? (format === 'text' ? 'medium' : 'info');
  if (failOn && severityRank(failOn) < severityRank(minSeverity)) minSeverity = failOn;

  const report = await runAudit({
    mode,
    paths,
    ...commonAuditOptions(values, logger, signal),
    minSeverity,
  });

  const color =
    values.color ?? (!values.output && process.stdout.isTTY && !process.env['NO_COLOR']);
  await emit(render(report, format, color), values.output);
  if (values.output) logger.info(`Report written to ${path.resolve(values.output)}`);
  return meetsFailOn(report, failOn) ? EXIT.findings : EXIT.ok;
}

async function dbCommand(sub: string | undefined, values: Values, logger: Logger): Promise<number> {
  if (sub === 'update') {
    const target = values.output ? path.resolve(values.output) : cachedDbPath();
    const token = process.env['GITHUB_TOKEN'] ?? process.env['GH_TOKEN'];
    const db = await buildDb({ logger, ...(token ? { githubToken: token } : {}) });
    await saveDb(db, target);
    const failed = db.sources.filter((source) => !source.ok);
    logger.info(
      `Saved database to ${target} (${db.electron.releases.length} Electron releases, ` +
        `${db.electron.advisories.length} advisories, ${db.chromiumKev.length} known exploited Chromium CVEs).`,
    );
    for (const source of failed)
      logger.warn(`${source.name} was unavailable: ${source.detail ?? 'unknown error'}`);
    return EXIT.ok;
  }
  if (sub === 'info') {
    const loaded = await loadDb(values.db);
    const age = dbAgeDays(loaded.db);
    const lines = [
      `Database:     ${loaded.path} (${loaded.origin})`,
      `Generated:    ${loaded.db.generatedAt} (${age} days old${age > STALE_AFTER_DAYS ? ', stale' : ''})`,
      `Electron:     ${loaded.db.electron.releases.length} releases, latest major ${loaded.db.electron.latestMajor}, supported ${loaded.db.electron.supportedMajors.join(', ')}`,
      `Advisories:   ${loaded.db.electron.advisories.length}`,
      `Chromium KEV: ${loaded.db.chromiumKev.length}`,
      `Release notes: ${loaded.db.coverage.releaseNoteMajors.length > 0 ? `majors ${loaded.db.coverage.releaseNoteMajors.join(', ')}` : 'not collected'}`,
      'Sources:',
      ...loaded.db.sources.map(
        (source) =>
          `  ${source.ok ? 'ok  ' : 'FAIL'} ${source.name} ${source.detail ? `- ${source.detail}` : ''}`,
      ),
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
    return EXIT.ok;
  }
  throw new UsageError(
    'usage: appxray db update [--output <file>] | appxray db info [--db <file>]',
  );
}

export async function main(argv: string[]): Promise<number> {
  let values: Values;
  let positionals: string[];
  try {
    ({ values, positionals } = parse(argv));
  } catch (error) {
    process.stderr.write(`error: ${(error as Error).message}\nRun "appxray --help" for usage.\n`);
    return EXIT.usage;
  }
  if (values.help) {
    process.stdout.write(`${HELP}\n`);
    return EXIT.ok;
  }
  if (values.version) {
    process.stdout.write(`${packageInfo().version}\n`);
    return EXIT.ok;
  }

  const level: LogLevel = values.quiet ? 'error' : values.verbose ? 'debug' : 'info';
  const logger = createLogger(level);
  const controller = new AbortController();
  const onSignal = () => {
    controller.abort();
  };
  process.once('SIGINT', onSignal);

  const [command = 'scan', ...rest] = positionals;
  try {
    switch (command) {
      case 'scan':
        if (rest.length > 0) throw new UsageError(`unexpected argument: ${rest[0] ?? ''}`);
        return await auditCommand('scan', [], values, logger, controller.signal);
      case 'inspect':
        return await auditCommand('inspect', rest, values, logger, controller.signal);
      case 'diff':
        return await diffCommand(rest, values, logger, controller.signal);
      case 'db':
        return await dbCommand(rest[0], values, logger);
      default:
        throw new UsageError(`unknown command "${command}"`);
    }
  } catch (error) {
    if (controller.signal.aborted) {
      logger.error('interrupted');
      return EXIT.interrupted;
    }
    if (error instanceof UsageError) {
      logger.error(`${error.message}\nRun "appxray --help" for usage.`);
      return EXIT.usage;
    }
    if (error instanceof UnsupportedPlatformError) {
      logger.error(error.message);
      return EXIT.usage;
    }
    logger.error((error as Error).message);
    if (level === 'debug' && error instanceof Error && error.stack) logger.debug(error.stack);
    const proxied = process.env['HTTPS_PROXY'] ?? process.env['https_proxy'];
    if (command === 'db' && proxied && !process.env['NODE_USE_ENV_PROXY']) {
      logger.error('An HTTPS proxy is configured. Set NODE_USE_ENV_PROXY=1 so Node.js uses it.');
    }
    return EXIT.error;
  } finally {
    process.off('SIGINT', onSignal);
  }
}
