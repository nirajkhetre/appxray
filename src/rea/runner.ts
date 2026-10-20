/**
 * Locating and running REA (https://github.com/morluto/rea), the engine behind appxray's deep
 * analysis.
 *
 * REA ships breaking changes often, so it is used under a contract:
 * - The tested version is pinned exactly as an optional dependency (see package.json).
 * - Every call goes through this module and the parsers next to it, which validate output.
 * - Versions outside REA_TESTED_RANGE are refused unless the user explicitly allows them.
 * - test/integration/rea-real.test.ts runs the real pinned REA in CI, so an upgrade that changes
 *   REA's output fails the build instead of silently changing results.
 */
import { execFile } from 'node:child_process';
import { access, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import semver from 'semver';

/** REA versions whose output contract is covered by appxray's tests. */
export const REA_TESTED_RANGE = '>=6.7.0 <6.8.0';

export class ReaUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReaUnavailableError';
  }
}

/** REA ran but reported an error or returned unusable output. */
export class ReaCommandError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'ReaCommandError';
  }
}

export interface ReaRunner {
  version: string;
  command: string;
  baseArgs: string[];
  /** Where REA was found: the bundled dependency, an explicit path, or PATH. */
  origin: 'bundled' | 'explicit' | 'path';
}

export interface LocateOptions {
  explicitPath?: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  allowUntested?: boolean;
  /** Look for the bundled rea-agents dependency (default true). */
  useBundled?: boolean;
}

interface ExecResult {
  stdout: string;
  stderr: string;
}

function runFile(
  command: string,
  args: readonly string[],
  options: { timeoutMs: number; maxBuffer?: number },
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      {
        timeout: options.timeoutMs,
        maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024,
        windowsHide: true,
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1' },
      },
      (error, stdout, stderr) => {
        if (error) {
          const failure: Error & { stdout?: string; stderr?: string } = error;
          failure.stdout = stdout;
          failure.stderr = stderr;
          reject(failure);
        } else resolve({ stdout, stderr });
      },
    );
  });
}

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

/** The rea-agents package installed next to appxray, if the optional install succeeded. */
export async function bundledReaScript(): Promise<string | undefined> {
  try {
    const require = createRequire(import.meta.url);
    const script = path.join(
      path.dirname(require.resolve('rea-agents/package.json')),
      'scripts',
      'rea.mjs',
    );
    return (await exists(script)) ? script : undefined;
  } catch {
    return undefined;
  }
}

async function findOnPath(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): Promise<string | undefined> {
  const dirs = (env['PATH'] ?? env['Path'] ?? '').split(path.delimiter).filter(Boolean);
  const names = platform === 'win32' ? ['rea.cmd', 'rea.exe'] : ['rea'];
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (await exists(candidate)) return candidate;
    }
  }
  return undefined;
}

/**
 * Turns a REA entry point into a command that runs without a shell. npm's Windows shims
 * (.cmd) cannot be spawned without one, so the package script is run with this Node.js.
 */
async function toCommand(
  file: string,
  platform: NodeJS.Platform,
): Promise<{ command: string; baseArgs: string[] }> {
  if (/\.(mjs|cjs|js)$/i.test(file)) return { command: process.execPath, baseArgs: [file] };
  if (platform === 'win32' && /\.cmd$/i.test(file)) {
    const script = path.join(
      path.dirname(file),
      'node_modules',
      'rea-agents',
      'scripts',
      'rea.mjs',
    );
    if (await exists(script)) return { command: process.execPath, baseArgs: [script] };
    throw new ReaUnavailableError(`found ${file} but not the rea-agents package script next to it`);
  }
  const resolved = await realpath(file).catch(() => file);
  if (/\.(mjs|cjs|js)$/i.test(resolved)) return { command: process.execPath, baseArgs: [resolved] };
  return { command: resolved, baseArgs: [] };
}

export async function locateRea(options: LocateOptions = {}): Promise<ReaRunner> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  let file: string | undefined;
  let origin: ReaRunner['origin'] = 'explicit';
  if (options.explicitPath ?? env['APPXRAY_REA']) {
    file = options.explicitPath ?? env['APPXRAY_REA'];
  } else if (options.useBundled !== false && (file = await bundledReaScript())) {
    origin = 'bundled';
  } else {
    file = await findOnPath(env, platform);
    origin = 'path';
  }
  if (!file) {
    throw new ReaUnavailableError(
      'REA is not available. Reinstall appxray (REA is an optional dependency), install the tested ' +
        'version with "npm install --global rea-agents@6.7.0", or pass --rea <path>.',
    );
  }
  const { command, baseArgs } = await toCommand(file, platform);
  let stdout: string;
  try {
    ({ stdout } = await runFile(command, [...baseArgs, '--version'], { timeoutMs: 60_000 }));
  } catch (error) {
    throw new ReaUnavailableError(`could not run REA at ${file}: ${(error as Error).message}`);
  }
  const version = semver.valid(stdout.trim().split(/\s+/).pop() ?? '');
  if (!version)
    throw new ReaUnavailableError(
      `unexpected "rea --version" output: ${stdout.trim().slice(0, 80)}`,
    );
  if (!semver.satisfies(version, REA_TESTED_RANGE) && !options.allowUntested) {
    throw new ReaUnavailableError(
      `REA ${version} is outside the tested range ${REA_TESTED_RANGE}. ` +
        'Use the bundled version or pass --rea-allow-untested to use it anyway.',
    );
  }
  return { version, command, baseArgs, origin };
}

function errorFromOutput(stdout: string): ReaCommandError | undefined {
  try {
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    if (typeof parsed['code'] === 'string' && typeof parsed['message'] === 'string') {
      return new ReaCommandError(
        `REA reported ${parsed['code']}: ${parsed['message']}`,
        parsed['code'],
      );
    }
  } catch {
    // Not a JSON error object.
  }
  return undefined;
}

/**
 * Runs a REA command with JSON output and returns the parsed result. REA reports failures as a
 * JSON object with `code` and `message` on stdout and a non-zero exit code.
 */
export async function runReaJson(
  runner: ReaRunner,
  args: readonly string[],
  options: { timeoutMs: number },
): Promise<Record<string, unknown>> {
  let stdout: string;
  try {
    ({ stdout } = await runFile(
      runner.command,
      [...runner.baseArgs, ...args, '--format', 'json'],
      options,
    ));
  } catch (error) {
    const output = (error as { stdout?: string }).stdout ?? '';
    const reported = errorFromOutput(output);
    if (reported) throw reported;
    const killed = (error as { killed?: boolean }).killed;
    throw new ReaCommandError(
      killed
        ? `REA did not finish within ${Math.round(options.timeoutMs / 1000)}s`
        : `REA failed: ${(error as Error).message}`,
    );
  }
  const reported = errorFromOutput(stdout);
  if (reported) throw reported;
  try {
    return JSON.parse(stdout) as Record<string, unknown>;
  } catch {
    throw new ReaCommandError('REA returned output that is not JSON');
  }
}
