/**
 * Optional cross-check through REA (https://github.com/morluto/rea).
 *
 * REA moves quickly and ships breaking changes often, so appxray treats it as an external,
 * version-pinned tool: it is never a dependency, it is only invoked when the user asks for
 * --deep, every call goes through this one module, and output is validated defensively.
 * A REA version outside REA_TESTED_RANGE is refused unless explicitly allowed.
 */
import { execFile } from 'node:child_process';
import { access, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import semver from 'semver';

import type { FuseState, FuseWire } from '../binary/fuses.js';
import type { Evidence } from '../detect/types.js';

const execFileAsync = promisify(execFile);

/** REA versions whose CLI contract is covered by test/unit/rea.test.ts. */
export const REA_TESTED_RANGE = '>=6.7.0 <6.8.0';

export class ReaUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReaUnavailableError';
  }
}

export interface ReaRunner {
  version: string;
  command: string;
  baseArgs: string[];
}

export interface LocateOptions {
  explicitPath?: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  allowUntested?: boolean;
}

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
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
 * Turns a located REA entry point into a command that runs without a shell. npm's Windows
 * shims (.cmd) cannot be spawned without one, so we run the package's script with Node.
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
  const file = options.explicitPath ?? env['APPXRAY_REA'] ?? (await findOnPath(env, platform));
  if (!file) {
    throw new ReaUnavailableError(
      'REA is not installed. Install the tested version with "npm install --global rea-agents@6.7" or pass --rea <path>.',
    );
  }
  const { command, baseArgs } = await toCommand(file, platform);
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(command, [...baseArgs, '--version'], {
      timeout: 60_000,
      windowsHide: true,
      encoding: 'utf8',
    }));
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
        'Install a tested version or pass --rea-allow-untested to use it anyway.',
    );
  }
  return { version, command, baseArgs };
}

interface ReaFuse {
  name?: unknown;
  state?: unknown;
}

export interface ReaFuseReading {
  evidenceId?: string;
  sha256?: string;
  fuses: Map<string, FuseState>;
}

/** Extracts fuse states from `rea inspect-electron-fuses --json` output. */
export function parseReaFuseOutput(stdout: string): ReaFuseReading {
  const parsed = JSON.parse(stdout) as Record<string, unknown>;
  if (typeof parsed['code'] === 'string' && typeof parsed['message'] === 'string') {
    throw new Error(`REA reported ${parsed['code']}: ${parsed['message']}`);
  }
  const result = parsed['normalized_result'] as
    { slices?: { sentinels?: { fuses?: ReaFuse[] }[] }[] } | undefined;
  const firstSentinel = result?.slices?.flatMap((slice) => slice.sentinels ?? [])[0];
  if (!firstSentinel || !Array.isArray(firstSentinel.fuses)) {
    throw new Error('REA output did not contain a fuse wire');
  }
  const fuses = new Map<string, FuseState>();
  for (const fuse of firstSentinel.fuses) {
    if (typeof fuse.name !== 'string' || typeof fuse.state !== 'string') continue;
    const state = ['enabled', 'disabled', 'removed'].includes(fuse.state)
      ? (fuse.state as FuseState)
      : 'unknown';
    fuses.set(fuse.name, state);
  }
  const reading: ReaFuseReading = { fuses };
  if (typeof parsed['evidence_id'] === 'string') reading.evidenceId = parsed['evidence_id'];
  const digest = (parsed['subject'] as { digest?: { sha256?: unknown } } | undefined)?.digest
    ?.sha256;
  if (typeof digest === 'string') reading.sha256 = digest;
  return reading;
}

/** Compares REA's independent fuse reading with appxray's. */
export function compareFuses(
  ours: FuseWire | undefined,
  theirs: ReaFuseReading,
): { agrees: boolean; differences: string[] } {
  const differences: string[] = [];
  for (const fuse of ours?.fuses ?? []) {
    const other = theirs.fuses.get(fuse.name);
    if (other !== undefined && other !== fuse.state)
      differences.push(`${fuse.name}: appxray ${fuse.state}, REA ${other}`);
  }
  if (!ours && theirs.fuses.size > 0)
    differences.push('REA found a fuse wire that appxray did not');
  return { agrees: differences.length === 0, differences };
}

export async function reaFuseEvidence(
  runner: ReaRunner,
  binary: string,
  ours: FuseWire | undefined,
): Promise<Evidence> {
  const base = { provider: 'rea', providerVersion: runner.version };
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(
      runner.command,
      [...runner.baseArgs, 'inspect-electron-fuses', binary, '--json'],
      {
        timeout: 180_000,
        maxBuffer: 32 * 1024 * 1024,
        windowsHide: true,
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1' },
      },
    ));
  } catch (error) {
    // REA exits non-zero with a JSON error on stdout; surface its message when present.
    const output = (error as { stdout?: string }).stdout;
    try {
      if (output) parseReaFuseOutput(output);
    } catch (parseError) {
      return {
        ...base,
        summary: `REA could not inspect the binary: ${(parseError as Error).message}`,
      };
    }
    return { ...base, summary: `REA could not inspect the binary: ${(error as Error).message}` };
  }
  try {
    const reading = parseReaFuseOutput(stdout);
    const { agrees, differences } = compareFuses(ours, reading);
    const evidence: Evidence = {
      ...base,
      agrees,
      summary: agrees
        ? `REA independently read the same ${reading.fuses.size} fuses`
        : `REA fuse reading differs: ${differences.join('; ')}`,
    };
    if (reading.evidenceId) evidence.id = reading.evidenceId;
    return evidence;
  } catch (error) {
    return { ...base, summary: `REA output could not be used: ${(error as Error).message}` };
  }
}
