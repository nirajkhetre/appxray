import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { decodeFuseWire } from '../../src/binary/fuses.js';
import { compareFuses, parseReaFuseOutput, reaFuseEvidence } from '../../src/rea/fuses.js';
import {
  locateRea,
  ReaCommandError,
  ReaUnavailableError,
  runReaJson,
} from '../../src/rea/runner.js';
import { tempDir } from '../helpers.js';

// Real `rea inspect-electron-fuses --json` output from REA 6.7.0 (paths anonymized).
// If a REA upgrade changes this contract, these tests fail before users see wrong results.
const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'rea');
const successText = readFileSync(path.join(fixtures, 'inspect-electron-fuses-6.7.0.json'), 'utf8');
const success = JSON.parse(successText) as Record<string, unknown>;
const failureText = readFileSync(
  path.join(fixtures, 'inspect-electron-fuses-error-6.7.0.json'),
  'utf8',
);
const failure = JSON.parse(failureText) as Record<string, unknown>;

// The same fuses REA saw in that binary: RunAsNode..LoadBrowserProcessSpecificV8Snapshot.
const ours = decodeFuseWire(Buffer.from([1, 7, ...Buffer.from('1011000')]), 0) ?? undefined;

describe('REA output contract (6.7.0)', () => {
  it('parses fuse states, evidence id and digest', () => {
    const reading = parseReaFuseOutput(success);
    expect(reading.evidenceId).toMatch(/^ev_[0-9a-f]{64}$/);
    expect(reading.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.fromEntries(reading.fuses)).toEqual({
      RunAsNode: 'enabled',
      EnableCookieEncryption: 'disabled',
      EnableNodeOptionsEnvironmentVariable: 'enabled',
      EnableNodeCliInspectArguments: 'enabled',
      EnableEmbeddedAsarIntegrityValidation: 'disabled',
      OnlyLoadAppFromAsar: 'disabled',
      LoadBrowserProcessSpecificV8Snapshot: 'disabled',
    });
  });

  it('surfaces REA error objects', () => {
    expect(() => parseReaFuseOutput(failure)).toThrow(/invalid_request/);
  });

  it('agrees with appxray on the same binary and reports differences', () => {
    const reading = parseReaFuseOutput(success);
    expect(compareFuses(ours, reading)).toEqual({ agrees: true, differences: [] });
    const flipped = decodeFuseWire(Buffer.from([1, 7, ...Buffer.from('0011000')]), 0) ?? undefined;
    expect(compareFuses(flipped, reading).differences).toEqual([
      'RunAsNode: appxray disabled, REA enabled',
    ]);
    expect(compareFuses(undefined, reading).agrees).toBe(false);
  });
});

describe('running REA', () => {
  let dir: string;
  let cleanup: () => Promise<void>;
  beforeEach(async () => ({ dir, cleanup } = await tempDir()));
  afterEach(async () => cleanup());

  /** Writes a stand-in for rea.mjs that answers like the real CLI. */
  async function fakeRea(version: string, inspectOutput: string, exitCode = 0): Promise<string> {
    const file = path.join(dir, 'rea.mjs');
    await writeFile(
      file,
      `const args = process.argv.slice(2);
if (args[0] === '--version') { console.log(${JSON.stringify(version)}); process.exit(0); }
if (args[0] === 'inspect-electron-fuses') { process.stdout.write(${JSON.stringify(inspectOutput)}); process.exit(${exitCode}); }
process.exit(2);`,
    );
    return file;
  }

  it('runs a tested version and records agreeing evidence', async () => {
    const runner = await locateRea({ explicitPath: await fakeRea('6.7.0', successText) });
    expect(runner.version).toBe('6.7.0');
    const binary = path.join(dir, 'app');
    await writeFile(binary, 'binary');
    const evidence = await reaFuseEvidence(runner, binary, ours);
    expect(evidence).toMatchObject({ provider: 'rea', providerVersion: '6.7.0', agrees: true });
    expect(evidence.id).toMatch(/^ev_/);
  });

  it('refuses untested versions unless allowed', async () => {
    const file = await fakeRea('7.0.0', successText);
    await expect(locateRea({ explicitPath: file })).rejects.toBeInstanceOf(ReaUnavailableError);
    await expect(locateRea({ explicitPath: file, allowUntested: true })).resolves.toMatchObject({
      version: '7.0.0',
    });
  });

  it('turns REA failures into evidence instead of crashing the scan', async () => {
    const runner = await locateRea({ explicitPath: await fakeRea('6.7.1', failureText, 1) });
    const binary = path.join(dir, 'app');
    await writeFile(binary, 'binary');
    const evidence = await reaFuseEvidence(runner, binary, ours);
    expect(evidence.agrees).toBeUndefined();
    expect(evidence.summary).toContain('invalid_request');
  });

  it('explains how to install REA when it is missing', async () => {
    await expect(locateRea({ env: { PATH: dir }, useBundled: false })).rejects.toThrow(
      /npm install --global rea-agents@6\.7\.0/,
    );
  });

  it('prefers the bundled, version-pinned REA', async () => {
    const runner = await locateRea({ env: { PATH: dir } });
    expect(runner.origin).toBe('bundled');
    expect(runner.version).toBe('6.7.0');
  });

  it('turns REA error objects and garbage output into ReaCommandError', async () => {
    const failing = await locateRea({ explicitPath: await fakeRea('6.7.0', failureText, 1) });
    await expect(
      runReaJson(failing, ['inspect-electron-fuses', 'x'], { timeoutMs: 30_000 }),
    ).rejects.toThrow(ReaCommandError);
    const garbage = await locateRea({ explicitPath: await fakeRea('6.7.0', 'not json') });
    await expect(
      runReaJson(garbage, ['inspect-electron-fuses', 'x'], { timeoutMs: 30_000 }),
    ).rejects.toThrow(/not JSON/);
  });
});
