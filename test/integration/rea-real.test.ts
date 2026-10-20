/**
 * Runs the real, version-pinned REA (the rea-agents optional dependency) on a deliberately
 * insecure app. This is the contract test that guards REA upgrades: if a new REA changes its
 * output, these assertions fail in CI before any user sees different results.
 *
 * Skipped only when REA is not installed and APPXRAY_REQUIRE_REA is not set; CI sets it.
 */
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { deepAnalyze } from '../../src/deep/analyze.js';
import { bundledReaScript, locateRea, type ReaRunner } from '../../src/rea/runner.js';
import { buildAsar, tempDir } from '../helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureApp = path.join(here, '..', 'fixtures', 'apps', 'insecure-electron');
const available = (await bundledReaScript()) !== undefined;
const required = process.env['APPXRAY_REQUIRE_REA'] === '1';

describe.skipIf(!available && !required)('real REA analysis', () => {
  let runner: ReaRunner;
  let dir: string;
  let cleanup: () => Promise<void>;
  let asar: string;

  beforeAll(async () => {
    runner = await locateRea();
    ({ dir, cleanup } = await tempDir());
    const files: Record<string, string> = {};
    for (const name of await readdir(fixtureApp)) {
      if (name !== 'README.md') files[name] = await readFile(path.join(fixtureApp, name), 'utf8');
    }
    asar = path.join(dir, 'app.asar');
    await writeFile(asar, buildAsar(files));
  });
  afterAll(async () => cleanup());

  it('uses the pinned bundled REA', () => {
    expect(runner.origin).toBe('bundled');
    expect(runner.version).toBe('6.7.0');
  });

  it('finds the insecure window, remote content and the command execution path', async () => {
    const result = await deepAnalyze(asar, runner, { timeoutMs: 240_000 });
    expect(result.error).toBeUndefined();
    expect(Object.keys(result.analyzedFiles).sort()).toEqual(['main.js', 'preload.js']);
    const posture = result.posture!;
    expect(
      posture.windows.some((window) => window.preferences['nodeIntegration']?.status === 'literal'),
    ).toBe(true);
    expect(
      posture.content.filter((content) => content.remote).map((content) => content.url),
    ).toEqual(['https://example.com/app']);
    expect(posture.attackPaths).toEqual([
      expect.objectContaining({
        entry: 'api.run',
        channel: 'run-command',
        sink: expect.objectContaining({ method: 'exec' }),
      }),
    ]);
  }, 300_000);
});
