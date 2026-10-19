import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { saveDb } from '../../src/db/load.js';
import { main } from '../../src/main.js';
import type { ScanReport } from '../../src/report/model.js';
import { fixtureDb } from '../fixtures/db.js';
import { fakeElectronApp, tempDir } from '../helpers.js';

let dir: string;
let cleanup: () => Promise<void>;
let dbFile: string;
let stdout: string;
let stderr: string;

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  dbFile = path.join(dir, 'db.json');
  await saveDb(fixtureDb({ generatedAt: new Date().toISOString() }), dbFile);
  stdout = '';
  stderr = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr += String(chunk);
    return true;
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

describe('appxray CLI', () => {
  it('prints help and version', async () => {
    expect(await main(['--help'])).toBe(0);
    expect(stdout).toContain('appxray inspect <path>');
    stdout = '';
    expect(await main(['--version'])).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it.each([
    [['--format', 'xml', 'inspect', '.']],
    [['--fail-on', 'severe', 'inspect', '.']],
    [['inspect']],
    [['frobnicate']],
    [['--no-such-flag']],
  ])('rejects bad usage %j with exit code 2', async (args) => {
    expect(await main(args)).toBe(2);
    expect(stderr).toMatch(/error/);
  });

  it('inspects a build output folder and fails on high severity findings', async () => {
    await fakeElectronApp(path.join(dir, 'dist', 'linux-unpacked'), {
      electron: '22.3.14',
      chrome: '108.0.5359.215',
    });
    const code = await main([
      'inspect',
      path.join(dir, 'dist'),
      '--db',
      dbFile,
      '--format',
      'json',
      '--fail-on',
      'high',
      '-q',
    ]);
    expect(code).toBe(1);
    const parsed = JSON.parse(stdout) as ScanReport;
    expect(parsed.apps).toHaveLength(1);
    expect(parsed.apps[0]).toMatchObject({
      name: 'Fake App',
      runtime: { electron: '22.3.14' },
      maxSeverity: 'critical',
    });
  });

  it('passes a current app and writes reports to a file', async () => {
    await fakeElectronApp(path.join(dir, 'app'), {
      electron: '44.9.0',
      chrome: '154.0.8100.1',
      fuses: '0000',
    });
    const out = path.join(dir, 'report.html');
    const code = await main([
      'inspect',
      path.join(dir, 'app'),
      '--db',
      dbFile,
      '-f',
      'html',
      '-o',
      out,
      '--fail-on',
      'low',
    ]);
    expect(code).toBe(0);
    expect(await readFile(out, 'utf8')).toContain('<!doctype html>');
    expect(stdout).toBe('');
  });

  it('accepts a binary path directly', async () => {
    const exe = await fakeElectronApp(path.join(dir, 'app'), {
      electron: '43.7.7',
      chrome: '150.0.7871.250',
    });
    expect(await main(['inspect', exe, '--db', dbFile, '-f', 'json', '-q'])).toBe(0);
    expect((JSON.parse(stdout) as ScanReport).apps[0]?.runtime.electron).toBe('43.7.7');
  });

  it('redacts the home folder on request', async () => {
    const { default: os } = await import('node:os');
    vi.spyOn(os, 'homedir').mockReturnValue(dir);
    await fakeElectronApp(path.join(dir, 'app'));
    await main([
      'inspect',
      path.join(dir, 'app'),
      '--db',
      dbFile,
      '-f',
      'json',
      '-q',
      '--redact-paths',
    ]);
    expect(stdout).not.toContain(dir);
    expect((JSON.parse(stdout) as ScanReport).apps[0]?.root).toBe(path.join('~', 'app'));
  });

  it('reports a missing database as a runtime error', async () => {
    expect(await main(['inspect', dir, '--db', path.join(dir, 'missing.json'), '-q'])).toBe(3);
    expect(stderr).toContain('missing.json');
  });

  it('scans extra roots without default locations', async () => {
    await fakeElectronApp(path.join(dir, 'apps', 'Tool'));
    const code = await main([
      'scan',
      '--no-default-roots',
      '--root',
      path.join(dir, 'apps'),
      '--db',
      dbFile,
      '-f',
      'json',
      '-q',
    ]);
    expect(code).toBe(0);
    expect((JSON.parse(stdout) as ScanReport).apps.map((app) => app.name)).toEqual(['Fake App']);
  });

  it('shows database information', async () => {
    expect(await main(['db', 'info', '--db', dbFile])).toBe(0);
    expect(stdout).toContain('Chromium KEV: 5');
  });
});
