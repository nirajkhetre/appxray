import { readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { deepFindings } from '../../src/analysis/deep.js';
import type { Finding } from '../../src/analysis/types.js';
import { analyzeApp } from '../../src/analysis/analyze.js';
import { diffApps } from '../../src/commands/diff.js';
import type { DeepAnalysis } from '../../src/deep/analyze.js';
import {
  classifyContent,
  findAttackPaths,
  parsePosture,
  type ElectronPosture,
} from '../../src/deep/posture.js';
import { resolveMain, scoreSource, selectSources } from '../../src/deep/select.js';
import type { InspectedApp } from '../../src/detect/types.js';
import { fixtureDb, NOW } from '../fixtures/db.js';
import { buildAsar, tempDir } from '../helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
// Real REA 6.7.0 output for test/fixtures/apps/insecure-electron (trimmed, paths anonymized).
const reaAnalysis = JSON.parse(
  readFileSync(
    path.join(here, '..', 'fixtures', 'rea', 'analyze-javascript-application-6.7.0.json'),
    'utf8',
  ),
) as Record<string, unknown>;

describe('selectSources', () => {
  let dir: string;
  let cleanup: () => Promise<void>;
  beforeEach(async () => ({ dir, cleanup } = await tempDir()));
  afterEach(async () => cleanup());

  const files = {
    'package.json': JSON.stringify({ name: 'x', main: './dist/main' }),
    'dist/main.js': "const { app } = require('electron'); app.whenReady();",
    'dist/windows.js':
      "new BrowserWindow({ webPreferences: { preload: 'p.js' } }); ipcMain.handle('x', () => 1);",
    'dist/preload.js':
      "contextBridge.exposeInMainWorld('api', { a: () => ipcRenderer.invoke('x') });",
    'dist/util.js': "require('child_process').exec('ls'); openExternal('https://a');",
    'node_modules/lib/index.js':
      "ipcMain.on('evil', () => {}); new BrowserWindow({ webPreferences: {} });",
    'dist/types.d.ts': 'declare const webPreferences: unknown;',
  };

  it('picks the main entry and Electron boundary code from an app.asar', async () => {
    const asar = path.join(dir, 'app.asar');
    await writeFile(asar, buildAsar(files));
    const selection = await selectSources(asar);
    expect(selection.format).toBe('asar');
    expect(selection.sources).toEqual(['dist/main.js', 'dist/windows.js', 'dist/preload.js']);
    expect(selection.reasons['dist/main.js']?.[0]).toBe('package.json main');
    expect(selection.reasons['dist/windows.js']).toEqual(
      expect.arrayContaining(['webPreferences', 'ipcMain', 'BrowserWindow']),
    );
  });

  it('works on unpacked resources/app folders and respects the file budget', async () => {
    const app = path.join(dir, 'app');
    for (const [file, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(app, file)), { recursive: true });
      await writeFile(path.join(app, file), content);
    }
    const selection = await selectSources(path.join(app, 'package.json'), { maxFiles: 2 });
    expect(selection.format).toBe('directory');
    expect(selection.appPath).toBe(app);
    expect(selection.sources).toEqual(['dist/main.js', 'dist/windows.js']);
    expect(selection.omitted).toBe(1);
  });

  it('resolves package.json main like Node does', () => {
    const available = new Set(['out/main.js', 'lib/index.js', 'index.js']);
    expect(resolveMain('./out/main', available)).toBe('out/main.js');
    expect(resolveMain('lib', available)).toBe('lib/index.js');
    expect(resolveMain(undefined, available)).toBe('index.js');
    expect(resolveMain('missing.js', available)).toBeUndefined();
  });

  it('requires a boundary signal', () => {
    expect(scoreSource("require('child_process'); shell.openExternal(x)").boundary).toBe(false);
    expect(scoreSource('contextBridge.exposeInMainWorld').boundary).toBe(true);
  });
});

describe('parsePosture (REA 6.7.0 contract)', () => {
  const posture = parsePosture(reaAnalysis);

  it('reads window settings with source locations', () => {
    const insecure = posture.windows.find((window) => window.preferences['nodeIntegration']);
    expect(insecure?.preferences).toMatchObject({
      nodeIntegration: { status: 'literal', value: true },
      contextIsolation: { status: 'literal', value: false },
      webSecurity: { status: 'literal', value: false },
      sandbox: { status: 'literal', value: false },
    });
    expect(insecure?.location).toMatchObject({ file: 'main.js', line: 5 });
    expect(insecure?.fullyKnown).toBe(true);
    expect(posture.windows).toHaveLength(2);
  });

  it('reads bridges, IPC handlers, content and command execution', () => {
    expect(posture.bridges).toEqual([
      expect.objectContaining({ apiKey: 'api', members: ['open', 'run'], dynamic: false }),
    ]);
    expect(posture.bridgeCalls).toEqual(
      expect.arrayContaining([
        { entry: 'api.run', channel: 'run-command' },
        { entry: 'api.open', channel: 'open-link' },
      ]),
    );
    expect(posture.mainHandlers.map((handler) => handler.channel).sort()).toEqual([
      'open-link',
      'run-command',
    ]);
    expect(
      posture.content.filter((content) => content.remote).map((content) => content.url),
    ).toEqual(['https://example.com/app']);
    expect(posture.commandSinks).toEqual([
      expect.objectContaining({
        method: 'exec',
        location: expect.objectContaining({ file: 'main.js', line: 20 }),
      }),
    ]);
    expect(posture.evidenceId).toMatch(/^ev_/);
  });

  it('links the exposed function to command execution', () => {
    expect(posture.attackPaths).toEqual([
      expect.objectContaining({
        entry: 'api.run',
        channel: 'run-command',
        sink: expect.objectContaining({ method: 'exec' }),
      }),
    ]);
  });

  it('rejects output without an application graph', () => {
    expect(() => parsePosture({ normalized_result: {} })).toThrow(/application graph/);
  });

  it('classifies loaded content', () => {
    expect(classifyContent('https://app.example.com')).toMatchObject({
      remote: true,
      insecureTransport: false,
    });
    expect(classifyContent('http://cdn.example.com/x')).toMatchObject({
      remote: true,
      insecureTransport: true,
    });
    expect(classifyContent('http://localhost:3000')).toMatchObject({
      remote: false,
      insecureTransport: false,
    });
    expect(classifyContent('index.html')).toMatchObject({ remote: false });
  });

  it('does not link sinks outside the handler', () => {
    const handler = {
      channel: 'c',
      mode: 'handle',
      location: { file: 'main.js', line: 10, column: 0 },
      handlerRange: {
        file: 'main.js',
        start: { line: 10, column: 5 },
        end: { line: 12, column: 1 },
      },
    };
    const sink = (line: number, file = 'main.js') => ({
      method: 'spawn',
      location: { file, line, column: 2 },
    });
    const calls = [{ entry: 'api.c', channel: 'c' }];
    expect(findAttackPaths(calls, [handler], [sink(11)])).toHaveLength(1);
    expect(findAttackPaths(calls, [handler], [sink(20)])).toHaveLength(0);
    expect(findAttackPaths(calls, [handler], [sink(11, 'other.js')])).toHaveLength(0);
    expect(
      findAttackPaths([{ entry: 'api.c', channel: null }], [handler], [sink(11)]),
    ).toHaveLength(0);
  });
});

function appWith(
  posture: ElectronPosture | undefined,
  overrides: Partial<InspectedApp> = {},
  error?: string,
): InspectedApp {
  const deep: DeepAnalysis = {
    engine: { name: 'rea', version: '6.7.0' },
    durationMs: 10,
    analyzedFiles: { 'main.js': ['package.json main', 'webPreferences'] },
    omittedFiles: 0,
  };
  if (posture) deep.posture = posture;
  if (error) deep.error = error;
  return {
    id: 'a',
    name: 'App',
    root: '/opt/app',
    binary: '/opt/app/app',
    binarySize: 1,
    kind: 'electron',
    source: 'explicit',
    runtime: { electron: '44.9.0', chromium: '154.0.8100.1' },
    otherCopies: [],
    notes: [],
    evidence: [],
    deep,
    ...overrides,
  };
}

const rule = (findings: Finding[], id: Finding['ruleId']) =>
  findings.find((finding) => finding.ruleId === id);

describe('deep findings', () => {
  const posture = parsePosture(reaAnalysis);

  it('reports the command execution path and window settings as critical with remote content', () => {
    const findings = deepFindings(appWith(posture));
    const path = rule(findings, 'electron/renderer-command-execution');
    expect(path?.severity).toBe('critical');
    expect(path?.detail).toContain('window.api.run');
    expect(path?.detail).toContain('main.js:20');
    const settings = rule(findings, 'electron/insecure-web-preferences');
    expect(settings?.severity).toBe('critical');
    expect(settings?.title).toContain('nodeIntegration: true');
    expect(rule(findings, 'electron/ipc-sender-not-validated')).toBeDefined();
  });

  it('is less severe when no remote content is loaded', () => {
    const local = { ...posture, content: posture.content.filter((content) => !content.remote) };
    const findings = deepFindings(appWith(local));
    expect(rule(findings, 'electron/renderer-command-execution')?.severity).toBe('high');
    expect(rule(findings, 'electron/insecure-web-preferences')?.severity).toBe('high');
    expect(rule(findings, 'electron/ipc-sender-not-validated')).toBeUndefined();
  });

  it('flags insecure defaults of old Electron versions only when all options are known', () => {
    const base: ElectronPosture = {
      ...posture,
      attackPaths: [],
      content: [],
      windows: [{ fullyKnown: true, preferences: {} }],
    };
    const old = deepFindings(appWith(base, { runtime: { electron: '11.5.0' } }));
    expect(rule(old, 'electron/insecure-web-preferences')?.title).toContain(
      'contextIsolation: false',
    );
    expect(rule(old, 'electron/insecure-web-preferences')?.detail).toContain('Electron 11 default');
    const modern = deepFindings(appWith(base));
    expect(rule(modern, 'electron/insecure-web-preferences')).toBeUndefined();
    const unknown = deepFindings(
      appWith(
        { ...base, windows: [{ fullyKnown: false, preferences: {} }] },
        { runtime: { electron: '11.5.0' } },
      ),
    );
    expect(rule(unknown, 'electron/insecure-web-preferences')).toBeUndefined();
  });

  it('reports raw IPC bridges and plain-HTTP content', () => {
    const findings = deepFindings(
      appWith({
        ...posture,
        attackPaths: [],
        windows: [],
        bridgeCalls: [{ entry: 'bridge.send', channel: null }],
        content: [classifyContent('http://updates.example.com/app')],
      }),
    );
    expect(rule(findings, 'electron/raw-ipc-bridge')?.severity).toBe('high');
    expect(rule(findings, 'electron/insecure-remote-content')).toBeDefined();
  });

  it('reports incomplete analysis instead of claiming the app is clean', () => {
    expect(
      rule(
        deepFindings(appWith(undefined, {}, 'REA did not finish within 300s')),
        'deep/limited-coverage',
      )?.detail,
    ).toContain('300s');
    const unresolved = { ...posture, windows: [], attackPaths: [], content: [] };
    expect(rule(deepFindings(appWith(unresolved)), 'deep/limited-coverage')?.detail).toContain(
      'could not be resolved',
    );
  });
});

describe('diffApps', () => {
  const posture = parsePosture(reaAnalysis);
  const db = fixtureDb();

  it('calls a release that removes the attack path safer, and the reverse riskier', () => {
    const fixed: ElectronPosture = {
      ...posture,
      attackPaths: [],
      windows: [],
      bridges: [{ apiKey: 'api', members: ['open', 'version'], dynamic: false }],
    };
    const before = analyzeApp(appWith(posture), db, { now: NOW });
    const after = analyzeApp(appWith(fixed, { appVersion: '1.3.0' }), db, { now: NOW });
    const diff = diffApps(before, after);
    expect(diff.verdict).toBe('safer');
    expect(diff.surface?.commandExecutionPaths.removed).toEqual([
      'window.api.run -> run-command -> exec',
    ]);
    expect(diff.surface?.exposedFunctions).toEqual({
      added: ['api.version'],
      removed: ['api.run'],
    });
    expect(diff.findings.resolved.map((finding) => finding.ruleId)).toContain(
      'electron/renderer-command-execution',
    );
    expect(diffApps(after, before).verdict).toBe('riskier');
    expect(diffApps(before, before).verdict).toBe('unchanged');
  });

  it('compares runtimes without deep data', () => {
    const plain = (electron: string, chromium: string) => {
      const app = appWith(undefined, { runtime: { electron, chromium } });
      delete app.deep;
      return analyzeApp(app, db, { now: NOW });
    };
    const diff = diffApps(plain('22.3.14', '108.0.5359.215'), plain('44.9.0', '154.0.8100.1'));
    expect(diff.runtime.electron).toEqual(['22.3.14', '44.9.0']);
    expect(diff.surface).toBeUndefined();
    expect(diff.verdict).toBe('safer');
  });
});
