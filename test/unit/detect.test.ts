import { mkdir, readdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { classifyDirectory } from '../../src/detect/classify.js';
import { appId, inspectCandidate } from '../../src/detect/inspect.js';
import { collapseSideBySideCopies, findCandidates } from '../../src/discovery/walk.js';
import { fakeBinary, fakeElectronApp, tempDir } from '../helpers.js';

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => ({ dir, cleanup } = await tempDir()));
afterEach(async () => cleanup());

const classify = async (folder: string, platform: NodeJS.Platform = process.platform) =>
  classifyDirectory(folder, await readdir(folder, { withFileTypes: true }), {
    source: 'explicit',
    platform,
  });

describe('classifyDirectory', () => {
  it('recognizes an Electron app and picks only the main executable', async () => {
    const exe = await fakeElectronApp(dir);
    const candidate = await classify(dir);
    expect(candidate?.kind).toBe('electron');
    expect(candidate?.binaries).toEqual([exe]);
    expect(candidate?.manifestPath).toBe(path.join(dir, 'resources', 'app.asar'));
  });

  it('recognizes a Windows layout and skips Squirrel helpers', async () => {
    const exe = await fakeElectronApp(dir, { platform: 'win32', exeName: 'Slack.exe' });
    const candidate = await classify(dir, 'win32');
    expect(candidate?.binaries).toEqual([exe]);
  });

  it('accepts unpacked resources/app folders', async () => {
    await fakeElectronApp(dir, { unpackedApp: true });
    expect((await classify(dir))?.manifestPath).toBe(
      path.join(dir, 'resources', 'app', 'package.json'),
    );
  });

  it('does not treat a plain Chromium browser folder as Electron', async () => {
    await writeFile(path.join(dir, 'icudtl.dat'), '');
    await writeFile(path.join(dir, 'chrome.exe'), fakeBinary({ chrome: '141.0.7390.37' }));
    await mkdir(path.join(dir, 'locales'));
    expect(await classify(dir)).toBeNull();
  });

  it('recognizes CEF and Qt WebEngine libraries', async () => {
    const cefDir = path.join(dir, 'cef');
    const qtDir = path.join(dir, 'qt');
    await mkdir(cefDir);
    await mkdir(qtDir);
    await writeFile(path.join(cefDir, 'libcef.dll'), '');
    await writeFile(path.join(qtDir, 'libQt6WebEngineCore.so.6'), '');
    expect((await classify(cefDir))?.kind).toBe('cef');
    expect((await classify(qtDir))?.kind).toBe('qtwebengine');
  });
});

describe('inspectCandidate', () => {
  it('reports versions, fuses and the manifest name', async () => {
    await fakeElectronApp(dir, { electron: '43.7.7', chrome: '150.0.7871.250', fuses: '1001' });
    const candidate = await classify(dir);
    const outcome = await inspectCandidate(candidate!, { hash: true });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.app).toMatchObject({
      name: 'Fake App',
      appVersion: '1.0.0',
      kind: 'electron',
      runtime: { electron: '43.7.7', chromium: '150.0.7871.250' },
      id: appId(dir),
    });
    expect(outcome.app.fuses?.fuses.map((fuse) => fuse.state)).toEqual([
      'enabled',
      'disabled',
      'disabled',
      'enabled',
    ]);
    expect(outcome.app.binarySha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('prefers names from discovery hints', async () => {
    await fakeElectronApp(dir);
    const candidate = await classify(dir);
    const outcome = await inspectCandidate({
      ...candidate!,
      hints: { name: 'Registry Name', version: '9.9' },
    });
    expect(outcome.ok && outcome.app.name).toBe('Registry Name');
    expect(outcome.ok && outcome.app.appVersion).toBe('9.9');
  });

  it('skips folders whose binary has no runtime markers', async () => {
    await fakeElectronApp(dir);
    const candidate = (await classify(dir))!;
    await writeFile(candidate.binaries[0]!, Buffer.alloc(100_000, 0x20));
    const outcome = await inspectCandidate(candidate);
    expect(outcome.ok).toBe(false);
  });
});

describe('findCandidates', () => {
  it('finds apps within depth, skips node_modules and does not descend into apps', async () => {
    await fakeElectronApp(path.join(dir, 'opt', 'Good'));
    await fakeElectronApp(path.join(dir, 'opt', 'vendor', 'Nested'));
    await fakeElectronApp(path.join(dir, 'opt', 'node_modules', 'electron', 'dist'));
    await fakeElectronApp(path.join(dir, 'opt', 'a', 'b', 'c', 'TooDeep'));
    await fakeElectronApp(path.join(dir, 'opt', 'Good', 'resources', 'Inner'));
    const result = await findCandidates([
      { path: path.join(dir, 'opt'), maxDepth: 3, source: 'filesystem' },
    ]);
    const roots = result.candidates.map((candidate) => path.relative(dir, candidate.root)).sort();
    expect(roots).toEqual([path.join('opt', 'Good'), path.join('opt', 'vendor', 'Nested')]);
  });

  it('survives symlink loops and reports an app reached twice once', async () => {
    await fakeElectronApp(path.join(dir, 'apps', 'One'));
    // Junctions on Windows need no special privileges; the type is ignored elsewhere.
    await symlink(path.join(dir, 'apps'), path.join(dir, 'apps', 'loop'), 'junction');
    await symlink(path.join(dir, 'apps', 'One'), path.join(dir, 'apps', 'alias'), 'junction');
    const result = await findCandidates([
      { path: path.join(dir, 'apps'), maxDepth: 6, source: 'filesystem' },
    ]);
    expect(result.candidates).toHaveLength(1);
  });

  it('reports unreadable roots and respects the directory budget', async () => {
    for (let i = 0; i < 10; i++) await mkdir(path.join(dir, 'many', `d${i}`), { recursive: true });
    const result = await findCandidates(
      [
        { path: path.join(dir, 'missing'), maxDepth: 2, source: 'filesystem' },
        { path: path.join(dir, 'many'), maxDepth: 2, source: 'filesystem' },
      ],
      { maxDirectories: 3 },
    );
    expect(result.limitReached).toBe(true);
    expect(result.skipped.some((item) => item.reason.includes('budget'))).toBe(true);
  });

  it('keeps only the newest Squirrel app-* folder', () => {
    const base = {
      kind: 'electron' as const,
      binaries: [],
      source: 'filesystem' as const,
      hints: {},
    };
    const collapsed = collapseSideBySideCopies(
      [
        { ...base, root: '/home/u/.local/Slack/app-4.9.1' },
        { ...base, root: '/home/u/.local/Slack/app-4.41.105' },
        { ...base, root: '/home/u/.local/Slack/app-4.40.0' },
        { ...base, root: '/opt/Other' },
      ],
      'linux',
    );
    const slack = collapsed.find((candidate) => candidate.root.includes('Slack'));
    expect(slack?.root).toBe('/home/u/.local/Slack/app-4.41.105');
    expect(slack?.otherCopies).toHaveLength(2);
    expect(collapsed).toHaveLength(2);
  });
});
