import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readAsarManifest, readDirectoryManifest } from '../../src/binary/asar.js';
import { decodeFuseWire, FUSE_SENTINEL, fuseState } from '../../src/binary/fuses.js';
import { scanBinary } from '../../src/binary/scan.js';
import { buildAsar, fakeBinary, tempDir } from '../helpers.js';

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => ({ dir, cleanup } = await tempDir()));
afterEach(async () => cleanup());

describe('decodeFuseWire', () => {
  it('decodes states and names in Electron order', () => {
    const wire = decodeFuseWire(Buffer.from([1, 4, 0x31, 0x30, 0x72, 0x31]), 100);
    expect(wire?.offset).toBe(100);
    expect(wire?.fuses.map((fuse) => [fuse.name, fuse.state])).toEqual([
      ['RunAsNode', 'enabled'],
      ['EnableCookieEncryption', 'disabled'],
      ['EnableNodeOptionsEnvironmentVariable', 'removed'],
      ['EnableNodeCliInspectArguments', 'enabled'],
    ]);
    expect(fuseState(wire ?? undefined, 'RunAsNode')).toBe('enabled');
  });

  it('names fuses newer than this release by index', () => {
    const states = '0'.repeat(11);
    const wire = decodeFuseWire(Buffer.from([1, 11, ...Buffer.from(states)]), 0);
    expect(wire?.fuses[9]?.name).toBe('Unknown9');
  });

  it.each([
    ['unknown wire version', [2, 1, 0x31]],
    ['zero fuses', [1, 0]],
    ['truncated wire', [1, 5, 0x31]],
    ['invalid state byte', [1, 2, 0x31, 0x39]],
  ])('rejects %s', (_label, bytes) => {
    expect(decodeFuseWire(Buffer.from(bytes), 0)).toBeNull();
  });
});

describe('scanBinary', () => {
  it('finds Electron, Chromium and fuse markers and hashes the file', async () => {
    const file = path.join(dir, 'app');
    const bytes = fakeBinary({ electron: '43.7.7', chrome: '150.0.7871.250', fuses: '101' });
    await writeFile(file, bytes);
    const result = await scanBinary(file, { hash: true });
    expect(result.electron.map((hit) => hit.value)).toEqual(['43.7.7']);
    expect(result.chrome.map((hit) => hit.value)).toEqual(['150.0.7871.250']);
    expect(result.fuseWires).toHaveLength(1);
    expect(result.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(result.truncated).toBe(false);
  });

  it('reads prerelease Electron versions and ignores format strings', async () => {
    const file = path.join(dir, 'app');
    await writeFile(file, fakeBinary({ electron: '44.0.0-beta.3' }));
    const result = await scanBinary(file);
    expect(result.electron.map((hit) => hit.value)).toEqual(['44.0.0-beta.3']);
  });

  it('does not read a four-part number as an Electron version', async () => {
    const file = path.join(dir, 'app');
    await writeFile(file, Buffer.from('xx Electron/1.2.3.4 yy Electron/5.6.7 zz'));
    const result = await scanBinary(file);
    expect(result.electron.map((hit) => hit.value)).toEqual(['5.6.7']);
  });

  it('counts repeated values and orders by frequency', async () => {
    const file = path.join(dir, 'app');
    await writeFile(file, Buffer.from('Electron/2.0.0 Electron/3.0.0 Electron/3.0.0 '));
    const result = await scanBinary(file);
    expect(result.electron).toMatchObject([
      { value: '3.0.0', count: 2 },
      { value: '2.0.0', count: 1 },
    ]);
  });

  it('reads the Qt WebEngine security patch level', async () => {
    const file = path.join(dir, 'libQt6WebEngineCore.so.6');
    await writeFile(file, fakeBinary({ chrome: '130.0.6723.192', qtPatch: '139.0.7258.67' }));
    const result = await scanBinary(file);
    expect(result.qtSecurityPatch.map((hit) => hit.value)).toEqual(['139.0.7258.67']);
  });

  // Markers that straddle a chunk boundary must be found exactly once.
  it('finds markers at every position relative to chunk boundaries', async () => {
    const chunkSize = 512;
    const marker = Buffer.concat([
      Buffer.from('Electron/12.3.4\0Chrome/120.0.6099.71\0', 'latin1'),
      FUSE_SENTINEL,
      Buffer.from([1, 3, 0x31, 0x30, 0x31]),
    ]);
    for (let offset = chunkSize - marker.length - 2; offset <= chunkSize + 2; offset++) {
      const file = path.join(dir, `boundary-${offset}`);
      const bytes = Buffer.alloc(chunkSize * 3, 0x20);
      marker.copy(bytes, offset);
      await writeFile(file, bytes);
      const result = await scanBinary(file, { chunkSize });
      expect(result.electron, `offset ${offset}`).toMatchObject([{ value: '12.3.4', count: 1 }]);
      expect(result.chrome, `offset ${offset}`).toMatchObject([
        { value: '120.0.6099.71', count: 1 },
      ]);
      expect(result.fuseWires, `offset ${offset}`).toHaveLength(1);
    }
  });

  it('stops at maxBytes and reports truncation', async () => {
    const file = path.join(dir, 'big');
    const bytes = Buffer.alloc(4096, 0x20);
    Buffer.from('Electron/9.9.9').copy(bytes, 3000);
    await writeFile(file, bytes);
    const result = await scanBinary(file, { maxBytes: 1024, chunkSize: 512, hash: true });
    expect(result.truncated).toBe(true);
    expect(result.electron).toEqual([]);
    expect(result.sha256).toBeUndefined();
  });

  it('honors an abort signal', async () => {
    const file = path.join(dir, 'app');
    await writeFile(file, fakeBinary({ electron: '1.0.0' }));
    await expect(scanBinary(file, { signal: AbortSignal.abort() })).rejects.toThrow();
  });
});

describe('ASAR manifests', () => {
  it('reads package.json from an archive', async () => {
    const file = path.join(dir, 'app.asar');
    const manifest = { name: 'demo', productName: 'Demo App', version: '2.3.4', main: 'main.js' };
    await writeFile(
      file,
      buildAsar({ 'main.js': 'console.log(1)', 'package.json': JSON.stringify(manifest) }),
    );
    expect(await readAsarManifest(file)).toEqual({
      name: 'demo',
      productName: 'Demo App',
      version: '2.3.4',
      main: 'main.js',
    });
  });

  it('follows unpacked entries', async () => {
    const file = path.join(dir, 'app.asar');
    const manifest = JSON.stringify({ name: 'demo', version: '1.0.0' });
    await writeFile(file, buildAsar({ 'package.json': manifest }, ['package.json']));
    const { mkdir } = await import('node:fs/promises');
    await mkdir(`${file}.unpacked`);
    await writeFile(`${file}.unpacked/package.json`, manifest);
    expect(await readAsarManifest(file)).toEqual({ name: 'demo', version: '1.0.0' });
  });

  it.each([
    ['not an archive', Buffer.from('hello world, definitely not asar')],
    ['empty file', Buffer.alloc(0)],
    [
      'header larger than file',
      Buffer.from([4, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0]),
    ],
  ])('returns null for %s', async (_label, bytes) => {
    const file = path.join(dir, 'bad.asar');
    await writeFile(file, bytes);
    expect(await readAsarManifest(file)).toBeNull();
  });

  it('ignores non-string fields in manifests', async () => {
    const file = path.join(dir, 'package.json');
    await writeFile(file, JSON.stringify({ name: 42, version: '3.0.0' }));
    expect(await readDirectoryManifest(file)).toEqual({ version: '3.0.0' });
  });
});
