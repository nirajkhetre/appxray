import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { FUSE_SENTINEL } from '../src/binary/fuses.js';

export async function tempDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'appxray-test-'));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export interface FakeBinaryOptions {
  electron?: string;
  chrome?: string;
  /** Fuse characters, e.g. "1011" ('0' disabled, '1' enabled, 'r' removed). */
  fuses?: string;
  qtPatch?: string;
  /** Filler bytes before the markers. */
  padding?: number;
}

/** Builds bytes that contain the same markers a real Electron/Qt binary does. */
export function fakeBinary(options: FakeBinaryOptions): Buffer {
  const parts: Buffer[] = [Buffer.alloc(options.padding ?? 1024, 0x41)];
  if (options.electron)
    parts.push(Buffer.from(`\0Chrome/%s Electron/${options.electron}\0`, 'latin1'));
  if (options.chrome) parts.push(Buffer.from(`\0Mozilla/5.0 Chrome/${options.chrome}\0`, 'latin1'));
  if (options.fuses !== undefined) {
    parts.push(
      FUSE_SENTINEL,
      Buffer.from([1, options.fuses.length]),
      Buffer.from(options.fuses, 'latin1'),
    );
  }
  if (options.qtPatch)
    parts.push(Buffer.from(`6.9.2\0QtWebEngineProcess\0${options.qtPatch}\0`, 'latin1'));
  parts.push(Buffer.alloc(512, 0x42));
  return Buffer.concat(parts);
}

interface AsarNode {
  files?: Record<string, AsarNode>;
  size?: number;
  offset?: string;
  unpacked?: boolean;
}

/**
 * Builds an ASAR archive in the format written by @electron/asar. Keys may contain "/" for
 * nested folders.
 */
export function buildAsar(files: Record<string, string>, unpacked: readonly string[] = []): Buffer {
  const root: AsarNode = { files: {} };
  const data: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const parts = name.split('/');
    let node = root;
    for (const dir of parts.slice(0, -1)) {
      node.files ??= {};
      node = node.files[dir] ??= { files: {} };
    }
    node.files ??= {};
    const bytes = Buffer.from(content, 'utf8');
    const leaf = parts[parts.length - 1] as string;
    if (unpacked.includes(name)) {
      node.files[leaf] = { size: bytes.length, unpacked: true };
      continue;
    }
    node.files[leaf] = { size: bytes.length, offset: String(offset) };
    data.push(bytes);
    offset += bytes.length;
  }
  const json = Buffer.from(JSON.stringify(root), 'utf8');
  const padded = Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(8 + padded);
  header.writeUInt32LE(4 + padded, 0);
  header.writeUInt32LE(json.length, 4);
  json.copy(header, 8);
  const size = Buffer.alloc(8);
  size.writeUInt32LE(4, 0);
  size.writeUInt32LE(header.length, 4);
  return Buffer.concat([size, header, ...data]);
}

export interface FakeAppOptions extends FakeBinaryOptions {
  platform?: 'linux' | 'win32';
  exeName?: string;
  manifest?: Record<string, string>;
  /** Use resources/app/ instead of resources/app.asar. */
  unpackedApp?: boolean;
}

/** Creates an Electron-style install folder and returns the main binary path. */
export async function fakeElectronApp(root: string, options: FakeAppOptions = {}): Promise<string> {
  const platform = options.platform ?? (process.platform === 'win32' ? 'win32' : 'linux');
  await mkdir(path.join(root, 'resources'), { recursive: true });
  await writeFile(path.join(root, 'icudtl.dat'), 'icu');
  await writeFile(path.join(root, 'v8_context_snapshot.bin'), 'snapshot');
  const manifest = JSON.stringify(
    options.manifest ?? { name: 'fake-app', productName: 'Fake App', version: '1.0.0' },
  );
  if (options.unpackedApp) {
    await mkdir(path.join(root, 'resources', 'app'), { recursive: true });
    await writeFile(path.join(root, 'resources', 'app', 'package.json'), manifest);
  } else {
    await writeFile(
      path.join(root, 'resources', 'app.asar'),
      buildAsar({ 'package.json': manifest }),
    );
  }
  const exe = path.join(
    root,
    options.exeName ?? (platform === 'win32' ? 'Fake App.exe' : 'fake-app'),
  );
  await writeFile(
    exe,
    fakeBinary({
      electron: '30.1.0',
      chrome: '124.0.6367.243',
      fuses: '1011',
      ...options,
      padding: options.padding ?? 64 * 1024,
    }),
  );
  await chmod(exe, 0o755);
  // Helpers that must never be picked as the main binary.
  if (platform === 'win32') {
    await writeFile(path.join(root, 'Update.exe'), Buffer.alloc(16));
  } else {
    await writeFile(path.join(root, 'chrome-sandbox'), Buffer.alloc(16));
    await chmod(path.join(root, 'chrome-sandbox'), 0o755);
  }
  return exe;
}
