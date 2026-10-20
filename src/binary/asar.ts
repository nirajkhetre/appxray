import { open, readFile, stat, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

/** Fields we read from an application's package.json. */
export interface AppManifest {
  name?: string;
  productName?: string;
  version?: string;
  /** Main-process entry point, relative to the app root. */
  main?: string;
}

const MAX_HEADER_BYTES = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
/** Archives with more entries than this are treated as malformed. */
const MAX_ENTRIES = 500_000;

interface AsarHeaderNode {
  files?: Record<string, AsarHeaderNode>;
  size?: number;
  offset?: string;
  unpacked?: boolean;
  link?: string;
}

export interface AsarEntry {
  /** Forward-slash path relative to the archive root. */
  path: string;
  size: number;
  unpacked: boolean;
  offset: number;
}

/**
 * Read-only view of an ASAR archive (Electron's app bundle format). Only the header is
 * parsed; file contents are read on demand with size limits. Nothing is extracted.
 */
export class AsarArchive {
  private constructor(
    readonly archivePath: string,
    private readonly dataStart: number,
    private readonly fileSize: number,
    readonly entries: ReadonlyMap<string, AsarEntry>,
  ) {}

  static async open(archivePath: string): Promise<AsarArchive> {
    const handle = await open(archivePath, 'r');
    try {
      const { size } = await handle.stat();
      const prefix = Buffer.alloc(16);
      const { bytesRead } = await handle.read(prefix, 0, 16, 0);
      if (bytesRead < 16 || prefix.readUInt32LE(0) !== 4) throw new Error('not an ASAR archive');
      const headerPickleSize = prefix.readUInt32LE(4);
      const jsonLength = prefix.readUInt32LE(12);
      if (
        headerPickleSize > MAX_HEADER_BYTES ||
        jsonLength > headerPickleSize ||
        16 + jsonLength > size
      ) {
        throw new Error('ASAR header is malformed or too large');
      }
      const json = Buffer.alloc(jsonLength);
      await handle.read(json, 0, jsonLength, 16);
      const header = JSON.parse(json.toString('utf8')) as AsarHeaderNode;
      const entries = new Map<string, AsarEntry>();
      collect(header, '', entries);
      return new AsarArchive(archivePath, 8 + headerPickleSize, size, entries);
    } finally {
      await handle.close();
    }
  }

  /** Reads one file, or returns null if it is missing, out of bounds or larger than maxBytes. */
  async read(entryPath: string, maxBytes: number, handle?: FileHandle): Promise<Buffer | null> {
    const entry = this.entries.get(entryPath);
    if (!entry || entry.size > maxBytes) return null;
    if (entry.unpacked) {
      const file = path.join(`${this.archivePath}.unpacked`, ...entry.path.split('/'));
      const info = await stat(file).catch(() => null);
      if (!info || info.size > maxBytes) return null;
      return readFile(file);
    }
    const start = this.dataStart + entry.offset;
    if (start + entry.size > this.fileSize) return null;
    const own = handle ?? (await open(this.archivePath, 'r'));
    try {
      const data = Buffer.alloc(entry.size);
      await own.read(data, 0, entry.size, start);
      return data;
    } finally {
      if (!handle) await own.close();
    }
  }

  /** Opens the archive for a batch of reads; close the handle when done. */
  openHandle(): Promise<FileHandle> {
    return open(this.archivePath, 'r');
  }
}

function collect(node: AsarHeaderNode, prefix: string, out: Map<string, AsarEntry>): void {
  for (const [name, child] of Object.entries(node.files ?? {})) {
    if (out.size >= MAX_ENTRIES) throw new Error('ASAR archive has too many entries');
    if (name.includes('/') || name.includes('\\') || name === '..' || name === '.') continue;
    const entryPath = prefix ? `${prefix}/${name}` : name;
    if (child.files) {
      collect(child, entryPath, out);
    } else if (typeof child.size === 'number' && child.link === undefined) {
      const offset = child.unpacked ? 0 : Number(child.offset);
      if (!child.unpacked && (!Number.isSafeInteger(offset) || offset < 0)) continue;
      out.set(entryPath, {
        path: entryPath,
        size: child.size,
        unpacked: child.unpacked === true,
        offset,
      });
    }
  }
}

export function pickManifest(raw: unknown): AppManifest | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Record<string, unknown>;
  const manifest: AppManifest = {};
  for (const key of ['name', 'productName', 'version', 'main'] as const) {
    const value = record[key];
    if (typeof value === 'string' && value.length > 0 && value.length <= 200) manifest[key] = value;
  }
  return manifest;
}

/**
 * Reads `package.json` from an ASAR archive without extracting it.
 * Returns null for anything that is not a well-formed archive with a bounded manifest.
 */
export async function readAsarManifest(asarPath: string): Promise<AppManifest | null> {
  try {
    const archive = await AsarArchive.open(asarPath);
    const data = await archive.read('package.json', MAX_MANIFEST_BYTES);
    return data ? pickManifest(JSON.parse(data.toString('utf8'))) : null;
  } catch {
    return null;
  }
}

/** Reads an unpacked `resources/app/package.json`. */
export async function readDirectoryManifest(packageJsonPath: string): Promise<AppManifest | null> {
  try {
    const handle = await open(packageJsonPath, 'r');
    try {
      const { size } = await handle.stat();
      if (size > MAX_MANIFEST_BYTES) return null;
      return pickManifest(JSON.parse(await handle.readFile('utf8')));
    } finally {
      await handle.close();
    }
  } catch {
    return null;
  }
}
