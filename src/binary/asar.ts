import { open, readFile } from 'node:fs/promises';

/** Fields we read from an application's package.json. */
export interface AppManifest {
  name?: string;
  productName?: string;
  version?: string;
}

const MAX_HEADER_BYTES = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

interface AsarFileEntry {
  size?: number;
  offset?: string;
  unpacked?: boolean;
}

function pickManifest(raw: unknown): AppManifest | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Record<string, unknown>;
  const manifest: AppManifest = {};
  for (const key of ['name', 'productName', 'version'] as const) {
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
  const handle = await open(asarPath, 'r');
  try {
    const { size } = await handle.stat();
    const prefix = Buffer.alloc(16);
    const { bytesRead } = await handle.read(prefix, 0, 16, 0);
    if (bytesRead < 16 || prefix.readUInt32LE(0) !== 4) return null;
    const headerPickleSize = prefix.readUInt32LE(4);
    const jsonLength = prefix.readUInt32LE(12);
    if (
      headerPickleSize > MAX_HEADER_BYTES ||
      jsonLength > headerPickleSize ||
      16 + jsonLength > size
    ) {
      return null;
    }
    const json = Buffer.alloc(jsonLength);
    await handle.read(json, 0, jsonLength, 16);
    const header = JSON.parse(json.toString('utf8')) as { files?: Record<string, AsarFileEntry> };
    const entry = header.files?.['package.json'];
    if (!entry || typeof entry.size !== 'number' || entry.size > MAX_MANIFEST_BYTES) return null;
    if (entry.unpacked) {
      const unpacked = await readFile(`${asarPath}.unpacked/package.json`, 'utf8');
      return pickManifest(JSON.parse(unpacked));
    }
    const offset = Number(entry.offset);
    const dataStart = 8 + headerPickleSize + offset;
    if (!Number.isSafeInteger(offset) || offset < 0 || dataStart + entry.size > size) return null;
    const data = Buffer.alloc(entry.size);
    await handle.read(data, 0, entry.size, dataStart);
    return pickManifest(JSON.parse(data.toString('utf8')));
  } catch {
    return null;
  } finally {
    await handle.close();
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
