import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { cacheDir } from '../util/paths.js';
import { PACKAGE_ROOT } from '../util/pkg.js';
import { validateDb, type VulnDb } from './schema.js';

export const BUNDLED_DB_PATH = path.join(PACKAGE_ROOT, 'data', 'appxray-db.json');
export const DB_FILE_NAME = 'appxray-db.json';

/** A database older than this is reported as stale. */
export const STALE_AFTER_DAYS = 14;

export type DbOrigin = 'explicit' | 'cache' | 'bundled';

export interface LoadedDb {
  db: VulnDb;
  path: string;
  origin: DbOrigin;
}

export function cachedDbPath(): string {
  return path.join(cacheDir(), DB_FILE_NAME);
}

export async function readDbFile(file: string): Promise<VulnDb> {
  const text = await readFile(file, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${file} is not valid JSON`);
  }
  return validateDb(parsed);
}

async function tryRead(file: string): Promise<VulnDb | null> {
  try {
    return await readDbFile(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Loads the database to scan with: an explicit file when given, otherwise whichever of the
 * per-user cache (written by `db update`) and the bundled copy is newer.
 */
export async function loadDb(explicitPath?: string): Promise<LoadedDb> {
  if (explicitPath) {
    const file = path.resolve(explicitPath);
    return { db: await readDbFile(file), path: file, origin: 'explicit' };
  }
  const cachePath = cachedDbPath();
  const [cached, bundled] = await Promise.all([
    tryRead(cachePath).catch(() => null),
    tryRead(BUNDLED_DB_PATH),
  ]);
  if (cached && (!bundled || cached.generatedAt > bundled.generatedAt)) {
    return { db: cached, path: cachePath, origin: 'cache' };
  }
  if (bundled) return { db: bundled, path: BUNDLED_DB_PATH, origin: 'bundled' };
  throw new Error(
    'No vulnerability database found. Run "appxray db update" to download one, or pass --db <file>.',
  );
}

/** Writes atomically so an interrupted update never leaves a truncated database behind. */
export async function saveDb(db: VulnDb, file: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(db, null, 1)}\n`, 'utf8');
  await rename(temporary, file);
}

export function dbAgeDays(db: VulnDb, now: Date = new Date()): number {
  return Math.max(0, Math.floor((now.getTime() - Date.parse(db.generatedAt)) / 86_400_000));
}
