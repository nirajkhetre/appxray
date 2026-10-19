import type { Dirent } from 'node:fs';
import { readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';

import { classifyDirectory } from '../detect/classify.js';
import type { AppCandidate, AppHints, DiscoverySource, SkippedPath } from '../detect/types.js';
import type { Logger } from '../util/log.js';
import { silentLogger } from '../util/log.js';

export interface RootSpec {
  path: string;
  maxDepth: number;
  source: DiscoverySource;
  hints?: AppHints;
}

export interface WalkOptions {
  platform?: NodeJS.Platform;
  /** Upper bound on directories listed across all roots. */
  maxDirectories?: number;
  signal?: AbortSignal;
  logger?: Logger;
  /** Supplies names and versions known from other sources (registry, .desktop files). */
  hintsFor?: (root: string) => AppHints | undefined;
}

export interface WalkResult {
  candidates: AppCandidate[];
  skipped: SkippedPath[];
  directoriesVisited: number;
  unreadableDirectories: number;
  limitReached: boolean;
}

/** Directory names that never contain an app install and can be large. */
const SKIP_NAMES = new Set([
  'node_modules',
  '.git',
  '__pycache__',
  'locales',
  'cache',
  'code cache',
  'gpucache',
  'dawncache',
  'shadercache',
  'crashpad',
  'crashdumps',
  'logs',
  'temp',
  'tmp',
  'windowsapps',
  'winsxs',
  'installer',
  '$recycle.bin',
  'system volume information',
  'indexeddb',
  'local storage',
  'session storage',
  'service worker',
  'blob_storage',
  // Windows: per-package app data for Store apps, and browser profiles; both huge, never installs.
  'packages',
  'user data',
  'proc',
  'sys',
  'dev',
]);

const normalize = (dir: string, platform: NodeJS.Platform) =>
  platform === 'win32' ? path.resolve(dir).toLowerCase() : path.resolve(dir);

/**
 * Breadth-first search of the given roots for app install folders. The walk is bounded by
 * per-root depth and a global directory budget, tolerates permission errors, follows
 * symlinked directories at most once, and never descends into a detected app.
 */
export async function findCandidates(
  roots: readonly RootSpec[],
  options: WalkOptions = {},
): Promise<WalkResult> {
  const platform = options.platform ?? process.platform;
  const maxDirectories = options.maxDirectories ?? 250_000;
  const logger = options.logger ?? silentLogger;
  const visited = new Set<string>();
  const found = new Map<string, AppCandidate>();
  const skipped: SkippedPath[] = [];
  let directoriesVisited = 0;
  let unreadableDirectories = 0;
  let limitReached = false;

  for (const root of roots) {
    const queue: { dir: string; depth: number }[] = [{ dir: root.path, depth: 0 }];
    for (let head = 0; head < queue.length; head++) {
      options.signal?.throwIfAborted();
      if (directoriesVisited >= maxDirectories) {
        limitReached = true;
        break;
      }
      const { dir, depth } = queue[head] as { dir: string; depth: number };
      let key = normalize(dir, platform);
      if (visited.has(key)) continue;
      visited.add(key);

      let entries: Dirent[];
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (error) {
        unreadableDirectories++;
        const code = (error as NodeJS.ErrnoException).code;
        if (depth === 0 && code !== 'ENOENT') {
          skipped.push({ path: dir, reason: `cannot list directory (${code ?? 'error'})` });
        }
        logger.debug(`skip ${dir}: ${code ?? String(error)}`);
        continue;
      }
      directoriesVisited++;

      const candidate = await classifyDirectory(dir, entries, { source: root.source, platform });
      if (candidate) {
        // Looked up only for detected apps: the index is linear and the walk is large.
        candidate.hints = { ...root.hints, ...options.hintsFor?.(dir) };
        // Resolve symlinks so the same install reached two ways is reported once.
        key = normalize(await realpath(dir).catch(() => dir), platform);
        if (!found.has(key)) found.set(key, candidate);
        continue;
      }
      if (depth >= root.maxDepth) continue;

      for (const entry of entries) {
        if (SKIP_NAMES.has(entry.name.toLowerCase())) continue;
        const child = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          queue.push({ dir: child, depth: depth + 1 });
        } else if (entry.isSymbolicLink()) {
          try {
            if ((await stat(child)).isDirectory()) {
              const target = normalize(await realpath(child), platform);
              if (!visited.has(target)) queue.push({ dir: child, depth: depth + 1 });
            }
          } catch {
            // Dangling or unreadable link.
          }
        }
      }
    }
    if (limitReached) {
      skipped.push({
        path: root.path,
        reason: `directory budget of ${maxDirectories} reached; results may be incomplete`,
      });
      break;
    }
  }

  return {
    candidates: collapseSideBySideCopies([...found.values()], platform),
    skipped,
    directoriesVisited,
    unreadableDirectories,
    limitReached,
  };
}

const SQUIRREL_FOLDER = /^app-(\d+(?:\.\d+){0,3})$/i;

/**
 * Squirrel.Windows keeps old versions next to the current one (`app-1.0.1`, `app-1.0.2`).
 * Only the newest is launched, so scan that one and list the rest.
 */
export function collapseSideBySideCopies(
  candidates: readonly AppCandidate[],
  platform: NodeJS.Platform = process.platform,
): AppCandidate[] {
  const groups = new Map<string, { version: string; candidate: AppCandidate }[]>();
  const result: AppCandidate[] = [];
  for (const candidate of candidates) {
    const match = SQUIRREL_FOLDER.exec(path.basename(candidate.root));
    const version = match?.[1] ? semver.coerce(match[1])?.version : undefined;
    if (!version) {
      result.push(candidate);
      continue;
    }
    const parent = normalize(path.dirname(candidate.root), platform);
    const group = groups.get(parent) ?? [];
    group.push({ version, candidate });
    groups.set(parent, group);
  }
  for (const group of groups.values()) {
    group.sort((a, b) => semver.rcompare(a.version, b.version));
    const [newest, ...older] = group;
    if (!newest) continue;
    result.push({
      ...newest.candidate,
      otherCopies: [...(newest.candidate.otherCopies ?? []), ...older.map((o) => o.candidate.root)],
    });
  }
  return result;
}
