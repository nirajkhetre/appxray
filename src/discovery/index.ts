import type { Dirent } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { classifyDirectory } from '../detect/classify.js';
import type { AppCandidate, AppHints, SkippedPath } from '../detect/types.js';
import type { Logger } from '../util/log.js';
import { silentLogger } from '../util/log.js';
import { planLinux } from './linux.js';
import { findCandidates, type RootSpec } from './walk.js';
import { planWindows } from './windows.js';

export interface DiscoverOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  allUsers?: boolean;
  /** Extra folders to search in addition to (or instead of) the defaults. */
  extraRoots?: string[];
  defaultRoots?: boolean;
  maxDirectories?: number;
  logger?: Logger;
  signal?: AbortSignal;
}

export interface DiscoveryResult {
  candidates: AppCandidate[];
  skipped: SkippedPath[];
  directoriesVisited: number;
  unreadableDirectories: number;
}

export class UnsupportedPlatformError extends Error {
  constructor(platform: string) {
    super(
      `Scanning installed apps is supported on Windows and Linux (this is ${platform}). ` +
        'Use "appxray inspect <path>" to check a specific app folder.',
    );
    this.name = 'UnsupportedPlatformError';
  }
}

/** Finds installed apps with an embedded Chromium runtime on this machine. */
export async function discoverApps(options: DiscoverOptions = {}): Promise<DiscoveryResult> {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const logger = options.logger ?? silentLogger;
  const useDefaults = options.defaultRoots ?? true;

  const roots: RootSpec[] = [];
  const skipped: SkippedPath[] = [];
  let hintsFor: ((dir: string) => AppHints | undefined) | undefined;

  if (useDefaults) {
    if (platform === 'win32') {
      const plan = await planWindows({ env, allUsers: options.allUsers ?? false, logger });
      roots.push(...plan.roots);
      hintsFor = (dir) => plan.hints.lookup(dir);
      logger.debug(`registry provided ${plan.hints.size} install locations`);
    } else if (platform === 'linux') {
      const plan = await planLinux({
        env,
        home: os.homedir(),
        allUsers: options.allUsers ?? false,
      });
      roots.push(...plan.roots);
      skipped.push(...plan.skipped);
      hintsFor = (dir) => plan.hints.lookup(dir);
    } else {
      throw new UnsupportedPlatformError(platform);
    }
  }
  for (const extra of options.extraRoots ?? []) {
    roots.push({ path: path.resolve(extra), maxDepth: 4, source: 'explicit' });
  }

  const walkOptions = {
    platform,
    logger,
    ...(options.maxDirectories ? { maxDirectories: options.maxDirectories } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    ...(hintsFor ? { hintsFor } : {}),
  };
  const result = await findCandidates(roots, walkOptions);
  return {
    candidates: result.candidates,
    skipped: [...skipped, ...result.skipped],
    directoriesVisited: result.directoriesVisited,
    unreadableDirectories: result.unreadableDirectories,
  };
}

const QT_LIBRARY = /^(?:lib)?qt[56]webenginecore(?:\.dll|\.so(?:\.\d+)*)$/i;

/**
 * Resolves user-supplied paths for `inspect`: folders are searched (so a build output such as
 * `dist/` works), files are treated as the runtime binary itself.
 */
export async function candidatesForPaths(
  paths: readonly string[],
  options: { logger?: Logger; platform?: NodeJS.Platform; signal?: AbortSignal } = {},
): Promise<DiscoveryResult> {
  const platform = options.platform ?? process.platform;
  const candidates: AppCandidate[] = [];
  const skipped: SkippedPath[] = [];
  const folders: RootSpec[] = [];
  for (const input of paths) {
    const resolved = path.resolve(input);
    let info;
    try {
      info = await stat(resolved);
    } catch (error) {
      skipped.push({
        path: resolved,
        reason: `not found (${(error as NodeJS.ErrnoException).code ?? 'error'})`,
      });
      continue;
    }
    if (info.isDirectory()) {
      folders.push({ path: resolved, maxDepth: 4, source: 'explicit' });
      continue;
    }
    const base = path.basename(resolved);
    const kind = /^libcef\.(dll|so)$/i.test(base)
      ? 'cef'
      : QT_LIBRARY.test(base)
        ? 'qtwebengine'
        : 'electron';
    const dir = path.dirname(resolved);
    let entries: Dirent[] = [];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      // The binary alone is still scannable.
    }
    const fromFolder = await classifyDirectory(dir, entries, { source: 'explicit', platform });
    const candidate: AppCandidate = {
      root: dir,
      kind,
      binaries: [resolved],
      source: 'explicit',
      hints: {},
    };
    if (fromFolder?.manifestPath && kind === 'electron')
      candidate.manifestPath = fromFolder.manifestPath;
    candidates.push(candidate);
  }
  const walked = await findCandidates(folders, {
    platform,
    ...(options.logger ? { logger: options.logger } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  });
  return {
    candidates: [...candidates, ...walked.candidates],
    skipped: [...skipped, ...walked.skipped],
    directoriesVisited: walked.directoriesVisited,
    unreadableDirectories: walked.unreadableDirectories,
  };
}
