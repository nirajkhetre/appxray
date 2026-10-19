import type { Dirent } from 'node:fs';
import { readdir } from 'node:fs/promises';
import path from 'node:path';

import type { AppHints } from '../detect/types.js';
import type { Logger } from '../util/log.js';
import { HintIndex } from './hints.js';
import { folderFromDisplayIcon, readUninstallEntries, type UninstallEntry } from './registry.js';
import type { RootSpec } from './walk.js';

const p = path.win32;

export interface WindowsPlanOptions {
  env: NodeJS.ProcessEnv;
  allUsers: boolean;
  /** Injected for tests; defaults to reading the registry. */
  uninstallEntries?: UninstallEntry[];
  logger: Logger;
}

export interface DiscoveryPlan {
  roots: RootSpec[];
  hints: HintIndex;
}

const PROFILE_SKIP = new Set(['all users', 'default', 'default user', 'public', 'defaultapppool']);

function env(envs: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = envs[name];
  return value && value.trim() ? value : undefined;
}

/** Install locations to search on Windows, plus names/versions from the registry. */
export async function planWindows(options: WindowsPlanOptions): Promise<DiscoveryPlan> {
  const e = options.env;
  const programFiles = [
    env(e, 'ProgramW6432'),
    env(e, 'ProgramFiles'),
    env(e, 'ProgramFiles(x86)'),
  ];
  const localAppData = env(e, 'LOCALAPPDATA');
  const appData = env(e, 'APPDATA');
  const programData = env(e, 'ProgramData');

  const roots: RootSpec[] = [];
  const add = (folder: string | undefined, maxDepth: number) => {
    if (folder) roots.push({ path: folder, maxDepth, source: 'filesystem' });
  };
  for (const folder of programFiles) add(folder, 3);
  if (localAppData) add(p.join(localAppData, 'Programs'), 3);
  add(localAppData, 3);
  add(appData, 2);
  add(programData, 3);

  if (options.allUsers) {
    for (const profile of await otherProfiles(e)) {
      add(p.join(profile, 'AppData', 'Local', 'Programs'), 3);
      add(p.join(profile, 'AppData', 'Local'), 3);
      add(p.join(profile, 'AppData', 'Roaming'), 2);
    }
  }

  const tooBroad = roots.map((root) => root.path);
  const hints = new HintIndex('win32', tooBroad);
  const entries = options.uninstallEntries ?? (await readUninstallEntries(options.logger));
  for (const entry of entries) {
    const entryHints: AppHints = { name: entry.displayName };
    if (entry.displayVersion) entryHints.version = entry.displayVersion;
    if (entry.publisher) entryHints.publisher = entry.publisher;
    const folders = [
      entry.installLocation?.replace(/^"(.*)"$/, '$1'),
      entry.displayIcon ? folderFromDisplayIcon(entry.displayIcon) : undefined,
    ];
    for (const folder of folders) {
      if (!folder || !/^[a-z]:\\/i.test(folder)) continue;
      hints.add(folder, entryHints);
      // Registered locations outside the default roots still need to be searched.
      if (!tooBroad.some((root) => isUnder(folder, root))) {
        roots.push({ path: folder, maxDepth: 2, source: 'registry', hints: entryHints });
      }
    }
  }
  return { roots, hints };
}

function isUnder(child: string, parent: string): boolean {
  const rel = p.relative(parent.toLowerCase(), child.toLowerCase());
  return rel === '' || (!rel.startsWith('..') && !p.isAbsolute(rel));
}

async function otherProfiles(e: NodeJS.ProcessEnv): Promise<string[]> {
  const userProfile = env(e, 'USERPROFILE');
  const usersDir = userProfile
    ? p.dirname(userProfile)
    : p.join(env(e, 'SystemDrive') ?? 'C:', '\\Users');
  let entries: Dirent[];
  try {
    entries = await readdir(usersDir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((entry) => entry.isDirectory() && !PROFILE_SKIP.has(entry.name.toLowerCase()))
    .map((entry) => p.join(usersDir, entry.name))
    .filter((profile) => !userProfile || profile.toLowerCase() !== userProfile.toLowerCase());
}
