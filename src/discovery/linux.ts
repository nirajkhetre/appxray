import type { Dirent } from 'node:fs';
import { readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

import type { SkippedPath } from '../detect/types.js';
import { HintIndex } from './hints.js';
import type { RootSpec } from './walk.js';

const p = path.posix;

export interface LinuxPlanOptions {
  env: NodeJS.ProcessEnv;
  home: string;
  allUsers: boolean;
  /** Filesystem prefix, used by tests to point at a fake root. */
  prefix?: string;
}

export interface LinuxPlan {
  roots: RootSpec[];
  hints: HintIndex;
  skipped: SkippedPath[];
}

/** Snaps that are runtimes or platform pieces rather than apps. */
const SNAP_SKIP =
  /^(bin|core\d*|snapd|bare|gtk-common-themes|gnome-\d.*|kde-frameworks.*|mesa-.*|gpu-.*)$/;

async function list(dir: string): Promise<Dirent[]> {
  try {
    return await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/** Install locations to search on Linux, plus names from .desktop launchers. */
export async function planLinux(options: LinuxPlanOptions): Promise<LinuxPlan> {
  const at = (absolute: string) => (options.prefix ? p.join(options.prefix, absolute) : absolute);
  const homes = [options.home];
  if (options.allUsers) {
    for (const entry of await list(at('/home'))) {
      if (entry.isDirectory()) homes.push(p.join('/home', entry.name));
    }
  }

  const roots: RootSpec[] = [];
  const add = (folder: string, maxDepth: number) =>
    roots.push({ path: at(folder), maxDepth, source: 'filesystem' });
  add('/opt', 4);
  add('/usr/lib', 3);
  add('/usr/lib64', 3);
  add('/usr/share', 3);
  add('/usr/local', 4);
  for (const home of new Set(homes)) {
    add(p.join(home, '.local', 'share'), 4);
    add(p.join(home, '.local', 'lib'), 3);
    add(p.join(home, 'opt'), 3);
    add(p.join(home, 'Applications'), 3);
  }

  for (const entry of await list(at('/snap'))) {
    if (!entry.isDirectory() || SNAP_SKIP.test(entry.name)) continue;
    roots.push({
      path: at(p.join('/snap', entry.name, 'current')),
      maxDepth: 6,
      source: 'snap',
      hints: { name: entry.name },
    });
  }

  const flatpakInstalls = [
    '/var/lib/flatpak/app',
    ...homes.map((home) => p.join(home, '.local/share/flatpak/app')),
  ];
  for (const installs of flatpakInstalls) {
    for (const entry of await list(at(installs))) {
      if (!entry.isDirectory()) continue;
      roots.push({
        path: at(p.join(installs, entry.name, 'current', 'active', 'files')),
        maxDepth: 5,
        source: 'flatpak',
        hints: { name: entry.name },
      });
    }
  }

  const hints = new HintIndex(
    'linux',
    roots.map((root) => root.path),
  );
  const applicationDirs = [
    '/usr/share/applications',
    '/usr/local/share/applications',
    '/var/lib/snapd/desktop/applications',
    '/var/lib/flatpak/exports/share/applications',
    ...homes.map((home) => p.join(home, '.local/share/applications')),
  ];
  const pathDirs = (options.env['PATH'] ?? '/usr/local/bin:/usr/bin:/bin').split(':');
  for (const dir of applicationDirs) {
    for (const entry of await list(at(dir))) {
      if (!entry.name.endsWith('.desktop')) continue;
      const desktop = await readDesktopEntry(at(p.join(dir, entry.name)));
      if (!desktop) continue;
      const target = await resolveExec(desktop.exec, pathDirs, at);
      if (!target) continue;
      const folder = p.dirname(target);
      // Launchers often point at a wrapper script in the app's bin/ folder.
      hints.add(p.basename(folder) === 'bin' ? p.dirname(folder) : folder, { name: desktop.name });
    }
  }

  const skipped: SkippedPath[] = [];
  for (const home of new Set(homes)) {
    for (const folder of ['Applications', 'Downloads', '.local/bin']) {
      for (const entry of await list(at(p.join(home, folder)))) {
        if (entry.isFile() && entry.name.toLowerCase().endsWith('.appimage')) {
          skipped.push({
            path: at(p.join(home, folder, entry.name)),
            reason: 'AppImage bundles are not inspected (contents are inside a compressed image)',
          });
        }
      }
    }
  }

  return { roots, hints, skipped };
}

export interface DesktopEntry {
  name: string;
  exec: string;
}

/** Reads Name and Exec from the [Desktop Entry] group of a .desktop file. */
export function parseDesktopEntry(content: string): DesktopEntry | null {
  let inMain = false;
  let name: string | undefined;
  let exec: string | undefined;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith('[')) {
      inMain = line === '[Desktop Entry]';
      continue;
    }
    if (!inMain) continue;
    if (line.startsWith('Name=') && name === undefined) name = line.slice(5).trim();
    else if (line.startsWith('Exec=') && exec === undefined) exec = line.slice(5).trim();
  }
  return name && exec ? { name, exec } : null;
}

async function readDesktopEntry(file: string): Promise<DesktopEntry | null> {
  try {
    const content = await readFile(file, 'utf8');
    return content.length > 256 * 1024 ? null : parseDesktopEntry(content);
  } catch {
    return null;
  }
}

/** First token of an Exec line, honouring simple double quotes and `env VAR=x` prefixes. */
export function execProgram(exec: string): string | undefined {
  const tokens = exec.match(/"[^"]*"|\S+/g)?.map((token) => token.replace(/^"(.*)"$/, '$1')) ?? [];
  let index = 0;
  if (tokens[index] === 'env') {
    index++;
    while (tokens[index]?.includes('=')) index++;
  }
  return tokens[index];
}

async function resolveExec(
  exec: string,
  pathDirs: readonly string[],
  at: (absolute: string) => string,
): Promise<string | undefined> {
  const program = execProgram(exec);
  if (!program) return undefined;
  const options = program.startsWith('/')
    ? [program]
    : program.includes('/')
      ? []
      : pathDirs.map((dir) => p.join(dir, program));
  for (const option of options) {
    try {
      return await realpath(at(option));
    } catch {
      // Not on this path entry.
    }
  }
  return undefined;
}
