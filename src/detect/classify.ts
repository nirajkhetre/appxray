import type { Dirent } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import type { AppCandidate, AppHints, DiscoverySource, RuntimeKind } from './types.js';

/** Files every Chromium-based runtime ships next to its main executable. */
const CHROMIUM_MARKERS = [
  'icudtl.dat',
  'v8_context_snapshot.bin',
  'snapshot_blob.bin',
  'chrome_100_percent.pak',
  'resources.pak',
];

/** Executables Electron and Squirrel ship that are never the app itself. */
const HELPER_EXECUTABLES = new Set([
  'update.exe',
  'squirrel.exe',
  'elevate.exe',
  'chrome_crashpad_handler.exe',
  'crashpad_handler.exe',
  'notification_helper.exe',
  'chrome-sandbox',
  'chrome_crashpad_handler',
  'crashpad_handler',
]);

const NON_EXECUTABLE_EXTENSIONS = new Set([
  '.so',
  '.pak',
  '.bin',
  '.dat',
  '.json',
  '.txt',
  '.html',
  '.png',
  '.svg',
  '.ico',
  '.desktop',
  '.sh',
  '.md',
  '.xml',
  '.yml',
  '.yaml',
]);

const CEF_LIBRARIES = ['libcef.dll', 'libcef.so'];
const QT_WEBENGINE_LIBRARY = /^(?:lib)?qt[56]webenginecore(?:\.dll|\.so(?:\.\d+)*)$/i;

export interface ClassifyContext {
  source: DiscoverySource;
  hints?: AppHints;
  platform?: NodeJS.Platform;
}

const lower = (name: string) => name.toLowerCase();

function hasMarker(names: ReadonlySet<string>): boolean {
  return CHROMIUM_MARKERS.some((marker) => names.has(marker));
}

/**
 * Decides whether `dir` is the root of an app with an embedded Chromium runtime, using
 * only the directory listing plus at most one listing of `resources/`. Returns null when
 * it is not. The result still needs a binary scan to confirm the runtime.
 */
export async function classifyDirectory(
  dir: string,
  entries: readonly Dirent[],
  context: ClassifyContext,
): Promise<AppCandidate | null> {
  const platform = context.platform ?? process.platform;
  const names = new Set(entries.map((entry) => lower(entry.name)));
  const hints = context.hints ?? {};

  const cef = entries.find((entry) => CEF_LIBRARIES.includes(lower(entry.name)));
  if (cef) {
    return candidate(dir, 'cef', [path.join(dir, cef.name)], context.source, hints);
  }

  const qt = entries.find((entry) => QT_WEBENGINE_LIBRARY.test(entry.name));
  if (qt) {
    return candidate(dir, 'qtwebengine', [path.join(dir, qt.name)], context.source, hints);
  }

  if (!hasMarker(names) || !names.has('resources')) return null;
  const resourcesEntry = entries.find((entry) => lower(entry.name) === 'resources');
  if (!resourcesEntry) return null;
  const resourcesDir = path.join(dir, resourcesEntry.name);
  let resources: Dirent[];
  try {
    resources = await readdir(resourcesDir, { withFileTypes: true });
  } catch {
    return null;
  }
  const asar = resources.find((entry) => lower(entry.name) === 'app.asar');
  const appDir = resources.find((entry) => lower(entry.name) === 'app' && entry.isDirectory());
  const defaultApp = resources.find((entry) => lower(entry.name) === 'default_app.asar');
  if (!asar && !appDir && !defaultApp) return null;

  const binaries = await pickExecutables(dir, entries, platform);
  if (binaries.length === 0) return null;

  const manifestPath = asar
    ? path.join(resourcesDir, asar.name)
    : appDir
      ? path.join(resourcesDir, appDir.name, 'package.json')
      : undefined;
  const result = candidate(dir, 'electron', binaries, context.source, hints);
  if (manifestPath) result.manifestPath = manifestPath;
  return result;
}

function candidate(
  root: string,
  kind: RuntimeKind,
  binaries: string[],
  source: DiscoverySource,
  hints: AppHints,
): AppCandidate {
  return { root, kind, binaries, source, hints };
}

/**
 * Lists plausible main executables, largest first. Electron statically links Chromium into
 * the main executable, so it is by far the largest file in the folder.
 */
async function pickExecutables(
  dir: string,
  entries: readonly Dirent[],
  platform: NodeJS.Platform,
): Promise<string[]> {
  const sized: { file: string; size: number }[] = [];
  for (const entry of entries) {
    if (!entry.isFile() && !entry.isSymbolicLink()) continue;
    const name = lower(entry.name);
    if (HELPER_EXECUTABLES.has(name) || name.startsWith('uninstall')) continue;
    const extension = path.extname(name);
    if (platform === 'win32') {
      if (extension !== '.exe') continue;
    } else if (NON_EXECUTABLE_EXTENSIONS.has(extension) || /\.so(\.\d+)*$/.test(name)) {
      continue;
    }
    const file = path.join(dir, entry.name);
    try {
      const info = await stat(file);
      if (!info.isFile()) continue;
      if (platform !== 'win32' && (info.mode & 0o111) === 0) continue;
      sized.push({ file, size: info.size });
    } catch {
      // Unreadable entries are simply not candidates.
    }
  }
  return sized.sort((a, b) => b.size - a.size).map((item) => item.file);
}
