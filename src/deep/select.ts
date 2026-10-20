import type { Dirent } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { AsarArchive, pickManifest } from '../binary/asar.js';

/**
 * Chooses which of an Electron app's JavaScript files REA should analyze.
 *
 * Full semantic analysis of a large app (VS Code ships ~1,500 JavaScript files) takes far too
 * long for a machine-wide scan, while the code that decides an app's Electron security posture
 * (window creation, preload scripts, IPC handlers) lives in a handful of files. appxray reads
 * the bundle itself, scores each file for Electron security APIs, and hands REA only the
 * relevant ones.
 */
export interface SourceSelection {
  /** Path given to REA: the app.asar file or the unpacked app folder. */
  appPath: string;
  format: 'asar' | 'directory';
  /** Selected sources, relative to the app root with forward slashes. */
  sources: string[];
  /** JavaScript files outside node_modules that were considered. */
  considered: number;
  /** Relevant files left out because of the file or byte budget. */
  omitted: number;
  /** Why each selected file was chosen. */
  reasons: Record<string, string[]>;
}

export interface SelectOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
}

/**
 * Boundary signals mark code that defines the Electron security boundary (windows, preload
 * bridges, main-process IPC). A file needs at least one to be selected; the others only rank.
 */
const SIGNALS: readonly { label: string; pattern: RegExp; weight: number; boundary: boolean }[] = [
  { label: 'webPreferences', pattern: /\bwebPreferences\b/, weight: 5, boundary: true },
  { label: 'contextBridge', pattern: /\bcontextBridge\b/, weight: 5, boundary: true },
  { label: 'ipcMain', pattern: /\bipcMain\b/, weight: 4, boundary: true },
  { label: 'BrowserWindow', pattern: /\bnew\s+[\w$.]*BrowserWindow\b/, weight: 3, boundary: true },
  { label: 'ipcRenderer', pattern: /\bipcRenderer\b/, weight: 2, boundary: false },
  { label: 'child_process', pattern: /\bchild_process\b/, weight: 2, boundary: false },
  { label: 'loadURL', pattern: /\.loadURL\(/, weight: 2, boundary: false },
  { label: 'openExternal', pattern: /\bopenExternal\b/, weight: 1, boundary: false },
];
const SCRIPT = /\.(?:js|cjs|mjs)$/i;
const EXCLUDED = /(?:^|\/)(?:node_modules|node_modules\.asar|\.git)(?:\/|$)|\.d\.ts$|\.min\.js$/i;
const MAX_LISTED = 100_000;

interface ListedFile {
  path: string;
  size: number;
}

interface AppFiles {
  files: ListedFile[];
  read(file: string, maxBytes: number): Promise<Buffer | null>;
  close(): Promise<void>;
}

async function asarFiles(archivePath: string): Promise<AppFiles> {
  const archive = await AsarArchive.open(archivePath);
  const handle = await archive.openHandle();
  return {
    files: [...archive.entries.values()].map((entry) => ({ path: entry.path, size: entry.size })),
    read: (file, maxBytes) => archive.read(file, maxBytes, handle),
    close: () => handle.close(),
  };
}

async function directoryFiles(root: string): Promise<AppFiles> {
  const files: ListedFile[] = [];
  const queue = [''];
  for (let head = 0; head < queue.length && files.length < MAX_LISTED; head++) {
    const relative = queue[head] as string;
    let entries: Dirent[];
    try {
      entries = await readdir(path.join(root, relative), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (EXCLUDED.test(child)) continue;
      if (entry.isDirectory()) queue.push(child);
      else if (entry.isFile()) {
        const info = await stat(path.join(root, child)).catch(() => null);
        if (info) files.push({ path: child, size: info.size });
      }
    }
  }
  return {
    files,
    read: async (file, maxBytes) => {
      const full = path.join(root, ...file.split('/'));
      const info = await stat(full).catch(() => null);
      return info && info.size <= maxBytes ? readFile(full) : null;
    },
    close: () => Promise.resolve(),
  };
}

/** Resolves package.json "main" the way Node does for the common cases. */
export function resolveMain(
  main: string | undefined,
  available: ReadonlySet<string>,
): string | undefined {
  const base = (main ?? 'index.js').replace(/^\.\//, '').replace(/\/$/, '');
  return [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, `${base}/index.js`].find((option) =>
    available.has(option),
  );
}

export function scoreSource(text: string): { score: number; labels: string[]; boundary: boolean } {
  let score = 0;
  let boundary = false;
  const labels: string[] = [];
  for (const signal of SIGNALS) {
    if (signal.pattern.test(text)) {
      score += signal.weight;
      boundary ||= signal.boundary;
      labels.push(signal.label);
    }
  }
  return { score, labels, boundary };
}

/**
 * @param manifestPath The app's `resources/app.asar`, or `resources/app/package.json` for apps
 *   shipped unpacked (as reported by the classifier).
 */
export async function selectSources(
  manifestPath: string,
  options: SelectOptions = {},
): Promise<SourceSelection> {
  const maxFiles = options.maxFiles ?? 12;
  const maxFileBytes = options.maxFileBytes ?? 32 * 1024 * 1024;
  const maxTotalBytes = options.maxTotalBytes ?? 48 * 1024 * 1024;
  const format = manifestPath.toLowerCase().endsWith('.asar') ? 'asar' : 'directory';
  const appPath = format === 'asar' ? manifestPath : path.dirname(manifestPath);
  const app = format === 'asar' ? await asarFiles(appPath) : await directoryFiles(appPath);
  try {
    const available = new Set(app.files.map((file) => file.path));
    const manifestBytes = await app.read('package.json', 1024 * 1024);
    const manifest = manifestBytes
      ? pickManifest(JSON.parse(manifestBytes.toString('utf8')))
      : null;
    const main = resolveMain(manifest?.main, available);

    const scripts = app.files.filter((file) => SCRIPT.test(file.path) && !EXCLUDED.test(file.path));
    const scored: { path: string; size: number; score: number; labels: string[] }[] = [];
    for (const file of scripts) {
      const isMain = file.path === main;
      if (file.size > maxFileBytes) continue;
      const bytes = await app.read(file.path, maxFileBytes);
      if (!bytes) continue;
      const { score, labels, boundary } = scoreSource(bytes.toString('latin1'));
      if (isMain)
        scored.push({
          ...file,
          score: Number.MAX_SAFE_INTEGER,
          labels: ['package.json main', ...labels],
        });
      else if (boundary) scored.push({ ...file, score, labels });
    }
    scored.sort((a, b) => b.score - a.score || a.size - b.size || a.path.localeCompare(b.path));

    const sources: string[] = [];
    const reasons: Record<string, string[]> = {};
    let total = 0;
    for (const file of scored) {
      if (sources.length >= maxFiles || total + file.size > maxTotalBytes) continue;
      sources.push(file.path);
      reasons[file.path] = file.labels;
      total += file.size;
    }
    return {
      appPath,
      format,
      sources,
      considered: scripts.length,
      omitted: scored.length - sources.length,
      reasons,
    };
  } finally {
    await app.close();
  }
}
