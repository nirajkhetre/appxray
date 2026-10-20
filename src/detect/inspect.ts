import { createHash } from 'node:crypto';
import path from 'node:path';

import { readAsarManifest, readDirectoryManifest, type AppManifest } from '../binary/asar.js';
import { scanBinary, type BinaryScanResult, type VersionHit } from '../binary/scan.js';
import type { AppCandidate, InspectedApp, RuntimeVersions } from './types.js';

export interface InspectOptions {
  hash?: boolean;
  signal?: AbortSignal;
}

export type InspectOutcome =
  { ok: true; app: InspectedApp } | { ok: false; path: string; reason: string };

export function appId(root: string, platform: NodeJS.Platform = process.platform): string {
  const normalized = platform === 'win32' ? path.resolve(root).toLowerCase() : path.resolve(root);
  return createHash('sha256').update(normalized).digest('hex').slice(0, 12);
}

function describeConflict(label: string, hits: readonly VersionHit[]): string | undefined {
  if (hits.length < 2) return undefined;
  const values = hits.map((hit) => `${hit.value} (x${hit.count})`).join(', ');
  return `Multiple ${label} version strings found; using the most frequent: ${values}`;
}

/** Folders such as `lib`, `bin` or Squirrel's `app-1.2.3` are not useful display names. */
function displayNameFromRoot(root: string): string {
  const base = path.basename(root);
  if (/^(lib|lib64|bin|app-[\d.]+|current|files|active)$/i.test(base)) {
    return displayNameFromRoot(path.dirname(root));
  }
  return base;
}

async function readManifest(candidate: AppCandidate): Promise<AppManifest | null> {
  if (!candidate.manifestPath) return null;
  return candidate.manifestPath.toLowerCase().endsWith('.asar')
    ? readAsarManifest(candidate.manifestPath)
    : readDirectoryManifest(candidate.manifestPath);
}

function runtimeFrom(scan: BinaryScanResult, kind: AppCandidate['kind']): RuntimeVersions {
  const runtime: RuntimeVersions = {};
  if (kind === 'electron' && scan.electron[0]) runtime.electron = scan.electron[0].value;
  if (scan.chrome[0]) runtime.chromium = scan.chrome[0].value;
  if (kind === 'qtwebengine' && scan.qtSecurityPatch[0]) {
    runtime.chromiumSecurityPatch = scan.qtSecurityPatch[0].value;
  }
  return runtime;
}

/**
 * Scans the candidate's binaries until one confirms the runtime and assembles the result.
 * Files are only read; nothing is executed.
 */
export async function inspectCandidate(
  candidate: AppCandidate,
  options: InspectOptions = {},
): Promise<InspectOutcome> {
  let chosen: BinaryScanResult | undefined;
  const errors: string[] = [];
  for (const binary of candidate.binaries) {
    try {
      const scanOptions = options.signal
        ? { hash: options.hash ?? false, signal: options.signal }
        : { hash: options.hash ?? false };
      const scan = await scanBinary(binary, scanOptions);
      const confirmed =
        candidate.kind === 'electron'
          ? scan.electron.length > 0 || scan.fuseWires.length > 0
          : scan.chrome.length > 0 || scan.qtSecurityPatch.length > 0;
      if (confirmed) {
        chosen = scan;
        break;
      }
    } catch (error) {
      if (options.signal?.aborted) throw error;
      errors.push(`${binary}: ${(error as Error).message}`);
    }
  }

  if (!chosen) {
    const reason =
      errors.length > 0
        ? `could not read runtime binary (${errors.join('; ')})`
        : `looked like ${candidate.kind} but no runtime version was found in its binaries`;
    return { ok: false, path: candidate.root, reason };
  }

  const manifest = candidate.kind === 'electron' ? await readManifest(candidate) : null;
  const notes: string[] = [];
  for (const note of [
    describeConflict('Electron', chosen.electron),
    describeConflict('Chromium', chosen.chrome),
  ]) {
    if (note) notes.push(note);
  }
  if (chosen.fuseWires.length > 1) {
    notes.push(`Found ${chosen.fuseWires.length} fuse wires; reporting the first one.`);
  }
  if (chosen.truncated) notes.push('Binary exceeded the scan size limit; only a prefix was read.');
  if (candidate.kind === 'electron' && !chosen.electron[0]) {
    notes.push('Electron fuse wire found but no Electron version string.');
  }

  const app: InspectedApp = {
    id: appId(candidate.root),
    name:
      candidate.hints.name ??
      manifest?.productName ??
      manifest?.name ??
      displayNameFromRoot(candidate.root),
    root: candidate.root,
    binary: chosen.path,
    binarySize: chosen.size,
    kind: candidate.kind,
    source: candidate.source,
    runtime: runtimeFrom(chosen, candidate.kind),
    otherCopies: candidate.otherCopies ?? [],
    notes,
    evidence: [],
  };
  const appVersion = candidate.hints.version ?? manifest?.version;
  if (appVersion) app.appVersion = appVersion;
  if (candidate.hints.publisher) app.publisher = candidate.hints.publisher;
  if (chosen.sha256) app.binarySha256 = chosen.sha256;
  if (chosen.fuseWires[0]) app.fuses = chosen.fuseWires[0];
  if (candidate.kind === 'electron' && candidate.manifestPath)
    app.appBundle = candidate.manifestPath;
  return { ok: true, app };
}
