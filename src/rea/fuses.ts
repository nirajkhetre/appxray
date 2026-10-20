import { realpath } from 'node:fs/promises';

import type { FuseState, FuseWire } from '../binary/fuses.js';
import type { Evidence } from '../detect/types.js';
import { ReaCommandError, runReaJson, type ReaRunner } from './runner.js';

interface ReaFuse {
  name?: unknown;
  state?: unknown;
}

export interface ReaFuseReading {
  evidenceId?: string;
  sha256?: string;
  fuses: Map<string, FuseState>;
}

/** Extracts fuse states from `rea inspect-electron-fuses` JSON output. */
export function parseReaFuseOutput(parsed: Record<string, unknown>): ReaFuseReading {
  if (typeof parsed['code'] === 'string' && typeof parsed['message'] === 'string') {
    throw new ReaCommandError(
      `REA reported ${parsed['code']}: ${parsed['message']}`,
      parsed['code'],
    );
  }
  const result = parsed['normalized_result'] as
    { slices?: { sentinels?: { fuses?: ReaFuse[] }[] }[] } | undefined;
  const firstSentinel = result?.slices?.flatMap((slice) => slice.sentinels ?? [])[0];
  if (!firstSentinel || !Array.isArray(firstSentinel.fuses)) {
    throw new ReaCommandError('REA output did not contain a fuse wire');
  }
  const fuses = new Map<string, FuseState>();
  for (const fuse of firstSentinel.fuses) {
    if (typeof fuse.name !== 'string' || typeof fuse.state !== 'string') continue;
    const state = ['enabled', 'disabled', 'removed'].includes(fuse.state)
      ? (fuse.state as FuseState)
      : 'unknown';
    fuses.set(fuse.name, state);
  }
  const reading: ReaFuseReading = { fuses };
  if (typeof parsed['evidence_id'] === 'string') reading.evidenceId = parsed['evidence_id'];
  const digest = (parsed['subject'] as { digest?: { sha256?: unknown } } | undefined)?.digest
    ?.sha256;
  if (typeof digest === 'string') reading.sha256 = digest;
  return reading;
}

/** Compares REA's independent fuse reading with appxray's. */
export function compareFuses(
  ours: FuseWire | undefined,
  theirs: ReaFuseReading,
): { agrees: boolean; differences: string[] } {
  const differences: string[] = [];
  for (const fuse of ours?.fuses ?? []) {
    const other = theirs.fuses.get(fuse.name);
    if (other !== undefined && other !== fuse.state) {
      differences.push(`${fuse.name}: appxray ${fuse.state}, REA ${other}`);
    }
  }
  if (!ours && theirs.fuses.size > 0)
    differences.push('REA found a fuse wire that appxray did not');
  return { agrees: differences.length === 0, differences };
}

export async function reaFuseEvidence(
  runner: ReaRunner,
  binary: string,
  ours: FuseWire | undefined,
): Promise<Evidence> {
  const base = { provider: 'rea', providerVersion: runner.version };
  try {
    const reading = parseReaFuseOutput(
      // REA only accepts real files, so resolve symlinks first.
      await runReaJson(runner, ['inspect-electron-fuses', await realpath(binary)], {
        timeoutMs: 180_000,
      }),
    );
    const { agrees, differences } = compareFuses(ours, reading);
    const evidence: Evidence = {
      ...base,
      agrees,
      summary: agrees
        ? `REA independently read the same ${reading.fuses.size} fuses`
        : `REA fuse reading differs: ${differences.join('; ')}`,
    };
    if (reading.evidenceId) evidence.id = reading.evidenceId;
    return evidence;
  } catch (error) {
    return { ...base, summary: `REA could not inspect the fuses: ${(error as Error).message}` };
  }
}
