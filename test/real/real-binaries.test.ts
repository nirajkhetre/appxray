/**
 * Scans real Electron/Qt builds. Opt-in: set APPXRAY_REAL_FIXTURES to a folder containing
 * `expected.json` ({ "<subfolder>": { "electron"?: "x.y.z", "chromiumMajor"?: n,
 * "qtPatch"?: "a.b.c.d" } }) and the extracted builds. CI downloads official Electron
 * releases for Windows and Linux into such a folder (see .github/workflows/ci.yml).
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import { inspectCandidate } from '../../src/detect/inspect.js';
import { candidatesForPaths } from '../../src/discovery/index.js';

interface Expected {
  electron?: string;
  chromiumMajor?: number;
  qtPatch?: string;
  fuses?: boolean;
}

const root = process.env['APPXRAY_REAL_FIXTURES'];
const expected: Record<string, Expected> = root
  ? (JSON.parse(readFileSync(path.join(root, 'expected.json'), 'utf8')) as Record<string, Expected>)
  : {};

describe.skipIf(!root)('real binaries', () => {
  it.each(Object.entries(expected))('%s', async (folder, want) => {
    const discovery = await candidatesForPaths([path.join(root ?? '', folder)]);
    expect(discovery.candidates, 'exactly one runtime should be found').toHaveLength(1);
    const outcome = await inspectCandidate(discovery.candidates[0]!, { hash: true });
    if (!outcome.ok) throw new Error(outcome.reason);
    const { app } = outcome;
    if (want.electron) expect(app.runtime.electron).toBe(want.electron);
    if (want.chromiumMajor)
      expect(app.runtime.chromium?.split('.')[0]).toBe(String(want.chromiumMajor));
    if (want.qtPatch) expect(app.runtime.chromiumSecurityPatch).toBe(want.qtPatch);
    if (want.fuses) expect(app.fuses?.fuses.length).toBeGreaterThanOrEqual(7);
    expect(app.notes).toEqual([]);
  });
});
