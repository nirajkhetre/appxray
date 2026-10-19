import semver from 'semver';

/** Parses a dotted numeric version such as a Chromium build `150.0.7871.250`. */
export function parseDotted(version: string): number[] | null {
  if (!/^\d+(\.\d+){1,3}$/.test(version)) return null;
  return version.split('.').map((part) => Number.parseInt(part, 10));
}

/**
 * Compares dotted numeric versions component by component. Missing components count as 0.
 * Throws on malformed input so callers never silently compare garbage.
 */
export function compareDotted(a: string, b: string): number {
  const left = parseDotted(a);
  const right = parseDotted(b);
  if (!left || !right) throw new TypeError(`not a dotted numeric version: ${!left ? a : b}`);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

export function majorOf(version: string): number | null {
  const parsed = semver.parse(version);
  return parsed ? parsed.major : null;
}

/** Highest-first sort for semver strings; invalid strings sort last. */
export function sortSemverDesc(versions: readonly string[]): string[] {
  return [...versions].sort((a, b) => {
    const va = semver.valid(a);
    const vb = semver.valid(b);
    if (va && vb) return semver.rcompare(va, vb);
    if (va) return -1;
    if (vb) return 1;
    return a.localeCompare(b);
  });
}
