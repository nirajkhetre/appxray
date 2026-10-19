import path from 'node:path';

import type { AppHints } from '../detect/types.js';
import { isInside } from '../util/paths.js';

/**
 * Maps install folders to known names/versions. Lookups match the folder itself or any
 * parent, preferring the deepest registered folder.
 */
export class HintIndex {
  private readonly entries: { folder: string; hints: AppHints }[] = [];

  constructor(
    private readonly platform: NodeJS.Platform,
    /** Folders too broad to describe a single app, such as Program Files. */
    private readonly tooBroad: readonly string[] = [],
  ) {}

  add(folder: string, hints: AppHints): void {
    const resolved = this.platform === 'win32' ? path.win32.resolve(folder) : path.resolve(folder);
    const parsed = (this.platform === 'win32' ? path.win32 : path.posix).parse(resolved);
    if (resolved === parsed.root) return;
    if (this.tooBroad.some((broad) => isInside(broad, resolved, this.platform))) return;
    this.entries.push({ folder: resolved, hints });
  }

  lookup(dir: string): AppHints | undefined {
    let best: { folder: string; hints: AppHints } | undefined;
    for (const entry of this.entries) {
      if (!isInside(dir, entry.folder, this.platform)) continue;
      if (!best || entry.folder.length > best.folder.length) best = entry;
    }
    return best?.hints;
  }

  get size(): number {
    return this.entries.length;
  }
}
