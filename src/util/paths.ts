import os from 'node:os';
import path from 'node:path';

/** Path helpers for the given platform, so Windows logic is testable on any host. */
export function pathFor(platform: NodeJS.Platform): path.PlatformPath {
  return platform === 'win32' ? path.win32 : path.posix;
}

/** Per-user cache directory following platform conventions. */
export function cacheDir(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  const p = pathFor(platform);
  if (platform === 'win32') {
    const base = env['LOCALAPPDATA'] ?? p.join(os.homedir(), 'AppData', 'Local');
    return p.join(base, 'appxray', 'cache');
  }
  if (platform === 'darwin') {
    return p.join(os.homedir(), 'Library', 'Caches', 'appxray');
  }
  const base = env['XDG_CACHE_HOME'] ?? p.join(os.homedir(), '.cache');
  return p.join(base, 'appxray');
}

/** True when `child` is `parent` or inside it. Case-insensitive on Windows. */
export function isInside(
  child: string,
  parent: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const p = pathFor(platform);
  const fold = (value: string) => (platform === 'win32' ? value.toLowerCase() : value);
  const rel = p.relative(fold(p.resolve(parent)), fold(p.resolve(child)));
  return rel === '' || (!rel.startsWith('..') && !p.isAbsolute(rel));
}
