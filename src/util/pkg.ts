import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the installed package (the directory holding package.json). */
export const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

interface PackageJson {
  name: string;
  version: string;
  homepage?: string;
}

let cached: PackageJson | undefined;

export function packageInfo(): PackageJson {
  cached ??= JSON.parse(
    readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'),
  ) as PackageJson;
  return cached;
}

export const TOOL_NAME = 'appxray';
