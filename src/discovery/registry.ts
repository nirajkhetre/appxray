import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

import type { Logger } from '../util/log.js';

const execFileAsync = promisify(execFile);

/** One "Apps & features" entry from the Windows uninstall registry keys. */
export interface UninstallEntry {
  displayName: string;
  displayVersion?: string;
  publisher?: string;
  installLocation?: string;
  displayIcon?: string;
}

export const UNINSTALL_KEYS = [
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
];

// PowerShell emits UTF-8 JSON, which keeps non-ASCII install paths intact
// (reg.exe output is in the console code page).
const POWERSHELL_SCRIPT = [
  "$ErrorActionPreference = 'SilentlyContinue'",
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  `$keys = @(${UNINSTALL_KEYS.map((key) => `'Registry::${key.replace('HKLM', 'HKEY_LOCAL_MACHINE').replace('HKCU', 'HKEY_CURRENT_USER')}\\*'`).join(', ')})`,
  'Get-ItemProperty -Path $keys | Where-Object { $_.DisplayName } |',
  '  Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, DisplayIcon |',
  '  ConvertTo-Json -Compress -Depth 2',
].join('\n');

const text = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;

function toEntry(raw: Record<string, unknown>): UninstallEntry | null {
  const displayName = text(raw['DisplayName']);
  if (!displayName) return null;
  const entry: UninstallEntry = { displayName };
  const displayVersion = text(raw['DisplayVersion']);
  const publisher = text(raw['Publisher']);
  const installLocation = text(raw['InstallLocation']);
  const displayIcon = text(raw['DisplayIcon']);
  if (displayVersion) entry.displayVersion = displayVersion;
  if (publisher) entry.publisher = publisher;
  if (installLocation) entry.installLocation = installLocation;
  if (displayIcon) entry.displayIcon = displayIcon;
  return entry;
}

export function parsePowerShellJson(output: string): UninstallEntry[] {
  const trimmed = output.trim();
  if (!trimmed) return [];
  const parsed = JSON.parse(trimmed) as unknown;
  const list = Array.isArray(parsed) ? parsed : [parsed];
  return list
    .filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
    .map(toEntry)
    .filter((entry): entry is UninstallEntry => entry !== null);
}

/** Parses `reg query <key> /s` output. */
export function parseRegQuery(output: string): UninstallEntry[] {
  const entries: UninstallEntry[] = [];
  let current: Record<string, string> | null = null;
  const flush = () => {
    if (current) {
      const entry = toEntry(current);
      if (entry) entries.push(entry);
    }
  };
  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith('HKEY_')) {
      flush();
      current = {};
      continue;
    }
    const match = /^ {4}(.+?) {4}(REG_[A-Z_]+)(?: {4}(.*))?$/.exec(line);
    if (match && current && match[1]) current[match[1]] = match[3] ?? '';
  }
  flush();
  return entries;
}

/**
 * Turns a DisplayIcon value such as `"C:\App\app.exe",0` into the folder holding the file.
 * Returns undefined for icons that are not files on disk.
 */
export function folderFromDisplayIcon(displayIcon: string): string | undefined {
  const withoutIndex = displayIcon.replace(/,\s*-?\d+\s*$/, '').trim();
  const unquoted = withoutIndex.replace(/^"(.*)"$/, '$1');
  if (!/^[a-z]:\\/i.test(unquoted) || !/\.(exe|ico|dll)$/i.test(unquoted)) return undefined;
  return path.win32.dirname(unquoted);
}

/** Reads uninstall entries via PowerShell, falling back to reg.exe. Never throws. */
export async function readUninstallEntries(logger: Logger): Promise<UninstallEntry[]> {
  try {
    const { stdout } = await execFileAsync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', POWERSHELL_SCRIPT],
      { timeout: 60_000, maxBuffer: 64 * 1024 * 1024, windowsHide: true, encoding: 'utf8' },
    );
    return parsePowerShellJson(stdout);
  } catch (error) {
    logger.debug(`PowerShell registry read failed, using reg.exe: ${(error as Error).message}`);
  }
  const entries: UninstallEntry[] = [];
  for (const key of UNINSTALL_KEYS) {
    try {
      const { stdout } = await execFileAsync('reg.exe', ['query', key, '/s'], {
        timeout: 60_000,
        maxBuffer: 64 * 1024 * 1024,
        windowsHide: true,
        encoding: 'latin1',
      });
      entries.push(...parseRegQuery(stdout));
    } catch (error) {
      logger.debug(`reg query ${key} failed: ${(error as Error).message}`);
    }
  }
  return entries;
}
