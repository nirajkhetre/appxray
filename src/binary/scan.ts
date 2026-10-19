import { createHash, type Hash } from 'node:crypto';
import { open } from 'node:fs/promises';

import { decodeFuseWire, FUSE_SENTINEL, FUSE_WIRE_READ_LENGTH, type FuseWire } from './fuses.js';

export interface VersionHit {
  value: string;
  count: number;
  /** Offset of the first occurrence, useful as evidence. */
  firstOffset: number;
}

export interface BinaryScanResult {
  path: string;
  size: number;
  sha256?: string;
  electron: VersionHit[];
  chrome: VersionHit[];
  /** Chromium security-patch level advertised by Qt WebEngine builds. */
  qtSecurityPatch: VersionHit[];
  fuseWires: FuseWire[];
  /** True when the file exceeded `maxBytes` and only a prefix was scanned. */
  truncated: boolean;
}

export interface BinaryScanOptions {
  hash?: boolean;
  /** Stop scanning after this many bytes. Default 2 GiB. */
  maxBytes?: number;
  /** Read size per iteration. Default 4 MiB. */
  chunkSize?: number;
  signal?: AbortSignal;
}

interface Pattern {
  key: 'electron' | 'chrome' | 'qt' | 'fuse';
  needle: Buffer;
}

const PATTERNS: readonly Pattern[] = [
  { key: 'electron', needle: Buffer.from('Electron/', 'latin1') },
  { key: 'chrome', needle: Buffer.from('Chrome/', 'latin1') },
  { key: 'qt', needle: Buffer.from('QtWebEngineProcess\0', 'latin1') },
  { key: 'fuse', needle: FUSE_SENTINEL },
];

/**
 * Bytes kept from the end of each chunk so that a match starting near a chunk boundary
 * is parsed once, in the next window, with enough trailing bytes to read its value.
 */
const OVERLAP = FUSE_SENTINEL.length + FUSE_WIRE_READ_LENGTH + 32;

const ELECTRON_VALUE =
  /^(\d{1,4}\.\d{1,4}\.\d{1,5}(?:-(?:alpha|beta|nightly)\.\d{1,10})?)(?![\d.])/;
const CHROME_VALUE = /^(\d{1,4}\.\d{1,4}\.\d{1,6}\.\d{1,6})(?![\d.])/;
const QT_PATCH_VALUE = /^\0{0,8}(\d{1,4}\.\d{1,4}\.\d{1,6}\.\d{1,6})\0/;

class HitCounter {
  private readonly hits = new Map<string, VersionHit>();

  add(value: string, offset: number): void {
    const existing = this.hits.get(value);
    if (existing) existing.count++;
    else this.hits.set(value, { value, count: 1, firstOffset: offset });
  }

  sorted(): VersionHit[] {
    return [...this.hits.values()].sort(
      (a, b) => b.count - a.count || a.firstOffset - b.firstOffset,
    );
  }
}

/**
 * Streams a file once and records Electron/Chromium version strings and Electron fuse
 * wires. The file is only read, never executed or mapped.
 */
export async function scanBinary(
  filePath: string,
  options: BinaryScanOptions = {},
): Promise<BinaryScanResult> {
  const chunkSize = options.chunkSize ?? 4 * 1024 * 1024;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024 * 1024;
  if (chunkSize < OVERLAP * 2) throw new RangeError(`chunkSize must be at least ${OVERLAP * 2}`);

  const handle = await open(filePath, 'r');
  try {
    const { size } = await handle.stat();
    const limit = Math.min(size, maxBytes);
    const hash: Hash | undefined = options.hash ? createHash('sha256') : undefined;

    const electron = new HitCounter();
    const chrome = new HitCounter();
    const qt = new HitCounter();
    const fuseWires: FuseWire[] = [];

    const buffer = Buffer.allocUnsafe(chunkSize + OVERLAP);
    let carry = 0;
    let position = 0;

    while (position < limit) {
      options.signal?.throwIfAborted();
      const toRead = Math.min(chunkSize, limit - position);
      const { bytesRead } = await handle.read(buffer, carry, toRead, position);
      if (bytesRead === 0) break;
      hash?.update(buffer.subarray(carry, carry + bytesRead));

      const windowLength = carry + bytesRead;
      const window = buffer.subarray(0, windowLength);
      const windowStart = position - carry;
      position += bytesRead;
      const isLast = position >= limit;
      // Matches that start in the tail are deferred to the next window, which begins there.
      const acceptBefore = isLast ? windowLength : windowLength - OVERLAP;

      for (const { key, needle } of PATTERNS) {
        let index = window.indexOf(needle);
        while (index !== -1 && index < acceptBefore) {
          const absolute = windowStart + index;
          const after = window.subarray(index + needle.length, index + needle.length + OVERLAP);
          switch (key) {
            case 'electron': {
              const match = ELECTRON_VALUE.exec(after.toString('latin1', 0, 40));
              if (match?.[1]) electron.add(match[1], absolute);
              break;
            }
            case 'chrome': {
              const match = CHROME_VALUE.exec(after.toString('latin1', 0, 32));
              if (match?.[1]) chrome.add(match[1], absolute);
              break;
            }
            case 'qt': {
              const match = QT_PATCH_VALUE.exec(after.toString('latin1', 0, 40));
              if (match?.[1]) qt.add(match[1], absolute);
              break;
            }
            case 'fuse': {
              const wire = decodeFuseWire(after, absolute);
              if (wire) fuseWires.push(wire);
              break;
            }
          }
          index = window.indexOf(needle, index + 1);
        }
      }

      if (!isLast) {
        carry = Math.min(OVERLAP, windowLength);
        buffer.copy(buffer, 0, windowLength - carry, windowLength);
      }
    }

    const result: BinaryScanResult = {
      path: filePath,
      size,
      electron: electron.sorted(),
      chrome: chrome.sorted(),
      qtSecurityPatch: qt.sorted(),
      fuseWires,
      truncated: size > maxBytes,
    };
    if (hash && size <= maxBytes) result.sha256 = hash.digest('hex');
    return result;
  } finally {
    await handle.close();
  }
}
