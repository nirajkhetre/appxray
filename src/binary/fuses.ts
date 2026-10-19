/**
 * Electron fuse wire decoding.
 *
 * Layout (Electron >= 12): the ASCII sentinel below, then one byte wire version,
 * one byte fuse count, then one byte per fuse. Byte values follow @electron/fuses:
 * '0' disabled, '1' enabled, 'r' removed. Fuse order is fixed by Electron
 * (see @electron/fuses FuseV1Options); unknown trailing fuses are reported by index.
 */
export const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');

export const FUSE_V1_NAMES = [
  'RunAsNode',
  'EnableCookieEncryption',
  'EnableNodeOptionsEnvironmentVariable',
  'EnableNodeCliInspectArguments',
  'EnableEmbeddedAsarIntegrityValidation',
  'OnlyLoadAppFromAsar',
  'LoadBrowserProcessSpecificV8Snapshot',
  'GrantFileProtocolExtraPrivileges',
  'WasmTrapHandlers',
] as const;

export type FuseName = (typeof FUSE_V1_NAMES)[number];
export type FuseState = 'enabled' | 'disabled' | 'removed' | 'unknown';

export interface FuseEntry {
  index: number;
  name: FuseName | `Unknown${number}`;
  state: FuseState;
}

export interface FuseWire {
  /** Byte offset of the sentinel in the file. */
  offset: number;
  wireVersion: number;
  fuses: FuseEntry[];
}

/** Wires longer than this are treated as corrupt rather than trusted. */
const MAX_FUSES = 64;

function stateOf(byte: number): FuseState {
  switch (byte) {
    case 0x30:
      return 'disabled';
    case 0x31:
      return 'enabled';
    case 0x72:
      return 'removed';
    default:
      return 'unknown';
  }
}

/**
 * Decodes the wire that follows a sentinel. `bytes` must start immediately after the
 * sentinel. Returns null when the bytes do not look like a fuse wire.
 */
export function decodeFuseWire(bytes: Buffer, sentinelOffset: number): FuseWire | null {
  if (bytes.length < 2) return null;
  const wireVersion = bytes[0] as number;
  const count = bytes[1] as number;
  if (wireVersion !== 1 || count === 0 || count > MAX_FUSES || bytes.length < 2 + count) {
    return null;
  }
  const fuses: FuseEntry[] = [];
  for (let index = 0; index < count; index++) {
    const state = stateOf(bytes[2 + index] as number);
    if (state === 'unknown') return null;
    fuses.push({ index, name: FUSE_V1_NAMES[index] ?? `Unknown${index}`, state });
  }
  return { offset: sentinelOffset, wireVersion, fuses };
}

/** Number of bytes needed after a sentinel to decode any valid wire. */
export const FUSE_WIRE_READ_LENGTH = 2 + MAX_FUSES;

export function fuseState(wire: FuseWire | undefined, name: FuseName): FuseState | undefined {
  return wire?.fuses.find((fuse) => fuse.name === name)?.state;
}
