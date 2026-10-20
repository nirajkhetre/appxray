import type { FuseWire } from '../binary/fuses.js';
import type { DeepAnalysis } from '../deep/analyze.js';

export type RuntimeKind = 'electron' | 'cef' | 'qtwebengine';

export type DiscoverySource = 'registry' | 'filesystem' | 'snap' | 'flatpak' | 'explicit';

/** Metadata a discovery source already knows about an install location. */
export interface AppHints {
  name?: string;
  version?: string;
  publisher?: string;
}

/** A directory that looks like it contains an embedded Chromium runtime. */
export interface AppCandidate {
  root: string;
  kind: RuntimeKind;
  /** Files to scan, best guess first. */
  binaries: string[];
  source: DiscoverySource;
  hints: AppHints;
  /** Path to app.asar or resources/app/package.json, when present. */
  manifestPath?: string;
  /** Older side-by-side copies of the same app that will not be scanned. */
  otherCopies?: string[];
}

export interface RuntimeVersions {
  electron?: string;
  chromium?: string;
  /** Qt WebEngine: Chromium version up to which security patches were applied. */
  chromiumSecurityPatch?: string;
}

export interface Evidence {
  provider: string;
  providerVersion?: string;
  id?: string;
  summary: string;
  agrees?: boolean;
}

export interface InspectedApp {
  /** Stable identifier derived from the install root. */
  id: string;
  name: string;
  appVersion?: string;
  publisher?: string;
  root: string;
  binary: string;
  binarySize: number;
  binarySha256?: string;
  kind: RuntimeKind;
  source: DiscoverySource;
  runtime: RuntimeVersions;
  fuses?: FuseWire;
  /** Older side-by-side copies (for example Squirrel `app-*` folders) that were not scanned. */
  otherCopies: string[];
  notes: string[];
  evidence: Evidence[];
  /** app.asar, or resources/app/package.json for unpacked apps (Electron only). */
  appBundle?: string;
  /** REA-powered code analysis, present with --deep. */
  deep?: DeepAnalysis;
}

export interface SkippedPath {
  path: string;
  reason: string;
}
