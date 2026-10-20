/**
 * Turns REA's `analyze-javascript-application` evidence into an Electron security posture:
 * how windows are configured, what the preload bridges expose, which IPC handlers exist, and
 * which exposed bridge calls reach command execution in the main process.
 *
 * REA's output is large and versioned by REA, so this parser reads only the fields it needs,
 * checks their types, and ignores everything else. test/integration/rea-real.test.ts runs the
 * real pinned REA against a known app to keep this contract honest.
 */
import { ReaCommandError } from '../rea/runner.js';

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
}

export type PreferenceValue =
  | { status: 'literal'; value: string | number | boolean | null }
  | { status: 'dynamic' | 'unknown'; expression?: string };

export interface WindowConfig {
  location?: SourceLocation;
  /** True when every option was visible to the analysis (an object literal). */
  fullyKnown: boolean;
  preferences: Record<string, PreferenceValue>;
  preload?: string;
}

export interface RendererContent {
  url: string;
  remote: boolean;
  /** http: URLs that are not on the local machine. */
  insecureTransport: boolean;
  mechanism?: string;
}

export interface BridgeApi {
  apiKey: string;
  members: string[];
  /** Members REA could not enumerate (for example a spread or computed object). */
  dynamic: boolean;
  location?: SourceLocation;
}

export interface BridgeCall {
  /** Renderer-visible entry such as `api.run`. */
  entry: string;
  /** Literal IPC channel, or null when the channel comes from the caller. */
  channel: string | null;
}

export interface IpcHandler {
  channel: string | null;
  mode: string;
  location?: SourceLocation;
  /** Range of an inline handler function, used to find what the handler does. */
  handlerRange?: { file: string; start: Position; end: Position };
}

export interface Position {
  line: number;
  column: number;
}

export interface CommandSink {
  method: string;
  location: SourceLocation;
}

export interface AttackPath {
  entry: string;
  channel: string;
  handler: SourceLocation;
  sink: CommandSink;
}

export interface ElectronPosture {
  evidenceId?: string;
  windows: WindowConfig[];
  content: RendererContent[];
  bridges: BridgeApi[];
  bridgeCalls: BridgeCall[];
  mainHandlers: IpcHandler[];
  commandSinks: CommandSink[];
  attackPaths: AttackPath[];
  nativeAddons: { path: string; bytes: number }[];
  networkEndpoints: string[];
  senderValidationCandidates: number;
  dynamicChannelOperations: number;
  coverage: {
    complete: boolean;
    parseFailures: number;
    parsedFiles: number;
    limitations: string[];
  };
}

type Json = Record<string, unknown>;

const isObject = (value: unknown): value is Json =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asString = (value: unknown): string | undefined =>
  typeof value === 'string' ? value : undefined;
const asNumber = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined;

function position(value: unknown): Position | undefined {
  if (!isObject(value)) return undefined;
  const line = asNumber(value['line']);
  const column = asNumber(value['column']);
  return line !== undefined && column !== undefined ? { line, column } : undefined;
}

function sourceLocation(value: unknown): SourceLocation | undefined {
  if (!isObject(value)) return undefined;
  const range = isObject(value['value']) ? value['value'] : value;
  const file = asString(range['source']) ?? asString(range['module_path']);
  const start = position(range['start']);
  if (!file || !start) return undefined;
  const location: SourceLocation = { file, line: start.line, column: start.column };
  const end = position(range['end']);
  if (end) {
    location.endLine = end.line;
    location.endColumn = end.column;
  }
  return location;
}

interface GraphNode {
  kind: string;
  properties: Json;
  location?: SourceLocation;
  observations: Json[];
}

function graphNodes(graph: Json): GraphNode[] {
  return asArray(graph['nodes']).flatMap((raw) => {
    if (!isObject(raw)) return [];
    const kind = asString(raw['kind']);
    const observations = asArray(raw['observations']).filter(isObject);
    const first = observations[0];
    if (!kind || !first) return [];
    const evidence = isObject(first['evidence']) ? first['evidence'] : {};
    const node: GraphNode = {
      kind,
      properties: isObject(first['properties']) ? first['properties'] : {},
      observations,
    };
    const location = sourceLocation(evidence['location']);
    if (location) node.location = location;
    return [node];
  });
}

function preferenceValue(raw: unknown): PreferenceValue {
  if (!isObject(raw)) return { status: 'unknown' };
  const value = raw['value'];
  if (
    raw['status'] === 'literal' &&
    (value === null || ['string', 'number', 'boolean'].includes(typeof value))
  ) {
    return { status: 'literal', value: value as string | number | boolean | null };
  }
  const expression = asString(raw['expression']);
  return {
    status: raw['status'] === 'dynamic' ? 'dynamic' : 'unknown',
    ...(expression ? { expression } : {}),
  };
}

const LOCAL_HOST = /^https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])(?::\d+)?(?:\/|$)/i;

export function classifyContent(url: string, mechanism?: string): RendererContent {
  const remote = /^https?:\/\//i.test(url) && !LOCAL_HOST.test(url);
  const content: RendererContent = {
    url,
    remote,
    insecureTransport: remote && /^http:/i.test(url),
  };
  if (mechanism) content.mechanism = mechanism;
  return content;
}

const before = (a: Position, b: Position) =>
  a.line < b.line || (a.line === b.line && a.column <= b.column);

/** Bridge entry → IPC channel → main handler whose inline body contains command execution. */
export function findAttackPaths(
  calls: readonly BridgeCall[],
  handlers: readonly IpcHandler[],
  sinks: readonly CommandSink[],
): AttackPath[] {
  const paths: AttackPath[] = [];
  for (const call of calls) {
    if (!call.channel) continue;
    for (const handler of handlers) {
      const range = handler.handlerRange;
      if (handler.channel !== call.channel || !range || !handler.location) continue;
      for (const sink of sinks) {
        const at = { line: sink.location.line, column: sink.location.column };
        if (sink.location.file === range.file && before(range.start, at) && before(at, range.end)) {
          paths.push({ entry: call.entry, channel: call.channel, handler: handler.location, sink });
        }
      }
    }
  }
  return paths;
}

/** Parses REA `analyze-javascript-application` JSON into an Electron security posture. */
export function parsePosture(evidence: Json): ElectronPosture {
  const result = evidence['normalized_result'];
  if (!isObject(result) || !isObject(result['graph'])) {
    throw new ReaCommandError('REA application analysis did not contain an application graph');
  }
  const graph = result['graph'];
  const nodes = graphNodes(graph);
  const of = (kind: string) => nodes.filter((node) => node.kind === kind);

  const windows: WindowConfig[] = of('browser-window').map((node) => {
    const preferences: Record<string, PreferenceValue> = {};
    for (const raw of asArray(node.properties['web_preferences'])) {
      if (isObject(raw) && typeof raw['name'] === 'string')
        preferences[raw['name']] = preferenceValue(raw['value']);
    }
    const config: WindowConfig = {
      fullyKnown: node.properties['web_preferences_status'] === 'object-literal',
      preferences,
    };
    if (node.location) config.location = node.location;
    const preload = asString(node.properties['preload_path']);
    if (preload) config.preload = preload;
    return config;
  });

  const content = of('electron-renderer').flatMap((node) => {
    const url = asString(node.properties['declared_path']);
    return url ? [classifyContent(url, asString(node.properties['mechanism']))] : [];
  });

  const bridges: BridgeApi[] = of('context-bridge-api').map((node) => {
    const bridge: BridgeApi = {
      apiKey: asString(node.properties['api_key']) ?? '(dynamic)',
      members: asArray(node.properties['members']).filter(
        (member): member is string => typeof member === 'string',
      ),
      dynamic:
        node.properties['api_status'] !== 'object-literal' ||
        (asNumber(node.properties['unknown_members']) ?? 0) > 0,
    };
    if (node.location) bridge.location = node.location;
    return bridge;
  });

  const bridgeCalls: BridgeCall[] = [];
  const seenCalls = new Set<string>();
  for (const raw of asArray(graph['edges'])) {
    if (!isObject(raw) || raw['relation'] !== 'calls' || !isObject(raw['properties'])) continue;
    const entry = asString(raw['properties']['entry']);
    if (!entry) continue;
    const channel = asString(raw['properties']['channel']) ?? null;
    const key = `${entry}\u0000${channel ?? ''}`;
    if (seenCalls.has(key)) continue;
    seenCalls.add(key);
    bridgeCalls.push({ entry, channel });
  }

  const mainHandlers: IpcHandler[] = of('ipc-handler')
    .filter((node) => node.properties['side'] === 'main')
    .map((node) => {
      const handler: IpcHandler = {
        channel: asString(node.properties['channel']) ?? null,
        mode: asString(node.properties['mode']) ?? 'unknown',
      };
      if (node.location) handler.location = node.location;
      const range = node.properties['handler_location'];
      const start = isObject(range) ? position(range['start']) : undefined;
      const end = isObject(range) ? position(range['end']) : undefined;
      if (node.location && start && end && node.properties['handler_kind'] === 'inline-function') {
        handler.handlerRange = { file: node.location.file, start, end };
      }
      return handler;
    });

  const semantic = isObject(result['semantic_graph']) ? result['semantic_graph'] : {};
  const commandSinks: CommandSink[] = asArray(semantic['nodes']).flatMap((raw) => {
    if (!isObject(raw) || raw['kind'] !== 'child-process' || !isObject(raw['identity'])) return [];
    const identity = raw['identity'];
    const range = isObject(identity['source_range']) ? identity['source_range'] : {};
    const location = sourceLocation({ ...range, module_path: identity['module_path'] });
    const properties = isObject(raw['properties']) ? raw['properties'] : {};
    return location
      ? [{ method: asString(properties['method']) ?? asString(raw['label']) ?? 'spawn', location }]
      : [];
  });

  const networkEndpoints = [
    ...new Set(
      of('endpoint')
        .filter((node) => node.properties['endpoint_kind'] === 'network')
        .map((node) => asString(node.properties['value']))
        .filter(
          (value): value is string => value !== undefined && /^(?:https?|wss?):\/\//i.test(value),
        ),
    ),
  ].sort();

  const summary = isObject(result['summary']) ? result['summary'] : {};
  const ipc = isObject(summary['ipc']) ? summary['ipc'] : {};
  const statistics = isObject(result['statistics']) ? result['statistics'] : {};
  const coverage = isObject(graph['coverage']) ? graph['coverage'] : {};
  const limitations = asArray(result['limitations']).filter(
    (item): item is string => typeof item === 'string',
  );

  const posture: ElectronPosture = {
    windows,
    content,
    bridges,
    bridgeCalls,
    mainHandlers,
    commandSinks,
    attackPaths: findAttackPaths(bridgeCalls, mainHandlers, commandSinks),
    nativeAddons: of('native-addon').flatMap((node) => {
      const addonPath = asString(node.properties['path']);
      return addonPath ? [{ path: addonPath, bytes: asNumber(node.properties['bytes']) ?? 0 }] : [];
    }),
    networkEndpoints,
    senderValidationCandidates: asNumber(summary['sender_validation_observations']) ?? 0,
    dynamicChannelOperations: asNumber(ipc['dynamic_channel_operations']) ?? 0,
    coverage: {
      complete: coverage['status'] === 'complete' && coverage['truncated'] !== true,
      parseFailures: asNumber(statistics['parse_failures']) ?? 0,
      parsedFiles: asNumber(statistics['parsed_javascript_files']) ?? 0,
      limitations,
    },
  };
  const evidenceId = asString(evidence['evidence_id']);
  if (evidenceId) posture.evidenceId = evidenceId;
  return posture;
}
