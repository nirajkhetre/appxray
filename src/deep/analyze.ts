import { runReaJson, type ReaRunner } from '../rea/runner.js';
import { parsePosture, type ElectronPosture } from './posture.js';
import { selectSources, type SelectOptions } from './select.js';

/** Result of REA-powered code analysis of one Electron app. */
export interface DeepAnalysis {
  engine: { name: 'rea'; version: string };
  durationMs: number;
  /** Files REA analyzed, relative to the app root, with the signals that selected them. */
  analyzedFiles: Record<string, string[]>;
  /** Relevant files left out by the selection budget. */
  omittedFiles: number;
  posture?: ElectronPosture;
  error?: string;
}

export interface DeepOptions extends SelectOptions {
  /** Upper bound for the whole REA run on one app. */
  timeoutMs?: number;
}

/**
 * Selects the security-relevant sources of an app and runs REA's static JavaScript/Electron
 * analysis on them. Never throws for app-specific problems; they are reported in `error`.
 */
export async function deepAnalyze(
  appBundle: string,
  runner: ReaRunner,
  options: DeepOptions = {},
): Promise<DeepAnalysis> {
  const started = Date.now();
  const timeoutMs = options.timeoutMs ?? 300_000;
  const result: DeepAnalysis = {
    engine: { name: 'rea', version: runner.version },
    durationMs: 0,
    analyzedFiles: {},
    omittedFiles: 0,
  };
  try {
    const selection = await selectSources(appBundle, options);
    result.analyzedFiles = selection.reasons;
    result.omittedFiles = selection.omitted;
    if (selection.sources.length === 0) {
      result.error = 'no JavaScript entry point or Electron boundary code was found to analyze';
      return result;
    }
    const evidence = await runReaJson(
      runner,
      [
        'analyze-javascript-application',
        selection.appPath,
        '--artifact-format',
        selection.format,
        '--integrity-policy',
        'record-and-continue',
        '--analysis-timeout-ms',
        String(Math.max(30_000, Math.floor(timeoutMs / 2))),
        ...selection.sources.flatMap((source) => ['--source-path', source]),
      ],
      { timeoutMs },
    );
    result.posture = parsePosture(evidence);
  } catch (error) {
    result.error = (error as Error).message;
  } finally {
    result.durationMs = Date.now() - started;
  }
  return result;
}
