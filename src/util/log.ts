export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

const ORDER: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

export interface Logger {
  readonly level: LogLevel;
  error(message: string): void;
  warn(message: string): void;
  info(message: string): void;
  debug(message: string): void;
}

/** Writes diagnostics to stderr so stdout stays reserved for the report. */
export function createLogger(
  level: LogLevel,
  write: (line: string) => void = (line) => process.stderr.write(line),
): Logger {
  const at = (wanted: LogLevel, prefix: string) => (message: string) => {
    if (ORDER[level] >= ORDER[wanted]) write(`${prefix}${message}\n`);
  };
  return {
    level,
    error: at('error', 'error: '),
    warn: at('warn', 'warning: '),
    info: at('info', ''),
    debug: at('debug', 'debug: '),
  };
}

export const silentLogger: Logger = createLogger('silent');
