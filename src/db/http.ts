import { packageInfo } from '../util/pkg.js';

export interface RequestOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  retries?: number;
  /** Responses larger than this are rejected. */
  maxBytes?: number;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class HttpError extends Error {
  constructor(
    message: string,
    readonly url: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function userAgent(): string {
  const { version, homepage } = packageInfo();
  return `appxray/${version}${homepage ? ` (+${homepage})` : ''}`;
}

async function readLimited(response: Response, url: string, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new HttpError(`response from ${url} is ${declared} bytes (limit ${maxBytes})`, url);
  }
  if (!response.body) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  // Leaving the loop early cancels the underlying stream.
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    total += chunk.byteLength;
    if (total > maxBytes)
      throw new HttpError(`response from ${url} exceeded ${maxBytes} bytes`, url);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Fetches text with a timeout, a size cap and retries on transient failures. */
export async function fetchText(
  url: string,
  options: RequestOptions = {},
  fetchImpl: FetchLike = fetch,
): Promise<string> {
  const retries = options.retries ?? 3;
  const maxBytes = options.maxBytes ?? 32 * 1024 * 1024;
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
    try {
      const init: RequestInit = {
        method: options.method ?? 'GET',
        headers: { 'user-agent': userAgent(), ...options.headers },
        signal: AbortSignal.timeout(options.timeoutMs ?? 60_000),
        redirect: 'follow',
      };
      if (options.body !== undefined) init.body = options.body;
      const response = await fetchImpl(url, init);
      if (response.ok) return await readLimited(response, url, maxBytes);
      const transient = response.status === 429 || response.status >= 500;
      lastError = new HttpError(`${url} returned HTTP ${response.status}`, url, response.status);
      await response.body?.cancel();
      if (!transient) break;
    } catch (error) {
      lastError = error instanceof HttpError ? error : new HttpError(describe(error, url), url);
      if (error instanceof HttpError && error.status === undefined) break;
    }
  }
  throw lastError;
}

export async function fetchJson<T>(
  url: string,
  options: RequestOptions = {},
  fetchImpl: FetchLike = fetch,
): Promise<T> {
  const text = await fetchText(url, options, fetchImpl);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(`${url} did not return valid JSON`, url);
  }
}

function describe(error: unknown, url: string): string {
  const err = error as Error & { cause?: { code?: string; message?: string } };
  const cause = err.cause?.code ?? err.cause?.message;
  return `request to ${url} failed: ${err.message}${cause ? ` (${cause})` : ''}`;
}
