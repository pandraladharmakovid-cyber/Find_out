/**
 * Small async helpers used to keep the monitoring and agent pipelines inside a
 * predictable time budget. Every helper resolves/rejects instead of leaving a
 * hanging promise, which is what produced the previous 120 s monitoring timeout.
 */

export class TimeoutError extends Error {
  readonly timeoutMs: number;

  constructor(label: string, timeoutMs: number) {
    super(`${label} timed out after ${Math.round(timeoutMs / 1000)}s`);
    this.name = "TimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Races a promise against a timer. The underlying promise is not cancelled
 * (fetch callers already use AbortController); the caller simply stops waiting.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return promise;
  }

  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TimeoutError(label, timeoutMs)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface DeadlineOutcome<T> {
  value?: T;
  error?: string;
  timedOut: boolean;
  durationMs: number;
}

/**
 * Runs a task with a deadline and never throws. Used by monitoring so a single
 * slow external source cannot block the whole scan.
 */
export async function runWithDeadline<T>(
  task: () => Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<DeadlineOutcome<T>> {
  const startedAt = Date.now();

  try {
    const value = await withTimeout(task(), timeoutMs, label);
    return { value, timedOut: false, durationMs: Date.now() - startedAt };
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : "Unknown error",
      timedOut: error instanceof TimeoutError,
      durationMs: Date.now() - startedAt,
    };
  }
}

/**
 * Bounded concurrency map, used for Play Store detail lookups so a scan does
 * not open dozens of sockets at once.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;

  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (cursor < items.length) {
        const index = cursor++;
        const item = items[index];
        if (item === undefined) continue;
        results[index] = await mapper(item, index);
      }
    },
  );

  await Promise.all(workers);
  return results;
}
