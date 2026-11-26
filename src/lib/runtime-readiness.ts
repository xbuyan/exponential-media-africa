export interface ReadinessGateOptions {
  /** Resolves when the dependency is usable; rejects (or never settles) when it is not. */
  probe: () => Promise<unknown>;
  /** Maximum time a single probe may take. */
  timeoutMs?: number;
  /** How long a successful result is trusted. */
  successTtlMs?: number;
  /** How long a failed result is trusted. Keep short, but long enough to avoid hammering slow lookups. */
  failureTtlMs?: number;
  now?: () => number;
  /** Called only when the ready state changes (and on the first determination). */
  onTransition?: (ready: boolean, detail: { errorName?: string }) => void;
}

export interface ReadinessGate {
  isReady(): Promise<boolean>;
  snapshot(): { ready: boolean; checkedAt: number } | null;
}

/**
 * Tracks whether a dependency is usable without ever throwing. Concurrent callers share
 * one probe, results are cached, and a probe that hangs is abandoned after timeoutMs.
 */
export function createReadinessGate(options: ReadinessGateOptions): ReadinessGate {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const successTtlMs = options.successTtlMs ?? 60_000;
  const failureTtlMs = options.failureTtlMs ?? 15_000;
  const now = options.now ?? Date.now;

  let state: { ready: boolean; checkedAt: number } | null = null;
  let inFlight: Promise<boolean> | null = null;

  async function runProbe(): Promise<boolean> {
    let ready = false;
    let errorName: string | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        options.probe(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error('Readiness probe timed out.')), timeoutMs);
        }),
      ]);
      ready = true;
    } catch (error) {
      errorName = error instanceof Error ? error.name : 'UnknownError';
    } finally {
      if (timer) clearTimeout(timer);
    }
    const previous = state ? state.ready : null;
    state = { ready, checkedAt: now() };
    if (previous !== ready) options.onTransition?.(ready, { errorName });
    return ready;
  }

  return {
    async isReady() {
      if (state) {
        const ttl = state.ready ? successTtlMs : failureTtlMs;
        if (now() - state.checkedAt < ttl) return state.ready;
      }
      if (!inFlight) {
        inFlight = runProbe().finally(() => {
          inFlight = null;
        });
      }
      return inFlight;
    },
    snapshot() {
      return state ? { ...state } : null;
    },
  };
}
