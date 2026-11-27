import { describeError, type LogFields, type LogLevel } from './log.ts';

export type FatalKind = 'unhandledRejection' | 'uncaughtException';

export interface FatalErrorHandlerOptions {
  /** Stop accepting connections and call done() once existing ones have finished. */
  closeServer: (done: () => void) => void;
  log: (level: LogLevel, event: string, fields?: LogFields) => void;
  exit: (code: number) => void;
  /** Hard ceiling on draining before the process exits regardless. */
  drainMs?: number;
}

/**
 * Policy for failures nobody handled: the process state can no longer be trusted, so
 * log, stop taking new work, let in-flight requests finish for a bounded time, and exit
 * non-zero so the hosting platform restarts a clean process. It never resumes serving.
 */
export function createFatalErrorHandler(options: FatalErrorHandlerOptions) {
  const drainMs = options.drainMs ?? 10_000;
  let shuttingDown = false;

  return function handleFatal(kind: FatalKind, error: unknown): void {
    options.log('error', 'process.fatal', { ...describeError(error), kind });

    if (shuttingDown) {
      // A second failure while draining: stop waiting.
      options.exit(1);
      return;
    }
    shuttingDown = true;

    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      options.exit(1);
    };

    // Deliberately not unref'd: if draining stalls, this timer is what guarantees exit(1).
    const timer = setTimeout(() => {
      options.log('error', 'process.drain_timeout', { drainMs });
      finish();
    }, drainMs);

    try {
      options.closeServer(finish);
    } catch {
      finish();
    }
  };
}

export function installFatalErrorHandlers(
  target: Pick<NodeJS.Process, 'on'>,
  handler: (kind: FatalKind, error: unknown) => void,
): void {
  target.on('unhandledRejection', (reason) => handler('unhandledRejection', reason));
  target.on('uncaughtException', (error) => handler('uncaughtException', error));
}
