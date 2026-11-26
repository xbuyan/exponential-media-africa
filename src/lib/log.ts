export type LogLevel = 'info' | 'warn' | 'error';
export type LogFields = Record<string, unknown>;
export type LogSink = (line: string) => void;

const REDACTIONS: Array<[RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]'],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, '[redacted-jwt]'],
  [/ya29\.[A-Za-z0-9._-]{20,}/g, '[redacted-token]'],
  [/AIza[0-9A-Za-z_-]{20,}/g, '[redacted-key]'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[redacted-private-key]'],
];

/** Best-effort removal of credential-shaped strings before anything is logged. */
export function redactSecrets(text: string): string {
  return REDACTIONS.reduce((value, [pattern, replacement]) => value.replace(pattern, replacement), text);
}

function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
}

/** Describes an error for logs: name, redacted message, and a short redacted stack. */
export function describeError(
  error: unknown,
  maxLength = 400,
): { errorName: string; errorMessage: string; errorStack?: string } {
  if (error instanceof Error) {
    const stack = error.stack
      ? truncate(redactSecrets(error.stack.split('\n').slice(0, 6).join('\n')), maxLength * 2)
      : undefined;
    return {
      errorName: error.name || 'Error',
      errorMessage: truncate(redactSecrets(error.message), maxLength),
      ...(stack ? { errorStack: stack } : {}),
    };
  }
  return { errorName: 'NonError', errorMessage: truncate(redactSecrets(String(error)), maxLength) };
}

const defaultSink: LogSink = (line) => {
  process.stdout.write(`${line}\n`);
};

/**
 * Writes one JSON line. Callers must not pass personal data or credentials; string
 * values are additionally passed through redactSecrets as a safety net.
 */
export function logEvent(
  level: LogLevel,
  event: string,
  fields: LogFields = {},
  sink: LogSink = defaultSink,
): void {
  const safeFields: LogFields = {};
  for (const [key, value] of Object.entries(fields)) {
    safeFields[key] = typeof value === 'string' ? redactSecrets(value) : value;
  }
  sink(JSON.stringify({ ts: new Date().toISOString(), level, event, ...safeFields }));
}
