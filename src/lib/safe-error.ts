const SAFE_ERROR_CODE_PATTERN = /^[A-Za-z][A-Za-z0-9_/-]{0,47}$/;
const SAFE_ERROR_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,47}$/;
const SENSITIVE_PREFIX_PATTERN = /^(?:AIza|eyJ|sk_|pk_|ghp_|gho_|xox[baprs]-)/i;
const LONG_HEX_PATTERN = /[0-9a-f]{16,}/i;

export const UNKNOWN_ERROR_CODE = 'unknown';
export const UNKNOWN_ERROR_NAME = 'UnknownError';

function readPropertySafely(target: unknown, key: string): { ok: true; value: unknown } | { ok: false } {
  if (target === null || (typeof target !== 'object' && typeof target !== 'function')) {
    return { ok: false };
  }
  try {
    return { ok: true, value: (target as Record<string, unknown>)[key] };
  } catch {
    return { ok: false };
  }
}

export function safeErrorCode(error: unknown): string {
  const result = readPropertySafely(error, 'code');
  if (!result.ok) {
    return UNKNOWN_ERROR_CODE;
  }

  const raw = result.value;
  if (typeof raw === 'number') {
    return Number.isInteger(raw) && raw >= 0 && raw <= 99999 ? String(raw) : UNKNOWN_ERROR_CODE;
  }

  if (typeof raw !== 'string') {
    return UNKNOWN_ERROR_CODE;
  }

  if (
    !SAFE_ERROR_CODE_PATTERN.test(raw) ||
    raw.includes('..') ||
    SENSITIVE_PREFIX_PATTERN.test(raw) ||
    LONG_HEX_PATTERN.test(raw)
  ) {
    return UNKNOWN_ERROR_CODE;
  }

  return raw;
}

export function safeErrorName(error: unknown): string {
  const result = readPropertySafely(error, 'name');
  if (!result.ok) {
    return UNKNOWN_ERROR_NAME;
  }

  const raw = result.value;
  if (typeof raw !== 'string') {
    return UNKNOWN_ERROR_NAME;
  }

  if (
    !SAFE_ERROR_NAME_PATTERN.test(raw) ||
    SENSITIVE_PREFIX_PATTERN.test(raw) ||
    LONG_HEX_PATTERN.test(raw)
  ) {
    return UNKNOWN_ERROR_NAME;
  }

  return raw;
}

export function safeErrorHttpStatus(error: unknown): number | undefined {
  for (const key of ['status', 'statusCode'] as const) {
    const result = readPropertySafely(error, key);
    if (!result.ok) continue;
    const raw = result.value;
    if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 100 && raw <= 599) {
      return raw;
    }
  }
  return undefined;
}
