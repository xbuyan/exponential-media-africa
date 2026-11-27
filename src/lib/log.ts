import { safeErrorCode, safeErrorHttpStatus, safeErrorName } from './safe-error.ts';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Record<string, unknown>;

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  event: string;
  fields?: Record<string, unknown>;
}

export type LogSink = (entry: LogEntry) => void;

export interface SafeErrorDescription {
  name: string;
  code: string;
  kind: 'error' | 'non_error';
  httpStatus?: number;
  hasStack?: boolean;
  cause?: {
    name: string;
    code: string;
  };
  context?: Record<string, unknown>;
}

const MAX_DEPTH = 8;
const MAX_ARRAY_ITEMS = 50;
const MAX_OBJECT_KEYS = 50;
const MAX_STRING_LENGTH = 500;
const MAX_EVENT_LENGTH = 120;

const CONTROL_CHARS_PATTERN =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SENSITIVE_KEY_EXACT = new Set([
  'password',
  'passwd',
  'secret',
  'clientsecret',
  'token',
  'idtoken',
  'accesstoken',
  'refreshtoken',
  'bearertoken',
  'unsubscribetoken',
  'authorization',
  'cookie',
  'setcookie',
  'apikey',
  'privatekey',
  'credential',
  'credentials',
  'session',
  'sessionid',
  'email',
  'businessemail',
  'actoremail',
  'useremail',
  'phone',
  'phonenumber',
  'mobile',
  'fullname',
  'displayname',
  'firstname',
  'lastname',
  'address',
  'streetaddress',
  'headquartersaddress',
  'campusaddress',
  'ip',
  'ipaddress',
  'clientip',
  'remoteaddress',
  'otp',
  'pin',
  'passcode',
  'verificationid',
  'errormessage',
  'rawmessage',
  'stack',
]);

const SENSITIVE_KEY_SUFFIXES = [
  'password',
  'secret',
  'token',
  'apikey',
  'privatekey',
  'credential',
  'credentials',
  'email',
  'phone',
  'cookie',
  'authorization',
];

const EMAIL_VALUE_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const BEARER_VALUE_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const JWT_VALUE_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const API_KEY_VALUE_PATTERN = /\b(?:AIza[0-9A-Za-z_-]{16,}|(?:sk|pk|ghp|gho)_[0-9A-Za-z_-]{16,})\b/g;
const PHONE_VALUE_PATTERN = /\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3}[\s.-]?\d{3,4}\b/g;
const QUERY_SECRET_PATTERN =
  /([?&](?:token|key|apiKey|api_key|secret|auth|password|signature|sig)=)[^&\s]+/gi;

function normalizeKeyForSensitivityCheck(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKeyForSensitivityCheck(key);
  if (!normalized) return false;
  if (SENSITIVE_KEY_EXACT.has(normalized)) return true;
  return SENSITIVE_KEY_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

function sanitizeLogString(value: string, maxLength = MAX_STRING_LENGTH): string {
  const clean = value
    .replace(/[\r\n\t]+/g, ' ')
    .replace(CONTROL_CHARS_PATTERN, '')
    .replace(BEARER_VALUE_PATTERN, 'Bearer [REDACTED]')
    .replace(JWT_VALUE_PATTERN, '[REDACTED_TOKEN]')
    .replace(API_KEY_VALUE_PATTERN, '[REDACTED_KEY]')
    .replace(EMAIL_VALUE_PATTERN, '[REDACTED_EMAIL]')
    .replace(PHONE_VALUE_PATTERN, '[REDACTED_PHONE]')
    .replace(QUERY_SECRET_PATTERN, '$1[REDACTED]')
    .trim();

  if (clean.length > maxLength) {
    return `${clean.slice(0, maxLength)}…[truncated]`;
  }
  return clean;
}

function isPlainObject(value: object): boolean {
  try {
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

function isErrorLike(value: unknown): value is Error {
  if (!value || typeof value !== 'object') return false;
  try {
    if (value instanceof Error) return true;
    return Object.prototype.toString.call(value) === '[object Error]';
  } catch {
    return false;
  }
}

function safeIsInstance(value: object, ctor: typeof Date | typeof RegExp): boolean {
  try {
    return value instanceof ctor;
  } catch {
    return false;
  }
}

function safeIsArray(value: unknown): value is unknown[] {
  try {
    return Array.isArray(value);
  } catch {
    return false;
  }
}

function sanitizeValue(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) {
    return value === null ? null : undefined;
  }

  const valueType = typeof value;
  if (valueType === 'boolean') return value;
  if (valueType === 'number') return Number.isFinite(value) ? value : String(value);
  if (valueType === 'bigint') return value.toString();
  if (valueType === 'string') return sanitizeLogString(value as string);
  if (valueType === 'symbol') return '[Symbol]';
  if (valueType === 'function') return '[Function]';

  if (typeof value !== 'object') {
    return '[UnexpectedValue]';
  }

  const obj = value as object;
  if (seen.has(obj)) {
    return '[Circular]';
  }
  if (depth >= MAX_DEPTH) {
    return '[MaxDepth]';
  }

  if (safeIsInstance(obj, Date)) {
    try {
      const time = (obj as Date).getTime();
      return Number.isNaN(time) ? '[InvalidDate]' : (obj as Date).toISOString();
    } catch {
      return '[InvalidDate]';
    }
  }

  if (safeIsInstance(obj, RegExp)) {
    return '[RegExp]';
  }

  if (isErrorLike(obj)) {
    return describeError(obj);
  }

  seen.add(obj);
  try {
    if (safeIsArray(obj)) {
      const out: unknown[] = [];
      let length = 0;
      try {
        length = obj.length;
      } catch {
        return '[UnreadableArray]';
      }
      const limit = Math.min(length, MAX_ARRAY_ITEMS);
      for (let i = 0; i < limit; i += 1) {
        try {
          const sanitizedItem = sanitizeValue(obj[i], depth + 1, seen);
          out.push(sanitizedItem === undefined ? null : sanitizedItem);
        } catch {
          out.push('[UnreadableItem]');
        }
      }
      if (length > MAX_ARRAY_ITEMS) {
        out.push(`[+${length - MAX_ARRAY_ITEMS} more]`);
      }
      return out;
    }

    if (!isPlainObject(obj)) {
      return '[UnexpectedObject]';
    }

    let keys: string[];
    try {
      keys = Object.keys(obj);
    } catch {
      return '[UnreadableObject]';
    }

    const sanitizedObj: Record<string, unknown> = Object.create(null);
    const limit = Math.min(keys.length, MAX_OBJECT_KEYS);
    for (let i = 0; i < limit; i += 1) {
      const key = keys[i];
      if (FORBIDDEN_KEYS.has(key)) continue;
      const safeKey = sanitizeLogString(key, 80) || '_key';
      if (isSensitiveKey(key)) {
        sanitizedObj[safeKey] = '[REDACTED]';
        continue;
      }
      try {
        const rawProp = (obj as Record<string, unknown>)[key];
        const cleanProp = sanitizeValue(rawProp, depth + 1, seen);
        if (cleanProp !== undefined) {
          sanitizedObj[safeKey] = cleanProp;
        }
      } catch {
        sanitizedObj[safeKey] = '[Unreadable]';
      }
    }
    if (keys.length > MAX_OBJECT_KEYS) {
      sanitizedObj._truncatedKeys = keys.length - MAX_OBJECT_KEYS;
    }
    return { ...sanitizedObj };
  } finally {
    seen.delete(obj);
  }
}

export function sanitizeLogFields(fields?: LogFields): Record<string, unknown> | undefined {
  if (!fields || typeof fields !== 'object') return undefined;
  const sanitized = sanitizeValue(fields, 0, new WeakSet<object>());
  if (!sanitized || typeof sanitized !== 'object' || Array.isArray(sanitized)) {
    return { value: sanitized };
  }
  return sanitized as Record<string, unknown>;
}

export function describeError(error: unknown, context?: LogFields): SafeErrorDescription {
  const name = safeErrorName(error);
  const code = safeErrorCode(error);
  const kind: 'error' | 'non_error' = isErrorLike(error) ? 'error' : 'non_error';
  const httpStatus = safeErrorHttpStatus(error);

  let hasStack: boolean | undefined;
  if (error !== null && typeof error === 'object') {
    try {
      const stackVal = (error as { stack?: unknown }).stack;
      if (typeof stackVal === 'string' && stackVal.length > 0) {
        hasStack = true;
      }
    } catch {
      hasStack = undefined;
    }
  }

  let cause: { name: string; code: string } | undefined;
  if (error !== null && typeof error === 'object') {
    try {
      const rawCause = (error as { cause?: unknown }).cause;
      if (rawCause !== undefined && rawCause !== null && rawCause !== error) {
        cause = {
          name: safeErrorName(rawCause),
          code: safeErrorCode(rawCause),
        };
      }
    } catch {
      cause = undefined;
    }
  }

  const sanitizedContext = sanitizeLogFields(context);
  const description: SafeErrorDescription = { name, code, kind };
  if (httpStatus !== undefined) description.httpStatus = httpStatus;
  if (hasStack) description.hasStack = true;
  if (cause) description.cause = cause;
  if (sanitizedContext && Object.keys(sanitizedContext).length > 0) {
    description.context = sanitizedContext;
  }
  return description;
}

function safeJsonSerialize(entry: LogEntry): string {
  try {
    return JSON.stringify(entry);
  } catch {
    return JSON.stringify({
      timestamp: entry.timestamp,
      level: entry.level,
      event: entry.event,
      serializationError: true,
    });
  }
}

export const defaultLogSink: LogSink = (entry) => {
  const line = safeJsonSerialize(entry);
  if (entry.level === 'error') {
    console.error(line);
  } else if (entry.level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
};

export function logEvent(
  level: LogLevel,
  event: string,
  fields?: LogFields,
  sink: LogSink = defaultLogSink
): LogEntry {
  const safeLevel: LogLevel =
    level === 'debug' || level === 'info' || level === 'warn' || level === 'error'
      ? level
      : 'info';
  const safeEvent =
    typeof event === 'string'
      ? sanitizeLogString(event, MAX_EVENT_LENGTH) || 'log_event'
      : 'log_event';

  let safeFields: Record<string, unknown> | undefined;
  try {
    safeFields = sanitizeLogFields(fields);
  } catch {
    safeFields = { sanitizationError: true };
  }

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level: safeLevel,
    event: safeEvent,
    ...(safeFields && Object.keys(safeFields).length > 0 ? { fields: safeFields } : {}),
  };

  try {
    sink(entry);
  } catch {
    try {
      defaultLogSink({
        timestamp: entry.timestamp,
        level: 'error',
        event: 'log_sink_failure',
      });
    } catch {
      // Never allow logging failures to disrupt process execution.
    }
  }

  return entry;
}
