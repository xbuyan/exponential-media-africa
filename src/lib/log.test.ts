import test from 'node:test';
import assert from 'node:assert/strict';
import {
  describeError,
  logEvent,
  type LogEntry,
  type LogFields,
  type LogLevel,
  type LogSink,
} from './log.ts';
import {
  safeErrorCode,
  safeErrorHttpStatus,
  safeErrorName,
  UNKNOWN_ERROR_CODE,
  UNKNOWN_ERROR_NAME,
} from './safe-error.ts';

test('logEvent sanitizes nested objects and arrays while preserving safe fields', () => {
  const captured: LogEntry[] = [];
  const sink: LogSink = (entry) => captured.push(entry);
  const level: LogLevel = 'info';
  const fields: LogFields = {
    requestId: 'req-42',
    nested: {
      businessEmail: 'founder@example.com',
      apiKey: 'secret-api-key',
      note: 'Contact jane.doe@example.com or +254 712 345 678\nforged=true',
      authHeader: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload123.sig456',
      url: 'https://example.com/callback?token=supersecret&ok=1',
    },
    items: [
      'hello\r\nworld',
      'user@example.org',
      {
        password: 'hunter2',
        tags: ['safe-tag', 'Bearer topsecrettoken1234'],
      },
    ],
  };

  const entry = logEvent(level, 'inquiry_checked\r\nforged', fields, sink);

  assert.equal(captured.length, 1);
  assert.equal(entry.event, 'inquiry_checked forged');
  assert.equal(entry.fields?.requestId, 'req-42');

  const nested = entry.fields?.nested as Record<string, unknown>;
  assert.equal(nested.businessEmail, '[REDACTED]');
  assert.equal(nested.apiKey, '[REDACTED]');
  assert.equal(nested.note, 'Contact [REDACTED_EMAIL] or [REDACTED_PHONE] forged=true');
  assert.equal(nested.authHeader, 'Bearer [REDACTED]');
  assert.equal(nested.url, 'https://example.com/callback?token=[REDACTED]&ok=1');

  const items = entry.fields?.items as unknown[];
  assert.equal(items[0], 'hello world');
  assert.equal(items[1], '[REDACTED_EMAIL]');
  const nestedItem = items[2] as Record<string, unknown>;
  assert.equal(nestedItem.password, '[REDACTED]');
  assert.deepEqual(nestedItem.tags, ['safe-tag', 'Bearer [REDACTED]']);
});

test('logEvent handles circular references, unexpected objects, and serialization failures safely', () => {
  const circular: Record<string, unknown> = { label: 'root' };
  circular.self = circular;

  const secretMap = new Map<string, string>([['secret', 'do-not-leak']]);
  const secretBuffer = Buffer.from('sensitive-binary-secret');
  const throwingProxy = new Proxy(
    {},
    {
      get() {
        throw new Error('proxy get trap boom');
      },
      getPrototypeOf() {
        throw new Error('proxy proto trap boom');
      },
      ownKeys() {
        throw new Error('proxy ownKeys trap boom');
      },
    }
  );
  const throwingGetterObj = Object.defineProperty({}, 'badField', {
    enumerable: true,
    get() {
      throw new Error('getter leaked secret');
    },
  });

  const captured: LogEntry[] = [];
  const entry = logEvent(
    'warn',
    'unexpected_payload',
    {
      circular,
      secretMap,
      secretBuffer,
      throwingProxy,
      throwingGetterObj,
      date: new Date('2026-11-27T12:00:00.000Z'),
      regex: /secret-pattern/i,
      fn: () => 'secret-return',
    },
    (e) => captured.push(e)
  );

  assert.equal(captured.length, 1);
  const circularOut = entry.fields?.circular as Record<string, unknown>;
  assert.equal(circularOut.label, 'root');
  assert.equal(circularOut.self, '[Circular]');
  assert.equal(entry.fields?.secretMap, '[UnexpectedObject]');
  assert.equal(entry.fields?.secretBuffer, '[UnexpectedObject]');
  assert.equal(entry.fields?.throwingProxy, '[UnexpectedObject]');
  assert.deepEqual(entry.fields?.throwingGetterObj, { badField: '[Unreadable]' });
  assert.equal(entry.fields?.date, '2026-11-27T12:00:00.000Z');
  assert.equal(entry.fields?.regex, '[RegExp]');
  assert.equal(entry.fields?.fn, '[Function]');

  const serialized = JSON.stringify(entry);
  assert.equal(serialized.includes('do-not-leak'), false);
  assert.equal(serialized.includes('sensitive-binary-secret'), false);
  assert.equal(serialized.includes('getter leaked secret'), false);
  assert.equal(serialized.includes('secret-pattern'), false);

  // Throwing sink must never crash caller or process-safety logging.
  assert.doesNotThrow(() => {
    logEvent(
      'error',
      'sink_failure_test',
      { ok: true },
      () => {
        throw new Error('sink crashed');
      }
    );
  });
});

test('safeErrorCode and safeErrorName handle throwing getters, proxies, and unsafe values safely', () => {
  const throwingError = {
    get code() {
      throw new Error('secret code failure');
    },
    get name() {
      throw new Error('secret name failure');
    },
    get status() {
      throw new Error('secret status failure');
    },
  };

  assert.equal(safeErrorCode(throwingError), UNKNOWN_ERROR_CODE);
  assert.equal(safeErrorName(throwingError), UNKNOWN_ERROR_NAME);
  assert.equal(safeErrorHttpStatus(throwingError), undefined);

  const throwingProxy = new Proxy(
    {},
    {
      get() {
        throw new Error('proxy exploded');
      },
    }
  );
  assert.equal(safeErrorCode(throwingProxy), UNKNOWN_ERROR_CODE);
  assert.equal(safeErrorName(throwingProxy), UNKNOWN_ERROR_NAME);

  const leakyError = {
    code: 'user@example.com',
    name: 'Error: leaked secret message',
  };
  assert.equal(safeErrorCode(leakyError), UNKNOWN_ERROR_CODE);
  assert.equal(safeErrorName(leakyError), UNKNOWN_ERROR_NAME);

  const tokenCodeError = {
    code: 'AIzaSyDfjoeE0g3DA-5NKsfuv5DdV8FXXX8mHYg',
    name: 'eyJhbGciOiJIUzI1NiJ9',
  };
  assert.equal(safeErrorCode(tokenCodeError), UNKNOWN_ERROR_CODE);
  assert.equal(safeErrorName(tokenCodeError), UNKNOWN_ERROR_NAME);

  assert.equal(safeErrorCode(null), UNKNOWN_ERROR_CODE);
  assert.equal(safeErrorName('raw string error'), UNKNOWN_ERROR_NAME);

  const validError = Object.assign(new TypeError('sensitive raw message for john@example.com'), {
    code: 'auth/user-not-found',
    status: 404,
  });
  assert.equal(safeErrorName(validError), 'TypeError');
  assert.equal(safeErrorCode(validError), 'auth/user-not-found');
  assert.equal(safeErrorHttpStatus(validError), 404);
});

test('describeError strips arbitrary messages and PII while preserving safe diagnostic context', () => {
  const cause = Object.assign(new Error('raw cause secret token=abc123'), {
    code: 'ECONNRESET',
  });
  const err = Object.assign(
    new RangeError('Failed to update user john@example.com with secret sk_test_1234567890abcdef'),
    {
      code: 'PERMISSION_DENIED',
      statusCode: 403,
      cause,
    }
  );

  const described = describeError(err, {
    route: '/api/admin/roles',
    actorEmail: 'admin@example.com',
    nested: {
      token: 'eyJhbGciOiJIUzI1NiJ9.aaa.bbb',
      retryAttempt: 2,
    },
  });

  assert.equal(described.name, 'RangeError');
  assert.equal(described.code, 'PERMISSION_DENIED');
  assert.equal(described.kind, 'error');
  assert.equal(described.httpStatus, 403);
  assert.equal(described.hasStack, true);
  assert.deepEqual(described.cause, { name: 'Error', code: 'ECONNRESET' });
  assert.deepEqual(described.context, {
    route: '/api/admin/roles',
    actorEmail: '[REDACTED]',
    nested: {
      token: '[REDACTED]',
      retryAttempt: 2,
    },
  });

  const serialized = JSON.stringify(described);
  assert.equal(serialized.includes('john@example.com'), false);
  assert.equal(serialized.includes('admin@example.com'), false);
  assert.equal(serialized.includes('sk_test_1234567890abcdef'), false);
  assert.equal(serialized.includes('Failed to update user'), false);
  assert.equal(serialized.includes('raw cause secret'), false);

  // Nested Error objects inside logEvent fields are also reduced via describeError.
  const entry = logEvent('error', 'request_failed', { err });
  const loggedErr = entry.fields?.err as Record<string, unknown>;
  assert.equal(loggedErr.name, 'RangeError');
  assert.equal(loggedErr.code, 'PERMISSION_DENIED');
  assert.equal('message' in loggedErr, false);
});
