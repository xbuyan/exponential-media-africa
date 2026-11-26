import test from 'node:test';
import assert from 'node:assert/strict';
import { createFatalErrorHandler, installFatalErrorHandlers } from './process-safety.ts';

function harness(options: { drainMs?: number; closeServer?: (done: () => void) => void } = {}) {
  const logs: Array<{ level: string; event: string; fields: Record<string, unknown> }> = [];
  const exits: number[] = [];
  const handler = createFatalErrorHandler({
    closeServer: options.closeServer ?? ((done) => done()),
    log: (level, event, fields = {}) => logs.push({ level, event, fields }),
    exit: (code) => exits.push(code),
    drainMs: options.drainMs ?? 50,
  });
  return { logs, exits, handler };
}

test('a fatal error is logged, the server is closed, and the process exits non-zero', () => {
  const closed: string[] = [];
  const h = harness({ closeServer: (done) => { closed.push('closed'); done(); } });
  h.handler('unhandledRejection', new Error('credentials missing'));
  assert.deepEqual(closed, ['closed']);
  assert.deepEqual(h.exits, [1]);
  assert.equal(h.logs[0].event, 'process.fatal');
  assert.equal(h.logs[0].level, 'error');
  assert.equal(h.logs[0].fields.kind, 'unhandledRejection');
});

test('if draining stalls, the process still exits non-zero after the drain limit', async () => {
  const h = harness({ drainMs: 30, closeServer: () => {} });
  h.handler('uncaughtException', new Error('stuck'));
  assert.deepEqual(h.exits, []);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(h.exits, [1]);
  assert.ok(h.logs.some((entry) => entry.event === 'process.drain_timeout'));
});

test('a second fatal error while draining exits immediately', () => {
  const h = harness({ drainMs: 10_000, closeServer: () => {} });
  h.handler('unhandledRejection', new Error('first'));
  assert.deepEqual(h.exits, []);
  h.handler('uncaughtException', new Error('second'));
  assert.deepEqual(h.exits, [1]);
});

test('if closing the server throws, the process still exits non-zero', () => {
  const h = harness({ closeServer: () => { throw new Error('close failed'); } });
  h.handler('uncaughtException', new Error('bad'));
  assert.deepEqual(h.exits, [1]);
});

test('exit is reported once even if both the drain and the timeout fire', async () => {
  const h = harness({ drainMs: 20, closeServer: (done) => { done(); setTimeout(done, 5); } });
  h.handler('unhandledRejection', new Error('x'));
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.deepEqual(h.exits, [1]);
});

test('logged errors never contain credential-shaped strings', () => {
  const h = harness();
  const fakeApiKey = ['AI', 'za', 'SyA1234567890abcdefghijklmnopqrstuv'].join('');
  h.handler('unhandledRejection', new Error(`call failed: Bearer super-secret-token ${fakeApiKey}`));
  const serialized = JSON.stringify(h.logs);
  assert.ok(!serialized.includes('super-secret-token'));
  assert.ok(!serialized.includes(fakeApiKey));
});

test('installFatalErrorHandlers wires both process events to the handler', () => {
  const registered: Record<string, (arg: unknown) => void> = {};
  const seen: Array<[string, unknown]> = [];
  installFatalErrorHandlers(
    { on: ((event: string, listener: (arg: unknown) => void) => { registered[event] = listener; return undefined as never; }) as never },
    (kind, error) => seen.push([kind, error]),
  );
  registered.unhandledRejection('reason');
  registered.uncaughtException('error');
  assert.deepEqual(seen, [['unhandledRejection', 'reason'], ['uncaughtException', 'error']]);
});
