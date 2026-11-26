import test from 'node:test';
import assert from 'node:assert/strict';
import { createReadinessGate } from './runtime-readiness.ts';

function clock(start = 1_000) {
  let current = start;
  return { now: () => current, advance: (ms: number) => { current += ms; } };
}

test('a successful probe is cached for the success TTL, then re-checked', async () => {
  const time = clock();
  let probes = 0;
  const gate = createReadinessGate({ probe: async () => { probes += 1; }, now: time.now, successTtlMs: 1_000 });
  assert.equal(await gate.isReady(), true);
  assert.equal(await gate.isReady(), true);
  assert.equal(probes, 1);
  time.advance(1_001);
  assert.equal(await gate.isReady(), true);
  assert.equal(probes, 2);
});

test('a failed probe is cached for the shorter failure TTL, then retried and can recover', async () => {
  const time = clock();
  let probes = 0;
  let healthy = false;
  const gate = createReadinessGate({
    probe: async () => { probes += 1; if (!healthy) throw new Error('no credentials'); },
    now: time.now,
    failureTtlMs: 500,
    successTtlMs: 60_000,
  });
  assert.equal(await gate.isReady(), false);
  assert.equal(await gate.isReady(), false);
  assert.equal(probes, 1, 'failure is cached, so slow lookups are not repeated per request');
  healthy = true;
  time.advance(501);
  assert.equal(await gate.isReady(), true);
  assert.equal(probes, 2);
});

test('concurrent callers share one probe', async () => {
  let probes = 0;
  let release!: () => void;
  const gate = createReadinessGate({
    probe: () => new Promise<void>((resolve) => { probes += 1; release = resolve; }),
  });
  const results = Promise.all([gate.isReady(), gate.isReady(), gate.isReady()]);
  await new Promise((resolve) => setImmediate(resolve));
  release();
  assert.deepEqual(await results, [true, true, true]);
  assert.equal(probes, 1);
});

test('a probe that never settles is abandoned after the timeout and reports not ready', async () => {
  const gate = createReadinessGate({ probe: () => new Promise<never>(() => {}), timeoutMs: 25 });
  const startedAt = Date.now();
  assert.equal(await gate.isReady(), false);
  assert.ok(Date.now() - startedAt < 1_000, 'must not hang');
});

test('isReady never throws, including when the probe throws synchronously', async () => {
  const gate = createReadinessGate({ probe: () => { throw new TypeError('boom'); } });
  assert.equal(await gate.isReady(), false);
});

test('transitions are reported once per change, with only the error name', async () => {
  const time = clock();
  const events: Array<[boolean, string | undefined]> = [];
  let healthy = false;
  const gate = createReadinessGate({
    probe: async () => { if (!healthy) { const e = new Error('Bearer secret'); e.name = 'CredErr'; throw e; } },
    now: time.now,
    failureTtlMs: 10,
    onTransition: (ready, detail) => events.push([ready, detail.errorName]),
  });
  await gate.isReady();
  time.advance(11);
  await gate.isReady();
  healthy = true;
  time.advance(11);
  await gate.isReady();
  assert.deepEqual(events, [[false, 'CredErr'], [true, undefined]]);
  assert.deepEqual(Object.keys(gate.snapshot() ?? {}).sort(), ['checkedAt', 'ready']);
});
