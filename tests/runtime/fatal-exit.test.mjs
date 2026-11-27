import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TSX_PACKAGE_PATH = path.join(ROOT, 'node_modules', 'tsx', 'package.json');
const TSX_PACKAGE = JSON.parse(fs.readFileSync(TSX_PACKAGE_PATH, 'utf8'));
const TSX_BIN = typeof TSX_PACKAGE.bin === 'string' ? TSX_PACKAGE.bin : TSX_PACKAGE.bin?.tsx;
const TSX_ENTRY = path.resolve(path.dirname(TSX_PACKAGE_PATH), TSX_BIN);
const FIXTURE = path.join(ROOT, 'tests', 'runtime', 'fatal-fixture.ts');

function runFixture(mode, drainMs) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    let output = '';
    const child = spawn(process.execPath, [TSX_ENTRY, FIXTURE], {
      cwd: ROOT,
      env: { ...process.env, FIXTURE_MODE: mode, FIXTURE_DRAIN_MS: String(drainMs) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => (output += chunk));
    child.stderr.on('data', (chunk) => (output += chunk));
    const guard = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`Fixture did not exit within 20s (mode=${mode}). Output:\n${output}`));
    }, 20_000);
    child.on('exit', (code, signal) => {
      clearTimeout(guard);
      resolve({ code, signal, output, elapsedMs: Date.now() - startedAt });
    });
  });
}

function jsonLines(output) {
  return output.split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
}

test('an unhandled rejection is logged and the process exits with code 1', async () => {
  const result = await runFixture('reject', 2_000);
  assert.equal(result.code, 1);
  assert.equal(result.signal, null);
  const fatal = jsonLines(result.output).find((entry) => entry.event === 'process.fatal');
  assert.ok(fatal, `expected a process.fatal log line, got:\n${result.output}`);
  assert.equal(fatal.fields.kind, 'unhandledRejection');
  assert.ok(!result.output.includes('abc123secret'), 'credential-shaped text must be redacted');
});

test('an uncaught exception is logged and the process exits with code 1', async () => {
  const result = await runFixture('throw', 2_000);
  assert.equal(result.code, 1);
  const fatal = jsonLines(result.output).find((entry) => entry.event === 'process.fatal');
  assert.equal(fatal?.fields?.kind, 'uncaughtException');
});

test('a connection that never finishes cannot keep the process alive past the drain limit', async () => {
  const result = await runFixture('hang', 800);
  assert.equal(result.code, 1);
  assert.ok(jsonLines(result.output).some((entry) => entry.event === 'process.drain_timeout'));
  assert.ok(result.elapsedMs < 15_000, `took ${result.elapsedMs}ms`);
});
