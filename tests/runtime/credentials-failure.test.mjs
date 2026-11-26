// Regression test for finding F1: a Firebase credentials failure must never terminate the server.
//
// It starts the real server with every way of obtaining Google credentials removed or broken, and
// asserts that Firebase-backed routes answer 503, static pages and /api/health keep working, and the
// process stays alive. Safety: HOME and gcloud config point at an empty temp directory, the cloud
// metadata server points at a dead local port, and FIREBASE_PROJECT_ID is a project that does not
// exist, so this test cannot reach any real Firebase project even on a machine with gcloud logged in.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TSX_PACKAGE_PATH = path.join(ROOT, 'node_modules', 'tsx', 'package.json');
const TSX_PACKAGE = JSON.parse(fs.readFileSync(TSX_PACKAGE_PATH, 'utf8'));
const TSX_BIN = typeof TSX_PACKAGE.bin === 'string' ? TSX_PACKAGE.bin : TSX_PACKAGE.bin?.tsx;
const TSX_ENTRY = path.resolve(path.dirname(TSX_PACKAGE_PATH), TSX_BIN);
const PORT = 3000; // server.ts currently listens on a fixed port (see AP-3)
const BASE = `http://127.0.0.1:${PORT}`;

const VALID_INQUIRY = {
  fullName: 'Test User',
  businessEmail: 'test@example.com',
  companyName: 'Acme Test Co',
  phone: '+254700000000',
  industry: 'Retail',
  requiredServices: ['Media Buying'],
  estimatedBudget: 'KES 1M',
  projectTimeline: '1 month',
  projectDescription: 'A valid description for the runtime regression test.',
  consentAccepted: true,
};

const SCENARIOS = [
  { name: 'no application default credentials', setup: () => ({}) },
  {
    name: 'credentials file that does not exist',
    setup: (dir) => ({ GOOGLE_APPLICATION_CREDENTIALS: path.join(dir, 'does-not-exist.json') }),
  },
  {
    name: 'credentials file that is not valid JSON',
    setup: (dir) => {
      const file = path.join(dir, 'broken.json');
      fs.writeFileSync(file, '{ this is not json');
      return { GOOGLE_APPLICATION_CREDENTIALS: file };
    },
  },
];

function portIsFree(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.once('listening', () => probe.close(() => resolve(true)));
    probe.listen(port, '0.0.0.0');
  });
}

function isolatedEnv(dir, extra) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(GOOGLE|GCLOUD|GCP_|CLOUDSDK|FIREBASE|FIRESTORE|VITE_FIREBASE|GCE_|NO_GCE|GEMINI)/.test(key)) continue;
    env[key] = value;
  }
  return {
    ...env,
    HOME: dir,
    XDG_CONFIG_HOME: dir,
    CLOUDSDK_CONFIG: dir,
    NO_GCE_CHECK: 'true',
    GCE_METADATA_HOST: '127.0.0.1:1',
    FIREBASE_PROJECT_ID: 'ema-runtime-test-nonexistent',
    NODE_ENV: 'development',
    ...extra,
  };
}

async function waitForHealth(child, getOutput, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Server exited early (code ${child.exitCode}). Output:\n${getOutput()}`);
    try {
      const response = await fetch(`${BASE}/api/health`);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Server did not become healthy. Output:\n${getOutput()}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise((resolve) => child.once('exit', () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), 5_000)),
  ]);
  if (!exited) child.kill('SIGKILL');
}

for (const scenario of SCENARIOS) {
  test(`credentials failure (${scenario.name}): Firebase routes return 503 and the process survives`, async (t) => {
    if (!(await portIsFree(PORT))) {
      throw new Error(`Port ${PORT} is in use. Stop the process using it (for example a dev server) and re-run.`);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ema-no-creds-'));
    let output = '';
    const child = spawn(process.execPath, [TSX_ENTRY, 'server.ts'], {
      cwd: ROOT,
      env: isolatedEnv(dir, scenario.setup(dir)),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => (output += chunk));
    child.stderr.on('data', (chunk) => (output += chunk));
    t.after(async () => {
      await stop(child);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    await waitForHealth(child, () => output);

    // The request that used to terminate the process goes first, so that on the original code this test
    // fails because the process died, not because a newer endpoint is missing.
    // Every Firebase-backed route fails closed with 503 instead of touching Firestore.
    const inquiry = await fetch(`${BASE}/api/inquiries`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify(VALID_INQUIRY),
    });
    assert.equal(inquiry.status, 503, 'public inquiry submission');

    const bearer = { authorization: 'Bearer not-a-real-token' };
    const session = await fetch(`${BASE}/api/auth/session`, { headers: bearer });
    assert.equal(session.status, 503, 'session lookup');
    const roles = await fetch(`${BASE}/api/admin/roles`, {
      method: 'POST',
      headers: { ...bearer, 'content-type': 'application/json' },
      body: JSON.stringify({ uid: 'abc', role: 'editor' }),
    });
    assert.equal(roles.status, 503, 'role provisioning');
    const rolePatch = await fetch(`${BASE}/api/admin/roles/abc`, {
      method: 'PATCH',
      headers: { ...bearer, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'editor' }),
    });
    assert.equal(rolePatch.status, 503, 'role update');
    const status = await fetch(`${BASE}/api/admin/inquiries/abc/status`, {
      method: 'PATCH',
      headers: { ...bearer, 'content-type': 'application/json' },
      body: JSON.stringify({ inquiryStatus: 'archived' }),
    });
    assert.equal(status.status, 503, 'inquiry status update');

    // The failure that used to kill the process arrives asynchronously, so wait for it.
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    assert.equal(child.exitCode, null, `server exited (code ${child.exitCode}). Output:\n${output}`);
    assert.equal((await fetch(`${BASE}/api/health`)).status, 200, 'liveness after the requests');
    assert.equal((await fetch(`${BASE}/`)).status, 200, 'static site still served');

    // Readiness reports the truth and reveals nothing else.
    const ready = await fetch(`${BASE}/api/ready`);
    assert.equal(ready.status, 503);
    assert.deepEqual(await ready.json(), { status: 'unavailable' });

    // The fault is visible in logs, and nothing credential-shaped is.
    assert.ok(output.includes('"event":"credentials.unavailable"'), `expected a credentials.unavailable log:\n${output}`);
    assert.ok(!output.includes('process.fatal'), 'no fatal-error path should have been taken');
    assert.ok(!/ya29\.|Bearer not-a-real-token|BEGIN PRIVATE KEY/.test(output), 'logs must not contain credentials');
  });
}
