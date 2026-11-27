#!/usr/bin/env node
// Runs the Firebase emulator integration suites with strict demo-project isolation.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  API_BASE,
  AUTH_EMULATOR_HOST,
  AUTH_EMULATOR_URL,
  DATABASE_ID,
  FIRESTORE_EMULATOR_HOST,
  FIRESTORE_EMULATOR_URL,
  PROJECT_ID,
} from '../tests/emulator/expected-config.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TSX_PACKAGE_PATH = path.join(ROOT, 'node_modules', 'tsx', 'package.json');
const TSX_PACKAGE = JSON.parse(fs.readFileSync(TSX_PACKAGE_PATH, 'utf8'));
const TSX_BIN = typeof TSX_PACKAGE.bin === 'string' ? TSX_PACKAGE.bin : TSX_PACKAGE.bin?.tsx;
if (typeof TSX_BIN !== 'string') {
  throw new Error(`Could not resolve the tsx executable from ${TSX_PACKAGE_PATH}.`);
}
const TSX_ENTRY = path.resolve(path.dirname(TSX_PACKAGE_PATH), TSX_BIN);
if (!fs.existsSync(TSX_ENTRY)) {
  throw new Error(`The tsx executable declared by ${TSX_PACKAGE_PATH} does not exist: ${TSX_ENTRY}`);
}
const FIREBASE_JSON = path.join(ROOT, 'firebase.json');
const AUTH_PORT = Number(AUTH_EMULATOR_HOST.split(':')[1]);
const FIRESTORE_PORT = Number(FIRESTORE_EMULATOR_HOST.split(':')[1]);
const APP_PORT = Number(new URL(API_BASE).port);
const RESERVED_PORTS = [
  [AUTH_PORT, 'Auth emulator'],
  [FIRESTORE_PORT, 'Firestore emulator'],
  [APP_PORT, 'application server'],
  [4400, 'Firebase Emulator Hub'],
  [4500, 'Firebase emulator reserved port'],
  [9150, 'Firestore emulator websocket'],
];
const SUITES = [
  { name: 'admin-auth', file: 'tests/admin-auth.test.mjs', needsServer: false },
  { name: 'server-auth', file: 'tests/emulator/server-auth.test.mjs', needsServer: true },
  { name: 'inquiry', file: 'tests/emulator/inquiry.test.mjs', needsServer: true },
  { name: 'inquiry-integrity', file: 'tests/emulator/inquiry-integrity.test.mjs', needsServer: true },
  { name: 'rate-limit', file: 'tests/emulator/rate-limit.test.mjs', needsServer: true },
  { name: 'provisioning', file: 'tests/emulator/provisioning.test.mjs', needsServer: true },
  { name: 'firestore-rules', file: 'tests/emulator/firestore-rules.test.mjs', needsServer: true },
];

const logsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ema-emulator-tests-'));
const emulatorLogPath = path.join(logsDir, 'emulators.log');
const appLogPath = path.join(logsDir, 'app.log');

let emulatorProcess = null;
let appProcess = null;
let testProcess = null;
let abortRequested = false;
let shuttingDown = false;
let cleanupPromise = null;
const trackedChildren = new Set();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function fail(message) {
  throw new Error(message);
}

function stripAnsi(value) {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function readFirebaseJson() {
  return JSON.parse(fs.readFileSync(FIREBASE_JSON, 'utf8'));
}

function trackChild(child, label) {
  const record = {
    child,
    label,
    pid: child.pid,
    error: null,
    exited: false,
    exitCode: null,
    signal: null,
    closed: false,
    stopping: false,
  };
  trackedChildren.add(record);
  child.on('error', (error) => {
    record.error = error;
  });
  child.once('exit', (code, signal) => {
    record.exited = true;
    record.exitCode = code;
    record.signal = signal;
    if (!record.stopping && !shuttingDown && ['Firebase emulators', 'application server'].includes(label)) {
      const logPath = label === 'Firebase emulators' ? emulatorLogPath : appLogPath;
      console.error(`${label} exited unexpectedly (code ${code}, signal ${signal}). See ${logPath}.`);
    }
  });
  child.once('close', () => {
    record.closed = true;
    trackedChildren.delete(record);
  });
  return record;
}

function assertInheritedEnvironment() {
  const expected = [
    ['FIREBASE_PROJECT_ID', PROJECT_ID],
    ['FIREBASE_FIRESTORE_DATABASE_ID', DATABASE_ID],
    ['FIREBASE_AUTH_EMULATOR_HOST', AUTH_EMULATOR_HOST],
    ['FIRESTORE_EMULATOR_HOST', FIRESTORE_EMULATOR_HOST],
    ['GCLOUD_PROJECT', PROJECT_ID],
    ['GOOGLE_CLOUD_PROJECT', PROJECT_ID],
    ['VITE_FIREBASE_USE_EMULATORS', 'true'],
    ['VITE_FIREBASE_PROJECT_ID', PROJECT_ID],
    ['VITE_FIREBASE_DATABASE_ID', DATABASE_ID],
    ['VITE_FIREBASE_AUTH_EMULATOR_URL', AUTH_EMULATOR_URL],
    ['VITE_FIREBASE_FIRESTORE_EMULATOR_HOST', '127.0.0.1'],
    ['VITE_FIREBASE_FIRESTORE_EMULATOR_PORT', String(FIRESTORE_PORT)],
  ];
  for (const [name, value] of expected) {
    const actual = process.env[name];
    if (actual !== undefined && actual !== value) {
      fail(`Refusing to start: inherited ${name} is "${actual}" but must be "${value}".`);
    }
  }
}

function assertFirebaseConfig() {
  const config = readFirebaseJson();
  const auth = config.emulators?.auth;
  const firestore = config.emulators?.firestore;
  const problems = [];
  if (auth?.host !== '127.0.0.1' || auth?.port !== AUTH_PORT) {
    problems.push(`emulators.auth must be 127.0.0.1:${AUTH_PORT}`);
  }
  if (firestore?.host !== '127.0.0.1' || firestore?.port !== FIRESTORE_PORT) {
    problems.push(`emulators.firestore must be 127.0.0.1:${FIRESTORE_PORT}`);
  }
  if (config.emulators?.ui?.enabled !== false) {
    problems.push('emulators.ui.enabled must be false');
  }
  if (config.emulators?.singleProjectMode !== true) {
    problems.push('emulators.singleProjectMode must be true');
  }
  const configuredDatabase = config.firestore?.database ?? config.emulators?.firestore?.database;
  if (configuredDatabase !== undefined && configuredDatabase !== DATABASE_ID) {
    problems.push(`Firestore database must be ${DATABASE_ID}`);
  }
  if (problems.length > 0) {
    fail(`Refusing to start with unsafe firebase.json:\n- ${problems.join('\n- ')}`);
  }
}

function resolveFirebaseCli() {
  const candidates = [];
  if (process.env.FIREBASE_CLI) candidates.push(process.env.FIREBASE_CLI);
  for (const directory of (process.env.PATH || '').split(path.delimiter)) {
    if (!directory) continue;
    if (process.platform === 'win32') {
      candidates.push(path.join(directory, 'firebase.exe'));
      candidates.push(path.join(directory, 'firebase.cmd'));
    } else {
      candidates.push(path.join(directory, 'firebase'));
    }
  }
  const npxRoot = path.join(os.homedir(), '.npm', '_npx');
  if (fs.existsSync(npxRoot)) {
    const cached = fs
      .readdirSync(npxRoot)
      .map((entry) => path.join(npxRoot, entry, 'node_modules', 'firebase-tools', 'lib', 'bin', 'firebase.js'))
      .filter((candidate) => fs.existsSync(candidate))
      .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
    candidates.push(...cached);
  }
  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (!found) {
    fail(
      'Firebase CLI was not found. Install firebase-tools or set FIREBASE_CLI to the firebase executable ' +
        '(or to firebase-tools/lib/bin/firebase.js). See docs/emulator-testing.md.',
    );
  }
  if (found.endsWith('.js')) {
    return { command: process.execPath, args: [found], display: found };
  }
  if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(found)) {
    return { command: process.env.ComSpec || 'cmd.exe', windowsScript: found, display: found };
  }
  return { command: found, args: [], display: found };
}

function firebaseCliArgs(cli, args) {
  if (!cli.windowsScript) return [...(cli.args || []), ...args];
  const command = [
    `"${cli.windowsScript}"`,
    ...args.map((argument) => `"${String(argument).replace(/"/g, '""')}"`),
  ].join(' ');
  return ['/d', '/s', '/c', `"${command}"`];
}

function baseEnvironment() {
  const env = { ...process.env };
  for (const name of [
    'GOOGLE_APPLICATION_CREDENTIALS',
    'FIREBASE_CONFIG',
    'FIREBASE_TOKEN',
    'CLOUDSDK_CORE_PROJECT',
    'FIREBASE_PROJECT_ID',
    'FIREBASE_FIRESTORE_DATABASE_ID',
    'FIREBASE_AUTH_EMULATOR_HOST',
    'FIRESTORE_EMULATOR_HOST',
    'FIREBASE_EMULATOR_MODE',
    'VITE_FIREBASE_USE_EMULATORS',
    'VITE_FIREBASE_PROJECT_ID',
    'VITE_FIREBASE_DATABASE_ID',
    'VITE_FIREBASE_AUTH_EMULATOR_URL',
    'VITE_FIREBASE_FIRESTORE_EMULATOR_HOST',
    'VITE_FIREBASE_FIRESTORE_EMULATOR_PORT',
  ]) {
    delete env[name];
  }
  env.NO_UPDATE_NOTIFIER = '1';
  env.CI = 'true';
  env.GCLOUD_PROJECT = PROJECT_ID;
  env.GOOGLE_CLOUD_PROJECT = PROJECT_ID;
  return env;
}

function emulatorEnvironment() {
  return {
    ...baseEnvironment(),
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_FIRESTORE_DATABASE_ID: DATABASE_ID,
  };
}

function applicationEnvironment() {
  return {
    ...baseEnvironment(),
    NODE_ENV: 'development',
    APP_URL: API_BASE,
    FIREBASE_EMULATOR_MODE: 'true',
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_FIRESTORE_DATABASE_ID: DATABASE_ID,
    FIREBASE_AUTH_EMULATOR_HOST: AUTH_EMULATOR_HOST,
    FIRESTORE_EMULATOR_HOST: FIRESTORE_EMULATOR_HOST,
    VITE_FIREBASE_USE_EMULATORS: 'true',
    VITE_FIREBASE_PROJECT_ID: PROJECT_ID,
    VITE_FIREBASE_DATABASE_ID: DATABASE_ID,
    VITE_FIREBASE_AUTH_EMULATOR_URL: AUTH_EMULATOR_URL,
    VITE_FIREBASE_FIRESTORE_EMULATOR_HOST: '127.0.0.1',
    VITE_FIREBASE_FIRESTORE_EMULATOR_PORT: String(FIRESTORE_PORT),
  };
}

function testEnvironment() {
  return {
    ...baseEnvironment(),
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_FIRESTORE_DATABASE_ID: DATABASE_ID,
    FIREBASE_AUTH_EMULATOR_HOST: AUTH_EMULATOR_HOST,
    FIRESTORE_EMULATOR_HOST: FIRESTORE_EMULATOR_HOST,
    EMA_API_BASE: API_BASE,
    EMA_EMULATOR_LOG: emulatorLogPath,
  };
}

function isPortOpen(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (open) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(750, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

async function assertPortsFree() {
  const conflicts = [];
  for (const [port, label] of RESERVED_PORTS) {
    if (await isPortOpen('127.0.0.1', port)) conflicts.push(`${label} (127.0.0.1:${port})`);
  }
  if (conflicts.length > 0) {
    fail(
      `Refusing to start because these ports are already in use:\n- ${conflicts.join('\n- ')}\n` +
        'Stop the existing emulator/server before running the isolated test workflow.',
    );
  }
}

function spawnLogged(command, args, options, logPath, label) {
  const logFd = fs.openSync(logPath, 'a');
  try {
    const child = spawn(command, args, {
      ...options,
      detached: process.platform !== 'win32',
      stdio: ['ignore', logFd, logFd],
    });
    return trackChild(child, label);
  } finally {
    fs.closeSync(logFd);
  }
}

async function waitForHttp(url, { timeoutMs = 60_000, child, label } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    if (child?.error) {
      fail(`${label || url} failed to start: ${child.error.message}. See ${logsDir}.`);
    }
    if (child?.exited) {
      fail(
        `${label || url} exited before becoming ready (code ${child.exitCode}, signal ${child.signal}). See ${logsDir}.`,
      );
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.status < 500) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(250);
  }
  fail(`Timed out waiting for ${label || url}: ${lastError instanceof Error ? lastError.message : lastError}`);
}

async function resetEmulators() {
  const authReset = await fetch(`${AUTH_EMULATOR_URL}/emulator/v1/projects/${PROJECT_ID}/accounts`, {
    method: 'DELETE',
    signal: AbortSignal.timeout(30_000),
  });
  if (!authReset.ok) fail(`Auth emulator reset failed with HTTP ${authReset.status}.`);
  const firestoreReset = await fetch(
    `${FIRESTORE_EMULATOR_URL}/emulator/v1/projects/${PROJECT_ID}/databases/${DATABASE_ID}/documents`,
    { method: 'DELETE', signal: AbortSignal.timeout(30_000) },
  );
  if (!firestoreReset.ok) fail(`Firestore emulator reset failed with HTTP ${firestoreReset.status}.`);
}

function readNewLog(path, offset) {
  if (!fs.existsSync(path)) return '';
  return fs.readFileSync(path).subarray(offset).toString('utf8');
}

async function waitForServerConfiguration(offset) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const chunk = readNewLog(appLogPath, offset);
    const configured =
      chunk.includes(`project=${PROJECT_ID}`) &&
      chunk.includes(`database=${DATABASE_ID}`) &&
      chunk.includes(`auth=${AUTH_EMULATOR_HOST}`) &&
      chunk.includes(`firestore=${FIRESTORE_EMULATOR_HOST}`) &&
      chunk.includes(`viteProject=${PROJECT_ID}`) &&
      chunk.includes(`viteDatabase=${DATABASE_ID}`) &&
      chunk.includes('viteEmulators=true');
    if (configured) return;
    await sleep(200);
  }
  fail(`The application server did not report the expected emulator configuration. See ${appLogPath}.`);
}

async function startEmulators(cli) {
  if (abortRequested) fail('Run interrupted before the emulators started.');
  emulatorProcess = spawnLogged(
    cli.command,
    firebaseCliArgs(cli, [
      'emulators:start',
      '--only',
      'auth,firestore',
      '--project',
      PROJECT_ID,
      '--config',
      FIREBASE_JSON,
    ]),
    { cwd: ROOT, env: emulatorEnvironment() },
    emulatorLogPath,
    'Firebase emulators',
  );
  if (abortRequested) {
    await stopEmulators();
    fail('Run interrupted while the emulators were starting.');
  }
  await waitForHttp(`${AUTH_EMULATOR_URL}/`, { child: emulatorProcess, label: 'Auth emulator' });
  await waitForHttp(`${FIRESTORE_EMULATOR_URL}/`, { child: emulatorProcess, label: 'Firestore emulator' });
}

async function startApplicationServer() {
  if (abortRequested) fail('Run interrupted before the application server started.');
  console.log('Starting application server (with embedded Vite dev server)...');
  const offset = fs.existsSync(appLogPath) ? fs.statSync(appLogPath).size : 0;
  appProcess = spawnLogged(
    process.execPath,
    [TSX_ENTRY, 'server.ts'],
    { cwd: ROOT, env: applicationEnvironment() },
    appLogPath,
    'application server',
  );
  if (abortRequested) {
    await stopApplicationServer();
    fail('Run interrupted while the application server was starting.');
  }
  await waitForHttp(`${API_BASE}/api/health`, { child: appProcess, label: 'application server' });
  await waitForServerConfiguration(offset);
}

function processGroupExists(pgid) {
  if (!pgid) return false;
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    if (error.code === 'EPERM') return true;
    throw new Error(`Unable to inspect process group ${pgid}: ${error.message}`, { cause: error });
  }
}

function signalProcessGroup(pgid, signal) {
  if (!Number.isSafeInteger(pgid) || pgid <= 0) {
    throw new Error(`Refusing to signal an invalid process-group ID: ${pgid}.`);
  }
  try {
    process.kill(-pgid, signal);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw new Error(`Unable to send ${signal} to process group ${pgid}: ${error.message}`, { cause: error });
  }
}

async function waitForProcessGroupExit(pgid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processGroupExists(pgid)) return true;
    await sleep(100);
  }
  return !processGroupExists(pgid);
}

function runTaskkill(pid, label) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'taskkill.exe',
      ['/PID', String(pid), '/T', '/F'],
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    const record = trackChild(child, `taskkill for ${label}`);
    let output = '';
    let settled = false;
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
    });
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      const failure = new Error(`Could not start taskkill for ${label} process tree ${pid}: ${error.message}`, {
        cause: error,
      });
      reject(failure);
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      if (code !== 0) {
        const detail = output.trim() || `taskkill exited with code ${code}, signal ${signal}`;
        reject(new Error(`Could not terminate ${label} process tree ${pid}: ${detail}`));
        return;
      }
      record.closed = true;
      resolve();
    });
  });
}

function childHasExited(record) {
  return record.exited || record.child.exitCode !== null || record.child.signalCode !== null;
}

async function waitForChildExit(record, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (childHasExited(record)) return true;
    await sleep(100);
  }
  return childHasExited(record);
}

async function stopProcess(record, label) {
  if (!record) return;
  record.stopping = true;
  const pid = record.pid;
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    if (record.error) return;
    throw new Error(`Cannot stop ${label}: no valid child process ID was assigned.`);
  }

  if (process.platform === 'win32') {
    if (childHasExited(record)) {
      throw new Error(
        `Cannot verify cleanup of ${label} process tree ${pid}: the tracked process exited before tree termination.`,
      );
    }
    await runTaskkill(pid, label);
    if (!(await waitForChildExit(record, 5_000))) {
      throw new Error(`${label} process ${pid} did not exit after taskkill terminated its process tree.`);
    }
    return;
  }

  if (!processGroupExists(pid)) return;
  signalProcessGroup(pid, 'SIGTERM');
  if (await waitForProcessGroupExit(pid, 5_000)) return;
  console.error(`Warning: ${label} process group ${pid} did not exit after SIGTERM; sending SIGKILL.`);
  signalProcessGroup(pid, 'SIGKILL');
  if (await waitForProcessGroupExit(pid, 2_000)) return;
  throw new Error(`${label} process group ${pid} is still running after SIGKILL.`);
}

async function stopApplicationServer() {
  const child = appProcess;
  appProcess = null;
  await stopProcess(child, 'application server');
}

async function stopEmulators() {
  const child = emulatorProcess;
  emulatorProcess = null;
  await stopProcess(child, 'Firebase emulators');
}

async function cleanup() {
  abortRequested = true;
  shuttingDown = true;
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    const processes = new Map();
    if (testProcess) processes.set(testProcess, 'test runner');
    if (appProcess) processes.set(appProcess, 'application server');
    if (emulatorProcess) processes.set(emulatorProcess, 'Firebase emulators');
    for (const record of trackedChildren) {
      if (!record.label.startsWith('taskkill for') && !processes.has(record)) {
        processes.set(record, record.label);
      }
    }
    testProcess = null;
    appProcess = null;
    emulatorProcess = null;
    const failures = [];
    for (const [record, label] of processes) {
      try {
        await stopProcess(record, label);
      } catch (error) {
        failures.push(`${label}: ${error instanceof Error ? error.message : error}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`One or more child processes could not be cleaned up:\n- ${failures.join('\n- ')}`);
    }
  })();
  return cleanupPromise;
}

function parseCounts(output) {
  const clean = stripAnsi(output);
  const count = (label) => {
    const match = clean.match(new RegExp(`(?:^|\\n)\\s*(?:ℹ|#)\\s*${label}\\s+(\\d+)`, 'm'));
    return match ? Number(match[1]) : 0;
  };
  return {
    tests: count('tests'),
    passed: count('pass'),
    failed: count('fail'),
    skipped: count('skipped'),
    ran: /(?:^|\n)\s*(?:ℹ|#)\s*tests\s+\d+/m.test(clean),
  };
}

function runSuite(suite, env) {
  return new Promise((resolve, reject) => {
    if (abortRequested) {
      reject(new Error('Run interrupted.'));
      return;
    }
    const child = spawn(
      process.execPath,
      ['--experimental-strip-types', '--test', '--test-concurrency=1', suite.file],
      { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' },
    );
    const record = trackChild(child, `${suite.name} test runner`);
    testProcess = record;
    let output = '';
    let settled = false;
    let timeoutError = null;
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      output += chunk.toString();
      process.stderr.write(chunk);
    });
    const timer = setTimeout(() => {
      timeoutError = new Error(`${suite.name} test runner exceeded the four-minute timeout.`);
      void stopProcess(record, `${suite.name} test runner`).catch((error) => {
        const failure = new Error(
          `${timeoutError.message} Process-tree termination failed: ${error.message}`,
          { cause: error },
        );
        if (settled) {
          console.error(failure.message);
          process.exitCode = 1;
          return;
        }
        settled = true;
        reject(failure);
      });
    }, 240_000);
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      testProcess = null;
      reject(new Error(`Could not start ${suite.name} test runner: ${error.message}`, { cause: error }));
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      testProcess = null;
      if (settled) return;
      settled = true;
      if (timeoutError) {
        reject(timeoutError);
        return;
      }
      resolve({ code, signal, counts: parseCounts(output) });
    });
  });
}

async function main() {
  assertInheritedEnvironment();
  assertFirebaseConfig();
  const cli = resolveFirebaseCli();
  await assertPortsFree();

  console.log(`Firebase CLI: ${cli.display}`);
  console.log(`Emulator project: ${PROJECT_ID}`);
  console.log(`Firestore database: ${DATABASE_ID}`);
  console.log(`Auth emulator: ${AUTH_EMULATOR_URL}`);
  console.log(`Firestore emulator: ${FIRESTORE_EMULATOR_URL}`);
  console.log(`Logs: ${logsDir}`);

  console.log('Starting Auth and Firestore emulators...');
  await startEmulators(cli);
  if (abortRequested) fail('Run interrupted.');
  console.log('Resetting emulator data...');
  await resetEmulators();
  if (abortRequested) fail('Run interrupted.');
  const results = [];
  const totals = { tests: 0, passed: 0, failed: 0, skipped: 0 };

  for (const suite of SUITES) {
    if (abortRequested) fail('Run interrupted.');
    if (emulatorProcess && emulatorProcess.exited) {
      fail(`Firebase emulators exited before suite ${suite.name}. See ${emulatorLogPath}.`);
    }
    if (suite.needsServer) {
      await stopApplicationServer();
      await startApplicationServer();
    } else {
      await stopApplicationServer();
    }
    if (abortRequested) fail('Run interrupted.');
    console.log(`\n=== ${suite.name} (${suite.file}) ===`);
    const result = await runSuite(suite, testEnvironment());
    results.push({ suite, ...result });
    totals.tests += result.counts.tests;
    totals.passed += result.counts.passed;
    totals.failed += result.counts.failed;
    totals.skipped += result.counts.skipped;
  }

  console.log('\n=== Emulator test summary ===');
  for (const { suite, code, counts } of results) {
    console.log(
      `${suite.name}: tests=${counts.tests} passed=${counts.passed} failed=${counts.failed} ` +
        `skipped=${counts.skipped} exit=${code ?? 'signal'}`,
    );
  }
  console.log(
    `Total: tests=${totals.tests} passed=${totals.passed} failed=${totals.failed} skipped=${totals.skipped}`,
  );
  console.log(`Project=${PROJECT_ID} database=${DATABASE_ID} logs=${logsDir}`);

  const incomplete = results.some(({ counts }) => !counts.ran);
  const unsuccessful = results.some(({ code, counts }) => code !== 0 || counts.failed > 0);
  if (incomplete || unsuccessful || totals.tests === 0) {
    process.exitCode = 1;
  }
}

async function handleSignal(signal, exitCode) {
  console.error(`\n${signal} received; shutting down test processes.`);
  try {
    await cleanup();
  } catch (error) {
    console.error(`Cleanup failed: ${error instanceof Error ? error.message : error}`);
    process.exitCode = 1;
  }
  process.exit(exitCode);
}

process.on('SIGINT', () => {
  void handleSignal('SIGINT', 130);
});
process.on('SIGTERM', () => {
  void handleSignal('SIGTERM', 143);
});

main()
  .catch(async (error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      await cleanup();
    } catch (error) {
      console.error(`Cleanup failed: ${error instanceof Error ? error.message : error}`);
      process.exitCode = 1;
    }
  });
