import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Structural guard for the AP-1 readiness protection: every Firebase-backed route must reach Firebase
// through getAdminServices(), which refuses to hand out services while credentials are unusable.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const rawSource = fs.readFileSync(path.join(ROOT, 'server.ts'), 'utf8');
// Type-only annotations such as `auth: import('firebase-admin/auth').Auth;` never execute, so ignore them.
const source = rawSource
  .split('\n')
  .filter((line) => !/^\s*(auth|db|FieldValue)\s*:\s*(typeof\s+)?import\(/.test(line))
  .join('\n');

function functionBody(name: string): string {
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `${name} not found`);
  const open = source.indexOf('{', source.indexOf(')', start));
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  throw new Error(`Unbalanced braces in ${name}`);
}

test('Firebase Admin is initialised in exactly one place', () => {
  for (const marker of ["import('firebase-admin/app')", "import('firebase-admin/auth')", "import('firebase-admin/firestore')", 'getFirestore(', 'getAuth(']) {
    assert.equal(source.split(marker).length - 1, 1, `${marker} must appear exactly once in server.ts`);
  }
  const init = functionBody('initAdminServices');
  for (const marker of ["import('firebase-admin/app')", 'getFirestore(', 'getAuth(']) {
    assert.ok(init.includes(marker), `${marker} must live inside initAdminServices`);
  }
});

test('initAdminServices is only called by getAdminServices, the readiness route and boot warm-up', () => {
  const callSites = source.split('initAdminServices()').length - 1;
  // definition is `initAdminServices() {` (counted), plus: getAdminServices, /api/ready, boot warm-up
  assert.equal(callSites, 4, `unexpected number of initAdminServices() references: ${callSites}`);
  assert.ok(functionBody('getAdminServices').includes('credentialReadiness.isReady()'));
});

test('getAdminServices is the only way routes obtain Firebase services', () => {
  assert.ok(functionBody('getAdminServices').includes('initAdminServices()'));
  assert.ok(!/adminServicesPromise/.test(functionBody('getAdminServices')), 'the gate must not read the cache directly');
  const outsideInit = source.replace(functionBody('initAdminServices'), '');
  assert.ok(!/\bgetFirestore\(|\bgetAuth\(/.test(outsideInit), 'Firestore/Auth must not be created outside initAdminServices');
});
