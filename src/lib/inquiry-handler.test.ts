import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../../server.ts', import.meta.url), 'utf8');
const handler = source.slice(source.indexOf("'/api/inquiries'"), source.indexOf("'/api/newsletter/validate'"));

test('inquiry handler keeps line breaks in the project description', () => {
  assert.match(handler, /projectDescription:\s*sanitizeMultilineText\(data\.projectDescription\)/);
  assert.doesNotMatch(handler, /projectDescription:\s*sanitizePlainText/);
});

test('honeypot hits are rejected visibly, offer the contact fallback and are logged', () => {
  const branch = handler.slice(handler.indexOf('websiteHoneypot'), handler.indexOf('idempotencyHeaderSchema.safeParse'));
  assert.match(branch, /inquiry_honeypot_rejected/);
  assert.match(branch, /status\(400\)/);
  assert.match(branch, /VERIFIED_CONTACT\.email/);
});

test('inquiry storage failures are logged, not swallowed', () => {
  assert.match(handler, /inquiry_store_unavailable/);
  assert.match(handler, /inquiry_store_failed/);
});
