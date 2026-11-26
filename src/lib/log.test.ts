import test from 'node:test';
import assert from 'node:assert/strict';
import { describeError, logEvent, redactSecrets } from './log.ts';

// Credential-shaped fixtures are assembled at runtime so no real-looking secret literal exists in the repo.
const fakeApiKey = ['AI', 'za', 'SyA1234567890abcdefghijklmnopqrstuv'].join('');
const fakeOauth = ['ya', '29.', 'a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxx'].join('');
const fakeKeyBlock = ['-----BEGIN ', 'PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END ', 'PRIVATE KEY-----'].join('');

test('redactSecrets removes bearer tokens, JWTs, Google tokens, API keys and private keys', () => {
  const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz';
  const input = [
    'Authorization: Bearer abc.def-ghi_123',
    `token ${jwt}`,
    `oauth ${fakeOauth}`,
    `key ${fakeApiKey}`,
    fakeKeyBlock,
  ].join('\n');
  const output = redactSecrets(input);
  for (const secret of ['abc.def-ghi_123', jwt, fakeOauth, fakeApiKey, 'MIIEvQIBADANBgkq']) {
    assert.ok(!output.includes(secret), `leaked: ${secret}`);
  }
  assert.match(output, /Bearer \[redacted\]/);
});

test('redactSecrets leaves ordinary text alone', () => {
  assert.equal(redactSecrets('Could not load the default credentials.'), 'Could not load the default credentials.');
});

test('describeError reports name, redacted message and a short stack', () => {
  const error = new Error('request failed with Bearer secret-token-value');
  error.name = 'CredentialsError';
  const described = describeError(error);
  assert.equal(described.errorName, 'CredentialsError');
  assert.ok(!described.errorMessage.includes('secret-token-value'));
  assert.ok((described.errorStack ?? '').split('\n').length <= 6);
});

test('describeError truncates very long messages and handles non-errors', () => {
  assert.ok(describeError(new Error('x'.repeat(5000))).errorMessage.length <= 401);
  const nonError = describeError('plain string with Bearer abc123');
  assert.equal(nonError.errorName, 'NonError');
  assert.ok(!nonError.errorMessage.includes('abc123'));
});

test('logEvent writes a single JSON line and redacts string fields', () => {
  const lines: string[] = [];
  logEvent('error', 'unit.event', { detail: 'Bearer leaked-token', count: 2 }, (line) => lines.push(line));
  assert.equal(lines.length, 1);
  assert.ok(!lines[0].includes('\n'));
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.event, 'unit.event');
  assert.equal(parsed.level, 'error');
  assert.equal(parsed.count, 2);
  assert.ok(!lines[0].includes('leaked-token'));
  assert.ok(!Number.isNaN(Date.parse(parsed.ts)));
});
