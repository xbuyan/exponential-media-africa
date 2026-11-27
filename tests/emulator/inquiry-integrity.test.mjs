import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { api, listCollection, resetEmulators } from './helpers.mjs';

const payload = (overrides = {}) => ({
  fullName: 'Achieng Otieno',
  businessEmail: 'achieng.otieno@example.com',
  companyName: 'Savanna Retail Ltd',
  phone: '+254 712 345 678',
  industry: 'Retail & FMCG',
  requiredServices: ['Media Buy', 'Brand Activations'],
  estimatedBudget: 'KES 2M - 5M',
  projectTimeline: '1-3 months',
  projectDescription: 'We need an integrated launch campaign across Nairobi and Nakuru.',
  consentAccepted: true,
  ...overrides,
});

const unwrap = (doc) => doc?.data ?? doc;

test.before(async () => {
  await resetEmulators();
});

test('a multi-line description keeps its line breaks when stored', async () => {
  const description = 'First paragraph.\n\nSecond paragraph.';
  const response = await api('/api/inquiries', {
    method: 'POST',
    headers: { 'Idempotency-Key': randomUUID() },
    body: payload({ projectDescription: description }),
  });
  assert.equal(response.status, 201, JSON.stringify(response.body));
  const stored = (await listCollection('inquiries'))
    .map(unwrap)
    .find((doc) => doc.referenceCode === response.body.referenceCode);
  assert.ok(stored, 'stored inquiry not found');
  assert.equal(stored.projectDescription, description);
});

test('a honeypot submission is rejected visibly, offers the contact fallback and is not stored', async () => {
  const before = (await listCollection('inquiries')).length;
  const response = await api('/api/inquiries', {
    method: 'POST',
    headers: { 'Idempotency-Key': randomUUID() },
    body: payload({ websiteHoneypot: 'https://spam.example' }),
  });
  assert.equal(response.status, 400);
  assert.match(String(response.body.error), /contact/i, JSON.stringify(response.body));
  assert.equal((await listCollection('inquiries')).length, before);
});
