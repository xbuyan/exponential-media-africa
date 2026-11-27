import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildInquiryEmailContent,
  DEFAULT_INQUIRY_FROM,
  DEFAULT_INQUIRY_RECIPIENT,
  escapeHtml,
  sendInquiryNotificationEmail,
  type InquiryEmailPayload,
} from './inquiry-email.ts';

const sampleInquiry: InquiryEmailPayload = {
  referenceCode: 'EMA-2026-ABCDEF123456',
  fullName: 'Achieng Otieno',
  businessEmail: 'Achieng.Otieno@Example.co.ke',
  companyName: 'Savanna & Sons "Kenya" Ltd',
  phone: '+254 712 345 678',
  industry: 'Retail & Convenience',
  requiredServices: ['Social Media Management', 'Brand Activation'],
  estimatedBudget: 'KES 400,000 – 1,000,000',
  projectTimeline: '1 – 2 Months',
  projectDescription: "Launch campaign for Nairobi & Mombasa stores with <script>alert('xss')</script> safety.",
};

test('escapeHtml neutralizes HTML special characters', () => {
  assert.equal(
    escapeHtml(`<a href="x" title='y'>&</a>`),
    '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;'
  );
});

test('buildInquiryEmailContent formats text and escapes HTML fields', () => {
  const content = buildInquiryEmailContent(sampleInquiry);
  assert.equal(
    content.subject,
    'New Project Inquiry (EMA-2026-ABCDEF123456) — Savanna & Sons "Kenya" Ltd'
  );
  assert.match(content.text, /Reference Code: EMA-2026-ABCDEF123456/);
  assert.match(content.text, /Required Services: Social Media Management, Brand Activation/);
  assert.equal(content.html.includes('<script>'), false);
  assert.equal(content.html.includes('Savanna &amp; Sons &quot;Kenya&quot; Ltd'), true);
});

test('sendInquiryNotificationEmail skips cleanly when disabled or RESEND_API_KEY is unset', async () => {
  let called = false;
  const mockFetch = (async () => {
    called = true;
    return new Response(JSON.stringify({ id: 'should-not-run' }), { status: 200 });
  }) as typeof fetch;

  const missingKey = await sendInquiryNotificationEmail(sampleInquiry, {
    env: {},
    fetchImpl: mockFetch,
  });
  assert.deepEqual(missingKey, { sent: false, skipped: true });

  const disabled = await sendInquiryNotificationEmail(sampleInquiry, {
    disabled: true,
    env: { RESEND_API_KEY: 're_test_123' },
    fetchImpl: mockFetch,
  });
  assert.deepEqual(disabled, { sent: false, skipped: true });
  assert.equal(called, false);
});

test('sendInquiryNotificationEmail posts to Resend targeting xtra8477@gmail.com by default', async () => {
  let capturedUrl = '';
  let capturedHeaders: Record<string, string> = {};
  let capturedBody: Record<string, unknown> = {};

  const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
    capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    return new Response(JSON.stringify({ id: 'email_12345' }), { status: 200 });
  }) as typeof fetch;

  const result = await sendInquiryNotificationEmail(sampleInquiry, {
    env: { RESEND_API_KEY: 're_test_key' },
    fetchImpl: mockFetch,
  });

  assert.deepEqual(result, { sent: true, id: 'email_12345' });
  assert.equal(capturedUrl, 'https://api.resend.com/emails');
  assert.equal(capturedHeaders.Authorization, 'Bearer re_test_key');
  assert.equal(capturedBody.from, DEFAULT_INQUIRY_FROM);
  assert.deepEqual(capturedBody.to, [DEFAULT_INQUIRY_RECIPIENT]);
  assert.equal(capturedBody.reply_to, 'achieng.otieno@example.co.ke');
});

test('sendInquiryNotificationEmail honors valid env overrides and handles API failures gracefully', async () => {
  let capturedBody: Record<string, unknown> = {};
  const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    return new Response(JSON.stringify({ message: 'Forbidden' }), { status: 403 });
  }) as typeof fetch;

  const result = await sendInquiryNotificationEmail(sampleInquiry, {
    env: {
      RESEND_API_KEY: 're_test_key',
      INQUIRY_TO_EMAIL: 'leads@exponentialmedia.africa',
      INQUIRY_FROM_EMAIL: 'Exponential Agency <inquiries@exponentialmedia.africa>',
    },
    fetchImpl: mockFetch,
  });

  assert.deepEqual(result, { sent: false, status: 403 });
  assert.deepEqual(capturedBody.to, ['leads@exponentialmedia.africa']);
  assert.equal(capturedBody.from, 'Exponential Agency <inquiries@exponentialmedia.africa>');
});

test('sendInquiryNotificationEmail skips sending in production when INQUIRY_TO_EMAIL is missing or invalid', async () => {
  let called = false;
  const mockFetch = (async () => {
    called = true;
    return new Response(JSON.stringify({ id: 'should-not-send' }), { status: 200 });
  }) as typeof fetch;

  const missingTo = await sendInquiryNotificationEmail(sampleInquiry, {
    env: { NODE_ENV: 'production', RESEND_API_KEY: 're_prod_key' },
    fetchImpl: mockFetch,
  });
  assert.deepEqual(missingTo, { sent: false, skipped: true });

  const invalidTo = await sendInquiryNotificationEmail(sampleInquiry, {
    env: { NODE_ENV: 'production', RESEND_API_KEY: 're_prod_key', INQUIRY_TO_EMAIL: 'not-an-email' },
    fetchImpl: mockFetch,
  });
  assert.deepEqual(invalidTo, { sent: false, skipped: true });
  assert.equal(called, false);
});

test('sendInquiryNotificationEmail sends in production when INQUIRY_TO_EMAIL is explicitly configured', async () => {
  let capturedBody: Record<string, unknown> = {};
  const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    return new Response(JSON.stringify({ id: 'email_prod_1' }), { status: 200 });
  }) as typeof fetch;

  const result = await sendInquiryNotificationEmail(sampleInquiry, {
    env: {
      NODE_ENV: 'production',
      RESEND_API_KEY: 're_prod_key',
      INQUIRY_TO_EMAIL: 'info@exponentialmedia.africa',
    },
    fetchImpl: mockFetch,
  });

  assert.deepEqual(result, { sent: true, id: 'email_prod_1' });
  assert.deepEqual(capturedBody.to, ['info@exponentialmedia.africa']);
});
