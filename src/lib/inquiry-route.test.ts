import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import express from 'express';
import {
  createInquiryRouteHandler,
  isInquiryEmailFallbackEnabled,
  type InquiryDocRef,
  type InquiryRouteDeps,
  type InquiryStore,
} from './inquiry-route.ts';
import type { InquiryEmailPayload, InquiryEmailResult } from './inquiry-email.ts';
import { jsonBodySecurityGuard, malformedJsonErrorHandler } from './server-security.ts';

const validPayload = (overrides: Record<string, unknown> = {}) => ({
  fullName: 'Achieng Otieno',
  businessEmail: 'Achieng.Otieno@Example.co.ke',
  companyName: 'Savanna Retail Ltd',
  phone: '+254 712 345 678',
  industry: 'Retail & Convenience',
  requiredServices: ['Social Media Management', 'Brand Activation'],
  estimatedBudget: 'KES 400,000 – 1,000,000',
  projectTimeline: '1 – 2 Months',
  projectDescription: 'Regional product launch across Nairobi and Nakuru retail locations.',
  consentAccepted: true,
  websiteHoneypot: '',
  ...overrides,
});

function createMemoryInquiryStore(): {
  store: InquiryStore;
  collections: Map<string, Map<string, Record<string, unknown>>>;
} {
  const collections = new Map<string, Map<string, Record<string, unknown>>>();
  const getCollectionMap = (name: string) => {
    let map = collections.get(name);
    if (!map) {
      map = new Map<string, Record<string, unknown>>();
      collections.set(name, map);
    }
    return map;
  };

  interface InternalDocRef extends InquiryDocRef {
    collectionName: string;
  }

  const store: InquiryStore = {
    db: {
      collection(name: string) {
        return {
          doc(id?: string): InternalDocRef {
            return {
              collectionName: name,
              id: id || crypto.randomUUID(),
            };
          },
        };
      },
      async runTransaction<T>(
        fn: Parameters<InquiryStore['db']['runTransaction']>[0]
      ): Promise<T> {
        const staged: Array<() => void> = [];
        const result = await fn({
          async get(ref) {
            const internal = ref as InternalDocRef;
            const map = getCollectionMap(internal.collectionName);
            const data = map.get(internal.id);
            return {
              exists: data !== undefined,
              data: () => (data ? { ...data } : undefined),
            };
          },
          create(ref, data) {
            const internal = ref as InternalDocRef;
            staged.push(() => {
              const map = getCollectionMap(internal.collectionName);
              if (map.has(internal.id)) {
                throw new Error(`Document already exists: ${internal.collectionName}/${internal.id}`);
              }
              map.set(internal.id, { ...data });
            });
          },
          set(ref, data) {
            const internal = ref as InternalDocRef;
            staged.push(() => {
              const map = getCollectionMap(internal.collectionName);
              map.set(internal.id, { ...data });
            });
          },
        });
        for (const op of staged) op();
        return result as T;
      },
    },
    FieldValue: {
      serverTimestamp() {
        const now = Date.now();
        return { toMillis: () => now };
      },
    },
  };

  return { store, collections };
}

async function withRouteServer(
  deps: InquiryRouteDeps,
  fn: (baseUrl: string) => Promise<void>
): Promise<void> {
  const app = express();
  app.use(express.json({ limit: '16kb' }));
  app.use('/api', jsonBodySecurityGuard);
  app.use(malformedJsonErrorHandler);
  app.post('/api/inquiries', createInquiryRouteHandler(deps));

  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

test('isInquiryEmailFallbackEnabled is off by default and always disabled in production or emulator mode', () => {
  assert.equal(isInquiryEmailFallbackEnabled({}, { isProduction: false, emulatorMode: false }), false);
  assert.equal(
    isInquiryEmailFallbackEnabled(
      { INQUIRY_EMAIL_FALLBACK: 'false' },
      { isProduction: false, emulatorMode: false }
    ),
    false
  );
  assert.equal(
    isInquiryEmailFallbackEnabled(
      { INQUIRY_EMAIL_FALLBACK: 'true' },
      { isProduction: false, emulatorMode: false }
    ),
    true
  );
  assert.equal(
    isInquiryEmailFallbackEnabled(
      { INQUIRY_EMAIL_FALLBACK: 'true' },
      { isProduction: true, emulatorMode: false }
    ),
    false
  );
  assert.equal(
    isInquiryEmailFallbackEnabled(
      { INQUIRY_EMAIL_FALLBACK: 'true' },
      { isProduction: false, emulatorMode: true }
    ),
    false
  );
});

test('POST /api/inquiries saves inquiry, replies 201 without awaiting email, and does not send a second email on duplicate submission', async () => {
  const { store, collections } = createMemoryInquiryStore();
  const sentEmails: InquiryEmailPayload[] = [];
  let resolveEmail: ((value: InquiryEmailResult) => void) | null = null;

  await withRouteServer(
    {
      getInquiryStore: async () => store,
      sendEmail: async (payload) => {
        sentEmails.push(payload);
        return new Promise<InquiryEmailResult>((resolve) => {
          resolveEmail = resolve;
        });
      },
      emulatorMode: false,
      isProduction: false,
      env: { RESEND_API_KEY: 're_test_key' },
      logError: () => {},
    },
    async (baseUrl) => {
      const idempotencyKey = crypto.randomUUID();

      // First submission: must return 201 immediately even while email promise is still pending.
      const firstRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload()),
      });
      const firstBody = (await firstRes.json()) as { success?: boolean; referenceCode?: string };

      assert.equal(firstRes.status, 201);
      assert.equal(firstBody.success, true);
      assert.match(firstBody.referenceCode || '', /^EMA-\d{4}-[A-Z0-9]{12}$/);
      assert.equal(collections.get('inquiries')?.size, 1);
      assert.equal(sentEmails.length, 1);
      assert.equal(sentEmails[0].referenceCode, firstBody.referenceCode);
      assert.equal(sentEmails[0].businessEmail, 'achieng.otieno@example.co.ke');

      // Complete background email promise now that HTTP response already returned.
      assert.ok(resolveEmail, 'background email promise should still be pending after 201 response');
      (resolveEmail as (value: InquiryEmailResult) => void)({ sent: true, id: 'email_bg_1' });

      // Duplicate submission with same Idempotency-Key and payload: 200, same reference, NO second email.
      const dupRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload()),
      });
      const dupBody = (await dupRes.json()) as { success?: boolean; referenceCode?: string };

      assert.equal(dupRes.status, 200);
      assert.equal(dupBody.referenceCode, firstBody.referenceCode);
      assert.equal(collections.get('inquiries')?.size, 1);
      assert.equal(sentEmails.length, 1, 'duplicate retry must not trigger a second email');

      // Conflicting payload with same Idempotency-Key: 409 and still no second email.
      const conflictRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload({ fullName: 'Different Person' })),
      });
      assert.equal(conflictRes.status, 409);
      assert.equal(sentEmails.length, 1);
    }
  );
});

test('POST /api/inquiries returns 503 and does not send fallback email when INQUIRY_EMAIL_FALLBACK is off (default)', async () => {
  const sentEmails: InquiryEmailPayload[] = [];
  const failingStore: InquiryStore = {
    db: {
      collection() {
        return { doc: (id?: string) => ({ id: id || 'doc-1' }) };
      },
      async runTransaction() {
        throw new Error('7 PERMISSION_DENIED: Missing or insufficient permissions.');
      },
    },
    FieldValue: { serverTimestamp: () => ({ toMillis: () => Date.now() }) },
  };

  for (const getInquiryStore of [async () => null, async () => failingStore]) {
    await withRouteServer(
      {
        getInquiryStore,
        sendEmail: async (payload) => {
          sentEmails.push(payload);
          return { sent: true, id: 'unexpected' };
        },
        emulatorMode: false,
        isProduction: false,
        env: { RESEND_API_KEY: 're_test_key' },
        logError: () => {},
      },
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/inquiries`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': crypto.randomUUID(),
          },
          body: JSON.stringify(validPayload()),
        });
        assert.equal(res.status, 503);
        assert.equal(sentEmails.length, 0);
      }
    );
  }
});

test('POST /api/inquiries uses email fallback in development when INQUIRY_EMAIL_FALLBACK=true and deduplicates retries', async () => {
  const sentEmails: InquiryEmailPayload[] = [];
  const failingStore: InquiryStore = {
    db: {
      collection() {
        return { doc: (id?: string) => ({ id: id || 'doc-1' }) };
      },
      async runTransaction() {
        throw new Error('7 PERMISSION_DENIED: Missing or insufficient permissions.');
      },
    },
    FieldValue: { serverTimestamp: () => ({ toMillis: () => Date.now() }) },
  };

  await withRouteServer(
    {
      getInquiryStore: async () => failingStore,
      sendEmail: async (payload) => {
        sentEmails.push(payload);
        return { sent: true, id: 'email_fallback_1' };
      },
      emulatorMode: false,
      isProduction: false,
      env: { RESEND_API_KEY: 're_test_key', INQUIRY_EMAIL_FALLBACK: 'true' },
      logError: () => {},
    },
    async (baseUrl) => {
      const idempotencyKey = crypto.randomUUID();
      const firstRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload()),
      });
      const firstBody = (await firstRes.json()) as { success?: boolean; referenceCode?: string };
      assert.equal(firstRes.status, 201);
      assert.equal(firstBody.success, true);
      assert.match(firstBody.referenceCode || '', /^EMA-\d{4}-[A-Z0-9]{12}$/);
      assert.equal(sentEmails.length, 1);

      const dupRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload()),
      });
      const dupBody = (await dupRes.json()) as { success?: boolean; referenceCode?: string };
      assert.equal(dupRes.status, 200);
      assert.equal(dupBody.referenceCode, firstBody.referenceCode);
      assert.equal(sentEmails.length, 1, 'fallback retry must not trigger a second email');

      const conflictRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(validPayload({ companyName: 'Other Co' })),
      });
      assert.equal(conflictRes.status, 409);
      assert.equal(sentEmails.length, 1);
    }
  );
});

test('POST /api/inquiries never enables email fallback in production even if INQUIRY_EMAIL_FALLBACK=true', async () => {
  const sentEmails: InquiryEmailPayload[] = [];
  await withRouteServer(
    {
      getInquiryStore: async () => null,
      sendEmail: async (payload) => {
        sentEmails.push(payload);
        return { sent: true, id: 'should-not-happen' };
      },
      emulatorMode: false,
      isProduction: true,
      env: {
        NODE_ENV: 'production',
        RESEND_API_KEY: 're_prod_key',
        INQUIRY_TO_EMAIL: 'info@exponentialmedia.africa',
        INQUIRY_EMAIL_FALLBACK: 'true',
      },
      logError: () => {},
    },
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(),
        },
        body: JSON.stringify(validPayload()),
      });
      assert.equal(res.status, 503);
      assert.equal(sentEmails.length, 0);
    }
  );
});
