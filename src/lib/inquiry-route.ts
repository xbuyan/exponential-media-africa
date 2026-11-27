import crypto from 'node:crypto';
import type { RequestHandler } from 'express';
import { z } from 'zod';
import { VERIFIED_CONTACT } from '../data/seedData.ts';
import {
  sendInquiryNotificationEmail,
  type InquiryEmailPayload,
  type InquiryEmailResult,
  type SendInquiryEmailOptions,
} from './inquiry-email.ts';
import { projectInquirySchema, sanitizePlainText } from './validation.ts';

const INQUIRY_IDEMPOTENCY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_LOCAL_INQUIRY_IDEMPOTENCY = 2_000;
const REFERENCE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const inquiryPayloadSchema = projectInquirySchema.strict();
const idempotencyHeaderSchema = z.string().uuid();

export interface InquiryDocRef {
  readonly id: string;
}

export interface InquiryDocSnapshot {
  readonly exists: boolean;
  data(): Record<string, unknown> | undefined;
}

export interface InquiryTransaction {
  get(ref: InquiryDocRef): Promise<InquiryDocSnapshot>;
  create(ref: InquiryDocRef, data: Record<string, unknown>): unknown;
  set(ref: InquiryDocRef, data: Record<string, unknown>): unknown;
}

export interface InquiryCollectionRef {
  doc(id?: string): InquiryDocRef;
}

export interface InquiryStore {
  db: {
    collection(name: string): InquiryCollectionRef;
    runTransaction<T>(fn: (transaction: InquiryTransaction) => Promise<T>): Promise<T>;
  };
  FieldValue: {
    serverTimestamp(): unknown;
  };
}

export type SendInquiryEmailFn = (
  inquiry: InquiryEmailPayload,
  options?: SendInquiryEmailOptions
) => Promise<InquiryEmailResult>;

export interface InquiryRouteDeps {
  getInquiryStore: () => Promise<InquiryStore | null>;
  sendEmail?: SendInquiryEmailFn;
  emulatorMode: boolean;
  isProduction: boolean;
  env?: NodeJS.ProcessEnv;
  logError?: (message: string) => void;
}

export function isInquiryEmailFallbackEnabled(
  env: NodeJS.ProcessEnv,
  options: { isProduction: boolean; emulatorMode: boolean }
): boolean {
  if (options.isProduction || options.emulatorMode) return false;
  return env.INQUIRY_EMAIL_FALLBACK?.trim().toLowerCase() === 'true';
}

function createProposedReference(): string {
  const suffix = Array.from(
    crypto.randomBytes(12),
    (byte) => REFERENCE_ALPHABET[byte % REFERENCE_ALPHABET.length]
  ).join('');
  return `EMA-${new Date().getFullYear()}-${suffix}`;
}

export function createInquiryRouteHandler(deps: InquiryRouteDeps): RequestHandler {
  const {
    getInquiryStore,
    sendEmail = sendInquiryNotificationEmail,
    emulatorMode,
    isProduction,
    logError = (message: string) => console.error(message),
  } = deps;
  const localInquiryIdempotency = new Map<
    string,
    { payloadHash: string; referenceCode: string; expiresAt: number }
  >();

  return async (req, res) => {
    const env = deps.env ?? process.env;
    const parsed = inquiryPayloadSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: parsed.error.issues[0]?.message || 'Invalid inquiry submission.',
      });
    }

    const data = parsed.data;
    if (data.websiteHoneypot && data.websiteHoneypot.length > 0) {
      return res.status(400).json({
        error: 'Submission could not be accepted. Please check the form and try again.',
      });
    }

    const idempotencyKey = idempotencyHeaderSchema.safeParse(req.get('Idempotency-Key'));
    if (!idempotencyKey.success) {
      return res.status(400).json({ error: 'Please retry the form submission.' });
    }

    const normalizedInput = {
      fullName: sanitizePlainText(data.fullName),
      businessEmail: sanitizePlainText(data.businessEmail).toLowerCase(),
      companyName: sanitizePlainText(data.companyName),
      phone: sanitizePlainText(data.phone),
      industry: sanitizePlainText(data.industry),
      requiredServices: data.requiredServices.map(sanitizePlainText),
      estimatedBudget: sanitizePlainText(data.estimatedBudget),
      projectTimeline: sanitizePlainText(data.projectTimeline),
      projectDescription: sanitizePlainText(data.projectDescription),
      consentAccepted: true as const,
      websiteHoneypot: '',
    };

    const normalizedResult = inquiryPayloadSchema.safeParse(normalizedInput);
    if (!normalizedResult.success) {
      return res.status(400).json({
        error: normalizedResult.error.issues[0]?.message || 'Please check the submitted details.',
      });
    }
    const sanitizedPayload = {
      fullName: normalizedResult.data.fullName,
      businessEmail: normalizedResult.data.businessEmail,
      companyName: normalizedResult.data.companyName,
      phone: normalizedResult.data.phone,
      industry: normalizedResult.data.industry,
      requiredServices: normalizedResult.data.requiredServices,
      estimatedBudget: normalizedResult.data.estimatedBudget,
      projectTimeline: normalizedResult.data.projectTimeline,
      projectDescription: normalizedResult.data.projectDescription,
      consentAccepted: normalizedResult.data.consentAccepted,
      inquiryStatus: 'new' as const,
    };

    const store = await getInquiryStore();
    const allowEmailFallback = isInquiryEmailFallbackEnabled(env, {
      isProduction,
      emulatorMode,
    });

    // The client key is an idempotency token, not an authorization credential.
    // Key the payload digest so the private record does not contain a plain PII hash.
    const payloadHash = crypto
      .createHmac('sha256', idempotencyKey.data)
      .update(JSON.stringify(sanitizedPayload))
      .digest('hex');
    const idempotencyId = crypto.createHash('sha256').update(idempotencyKey.data).digest('hex');

    const deliverViaEmailFallback = async () => {
      const now = Date.now();
      const existingLocal = localInquiryIdempotency.get(idempotencyId);
      if (existingLocal && existingLocal.expiresAt > now) {
        if (existingLocal.payloadHash !== payloadHash) {
          return res.status(409).json({
            error:
              'This submission key was already used for different form details. Please submit again.',
          });
        }
        return res.status(200).json({ success: true, referenceCode: existingLocal.referenceCode });
      }

      const proposedReference = createProposedReference();
      const emailResult = await sendEmail(
        {
          referenceCode: proposedReference,
          ...sanitizedPayload,
        },
        { disabled: emulatorMode, env }
      );

      if (emailResult.sent) {
        if (localInquiryIdempotency.size >= MAX_LOCAL_INQUIRY_IDEMPOTENCY) {
          for (const [k, entry] of localInquiryIdempotency) {
            if (entry.expiresAt <= now) localInquiryIdempotency.delete(k);
            if (localInquiryIdempotency.size < MAX_LOCAL_INQUIRY_IDEMPOTENCY) break;
          }
          if (localInquiryIdempotency.size >= MAX_LOCAL_INQUIRY_IDEMPOTENCY) {
            const oldestKey = localInquiryIdempotency.keys().next().value;
            if (oldestKey) localInquiryIdempotency.delete(oldestKey);
          }
        }
        localInquiryIdempotency.set(idempotencyId, {
          payloadHash,
          referenceCode: proposedReference,
          expiresAt: now + INQUIRY_IDEMPOTENCY_TTL_MS,
        });
        return res.status(201).json({ success: true, referenceCode: proposedReference });
      }

      if (emailResult.skipped) {
        logError(
          `[inquiries] Inquiry ${proposedReference} not delivered: Firestore Admin unavailable and email delivery was skipped.`
        );
      } else {
        logError(
          `[inquiries] Inquiry ${proposedReference} email delivery failed (status=${emailResult.status ?? 'network'}, code=${emailResult.errorName ?? 'unknown'})`
        );
      }
      return res.status(503).json({
        error: `We could not confirm that your inquiry was recorded. Your entries remain in this form; contact ${VERIFIED_CONTACT.email} or ${VERIFIED_CONTACT.primaryPhone}.`,
      });
    };

    if (!store) {
      if (!allowEmailFallback) {
        return res.status(503).json({
          error: `Online submission is temporarily unavailable. Your entries remain in this form; contact ${VERIFIED_CONTACT.email} or ${VERIFIED_CONTACT.primaryPhone}.`,
        });
      }
      return deliverViaEmailFallback();
    }

    const idempotencyRef = store.db.collection('_inquiry_idempotency').doc(idempotencyId);

    try {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const proposedReference = createProposedReference();
        const inquiryRef = store.db.collection('inquiries').doc();
        const referenceRef = store.db.collection('_inquiry_references').doc(proposedReference);

        const result = await store.db.runTransaction(async (transaction) => {
          const previous = await transaction.get(idempotencyRef);
          if (previous.exists) {
            const saved = previous.data();
            const expiresAt = saved?.expiresAt as { toMillis?: () => number } | undefined;
            const createdAt = saved?.createdAt as { toMillis?: () => number } | undefined;
            const expiresAtMillis =
              expiresAt && typeof expiresAt.toMillis === 'function'
                ? expiresAt.toMillis()
                : createdAt && typeof createdAt.toMillis === 'function'
                  ? createdAt.toMillis() + INQUIRY_IDEMPOTENCY_TTL_MS
                  : null;
            const expired = expiresAtMillis !== null && expiresAtMillis <= Date.now();
            if (!expired) {
              if (saved?.payloadHash !== payloadHash || typeof saved?.referenceCode !== 'string') {
                return { kind: 'conflict' as const };
              }
              return { kind: 'saved' as const, referenceCode: saved.referenceCode, duplicate: true };
            }
          }

          const reference = await transaction.get(referenceRef);
          if (reference.exists) return { kind: 'collision' as const };

          const createdAt = store.FieldValue.serverTimestamp();
          transaction.create(inquiryRef, {
            ...sanitizedPayload,
            referenceCode: proposedReference,
            createdAt,
          });
          const idempotencyRecord = {
            payloadHash,
            referenceCode: proposedReference,
            createdAt,
            expiresAt: new Date(Date.now() + INQUIRY_IDEMPOTENCY_TTL_MS),
          };
          if (previous.exists) transaction.set(idempotencyRef, idempotencyRecord);
          else transaction.create(idempotencyRef, idempotencyRecord);
          transaction.create(referenceRef, {
            inquiryId: inquiryRef.id,
            createdAt,
          });
          return { kind: 'saved' as const, referenceCode: proposedReference, duplicate: false };
        });

        if (result.kind === 'conflict') {
          return res.status(409).json({
            error:
              'This submission key was already used for different form details. Please submit again.',
          });
        }
        if (result.kind === 'saved') {
          if (!result.duplicate) {
            void sendEmail(
              {
                referenceCode: result.referenceCode,
                ...sanitizedPayload,
              },
              { disabled: emulatorMode, env }
            )
              .then((emailResult) => {
                if (!emailResult.sent && !emailResult.skipped) {
                  logError(
                    `[inquiries] Email notification failed for ${result.referenceCode} (status=${emailResult.status ?? 'network'}, code=${emailResult.errorName ?? 'unknown'})`
                  );
                }
              })
              .catch(() => {
                logError(
                  `[inquiries] Email notification failed unexpectedly for ${result.referenceCode}`
                );
              });
          }
          return res
            .status(result.duplicate ? 200 : 201)
            .json({ success: true, referenceCode: result.referenceCode });
        }
      }
      return res.status(503).json({
        error: `We could not confirm that your inquiry was recorded. Your entries remain in this form; contact ${VERIFIED_CONTACT.email} or ${VERIFIED_CONTACT.primaryPhone}.`,
      });
    } catch {
      if (allowEmailFallback) {
        return deliverViaEmailFallback();
      }
      return res.status(503).json({
        error: `We could not confirm that your inquiry was recorded. Your entries remain in this form; contact ${VERIFIED_CONTACT.email} or ${VERIFIED_CONTACT.primaryPhone}.`,
      });
    }
  };
}
