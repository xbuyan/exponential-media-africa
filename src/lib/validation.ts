import { z } from 'zod';
import type {
  ImpactMetricConfig,
  SiteSettings,
  TestimonialItem,
} from '../types/cms';

export const DOC_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
export const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
export const HOSTNAME_PATTERN = /^[a-zA-Z0-9.-]+(:\d{1,5})?$/;
export const INQUIRY_REFERENCE_PATTERN = /^EMA-\d{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6,12}$/;

const CONTROL_AND_BIDI_CHARS_SINGLELINE =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

const CONTROL_AND_BIDI_CHARS_MULTILINE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * HTML markup stripping.
 *
 * A `<` only begins markup when it looks like a real tag: `<` or `</` followed
 * by a tag name, or `<!` followed by a letter for declarations such as
 * `<!DOCTYPE html>`. A tag name is ASCII letters, digits or hyphens (so
 * `<my-widget>` works) and must be followed by whitespace, `/`, `>` or the end
 * of the input. That keeps angle-bracket prose such as `<https://example.com>`
 * and `<mailto:hi@example.com>` intact, and numeric comparisons (`Budget <5000`,
 * `Between <5 and >3`) never match.
 *
 * A `<` followed directly by a letter is necessarily ambiguous (`a<b` vs. an
 * incomplete `<b>`) and is treated as markup, matching the trailing-fragment
 * behavior below.
 *
 * This is text normalization for fields rendered as plain text. It is not, by
 * itself, an XSS boundary: rendered output still needs context-appropriate
 * escaping, and URLs still go through isSafeHttpOrLocalUrl
 * / isSafeExternalHttpUrl below.
 */
const HTML_COMMENT = /<!--[\s\S]*?(?:-->|$)/g;
// One pattern handles complete tags and a trailing fragment without a closing
// `>` (e.g. `<img src=x onerror=...`), so both share the same tag grammar.
const HTML_MARKUP = /<(?:!|\/?)[a-zA-Z][a-zA-Z0-9-]*(?=[\s/>]|$)[^<>]*(?:>|$)/g;

function stripHtmlMarkup(input: string): string {
  // Comments are removed before tags in each pass so their contents cannot be
  // reinterpreted as tags. Either removal can expose the other: `<a>` inside
  // `<!<a>--x-->` leaves a comment behind, while a comment can hide part of a
  // tag. Repeat both until the text stops changing.
  let current = input;
  let next = current.replace(HTML_COMMENT, '').replace(HTML_MARKUP, '');
  // Every changing pass removes at least two characters, so this always
  // terminates.
  while (next !== current) {
    current = next;
    next = current.replace(HTML_COMMENT, '').replace(HTML_MARKUP, '');
  }
  return next;
}

export function sanitizePlainText(input: string): string {
  return stripHtmlMarkup(String(input ?? ''))
    .replace(/[\t\n\r]/g, ' ')
    .replace(CONTROL_AND_BIDI_CHARS_SINGLELINE, '')
    .trim();
}

export function sanitizeMultilineText(input: string): string {
  return stripHtmlMarkup(String(input ?? '').replace(/\r\n?/g, '\n'))
    .replace(/\t/g, ' ')
    .replace(CONTROL_AND_BIDI_CHARS_MULTILINE, '')
    .trim();
}

export function sanitizeSlug(input: string): string {
  return sanitizePlainText(input)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120);
}

export function sanitizeTelHref(phone: string): string {
  const plain = sanitizePlainText(phone);
  if (!plain || !/^[+0-9()\s.-]+$/.test(plain)) {
    return '#';
  }
  const cleaned = plain.replace(/[^+0-9]/g, '');
  return /\d{7,}/.test(cleaned) ? `tel:${cleaned}` : '#';
}

export function sanitizeMailtoHref(email: string): string {
  const plain = sanitizePlainText(email).toLowerCase();
  if (!plain || plain.length > 160 || !EMAIL_PATTERN.test(plain) || /[?#&\s\\]/.test(plain)) {
    return '#';
  }
  return `mailto:${plain}`;
}

export function isValidDocId(id: string): boolean {
  return DOC_ID_PATTERN.test(id);
}

export function isSafeHttpOrLocalUrl(url: string): boolean {
  if (!url) return true;
  const trimmed = url.trim();
  if (!trimmed) return true;
  if (/[\u0000-\u001F\u007F-\u009F\s]/.test(trimmed)) return false;
  if (trimmed.startsWith('/')) return !trimmed.startsWith('//') && !trimmed.startsWith('/\\');
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function isSafeExternalHttpUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed) return false;
  if (/[\u0000-\u001F\u007F-\u009F\s]/.test(trimmed)) return false;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function cleanExternalSocialUrl(url: string | undefined, fallback = ''): string {
  const trimmed = sanitizePlainText(url || '');
  if (
    !trimmed ||
    trimmed === 'https://exponentialmedia.africa/' ||
    trimmed === 'https://exponentialmedia.africa' ||
    !isSafeExternalHttpUrl(trimmed)
  ) {
    return fallback;
  }
  return trimmed.slice(0, 300);
}

export function sanitizeImpactMetric(
  raw: Partial<ImpactMetricConfig> | undefined,
  fallback: ImpactMetricConfig
): ImpactMetricConfig {
  const label = sanitizePlainText(raw?.label || '').slice(0, 80);
  const value = sanitizePlainText(raw?.value || '').slice(0, 40);
  const unitOrContext = sanitizePlainText(raw?.unitOrContext || '').slice(0, 120);
  return {
    id: fallback.id,
    label: label.length >= 2 ? label : fallback.label,
    value: value.length >= 1 ? value : fallback.value,
    unitOrContext: unitOrContext.length >= 2 ? unitOrContext : fallback.unitOrContext,
    isPlaceholder:
      typeof raw?.isPlaceholder === 'boolean' ? raw.isPlaceholder : fallback.isPlaceholder,
  };
}

export function sanitizeSiteSettings(
  raw: Partial<SiteSettings> | undefined,
  defaults: SiteSettings
): SiteSettings {
  const cleanCompany = sanitizePlainText(raw?.companyName || '').slice(0, 120);
  const cleanTagline = sanitizePlainText(raw?.tagline || '').slice(0, 240);
  const cleanEmail = sanitizePlainText(raw?.email || '').toLowerCase().slice(0, 160);
  const cleanPrimaryPhone = sanitizePlainText(raw?.primaryPhone || '').slice(0, 40);
  const cleanSecondaryPhone = sanitizePlainText(raw?.secondaryPhone || '').slice(0, 40);
  const cleanAddress = sanitizePlainText(raw?.headquartersAddress || '').slice(0, 240);

  return {
    companyName: cleanCompany.length >= 2 ? cleanCompany : defaults.companyName,
    tagline: cleanTagline.length >= 5 ? cleanTagline : defaults.tagline,
    email:
      EMAIL_PATTERN.test(cleanEmail) && !/[?#&\s\\]/.test(cleanEmail)
        ? cleanEmail
        : defaults.email,
    primaryPhone: /^[+0-9()\s-]{5,40}$/.test(cleanPrimaryPhone)
      ? cleanPrimaryPhone
      : defaults.primaryPhone,
    secondaryPhone: !cleanSecondaryPhone
      ? ''
      : /^[+0-9()\s-]{5,40}$/.test(cleanSecondaryPhone)
        ? cleanSecondaryPhone
        : defaults.secondaryPhone || '',
    headquartersAddress:
      cleanAddress.length >= 5 ? cleanAddress : defaults.headquartersAddress,
    campusAddress: '',
    socialLinks: {
      instagram: cleanExternalSocialUrl(
        raw?.socialLinks?.instagram,
        defaults.socialLinks.instagram
      ),
      linkedin: cleanExternalSocialUrl(
        raw?.socialLinks?.linkedin,
        defaults.socialLinks.linkedin
      ),
      youtube: cleanExternalSocialUrl(raw?.socialLinks?.youtube),
      x: cleanExternalSocialUrl(raw?.socialLinks?.x),
    },
    impactMetrics: {
      projectsCompleted: sanitizeImpactMetric(
        raw?.impactMetrics?.projectsCompleted,
        defaults.impactMetrics.projectsCompleted
      ),
      brandsServed: sanitizeImpactMetric(
        raw?.impactMetrics?.brandsServed,
        defaults.impactMetrics.brandsServed
      ),
      campaignsExecuted: sanitizeImpactMetric(
        raw?.impactMetrics?.campaignsExecuted,
        defaults.impactMetrics.campaignsExecuted
      ),
      yearsExperience: sanitizeImpactMetric(
        raw?.impactMetrics?.yearsExperience,
        defaults.impactMetrics.yearsExperience
      ),
      geographicReach: sanitizeImpactMetric(
        raw?.impactMetrics?.geographicReach,
        defaults.impactMetrics.geographicReach
      ),
    },
  };
}

export function sanitizeTestimonialRecord(
  id: string,
  raw: Omit<TestimonialItem, 'id'>
): TestimonialItem {
  const cleanVideoUrl = sanitizePlainText(raw.videoUrl || '').slice(0, 500);
  return {
    id,
    quote: sanitizePlainText(raw.quote || '').slice(0, 1000),
    clientName: sanitizePlainText(raw.clientName || '').slice(0, 100),
    clientRole: sanitizePlainText(raw.clientRole || '').slice(0, 120),
    companyName: sanitizePlainText(raw.companyName || '').slice(0, 120),
    videoUrl: cleanVideoUrl && isSafeExternalHttpUrl(cleanVideoUrl) ? cleanVideoUrl : undefined,
    isPlaceholder: Boolean(raw.isPlaceholder),
    status: raw.status === 'published' ? 'published' : 'draft',
    isDeleted: Boolean(raw.isDeleted),
  };
}

/**
 * Inspects parsed JSON input payloads for prototype-pollution keys,
 * NoSQL operator injection keys (`$where`, `$ne`, dotted paths),
 * excessive recursion depth, or unbounded array fan-out.
 */
export function hasUnsafeJsonPayload(value: unknown, depth = 0, maxDepth = 8): boolean {
  if (depth > maxDepth) return true;
  if (value === null || value === undefined) return false;
  if (typeof value !== 'object') return false;

  if (Array.isArray(value)) {
    if (value.length > 200) return true;
    return value.some((item) => hasUnsafeJsonPayload(item, depth + 1, maxDepth));
  }

  for (const key of Object.keys(value as Record<string, unknown>)) {
    if (FORBIDDEN_OBJECT_KEYS.has(key) || key.startsWith('$') || key.includes('.')) {
      return true;
    }
    const propVal = (value as Record<string, unknown>)[key];
    if (hasUnsafeJsonPayload(propVal, depth + 1, maxDepth)) {
      return true;
    }
  }

  return false;
}

export const projectInquirySchema = z.object({
  fullName: z
    .string()
    .trim()
    .min(2, 'Please enter your full name.')
    .max(120, 'Full name must be under 120 characters.'),
  businessEmail: z
    .string()
    .trim()
    .email('Please enter a valid business email address.')
    .max(160),
  companyName: z
    .string()
    .trim()
    .min(2, 'Please enter your company or organisation name.')
    .max(140),
  phone: z
    .string()
    .trim()
    .min(7, 'Please enter a valid telephone number.')
    .max(30)
    .regex(/^[+0-9()\s-]+$/, 'Telephone number contains invalid characters.'),
  industry: z
    .string()
    .trim()
    .min(2, 'Please select or enter an industry.')
    .max(100),
  requiredServices: z
    .array(z.string().trim().min(2).max(120))
    .min(1, 'Please select at least one required service.')
    .max(20),
  estimatedBudget: z
    .string()
    .trim()
    .min(2, 'Please select an estimated budget range.')
    .max(80),
  projectTimeline: z
    .string()
    .trim()
    .min(2, 'Please select a project timeline.')
    .max(80),
  projectDescription: z
    .string()
    .trim()
    .min(10, 'Please share at least 10 characters describing your brief.')
    .max(3000),
  consentAccepted: z.literal(true, {
    message: 'You must consent to our Privacy Policy before submitting.',
  }),
  websiteHoneypot: z.string().max(0).optional(),
});

export type ProjectInquiryInput = z.infer<typeof projectInquirySchema>;

export const newsletterSchema = z.object({
  email: z
    .string()
    .trim()
    .email('Please enter a valid email address.')
    .max(160),
  consentAccepted: z.literal(true, {
    message: 'Explicit consent is required under the Kenya Data Protection Act, 2019.',
  }),
  websiteHoneypot: z.string().max(0).optional(),
});

export type NewsletterInput = z.infer<typeof newsletterSchema>;

export async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateInquiryReference(): string {
  const year = new Date().getFullYear();
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  const suffix = Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join('');
  return `EMA-${year}-${suffix}`;
}
