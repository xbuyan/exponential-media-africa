import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateInquiryReference,
  hasUnsafeJsonPayload,
  isSafeExternalHttpUrl,
  isSafeHttpOrLocalUrl,
  isValidDocId,
  newsletterSchema,
  projectInquirySchema,
  sanitizeImpactMetric,
  sanitizeMailtoHref,
  sanitizeMultilineText,
  sanitizePlainText,
  sanitizeSiteSettings,
  sanitizeSlug,
  sanitizeTelHref,
  sanitizeTestimonialRecord,
  sha256Hex,
} from './validation.ts';
import { DEFAULT_SITE_SETTINGS } from '../data/seedData.ts';

test('sanitizePlainText strips HTML tags multi-pass, bidi/control chars, and trims whitespace', () => {
  assert.equal(sanitizePlainText('  <script>alert(1)</script>Hello\u0007 World  '), 'alert(1)Hello World');
  assert.equal(sanitizePlainText('<<script>script>alert(1)</</script>script>'), 'alert(1)');
  assert.equal(sanitizePlainText('<b>Bold</b>\n\tCopy\u202E'), 'Bold  Copy');
  assert.equal(sanitizePlainText('   Plain text   '), 'Plain text');
});

test('sanitizeMultilineText preserves paragraph breaks while stripping tags and bidi characters', () => {
  const input = '## Heading\r\n\r\n<img src=x onerror=alert(1)>Paragraph\u200B\n- Item 1\u202E';
  assert.equal(sanitizeMultilineText(input), '## Heading\n\nParagraph\n- Item 1');
});

test('sanitizeTelHref and isValidDocId validate structured identifiers safely', () => {
  assert.equal(sanitizeTelHref('+254 712 345 678'), 'tel:+254712345678');
  assert.equal(sanitizeTelHref('javascript:alert(1)'), '#');
  assert.equal(isValidDocId('user_123-ABC'), true);
  assert.equal(isValidDocId('../admin'), false);
  assert.equal(isValidDocId('id with space'), false);
  assert.equal(isValidDocId(''), false);
});

test('sanitizeSlug normalizes case, punctuation, and leading/trailing hyphens', () => {
  assert.equal(
    sanitizeSlug('  Cinnamon Energies — Brand Identity 2026! '),
    'cinnamon-energies-brand-identity-2026'
  );
  assert.equal(sanitizeSlug('---Hello---World---'), 'hello-world');
  assert.ok(sanitizeSlug('a'.repeat(200)).length <= 120);
});

test('isSafeHttpOrLocalUrl and isSafeExternalHttpUrl enforce safe schemes and block smuggling', () => {
  assert.equal(isSafeHttpOrLocalUrl(''), true);
  assert.equal(isSafeHttpOrLocalUrl('/assets/profile/work/pepsi.jpg'), true);
  assert.equal(isSafeHttpOrLocalUrl('https://exponentialmedia.africa/work'), true);
  assert.equal(isSafeHttpOrLocalUrl('http://localhost:3000'), true);
  assert.equal(isSafeHttpOrLocalUrl('//evil.example.com/phish'), false);
  assert.equal(isSafeHttpOrLocalUrl('/\\evil.example.com'), false);
  assert.equal(isSafeHttpOrLocalUrl('https://example.com/\nheader'), false);
  assert.equal(isSafeHttpOrLocalUrl('javascript:alert(1)'), false);
  assert.equal(isSafeHttpOrLocalUrl('data:text/html,<script>'), false);
  assert.equal(isSafeHttpOrLocalUrl('not a url'), false);

  assert.equal(isSafeExternalHttpUrl('https://instagram.com/exponentialmedia'), true);
  assert.equal(isSafeExternalHttpUrl('/assets/local.png'), false);
  assert.equal(isSafeExternalHttpUrl('javascript:alert(1)'), false);
});

test('hasUnsafeJsonPayload blocks prototype pollution, NoSQL operators, dotted keys, and excessive nesting', () => {
  assert.equal(hasUnsafeJsonPayload({ name: 'Amina', services: ['Media Buying'] }), false);
  assert.equal(hasUnsafeJsonPayload(JSON.parse('{"__proto__":{"admin":true}}')), true);
  assert.equal(hasUnsafeJsonPayload({ constructor: { prototype: {} } }), true);
  assert.equal(hasUnsafeJsonPayload({ email: { $ne: '' } }), true);
  assert.equal(hasUnsafeJsonPayload({ 'user.role': 'admin' }), true);

  let deep: Record<string, unknown> = { ok: true };
  for (let i = 0; i < 12; i += 1) {
    deep = { nested: deep };
  }
  assert.equal(hasUnsafeJsonPayload(deep), true);
});

test('projectInquirySchema validates complete inquiries and rejects honeypot/invalid payloads', () => {
  const validPayload = {
    fullName: 'Amina Wanjiku',
    businessEmail: 'amina@brand.co.ke',
    companyName: 'Savanna Retail Ltd',
    phone: '+254 712 345 678',
    industry: 'Retail & Consumer Goods',
    requiredServices: ['Social Media Management', 'Brand Activation'],
    estimatedBudget: 'KES 500,000 - KES 1,000,000',
    projectTimeline: '1 - 3 Months',
    projectDescription: 'Regional product launch across five Nairobi shopping malls with creator coverage.',
    consentAccepted: true,
    websiteHoneypot: '',
  };

  const ok = projectInquirySchema.safeParse(validPayload);
  assert.equal(ok.success, true);

  const missingServices = projectInquirySchema.safeParse({
    ...validPayload,
    requiredServices: [],
  });
  assert.equal(missingServices.success, false);

  const badEmail = projectInquirySchema.safeParse({
    ...validPayload,
    businessEmail: 'not-an-email',
  });
  assert.equal(badEmail.success, false);

  const badPhone = projectInquirySchema.safeParse({
    ...validPayload,
    phone: 'call-me-abc',
  });
  assert.equal(badPhone.success, false);

  const botTriggered = projectInquirySchema.safeParse({
    ...validPayload,
    websiteHoneypot: 'https://spam.example',
  });
  assert.equal(botTriggered.success, false);

  const noConsent = projectInquirySchema.safeParse({
    ...validPayload,
    consentAccepted: false,
  });
  assert.equal(noConsent.success, false);
});

test('newsletterSchema enforces email format, KDPA consent, and empty honeypot', () => {
  assert.equal(
    newsletterSchema.safeParse({
      email: 'marketing@company.co.ke',
      consentAccepted: true,
      websiteHoneypot: '',
    }).success,
    true
  );

  assert.equal(
    newsletterSchema.safeParse({
      email: 'bad-email',
      consentAccepted: true,
    }).success,
    false
  );

  assert.equal(
    newsletterSchema.safeParse({
      email: 'marketing@company.co.ke',
      consentAccepted: false,
    }).success,
    false
  );
});

test('sha256Hex produces consistent case-insensitive lowercase 64-char hex digests', async () => {
  const hashA = await sha256Hex('  Info@ExponentialMedia.Africa ');
  const hashB = await sha256Hex('info@exponentialmedia.africa');
  assert.equal(hashA, hashB);
  assert.match(hashA, /^[a-f0-9]{64}$/);
});

test('generateInquiryReference produces formatted EMA-YYYY-XXXXXX references', () => {
  const year = new Date().getFullYear();
  const ref = generateInquiryReference();
  assert.match(ref, new RegExp(`^EMA-${year}-[A-Z0-9]{6}$`));
});

test('sanitizeMailtoHref prevents header/query injection and rejects malformed addresses', () => {
  assert.equal(sanitizeMailtoHref('  Info@ExponentialMedia.Africa  '), 'mailto:info@exponentialmedia.africa');
  assert.equal(sanitizeMailtoHref('info@exponentialmedia.africa?bcc=evil@example.com'), '#');
  assert.equal(sanitizeMailtoHref('javascript:alert(1)'), '#');
  assert.equal(sanitizeMailtoHref('not an email'), '#');
});

test('sanitizeSiteSettings and sanitizeImpactMetric strip HTML tags, unsafe URLs, and invalid contacts', () => {
  const metric = sanitizeImpactMetric(
    { label: '<img src=x>Brands Served\u202E', value: '<b>50+</b>' },
    DEFAULT_SITE_SETTINGS.impactMetrics.brandsServed
  );
  assert.equal(metric.label, 'Brands Served');
  assert.equal(metric.value, '50+');

  const cleaned = sanitizeSiteSettings(
    {
      companyName: '<script>x</script>Exponential Marketing Agency',
      email: 'bad@email?bcc=attacker@evil.com',
      primaryPhone: 'javascript:alert(1)',
      secondaryPhone: '+254 728 232 723',
      headquartersAddress: '<b>A3-10 Casamia</b>, Kilimani',
      campusAddress: 'Should stay cleared',
      socialLinks: {
        instagram: 'javascript:alert(1)',
        linkedin: 'https://www.linkedin.com/company/exponentialmediaagency/',
        youtube: '/relative-not-allowed',
        x: 'https://x.com/exponentialke',
      },
      impactMetrics: {
        ...DEFAULT_SITE_SETTINGS.impactMetrics,
        brandsServed: {
          ...DEFAULT_SITE_SETTINGS.impactMetrics.brandsServed,
          label: '<b>Active Brands</b>',
          value: '<i>27+</i>',
        },
      },
    },
    DEFAULT_SITE_SETTINGS
  );

  assert.equal(cleaned.email, DEFAULT_SITE_SETTINGS.email);
  assert.equal(cleaned.primaryPhone, DEFAULT_SITE_SETTINGS.primaryPhone);
  assert.equal(cleaned.campusAddress, '');
  assert.equal(cleaned.headquartersAddress, 'A3-10 Casamia, Kilimani');
  assert.equal(cleaned.socialLinks.instagram, DEFAULT_SITE_SETTINGS.socialLinks.instagram);
  assert.equal(cleaned.socialLinks.youtube, '');
  assert.equal(cleaned.socialLinks.x, 'https://x.com/exponentialke');
  assert.equal(cleaned.impactMetrics.brandsServed.label, 'Active Brands');
  assert.equal(cleaned.impactMetrics.brandsServed.value, '27+');
});

test('sanitizeTestimonialRecord strips HTML and blocks unsafe videoUrl protocols', () => {
  const clean = sanitizeTestimonialRecord('t-1', {
    quote: '<script>alert(1)</script>Great regional campaign execution.',
    clientName: '<b>Jane Doe</b>',
    clientRole: 'Marketing Lead',
    companyName: 'Partner Co',
    videoUrl: 'javascript:alert(1)',
    isPlaceholder: false,
    status: 'published',
    isDeleted: false,
  });
  assert.equal(clean.clientName, 'Jane Doe');
  assert.equal(clean.videoUrl, undefined);

  const safeVideo = sanitizeTestimonialRecord('t-2', {
    quote: 'Trusted studio partner.',
    clientName: 'John',
    clientRole: 'Director',
    companyName: 'Brand Ltd',
    videoUrl: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    isPlaceholder: false,
    status: 'published',
    isDeleted: false,
  });
  assert.equal(safeVideo.videoUrl, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');
});

test('sanitizers keep text that merely contains < or > but is not markup', () => {
  assert.equal(sanitizePlainText('Budget <5000 KES, timeline 2 months'), 'Budget <5000 KES, timeline 2 months');
  assert.equal(sanitizePlainText('Between <5 and >3 options'), 'Between <5 and >3 options');
  assert.equal(sanitizePlainText('Reach is < 2M people'), 'Reach is < 2M people');
  assert.equal(sanitizeMultilineText('Line one <5\n\nLine two >3'), 'Line one <5\n\nLine two >3');
});

test('sanitizers still strip real markup and unterminated tag fragments', () => {
  assert.equal(sanitizePlainText('Hi <b>there</b>'), 'Hi there');
  assert.equal(sanitizePlainText('<img src=x onerror=alert(1)'), '');
  assert.equal(sanitizePlainText('a <!-- hidden --> b'), 'a  b');
  assert.equal(sanitizePlainText('<<script>script>alert(1)</</script>script>'), 'alert(1)');
});
