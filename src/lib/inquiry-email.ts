import { EMAIL_PATTERN, sanitizePlainText } from './validation.ts';

export const DEFAULT_INQUIRY_RECIPIENT = 'xtra8477@gmail.com';
export const DEFAULT_INQUIRY_FROM = 'Exponential Marketing Agency <onboarding@resend.dev>';
const RESEND_EMAILS_ENDPOINT = 'https://api.resend.com/emails';
const DEFAULT_TIMEOUT_MS = 8_000;

export interface InquiryEmailPayload {
  referenceCode: string;
  fullName: string;
  businessEmail: string;
  companyName: string;
  phone: string;
  industry: string;
  requiredServices: string[];
  estimatedBudget: string;
  projectTimeline: string;
  projectDescription: string;
}

export interface InquiryEmailResult {
  sent: boolean;
  skipped?: boolean;
  id?: string;
  status?: number;
  errorName?: string;
}

export interface SendInquiryEmailOptions {
  disabled?: boolean;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export function escapeHtml(value: string): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isValidEmailAddress(value: string): boolean {
  const cleaned = sanitizePlainText(value).toLowerCase();
  return cleaned.length > 0 && cleaned.length <= 160 && EMAIL_PATTERN.test(cleaned) && !/[?#&\s\\]/.test(cleaned);
}

function normalizeFromHeader(value: string): string {
  const raw = String(value ?? '')
    .replace(/[\r\n\t\u0000-\u001F\u007F-\u009F]/g, '')
    .trim();
  if (!raw || raw.length > 200) return DEFAULT_INQUIRY_FROM;
  if (isValidEmailAddress(raw)) {
    return sanitizePlainText(raw).toLowerCase();
  }
  const angleMatch = /^([^<>]{1,100})<([^<>\s]+)>$/.exec(raw);
  if (!angleMatch) return DEFAULT_INQUIRY_FROM;
  const displayName = sanitizePlainText(angleMatch[1]);
  const address = sanitizePlainText(angleMatch[2]).toLowerCase();
  if (!displayName || !isValidEmailAddress(address)) {
    return DEFAULT_INQUIRY_FROM;
  }
  return `${displayName} <${address}>`;
}

export function buildInquiryEmailContent(inquiry: InquiryEmailPayload): {
  subject: string;
  text: string;
  html: string;
} {
  const referenceCode = sanitizePlainText(inquiry.referenceCode);
  const fullName = sanitizePlainText(inquiry.fullName);
  const businessEmail = sanitizePlainText(inquiry.businessEmail).toLowerCase();
  const companyName = sanitizePlainText(inquiry.companyName);
  const phone = sanitizePlainText(inquiry.phone);
  const industry = sanitizePlainText(inquiry.industry);
  const requiredServices = inquiry.requiredServices
    .map((service) => sanitizePlainText(service))
    .filter(Boolean);
  const estimatedBudget = sanitizePlainText(inquiry.estimatedBudget);
  const projectTimeline = sanitizePlainText(inquiry.projectTimeline);
  const projectDescription = sanitizePlainText(inquiry.projectDescription);

  const subject = `New Project Inquiry (${referenceCode}) — ${companyName || fullName}`;

  const text = [
    'New Project Inquiry — Exponential Marketing Agency',
    '--------------------------------------------------',
    `Reference Code: ${referenceCode}`,
    `Full Name: ${fullName}`,
    `Business Email: ${businessEmail}`,
    `Company / Organisation: ${companyName}`,
    `Telephone Number: ${phone}`,
    `Industry: ${industry}`,
    `Estimated Budget: ${estimatedBudget}`,
    `Project Timeline: ${projectTimeline}`,
    `Required Services: ${requiredServices.join(', ')}`,
    '',
    'Project Description & Objectives:',
    projectDescription,
  ].join('\n');

  const rows: Array<[string, string]> = [
    ['Reference Code', referenceCode],
    ['Full Name', fullName],
    ['Business Email', businessEmail],
    ['Company / Organisation', companyName],
    ['Telephone Number', phone],
    ['Industry', industry],
    ['Estimated Budget', estimatedBudget],
    ['Project Timeline', projectTimeline],
    ['Required Services', requiredServices.join(', ')],
  ];

  const rowsHtml = rows
    .map(
      ([label, val]) =>
        `<tr>
          <td style="padding:10px 14px;border-bottom:1px solid #f0e4e4;font-weight:600;color:#5c3a3c;width:210px;vertical-align:top;">${escapeHtml(label)}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #f0e4e4;color:#1a0809;vertical-align:top;">${escapeHtml(val)}</td>
        </tr>`
    )
    .join('');

  const html = `<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background-color:#faf5f5;font-family:Arial,Helvetica,sans-serif;color:#1a0809;">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #f0dede;">
      <tr>
        <td style="background:#b81118;color:#ffffff;padding:22px 24px;">
          <div style="font-size:12px;letter-spacing:0.08em;text-transform:uppercase;opacity:0.9;">Exponential Marketing Agency</div>
          <h1 style="margin:6px 0 0;font-size:20px;line-height:1.3;">New Project Inquiry</h1>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 24px 8px;">
          <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;font-size:14px;">
            ${rowsHtml}
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:16px 24px 24px;">
          <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:#b81118;margin-bottom:8px;">
            Project Description &amp; Objectives
          </div>
          <div style="padding:14px;background:#faf5f5;border-radius:8px;font-size:14px;line-height:1.6;color:#1a0809;white-space:pre-wrap;">${escapeHtml(projectDescription)}</div>
        </td>
      </tr>
    </table>
  </body>
</html>`;

  return { subject, text, html };
}

export async function sendInquiryNotificationEmail(
  inquiry: InquiryEmailPayload,
  options: SendInquiryEmailOptions = {}
): Promise<InquiryEmailResult> {
  if (options.disabled) {
    return { sent: false, skipped: true };
  }

  const env = options.env ?? process.env;
  const isProduction = env.NODE_ENV === 'production';
  const apiKey = env.RESEND_API_KEY?.trim();
  if (!apiKey) {
    return { sent: false, skipped: true };
  }

  const configuredTo = env.INQUIRY_TO_EMAIL?.trim() || '';
  const toEmail = isValidEmailAddress(configuredTo)
    ? sanitizePlainText(configuredTo).toLowerCase()
    : isProduction
      ? ''
      : DEFAULT_INQUIRY_RECIPIENT;

  if (!toEmail) {
    return { sent: false, skipped: true };
  }

  const fromHeader = normalizeFromHeader(env.INQUIRY_FROM_EMAIL || '');

  const { subject, text, html } = buildInquiryEmailContent(inquiry);
  const replyTo = isValidEmailAddress(inquiry.businessEmail)
    ? sanitizePlainText(inquiry.businessEmail).toLowerCase()
    : undefined;

  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(RESEND_EMAILS_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromHeader,
        to: [toEmail],
        ...(replyTo ? { reply_to: replyTo } : {}),
        subject,
        text,
        html,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errPayload = (await response.json().catch(() => null)) as { name?: unknown } | null;
      const errorName =
        typeof errPayload?.name === 'string' && /^[a-z0-9_.-]{1,64}$/i.test(errPayload.name)
          ? errPayload.name
          : undefined;
      return { sent: false, status: response.status, ...(errorName ? { errorName } : {}) };
    }

    const payload = (await response.json().catch(() => null)) as { id?: unknown } | null;
    return {
      sent: true,
      id: typeof payload?.id === 'string' ? payload.id : undefined,
    };
  } catch {
    return { sent: false };
  } finally {
    clearTimeout(timer);
  }
}
