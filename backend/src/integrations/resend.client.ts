import { config } from "../config";
import { logger } from "../utils/logger";

/**
 * Resend transactional e-mail client (https://resend.com).
 *
 * Used by the Brand Guard module to notify an officially registered brand
 * when somebody attempts to register a confusingly similar profile.
 *
 * Design rules (same as the complaint transports):
 *   - With no RESEND_API_KEY configured the module reports "not_configured";
 *     it never pretends an e-mail was sent.
 *   - An alert is only marked "sent" after Resend actually accepted it
 *     (HTTP 2xx with a message id).
 */

export interface ResendSendRequest {
  to: string[];
  subject: string;
  html: string;
  text?: string;
  replyTo?: string;
}

export interface ResendSendResult {
  delivered: boolean;
  /** Resend message id (e.g. "re_123...") when delivered. */
  id: string | null;
  statusCode: number | null;
  error: string | null;
}

const RESEND_TIMEOUT_MS = 15_000;

export function isResendConfigured(): boolean {
  return Boolean(config.RESEND_API_KEY);
}

export function resendFromAddress(): string {
  const email = config.RESEND_FROM_EMAIL || "onboarding@resend.dev";
  const name = config.RESEND_FROM_NAME || "Find_out Brand Guard";
  return `${name} <${email}>`;
}

export async function sendResendEmail(
  request: ResendSendRequest,
): Promise<ResendSendResult> {
  if (!isResendConfigured()) {
    return {
      delivered: false,
      id: null,
      statusCode: null,
      error: "RESEND_API_KEY is not configured",
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RESEND_TIMEOUT_MS);

  try {
    const response = await fetch(config.RESEND_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: resendFromAddress(),
        to: request.to,
        subject: request.subject,
        html: request.html,
        ...(request.text ? { text: request.text } : {}),
        ...(request.replyTo ? { reply_to: request.replyTo } : {}),
      }),
      signal: controller.signal,
    });

    const raw = await response.text().catch(() => "");
    let payload: Record<string, unknown> = {};
    try {
      payload = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    } catch {
      payload = { message: raw.slice(0, 500) };
    }

    if (!response.ok) {
      const message =
        typeof payload.message === "string" && payload.message.trim()
          ? payload.message
          : `Resend API responded with HTTP ${response.status}`;
      logger.warn("[resend] E-mail rejected", {
        statusCode: response.status,
        error: message,
      });
      return {
        delivered: false,
        id: null,
        statusCode: response.status,
        error: message,
      };
    }

    const id = typeof payload.id === "string" ? payload.id : null;
    logger.info("[resend] E-mail accepted", { id });
    return { delivered: true, id, statusCode: response.status, error: null };
  } catch (error) {
    const message =
      error instanceof Error && error.name === "AbortError"
        ? `Resend API timed out after ${RESEND_TIMEOUT_MS / 1000}s`
        : error instanceof Error
          ? error.message
          : "Unknown Resend transport error";
    logger.error("[resend] E-mail delivery failed", { error: message });
    return { delivered: false, id: null, statusCode: null, error: message };
  } finally {
    clearTimeout(timeout);
  }
}

export default sendResendEmail;
