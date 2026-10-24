import nodemailer, { type Transporter } from "nodemailer";

import { config } from "./config";
import { query } from "./db";
import { AuditLogsRepository } from "./repositories";
import type { ComplaintRecord } from "./complaints";
import { logger } from "./utils/logger";

/**
 * Outbound delivery for takedown notices.
 *
 * Historically the platform generated a notice, stored it, and then flipped its
 * status to "sent" without contacting anybody. This service performs a real
 * delivery and refuses to report success otherwise.
 *
 * Transport priority:
 *   1. SMTP (SMTP_HOST / SMTP_USER / SMTP_PASS / COMPLAINT_FROM_EMAIL)
 *   2. HTTP relay (COMPLAINT_WEBHOOK_URL)
 *
 * When neither is configured the result is `not_configured` and the complaint
 * stays in `generated` state, so the UI can say "ready to send, delivery not
 * configured" instead of lying about a submission.
 */

export type DeliveryStatus = "sent" | "failed" | "not_configured";

export interface DeliveryResult {
  status: DeliveryStatus;
  transport: "smtp" | "webhook" | "none";
  deliveredAt: string | null;
  detail: string;
  providerMessageId: string | null;
  attempts: Array<{ transport: string; ok: boolean; detail: string; durationMs: number }>;
}

let cachedTransporter: Transporter | null = null;

function smtpConfigured(): boolean {
  return Boolean(config.SMTP_HOST && config.COMPLAINT_FROM_EMAIL);
}

function webhookConfigured(): boolean {
  return Boolean(config.COMPLAINT_WEBHOOK_URL);
}

function getTransporter(): Transporter {
  if (cachedTransporter) return cachedTransporter;

  cachedTransporter = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    secure: Boolean(config.SMTP_SECURE),
    ...(config.SMTP_USER
      ? { auth: { user: config.SMTP_USER, pass: config.SMTP_PASS } }
      : {}),
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 30_000,
  });

  return cachedTransporter;
}

/** Exposed for tests: clears the memoised SMTP transport. */
export function resetTransporterCache(): void {
  cachedTransporter = null;
}

async function sendViaSmtp(complaint: ComplaintRecord): Promise<DeliveryResult> {
  const startedAt = Date.now();
  const transporter = getTransporter();

  const info = await transporter.sendMail({
    from: `"${config.COMPLAINT_FROM_NAME}" <${config.COMPLAINT_FROM_EMAIL}>`,
    to: complaint.recipient_email,
    subject: complaint.subject,
    text: complaint.body_text,
    headers: {
      "X-Find-Out-Complaint-Id": complaint.id,
      "X-Find-Out-Complaint-Type": complaint.complaint_type,
    },
  });

  return {
    status: "sent",
    transport: "smtp",
    deliveredAt: new Date().toISOString(),
    detail: `SMTP accepted the message for ${complaint.recipient_email}.`,
    providerMessageId: typeof info.messageId === "string" ? info.messageId : null,
    attempts: [
      {
        transport: "smtp",
        ok: true,
        detail: `accepted by ${config.SMTP_HOST}:${config.SMTP_PORT}`,
        durationMs: Date.now() - startedAt,
      },
    ],
  };
}

async function sendViaWebhook(complaint: ComplaintRecord): Promise<DeliveryResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  const startedAt = Date.now();

  try {
    const response = await fetch(config.COMPLAINT_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(config.COMPLAINT_WEBHOOK_TOKEN
          ? { Authorization: `Bearer ${config.COMPLAINT_WEBHOOK_TOKEN}` }
          : {}),
      },
      body: JSON.stringify({
        complaintId: complaint.id,
        investigationId: complaint.investigation_id,
        brandId: complaint.brand_id,
        type: complaint.complaint_type,
        recipient: complaint.recipient_email,
        targetUrl: complaint.target_url,
        subject: complaint.subject,
        body: complaint.body_text,
        metadata: complaint.metadata,
      }),
      signal: controller.signal,
    });

    const text = (await response.text()).slice(0, 500);

    if (!response.ok) {
      return {
        status: "failed",
        transport: "webhook",
        deliveredAt: null,
        detail: `The delivery relay answered HTTP ${response.status}: ${text}`,
        providerMessageId: null,
        attempts: [
          {
            transport: "webhook",
            ok: false,
            detail: `HTTP ${response.status}`,
            durationMs: Date.now() - startedAt,
          },
        ],
      };
    }

    let messageId: string | null = null;
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (typeof parsed.messageId === "string") messageId = parsed.messageId;
    } catch {
      // A plain-text 2xx is still a successful hand-off.
    }

    return {
      status: "sent",
      transport: "webhook",
      deliveredAt: new Date().toISOString(),
      detail: "The delivery relay accepted the notice.",
      providerMessageId: messageId,
      attempts: [
        {
          transport: "webhook",
          ok: true,
          detail: `HTTP ${response.status}`,
          durationMs: Date.now() - startedAt,
        },
      ],
    };
  } finally {
    clearTimeout(timer);
  }
}

export class ComplaintDispatchService {
  get configured(): boolean {
    return smtpConfigured() || webhookConfigured();
  }

  get transport(): "smtp" | "webhook" | "none" {
    if (smtpConfigured()) return "smtp";
    if (webhookConfigured()) return "webhook";
    return "none";
  }

  status(): { configured: boolean; transport: string; detail: string } {
    if (!this.configured) {
      return {
        configured: false,
        transport: "none",
        detail:
          "No outbound transport is configured. Set SMTP_HOST + COMPLAINT_FROM_EMAIL (and SMTP_USER/SMTP_PASS) or COMPLAINT_WEBHOOK_URL so notices can actually be submitted.",
      };
    }
    if (smtpConfigured()) {
      return {
        configured: true,
        transport: "smtp",
        detail: `Notices are delivered through ${config.SMTP_HOST}:${config.SMTP_PORT} as ${config.COMPLAINT_FROM_EMAIL}.`,
      };
    }
    return {
      configured: true,
      transport: "webhook",
      detail: "Notices are delivered through the configured HTTP relay.",
    };
  }

  async deliver(complaintId: string): Promise<{ complaint: ComplaintRecord | null; result: DeliveryResult }> {
    const found = await query<ComplaintRecord>(`SELECT * FROM complaints WHERE id = $1::uuid;`, [complaintId]);
    const complaint = found.rows[0];

    if (!complaint) {
      return {
        complaint: null,
        result: {
          status: "failed",
          transport: "none",
          deliveredAt: null,
          detail: "Complaint not found.",
          providerMessageId: null,
          attempts: [],
        },
      };
    }

    if (complaint.status === "sent" || complaint.status === "accepted") {
      return {
        complaint,
        result: {
          status: "sent",
          transport: "none",
          deliveredAt: complaint.sent_at,
          detail: "This notice has already been submitted.",
          providerMessageId: null,
          attempts: [],
        },
      };
    }

    if (!this.configured) {
      const result: DeliveryResult = {
        status: "not_configured",
        transport: "none",
        deliveredAt: null,
        detail: this.status().detail,
        providerMessageId: null,
        attempts: [],
      };

      await this.recordAttempt(complaint, result);
      return { complaint, result };
    }

    let result: DeliveryResult;

    try {
      result = smtpConfigured() ? await sendViaSmtp(complaint) : await sendViaWebhook(complaint);
    } catch (error) {
      result = {
        status: "failed",
        transport: smtpConfigured() ? "smtp" : "webhook",
        deliveredAt: null,
        detail: error instanceof Error ? error.message : "Delivery failed.",
        providerMessageId: null,
        attempts: [
          {
            transport: smtpConfigured() ? "smtp" : "webhook",
            ok: false,
            detail: error instanceof Error ? error.message : "unknown error",
            durationMs: 0,
          },
        ],
      };
    }

    const updated = await this.recordAttempt(complaint, result);
    return { complaint: updated, result };
  }

  /**
   * Records the delivery outcome on the complaint. A complaint only reaches
   * `sent` once a transport confirmed the hand-off.
   */
  private async recordAttempt(
    complaint: ComplaintRecord,
    result: DeliveryResult,
  ): Promise<ComplaintRecord> {
    const metadata = {
      ...(complaint.metadata ?? {}),
      delivery: {
        status: result.status,
        transport: result.transport,
        detail: result.detail,
        providerMessageId: result.providerMessageId,
        attemptedAt: new Date().toISOString(),
        deliveredAt: result.deliveredAt,
        attempts: result.attempts,
      },
    };

    const updated = await query<ComplaintRecord>(
      `UPDATE complaints
       SET status = $2::text,
           submission_status = CASE WHEN $2::text = 'sent' THEN 'SUBMITTED' ELSE submission_status END,
           sent_at = CASE WHEN $2::text = 'sent' THEN NOW() ELSE sent_at END,
           metadata = $3::jsonb,
           updated_at = NOW()
       WHERE id = $1::uuid
       RETURNING *;`,
      [complaint.id, result.status === "sent" ? "sent" : "generated", JSON.stringify(metadata)],
    );

    const row = updated.rows[0];
    if (!row) {
      throw new Error(`Complaint ${complaint.id} disappeared during delivery.`);
    }

    try {
      await AuditLogsRepository.recordLog({
        investigation_id: complaint.investigation_id ?? null,
        source: `complaint:${result.transport}`,
        status: result.status === "sent" ? "DELIVERED" : "FAILED",
        latency_ms: result.attempts[0]?.durationMs ?? 0,
        error_message:
          result.status === "sent"
            ? null
            : `${result.detail} (recipient ${complaint.recipient_email})`,
      });
    } catch (error) {
      logger.warn("[complaints] Could not write the delivery audit log", {
        complaintId: complaint.id,
        error: error instanceof Error ? error.message : "unknown",
      });
    }

    logger.info("[complaints] Delivery attempt recorded", {
      complaintId: complaint.id,
      status: result.status,
      transport: result.transport,
    });

    return row;
  }
}

export const complaintDispatchService = new ComplaintDispatchService();
export default complaintDispatchService;
