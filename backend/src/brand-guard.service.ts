import { query } from "./db";
import { config } from "./config";
import { logger } from "./utils/logger";
import {
  lookalikeDetectionService,
  normalizeComparableName,
  stripDeceptiveAffixes,
} from "./lookalike.service";
import {
  isResendConfigured,
  resendFromAddress,
  sendResendEmail,
} from "./integrations/resend.client";

/**
 * Brand Guard — protects officially registered brands at registration time.
 *
 * When a new brand profile is submitted, this service compares the submitted
 * name/domain against every active registered brand. A confusingly similar
 * submission produces a conflict list that the frontend shows as a pop-up.
 * The pop-up's "Notify official brand" button calls sendImpersonationAlert,
 * which e-mails the official brand's registered contact through Resend and
 * records an auditable alert row.
 */

export class BrandGuardError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "BrandGuardError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type BrandGuardMatchType = "name" | "alternate_name" | "domain";
export type BrandGuardVerdict = "exact" | "impersonation" | "lookalike";

export interface BrandGuardConflict {
  brandId: string;
  brandName: string;
  primaryDomain: string;
  website: string | null;
  logoUrl: string | null;
  /** True when the official brand has a contact e-mail an alert can go to. */
  canNotify: boolean;
  matchType: BrandGuardMatchType;
  /** The official value the submission collided with. */
  matchedValue: string;
  similarity: number;
  verdict: BrandGuardVerdict;
  summary: string;
}

export interface BrandGuardCheckInput {
  name: string;
  domain?: string | null;
  /** Skip this brand id (used when an existing profile is being updated). */
  excludeBrandId?: string | null;
}

export interface BrandGuardCheckResult {
  evaluated: boolean;
  conflict: boolean;
  threshold: number;
  suspectName: string;
  suspectDomain: string | null;
  conflicts: BrandGuardConflict[];
}

export interface ImpersonationAlertInput {
  brandId: string;
  suspectName: string;
  suspectDomain?: string | null;
  suspectWebsite?: string | null;
  matchType?: BrandGuardMatchType;
  similarity?: number | null;
  verdict?: BrandGuardVerdict;
  reporterNote?: string | null;
}

export interface ImpersonationAlertRecord {
  id: string;
  brand_id: string;
  suspect_name: string;
  suspect_domain: string | null;
  suspect_website: string | null;
  match_type: string;
  similarity: string | number | null;
  verdict: string;
  recipient_email: string;
  subject: string;
  status: "pending" | "sent" | "failed" | "not_configured";
  provider: string;
  provider_message_id: string | null;
  error_detail: string | null;
  reporter_note: string | null;
  created_at: string;
}

interface GuardBrandRow {
  id: string;
  name: string;
  primary_domain: string;
  website: string | null;
  logo_url: string | null;
  contact_email: string | null;
  alternate_names: string[] | null;
  associated_domains: string[] | null;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function isValidAlertEmail(value: string): boolean {
  return value.length <= 320 && EMAIL_PATTERN.test(value);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function verdictFor(similarity: number, exact: boolean): BrandGuardVerdict {
  if (exact || similarity >= 0.999) return "exact";
  if (similarity >= 0.88) return "impersonation";
  return "lookalike";
}

function domainLabel(value: string): string {
  return lookalikeDetectionService.extractDomainLabel(value);
}

export class BrandGuardService {
  /**
   * Compares a submitted brand name/domain against all active registered
   * brands and returns every confusing collision at or above the threshold.
   */
  async findConflicts(input: BrandGuardCheckInput): Promise<BrandGuardCheckResult> {
    const threshold = config.BRAND_GUARD_SIMILARITY_THRESHOLD;
    const suspectName = (input.name ?? "").trim();
    const suspectDomain = input.domain?.trim() ? input.domain.trim().toLowerCase() : null;

    if (!suspectName) {
      return {
        evaluated: false,
        conflict: false,
        threshold,
        suspectName,
        suspectDomain,
        conflicts: [],
      };
    }

    const result = await query<GuardBrandRow>(
      `SELECT id, name, primary_domain, website, logo_url, contact_email,
              alternate_names, associated_domains
         FROM brands
        WHERE status = 'active'
        ORDER BY created_at ASC;`,
    );

    const conflicts: BrandGuardConflict[] = [];

    for (const brand of result.rows) {
      if (input.excludeBrandId && brand.id === input.excludeBrandId) continue;

      let best: {
        matchType: BrandGuardMatchType;
        matchedValue: string;
        similarity: number;
        exact: boolean;
      } | null = null;

      const consider = (
        matchType: BrandGuardMatchType,
        matchedValue: string,
        similarity: number,
        exact: boolean,
      ) => {
        if (similarity < threshold) return;
        if (!best || similarity > best.similarity) {
          best = { matchType, matchedValue, similarity, exact };
        }
      };

      // --- 1. Submitted name vs official name and alternates ---------------
      const normalizedSuspect = normalizeComparableName(suspectName);
      const strippedSuspect = stripDeceptiveAffixes(suspectName, brand.name);

      const officialNames: Array<{ value: string; type: BrandGuardMatchType }> = [
        { value: brand.name, type: "name" },
        ...(brand.alternate_names ?? [])
          .filter(Boolean)
          .map((value) => ({ value, type: "alternate_name" as BrandGuardMatchType })),
      ];

      for (const official of officialNames) {
        const normalizedOfficial = normalizeComparableName(official.value);
        if (!normalizedOfficial) continue;

        const direct = lookalikeDetectionService.similarityRatio(
          suspectName,
          official.value,
        );
        // "NexusPay Login" / "NexusPay Official" style padding.
        const stripped = lookalikeDetectionService.similarityRatio(
          stripDeceptiveAffixes(suspectName, official.value),
          official.value,
        );
        // Containment: "NexusPay Secure Wallet" fully contains the brand.
        const contains =
          normalizedOfficial.length >= 4 &&
          normalizedSuspect.includes(normalizedOfficial);

        const similarity = Math.max(direct, stripped, contains ? 0.9 : 0);
        consider(
          official.type,
          official.value,
          similarity,
          normalizedSuspect === normalizedOfficial ||
            strippedSuspect === normalizedOfficial,
        );
      }

      // --- 2. Submitted domain vs official domains --------------------------
      if (suspectDomain) {
        const officialDomains = [
          brand.primary_domain,
          ...(brand.associated_domains ?? []),
        ].filter(Boolean);

        for (const official of officialDomains) {
          const normalizedOfficial = official.toLowerCase().replace(/^www\./, "");
          const normalizedSuspectDomain = suspectDomain.replace(/^www\./, "");

          if (normalizedSuspectDomain === normalizedOfficial) {
            consider("domain", official, 1, true);
            continue;
          }

          const evaluation = lookalikeDetectionService.evaluateLookalike(
            suspectDomain,
            domainLabel(official) || brand.name,
          );
          const labelSimilarity = lookalikeDetectionService.similarityRatio(
            domainLabel(suspectDomain),
            domainLabel(official),
          );
          const similarity = Math.max(
            evaluation.isLookalike ? Math.max(evaluation.similarityRatio, threshold) : 0,
            labelSimilarity,
          );
          consider("domain", official, similarity, false);
        }

        // Domain that spoofs the brand *name* ("nexusp4y-login.top").
        const nameEvaluation = lookalikeDetectionService.evaluateLookalike(
          suspectDomain,
          brand.name,
        );
        if (nameEvaluation.isLookalike) {
          consider(
            "domain",
            brand.primary_domain,
            Math.max(nameEvaluation.similarityRatio, threshold),
            false,
          );
        }
      }

      if (best) {
        const matched: {
          matchType: BrandGuardMatchType;
          matchedValue: string;
          similarity: number;
          exact: boolean;
        } = best;
        const similarity = Number(Math.min(1, matched.similarity).toFixed(3));
        const verdict = verdictFor(similarity, matched.exact);
        conflicts.push({
          brandId: brand.id,
          brandName: brand.name,
          primaryDomain: brand.primary_domain,
          website: brand.website,
          logoUrl: brand.logo_url,
          canNotify: Boolean(
            brand.contact_email && isValidAlertEmail(brand.contact_email),
          ),
          matchType: matched.matchType,
          matchedValue: matched.matchedValue,
          similarity,
          verdict,
          summary:
            verdict === "exact"
              ? `"${suspectName}" matches the registered brand "${brand.name}" exactly.`
              : `"${suspectName}" is ${(similarity * 100).toFixed(1)}% similar to the registered ${
                  matched.matchType === "domain" ? "domain" : "brand"
                } "${matched.matchedValue}" of ${brand.name}.`,
        });
      }
    }

    conflicts.sort((a, b) => b.similarity - a.similarity);

    if (conflicts.length > 0) {
      logger.warn("[brand-guard] Registration conflicts detected", {
        suspectName,
        suspectDomain,
        conflicts: conflicts.length,
        top: conflicts[0]?.brandName,
      });
    }

    return {
      evaluated: true,
      conflict: conflicts.length > 0,
      threshold,
      suspectName,
      suspectDomain,
      conflicts,
    };
  }

  /**
   * E-mails the officially registered brand (via Resend) that somebody tried
   * to register a confusingly similar profile, and records an audit row.
   * The row is only marked "sent" after Resend accepted the message.
   */
  async sendImpersonationAlert(
    input: ImpersonationAlertInput,
  ): Promise<ImpersonationAlertRecord> {
    const suspectName = (input.suspectName ?? "").trim();
    if (!suspectName) {
      throw new BrandGuardError(400, "MISSING_SUSPECT_NAME", "Provide the suspicious brand name that was submitted.");
    }
    if (suspectName.length > 200) {
      throw new BrandGuardError(400, "SUSPECT_NAME_TOO_LONG", "The suspicious brand name is limited to 200 characters.");
    }

    const brandResult = await query<GuardBrandRow & { status: string }>(
      `SELECT id, name, primary_domain, website, logo_url, contact_email,
              alternate_names, associated_domains, status
         FROM brands
        WHERE id = $1;`,
      [input.brandId],
    );
    const brand = brandResult.rows[0];
    if (!brand) {
      throw new BrandGuardError(404, "BRAND_NOT_FOUND", "The official brand to notify was not found.");
    }
    if (!brand.contact_email || !isValidAlertEmail(brand.contact_email)) {
      throw new BrandGuardError(
        409,
        "NO_CONTACT_EMAIL",
        `"${brand.name}" has no registered contact e-mail. Edit the brand profile and add one before sending alerts.`,
      );
    }

    const suspectDomain = input.suspectDomain?.trim() || null;
    const suspectWebsite = input.suspectWebsite?.trim() || null;
    const matchType: BrandGuardMatchType = input.matchType ?? "name";
    const similarity =
      typeof input.similarity === "number" && Number.isFinite(input.similarity)
        ? Number(Math.min(1, Math.max(0, input.similarity)).toFixed(3))
        : null;
    const verdict: BrandGuardVerdict = input.verdict ?? "lookalike";
    const reporterNote = input.reporterNote?.trim()
      ? input.reporterNote.trim().slice(0, 1000)
      : null;

    const subject = `[Find_out] Impersonation attempt detected against ${brand.name}`;
    const detectedAt = new Date().toISOString();
    const similarityText = similarity !== null ? `${(similarity * 100).toFixed(1)}%` : "n/a";

    const text = [
      `Impersonation alert for ${brand.name}`,
      ``,
      `Somebody attempted to register a brand profile on the Find_out`,
      `Digital Risk Protection platform that is confusingly similar to your`,
      `officially registered brand.`,
      ``,
      `  Official brand   : ${brand.name} (${brand.primary_domain})`,
      `  Attempted name   : ${suspectName}`,
      `  Attempted domain : ${suspectDomain ?? "not provided"}`,
      `  Attempted website: ${suspectWebsite ?? "not provided"}`,
      `  Match type       : ${matchType}`,
      `  Similarity       : ${similarityText}`,
      `  Verdict          : ${verdict}`,
      `  Detected at      : ${detectedAt}`,
      reporterNote ? `  Analyst note     : ${reporterNote}` : null,
      ``,
      `Recommended next steps:`,
      `  1. Verify that this registration attempt did not come from your own team.`,
      `  2. Review the attempted name/domain for trademark or phishing abuse.`,
      `  3. Use your Find_out dashboard to open an investigation and, if`,
      `     needed, dispatch a takedown complaint.`,
      ``,
      `This alert was generated by the Find_out Brand Guard module.`,
    ]
      .filter((line): line is string => line !== null)
      .join("\n");

    const html = `
      <div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:0 auto;color:#0f172a">
        <div style="background:#0f172a;border-radius:12px 12px 0 0;padding:20px 28px">
          <h1 style="margin:0;font-size:18px;color:#f8fafc">&#128737; Find_out Brand Guard</h1>
          <p style="margin:6px 0 0;font-size:13px;color:#94a3b8">Impersonation attempt detected against your registered brand</p>
        </div>
        <div style="border:1px solid #e2e8f0;border-top:0;border-radius:0 0 12px 12px;padding:24px 28px">
          <p style="font-size:14px;line-height:1.6">
            Somebody attempted to register a brand profile on the
            <strong>Find_out Digital Risk Protection platform</strong> that is
            confusingly similar to your officially registered brand
            <strong>${escapeHtml(brand.name)}</strong>.
          </p>
          <table style="width:100%;border-collapse:collapse;font-size:13px;margin:16px 0">
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0;width:40%"><strong>Official brand</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(brand.name)} (${escapeHtml(brand.primary_domain)})</td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Attempted name</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0;color:#b91c1c"><strong>${escapeHtml(suspectName)}</strong></td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Attempted domain</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(suspectDomain ?? "not provided")}</td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Match type</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(matchType)}</td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Similarity</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(similarityText)}</td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Verdict</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(verdict)}</td></tr>
            <tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Detected at</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(detectedAt)}</td></tr>
            ${reporterNote ? `<tr><td style="padding:7px 10px;background:#f8fafc;border:1px solid #e2e8f0"><strong>Analyst note</strong></td><td style="padding:7px 10px;border:1px solid #e2e8f0">${escapeHtml(reporterNote)}</td></tr>` : ""}
          </table>
          <p style="font-size:13px;line-height:1.7;margin:16px 0 4px"><strong>Recommended next steps</strong></p>
          <ol style="font-size:13px;line-height:1.8;margin:0;padding-left:20px">
            <li>Verify this registration attempt did not come from your own team.</li>
            <li>Review the attempted name/domain for trademark or phishing abuse.</li>
            <li>Open an investigation in your Find_out dashboard and, if needed, dispatch a takedown complaint.</li>
          </ol>
          <p style="font-size:11px;color:#94a3b8;margin-top:22px">
            This alert was generated automatically by the Find_out Brand Guard module
            and sent from ${escapeHtml(resendFromAddress())}.
          </p>
        </div>
      </div>`;

    // Transport not configured: record the attempt honestly and surface 503.
    if (!isResendConfigured()) {
      const row = await this.insertAlertRow({
        brandId: brand.id,
        suspectName,
        suspectDomain,
        suspectWebsite,
        matchType,
        similarity,
        verdict,
        recipient: brand.contact_email,
        subject,
        status: "not_configured",
        providerMessageId: null,
        errorDetail: "RESEND_API_KEY is not configured",
        reporterNote,
      });
      throw new BrandGuardError(
        503,
        "EMAIL_NOT_CONFIGURED",
        `E-mail delivery is not configured. Set RESEND_API_KEY in backend/.env to deliver alerts. The attempt was recorded (alert ${row.id}).`,
      );
    }

    const delivery = await sendResendEmail({
      to: [brand.contact_email],
      subject,
      html,
      text,
    });

    const row = await this.insertAlertRow({
      brandId: brand.id,
      suspectName,
      suspectDomain,
      suspectWebsite,
      matchType,
      similarity,
      verdict,
      recipient: brand.contact_email,
      subject,
      status: delivery.delivered ? "sent" : "failed",
      providerMessageId: delivery.id,
      errorDetail: delivery.error,
      reporterNote,
    });

    if (!delivery.delivered) {
      throw new BrandGuardError(
        502,
        "EMAIL_DELIVERY_FAILED",
        `Resend did not accept the alert e-mail: ${delivery.error ?? "unknown error"}. The attempt was recorded (alert ${row.id}).`,
      );
    }

    logger.info("[brand-guard] Impersonation alert delivered", {
      alertId: row.id,
      brandId: brand.id,
      recipient: brand.contact_email,
      providerMessageId: delivery.id,
    });

    return row;
  }

  async listAlerts(brandId?: string | null, limit = 50): Promise<ImpersonationAlertRecord[]> {
    const boundedLimit = Math.min(Math.max(limit, 1), 200);
    if (brandId) {
      const result = await query<ImpersonationAlertRecord>(
        `SELECT * FROM impersonation_alerts
          WHERE brand_id = $1
          ORDER BY created_at DESC
          LIMIT $2;`,
        [brandId, boundedLimit],
      );
      return result.rows;
    }
    const result = await query<ImpersonationAlertRecord>(
      `SELECT * FROM impersonation_alerts
        ORDER BY created_at DESC
        LIMIT $1;`,
      [boundedLimit],
    );
    return result.rows;
  }

  /**
   * Registers an initial Brand Guard alert e-mail on an existing brand profile
   * that did not have one when created. Overwriting an already-configured
   * contact e-mail requires `allowOverwrite = true` (operator authorization).
   */
  async configureContactEmail(
    brandId: string,
    contactEmailInput: string,
    allowOverwrite = false,
  ): Promise<{ id: string; name: string; contact_email: string }> {
    const email = contactEmailInput.trim().toLowerCase();
    if (!isValidAlertEmail(email)) {
      throw new BrandGuardError(
        400,
        "INVALID_CONTACT_EMAIL",
        "Enter a valid contact e-mail address for impersonation alerts.",
      );
    }

    const existingResult = await query<{ id: string; name: string; contact_email: string | null }>(
      `SELECT id, name, contact_email FROM brands WHERE id = $1;`,
      [brandId],
    );
    const existing = existingResult.rows[0];
    if (!existing) {
      throw new BrandGuardError(404, "BRAND_NOT_FOUND", "Brand not found.");
    }

    if (
      existing.contact_email &&
      existing.contact_email.toLowerCase() !== email &&
      !allowOverwrite
    ) {
      throw new BrandGuardError(
        409,
        "CONTACT_EMAIL_ALREADY_SET",
        "A contact e-mail is already registered for this brand. Operator authorization is required to replace an existing alert address.",
      );
    }

    const updated = await query<{ id: string; name: string; contact_email: string }>(
      `UPDATE brands
          SET contact_email = $1,
              updated_at = NOW()
        WHERE id = $2
        RETURNING id, name, contact_email;`,
      [email, brandId],
    );

    const row = updated.rows[0];
    if (!row) {
      throw new BrandGuardError(500, "UPDATE_FAILED", "Failed to save contact e-mail.");
    }
    return row;
  }

  private async insertAlertRow(input: {
    brandId: string;
    suspectName: string;
    suspectDomain: string | null;
    suspectWebsite: string | null;
    matchType: BrandGuardMatchType;
    similarity: number | null;
    verdict: BrandGuardVerdict;
    recipient: string;
    subject: string;
    status: ImpersonationAlertRecord["status"];
    providerMessageId: string | null;
    errorDetail: string | null;
    reporterNote: string | null;
  }): Promise<ImpersonationAlertRecord> {
    const result = await query<ImpersonationAlertRecord>(
      `INSERT INTO impersonation_alerts (
         brand_id, suspect_name, suspect_domain, suspect_website,
         match_type, similarity, verdict, recipient_email, subject,
         status, provider, provider_message_id, error_detail, reporter_note
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'resend', $11, $12, $13)
       RETURNING *;`,
      [
        input.brandId,
        input.suspectName,
        input.suspectDomain,
        input.suspectWebsite,
        input.matchType,
        input.similarity,
        input.verdict,
        input.recipient,
        input.subject,
        input.status,
        input.providerMessageId,
        input.errorDetail,
        input.reporterNote,
      ],
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error("Failed to persist impersonation alert record");
    }
    return row;
  }
}

export const brandGuardService = new BrandGuardService();
export default brandGuardService;
