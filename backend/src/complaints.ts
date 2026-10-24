import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import type { QueryResultRow } from "pg";

export type ComplaintType = "dmca_takedown" | "trademark_infringement" | "registrar_abuse" | "app_store_violation";
export type ComplaintStatus = "draft" | "generated" | "sent" | "accepted" | "rejected";

export interface ComplaintRecord extends QueryResultRow {
  id: string;
  investigation_id: string;
  brand_id: string;
  complaint_type: ComplaintType;
  recipient_email: string;
  target_url: string;
  status: ComplaintStatus;
  subject: string;
  body_text: string;
  metadata: Record<string, unknown>;
  sent_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateComplaintDTO {
  investigationId: string;
  brandId: string;
  brandName: string;
  brandContactEmail: string;
  complaintType: ComplaintType;
  recipientEmail: string;
  targetUrl: string;
  infringingEvidenceSummary?: string;
  trademarkNumber?: string;
}

export class ComplaintService {
  /**
   * Constructs the formal legal and abuse notice body text.
   */
  private generateNoticeTemplate(dto: CreateComplaintDTO): { subject: string; bodyText: string } {
    const timestamp = new Date().toUTCString();

    switch (dto.complaintType) {
      case "dmca_takedown":
        return {
          subject: `DMCA Copyright Infringement Takedown Notice: Impersonation of ${dto.brandName}`,
          bodyText: `
LEGAL NOTICE: NOTICE OF COPYRIGHT INFRINGEMENT (DMCA)
Date: ${timestamp}
To Abuse / DMCA Agent (${dto.recipientEmail}):

I am writing on behalf of ${dto.brandName} ("Complainant"). It has come to our attention that your service is hosting unauthorized content that infringes upon Complainant's registered rights.

Infringing URL / Resource:
${dto.targetUrl}

Description of Infringement:
${dto.infringingEvidenceSummary || "Unauthorized brand duplication and credential harvesting targeting brand customers."}

Complainant has a good faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.

We kindly demand the immediate removal or disablement of access to the infringing material.

Sincerely,
Representative of ${dto.brandName}
Contact: ${dto.brandContactEmail}
          `.trim(),
        };

      case "trademark_infringement":
        return {
          subject: `Trademark Infringement Notice - ${dto.brandName} [Ref: ${dto.trademarkNumber || "COMMERCIAL-USE"}]`,
          bodyText: `
OFFICIAL NOTICE OF TRADEMARK INFRINGEMENT
Date: ${timestamp}
To: ${dto.recipientEmail}

Complainant: ${dto.brandName}
Official Contact: ${dto.brandContactEmail}
Trademark Identifier: ${dto.trademarkNumber || "Common Law & Federal Rights"}

Unauthorized Target Location:
${dto.targetUrl}

Summary:
The target above uses confusingly similar marks and brand identifiers to mislead consumers and conduct unauthorized commercial operations.

We request you take prompt action to investigate this entity and suspend services facilitating this impersonation.
          `.trim(),
        };

      case "registrar_abuse":
      default:
        return {
          subject: `URGENT: Phishing and Brand Impersonation Abuse Report - ${dto.targetUrl}`,
          bodyText: `
DOMAIN ABUSE & MALICIOUS ACTIVITY NOTIFICATION
Date: ${timestamp}
To Abuse Desk (${dto.recipientEmail}):

Target Domain / Host:
${dto.targetUrl}

Target Brand:
${dto.brandName}

Evidence Summary:
${dto.infringingEvidenceSummary || "High-confidence deceptive domain mimicking corporate login flow."}

The domain cited above is violating acceptable use policies by actively impersonating ${dto.brandName}. Please suspend DNS resolution or domain routing immediately to prevent harm to users.

Reporter Contact: ${dto.brandContactEmail}
          `.trim(),
        };
    }
  }

  /**
   * Generates and stores a new complaint notice.
   */
  async createComplaint(dto: CreateComplaintDTO): Promise<ComplaintRecord> {
    const { subject, bodyText } = this.generateNoticeTemplate(dto);

    logger.info("[complaints] Generating legal takedown complaint", {
      investigationId: dto.investigationId,
      type: dto.complaintType,
      targetUrl: dto.targetUrl,
    });

    // The table carries both the legacy report columns (platform,
    // claim_description, complaint_category) and the newer complaint columns.
    // Every NOT NULL column must be populated or the insert fails.
    let platform = "web";
    try {
      platform = new URL(dto.targetUrl).hostname.replace(/^www\./, "");
    } catch {
      platform = "web";
    }

    const text = `
      INSERT INTO complaints (
        investigation_id, brand_id, platform, target_identifier, target_url,
        complaint_category, description, claim_description, reporter_email,
        complaint_type, recipient_email, status, submission_status, subject,
        body_text, metadata
      ) VALUES (
        $1, $2, $3, $4, $5,
        'brand_impersonation', $6, $6, $7,
        $8, $9, 'generated', 'DRAFT', $10,
        $11, $12
      )
      RETURNING *;
    `;

    const res = await query<ComplaintRecord>(text, [
      dto.investigationId,
      dto.brandId,
      platform,
      dto.targetUrl,
      dto.targetUrl,
      dto.infringingEvidenceSummary ?? `Impersonation of ${dto.brandName} at ${dto.targetUrl}.`,
      dto.brandContactEmail,
      dto.complaintType,
      dto.recipientEmail,
      subject,
      bodyText,
      JSON.stringify({
        trademarkNumber: dto.trademarkNumber ?? null,
        evidenceSummary: dto.infringingEvidenceSummary ?? null,
        brandName: dto.brandName,
      }),
    ]);

    const complaint = res.rows[0];
    if (!complaint) {
      throw new Error("Failed to persist takedown complaint");
    }

    return complaint;
  }

  /**
   * Retrieves complaints for an investigation.
   */
  async getComplaintsByInvestigation(investigationId: string): Promise<ComplaintRecord[]> {
    const res = await query<ComplaintRecord>(
      `SELECT * FROM complaints WHERE investigation_id = $1 ORDER BY created_at DESC;`,
      [investigationId]
    );
    return res.rows;
  }

  /**
   * Updates complaint dispatch status.
   */
  async updateStatus(id: string, status: ComplaintStatus): Promise<ComplaintRecord> {
    const sentAtSql = status === "sent" ? "sent_at = NOW()," : "";
    const submissionStatus = status === "sent" ? "SUBMITTED" : status.toUpperCase();
    const text = `
      UPDATE complaints
      SET status = $2,
          submission_status = $3,
          ${sentAtSql}
          updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await query<ComplaintRecord>(text, [id, status, submissionStatus]);
    const updated = res.rows[0];
    if (!updated) {
      throw new Error(`Complaint with id ${id} not found`);
    }

    return updated;
  }
}

export const complaintService = new ComplaintService();
export default complaintService;
