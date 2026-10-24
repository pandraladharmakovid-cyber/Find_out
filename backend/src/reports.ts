import { query } from "./db";
import { logger } from "./utils/logger";
import { investigationService, type InvestigationRecord } from "./investigations";
import type { QueryResultRow } from "pg";

export interface EvidenceRecordRow extends QueryResultRow {
  id: string;
  investigation_id: string;
  source: string;
  source_url: string | null;
  reliability_score: number;
  extracted_claim: string | null;
  is_verified: boolean;
  raw_payload: Record<string, unknown>;
  created_at: string;
}

export interface AuditRecordRow extends QueryResultRow {
  id: string;
  investigation_id: string | null;
  source: string;
  status: string;
  latency_ms: number | null;
  error_message: string | null;
  created_at: string;
}

export interface InvestigationReportRecord extends QueryResultRow {
  id: string;
  investigation_id: string;
  title: string;
  format: "json" | "markdown" | "html";
  content: string;
  created_at: string;
}

export interface StructuredDossier {
  investigationId: string;
  title: string;
  targetUrl: string | null;
  verdict: string;
  riskScore: number;
  confidenceScore: number;
  summary: string | null;
  createdAt: string;
  evidenceItems: EvidenceRecordRow[];
  auditTimeline: AuditRecordRow[];
  recommendations: string[];
}

export class ReportsService {
  /**
   * Generates actionable mitigation recommendations based on verdict and risk factors.
   */
  private generateRecommendations(investigation: InvestigationRecord): string[] {
    const recommendations: string[] = [];

    if (investigation.verdict === "malicious" || investigation.verdict === "phishing") {
      recommendations.push("Dispatch immediate abuse takedown requests to authoritative domain registrar and upstream DNS providers.");
      recommendations.push("Submit domain indicators to Google Safe Browsing and URLhaus threat feeds.");
      recommendations.push("Notify customer trust and safety channels to monitor for targeted credential replay attempts.");
    } else if (investigation.verdict === "suspicious") {
      recommendations.push("Enroll target domain into high-frequency surveillance monitoring queue.");
      recommendations.push("Monitor SSL/TLS certificate transparency logs for new hostnames bound to this target.");
      recommendations.push("Prepare draft cease-and-desist documentation in case deceptive activity escalates.");
    } else if (investigation.verdict === "clean") {
      recommendations.push("Target currently presents low risk profile. Maintain periodic baseline scanning.");
    } else {
      recommendations.push("Evidence is insufficient for a clean or malicious determination. Keep the target unverified and review unavailable sources before retrying.");
      recommendations.push("Do not treat the absence of a threat match as proof of safety.");
    }

    return recommendations;
  }

  /**
   * Compiles complete structured intelligence dossier for an investigation.
   */
  async buildDossier(investigationId: string): Promise<StructuredDossier> {
    const investigation = await investigationService.getInvestigationById(investigationId);
    if (!investigation) {
      throw new Error(`Cannot compile report: Investigation ${investigationId} not found`);
    }

    // Query evidence and audit logs directly
    const [evidenceRes, auditRes] = await Promise.all([
      query<EvidenceRecordRow>(
        `SELECT * FROM evidence_items WHERE investigation_id = $1 ORDER BY created_at ASC;`,
        [investigationId]
      ),
      query<AuditRecordRow>(
        `SELECT id, investigation_id, source, status, latency_ms, error_message,
                attempted_at AS created_at
         FROM source_audit_logs WHERE investigation_id = $1 ORDER BY attempted_at ASC;`,
        [investigationId]
      ),
    ]);

    const recommendations = this.generateRecommendations(investigation);

    return {
      investigationId: investigation.id,
      title: investigation.title,
      targetUrl: investigation.target_url,
      verdict: investigation.verdict,
      riskScore: investigation.risk_score,
      confidenceScore: investigation.confidence_score,
      summary: investigation.summary,
      createdAt: investigation.created_at,
      evidenceItems: evidenceRes.rows,
      auditTimeline: auditRes.rows,
      recommendations,
    };
  }

  /**
   * Generates an executive Markdown forensic summary report.
   */
  async generateMarkdownReport(investigationId: string): Promise<string> {
    const dossier = await this.buildDossier(investigationId);

    const evidenceRows = dossier.evidenceItems
      .map(
        (e) =>
          `| ${e.source} | ${e.reliability_score}% | ${e.source_url ?? "N/A"} | ${e.extracted_claim ?? "Observed indicator"} |`
      )
      .join("\n");

    const timelineRows = dossier.auditTimeline
      .map((t) => `| ${t.created_at} | ${t.source} | ${t.status} | ${t.latency_ms ?? 0}ms |`)
      .join("\n");

    const recsList = dossier.recommendations.map((r) => `- ${r}`).join("\n");

    return `
# Threat Intelligence Forensics Report: ${dossier.title}

- **Investigation ID**: \`${dossier.investigationId}\`
- **Target URL**: ${dossier.targetUrl ?? "N/A"}
- **Final Verdict**: **${dossier.verdict.toUpperCase()}**
- **Composite Risk Score**: **${dossier.riskScore} / 100**
- **Confidence Score**: **${dossier.confidenceScore}%**
- **Generated At**: ${new Date().toUTCString()}

---

## Executive Summary
${dossier.summary ?? "Automated threat evaluation complete."}

---

## Identified Evidence Artifacts
| Source | Reliability | Target Indicator | Observation |
|---|---|---|---|
${evidenceRows || "| None | - | - | No evidence artifacts were recorded; no conclusion is inferred. |"}

---

## Actionable Mitigation Steps
${recsList}

---

## Audit Trail & Telemetry
| Timestamp | Service | Status | Latency |
|---|---|---|---|
${timelineRows || "| None | - | - | - |"}
    `.trim();
  }

  /**
   * Persists report output to database.
   */
  async saveReport(investigationId: string, format: "json" | "markdown" = "markdown"): Promise<InvestigationReportRecord> {
    const investigation = await investigationService.getInvestigationById(investigationId);
    if (!investigation) {
      throw new Error(`Investigation with ID ${investigationId} not found`);
    }

    let content = "";
    if (format === "json") {
      const dossier = await this.buildDossier(investigationId);
      content = JSON.stringify(dossier, null, 2);
    } else {
      content = await this.generateMarkdownReport(investigationId);
    }

    const title = `Forensic Threat Report - ${investigation.title}`;

    const text = `
      INSERT INTO reports (investigation_id, title, format, content)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;

    const res = await query<InvestigationReportRecord>(text, [
      investigationId,
      title,
      format,
      content,
    ]);

    const report = res.rows[0];
    if (!report) {
      throw new Error("Failed to persist forensic report");
    }

    logger.info("[reports] Persisted threat report", {
      investigationId,
      reportId: report.id,
      format,
    });

    return report;
  }
}

export const reportsService = new ReportsService();
export default reportsService;
