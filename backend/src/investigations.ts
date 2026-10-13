
import { query } from "./db";
import { logger } from "./utils/logger";
import { urlhausClient } from "./integrations/urlhaus.client";
import { safeBrowsingClient } from "./integrations/safebrowsing.client";
import { geminiClient } from "./integrations/gemini.client";
import { redditClient } from "./integrations/reddit.client";
import { youtubeClient } from "./integrations/youtube.client";
import { urlSafetyEngine } from "./url-safety";
import { threatDetectionEngine } from "./detection";
import { evidenceCollectorService } from "./evidence";
import { riskScoringEngine, type FinalVerdict } from "./risk";
import { exclusionEngineService } from "./exclusion-engine.service";
import type { QueryResultRow } from "pg";

export interface InvestigationRecord extends QueryResultRow {
  id: string;
  title: string;
  target_url: string | null;
  brand_id: string | null;
  status: "pending" | "analyzing" | "completed" | "failed";
  verdict: FinalVerdict;
  risk_score: number;
  confidence_score: number;
  summary: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface StartInvestigationDTO {
  title?: string;
  targetUrl: string;
  brandId?: string;
  brandName?: string;
}

export class InvestigationService {
  async runInvestigation(dto: StartInvestigationDTO): Promise<InvestigationRecord> {
    const targetUrl = dto.targetUrl.trim();
    const title = dto.title ?? `Scan for ${targetUrl}`;

    logger.info("[investigations] Initiating threat investigation workflow", {
      targetUrl,
      brandId: dto.brandId,
    });

    const initialRes = await query<InvestigationRecord>(
      `INSERT INTO investigations (
        title, target_url, brand_id, status, verdict, risk_score, confidence_score, metadata
      ) VALUES ($1, $2, $3, 'analyzing', 'unverified', 0, 0, '{}'::jsonb)
      RETURNING *;`,
      [title, targetUrl, dto.brandId ?? null]
    );

    const investigation = initialRes.rows[0];
    if (!investigation) {
      throw new Error("Failed to initialize investigation record");
    }

    const investigationId = investigation.id;

    try {
      const exclusionCheck = await exclusionEngineService.checkExclusion(targetUrl);
      if (exclusionCheck.isExcluded) {
        logger.info("[investigations] Target is whitelisted; finalizing as clean", { targetUrl });

        return await this.updateInvestigationVerdict(investigationId, {
          status: "completed",
          verdict: "clean",
          riskScore: 0,
          confidenceScore: 100,
          summary: `Target URL is excluded from threat detection: ${exclusionCheck.reason}`,
          metadata: { isExcluded: true, exclusionReason: exclusionCheck.reason },
        });
      }

      const contextSummary = `Investigating domain impersonation against brand: ${dto.brandName ?? "Unknown"}`;

      const [
        detectionEval,
        urlhausRes,
        safeBrowsingRes,
        geminiRes,
        redditRes,
        youtubeRes,
      ] = await Promise.all([
        threatDetectionEngine.evaluateTarget(targetUrl),
        urlhausClient.checkUrl(targetUrl, investigationId),
        safeBrowsingClient.checkUrl(targetUrl, investigationId),
        geminiClient.analyzeTarget(
          targetUrl,
          dto.brandName ?? null,
          contextSummary,
          investigationId
        ),
        redditClient.searchDiscussions(targetUrl, investigationId),
        youtubeClient.searchVideos(targetUrl, investigationId),
      ]);

      const safetyAnalysis = urlSafetyEngine.analyzeUrl(targetUrl);

      const normalizedEvidence = evidenceCollectorService.normalizeSignals({
        targetUrl,
        urlhausResult: urlhausRes,
        safeBrowsingResult: safeBrowsingRes,
        redditResult: redditRes,
        youtubeResult: youtubeRes,
        urlSafetyAnalysis: safetyAnalysis,
      });

      await evidenceCollectorService.recordEvidenceBatch(investigationId, normalizedEvidence);

      const riskEvaluation = riskScoringEngine.evaluate({
        evidenceItems: normalizedEvidence,
        geminiResult: geminiRes,
        heuristicRiskScore: detectionEval.compositeRiskScore,
      });

      return await this.updateInvestigationVerdict(investigationId, {
        status: "completed",
        verdict: riskEvaluation.verdict,
        riskScore: riskEvaluation.compositeRiskScore,
        confidenceScore: riskEvaluation.confidenceScore,
        summary: riskEvaluation.summary,
        metadata: {
          factors: riskEvaluation.factors,
          highRiskFlags: riskEvaluation.highRiskFlags,
          signalsCount: detectionEval.signals.length,
          detectionSignals: detectionEval.signals,
        },
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Investigation failed";
      logger.error("[investigations] Investigation pipeline execution error", {
        investigationId,
        error: errorMessage,
      });

      return await this.updateInvestigationVerdict(investigationId, {
        status: "failed",
        verdict: "unverified",
        riskScore: 0,
        confidenceScore: 0,
        summary: `Pipeline halted: ${errorMessage}`,
        metadata: { error: errorMessage },
      });
    }
  }

  async getInvestigationById(id: string): Promise<InvestigationRecord | null> {
    const res = await query<InvestigationRecord>(
      `SELECT * FROM investigations WHERE id = $1;`,
      [id]
    );
    return res.rows[0] ?? null;
  }

  async listInvestigations(limit = 25, offset = 0): Promise<InvestigationRecord[]> {
    const res = await query<InvestigationRecord>(
      `SELECT * FROM investigations ORDER BY created_at DESC LIMIT $1 OFFSET $2;`,
      [limit, offset]
    );
    return res.rows;
  }

  private async updateInvestigationVerdict(
    id: string,
    params: {
      status: "completed" | "failed";
      verdict: FinalVerdict;
      riskScore: number;
      confidenceScore: number;
      summary: string;
      metadata: Record<string, unknown>;
    }
  ): Promise<InvestigationRecord> {
    const text = `
      UPDATE investigations
      SET status = $2,
          verdict = $3,
          risk_score = $4,
          confidence_score = $5,
          summary = $6,
          metadata = $7,
          updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await query<InvestigationRecord>(text, [
      id,
      params.status,
      params.verdict,
      params.riskScore,
      params.confidenceScore,
      params.summary,
      JSON.stringify(params.metadata),
    ]);

    const updated = res.rows[0];
    if (!updated) {
      throw new Error(`Failed to update investigation record ${id}`);
    }

    return updated;
  }
}

export const investigationService = new InvestigationService();
export default investigationService;