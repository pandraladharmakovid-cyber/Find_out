
import { query } from "./db";
import { logger } from "./utils/logger";
import { urlhausClient } from "./integrations/urlhaus.client";
import { safeBrowsingClient } from "./integrations/safebrowsing.client";
import { geminiClient } from "./integrations/gemini.client";
import { blueskyClient } from "./integrations/bluesky.client";
import { youtubeClient } from "./integrations/youtube.client";
import { urlSafetyEngine } from "./url-safety";
import { threatDetectionEngine } from "./detection";
import { evidenceCollectorService } from "./evidence";
import { riskScoringEngine, type FinalVerdict } from "./risk";
import { evaluateBrandImpersonation } from "./brand-impersonation.service";
import { buildEvidenceNarrative } from "./evidence-narrative";
import { brandService } from "./brands";
import { exclusionEngineService } from "./exclusion-engine.service";
import { runWithDeadline } from "./utils/timeout";
import { config } from "./config";
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
      const exclusionCheck = await exclusionEngineService.checkExclusion(targetUrl, dto.brandId);
      if (exclusionCheck.isExcluded) {
        logger.info("[investigations] Target matched a brand-scoped verified asset; no safety verdict inferred", {
          targetUrl,
          brandId: dto.brandId,
        });

        return await this.updateInvestigationVerdict(investigationId, {
          status: "completed",
          verdict: "unverified",
          riskScore: 0,
          confidenceScore: 0,
          summary: `Exact verified asset association excluded this target from impersonation analysis for this brand. This is not a safety guarantee: ${exclusionCheck.reason}`,
          metadata: {
            isExcluded: true,
            associationVerified: true,
            safetyAssessment: "NOT_ASSESSED_BY_EXCLUSION",
            exclusionReason: exclusionCheck.reason,
            factors: [],
            signalsCount: 0,
          },
        });
      }

      // Resolve the protected brand so hostname resemblance can be scored even
      // when every third-party feed is down.
      const brand = dto.brandId ? await brandService.getBrandById(dto.brandId).catch(() => null) : null;
      const brandName = dto.brandName?.trim() || brand?.name || null;
      const brandDomains = [
        ...(brand?.primary_domain ? [brand.primary_domain] : []),
        ...((brand as unknown as { associated_domains?: string[] } | null)?.associated_domains ?? []),
      ];

      const brandImpersonation = evaluateBrandImpersonation({
        targetUrl,
        brandName,
        brandDomains,
      });

      const contextSummary = `Investigating domain impersonation against brand: ${brandName ?? "Unknown"}`;

      // Each external source is bounded independently. A source that exceeds its
      // budget is recorded as unavailable instead of failing the investigation.
      const sourceBudgetMs = config.REQUEST_TIMEOUT_MS + 5_000;

      const [detectionOutcome, urlhausOutcome, safeBrowsingOutcome, geminiOutcome, blueskyOutcome, youtubeOutcome] =
        await Promise.all([
          runWithDeadline(() => threatDetectionEngine.evaluateTarget(targetUrl), sourceBudgetMs, "Detection engine"),
          runWithDeadline(() => urlhausClient.checkUrl(targetUrl, investigationId), sourceBudgetMs, "URLhaus"),
          runWithDeadline(() => safeBrowsingClient.checkUrl(targetUrl, investigationId), sourceBudgetMs, "Safe Browsing"),
          runWithDeadline(
            () => geminiClient.analyzeTarget(targetUrl, brandName, contextSummary, investigationId),
            config.REQUEST_TIMEOUT_MS * 2 + 5_000,
            "Gemini analysis",
          ),
          runWithDeadline(() => blueskyClient.searchDiscussions(targetUrl, investigationId), sourceBudgetMs, "Bluesky"),
          runWithDeadline(() => youtubeClient.searchVideos(targetUrl, investigationId), sourceBudgetMs, "YouTube"),
        ]);

      const detectionEval = detectionOutcome.value ?? {
        compositeRiskScore: 0,
        signals: [],
      };

      const urlhausRes = urlhausOutcome.value ?? {
        source: "urlhaus" as const,
        status: "unavailable" as const,
        isMalicious: false,
        threatType: null,
        urlStatus: "unknown" as const,
        confidence: 0,
        error: urlhausOutcome.error ?? "URLhaus timed out.",
        rawPayload: { error: urlhausOutcome.error ?? "URLhaus timed out." },
      };

      const safeBrowsingRes = safeBrowsingOutcome.value ?? {
        source: "safebrowsing" as const,
        status: "unavailable" as const,
        isThreat: false,
        threatTypes: [],
        rawMatches: [],
        confidence: 0,
        error: safeBrowsingOutcome.error ?? "Safe Browsing timed out.",
      };

      const geminiRes = geminiOutcome.value ?? {
        source: "gemini" as const,
        status: "unavailable" as const,
        model: null,
        riskScore: 0,
        confidenceScore: 0,
        verdict: "unverified" as const,
        summary: geminiOutcome.error ?? "Gemini analysis timed out.",
        keyFindings: [],
        rawResponse: {},
      };

      const blueskyRes = blueskyOutcome.value ?? {
        source: "bluesky" as const,
        query: targetUrl,
        totalFound: 0,
        posts: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: {
          sourceStatus: "unavailable",
          skipped: true,
          reason: blueskyOutcome.error ?? "Bluesky timed out.",
        },
      };

      const youtubeRes = youtubeOutcome.value ?? {
        source: "youtube" as const,
        query: targetUrl,
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { error: youtubeOutcome.error ?? "YouTube timed out." },
      };

      const silence = (outcome: { error?: string; timedOut: boolean }): string | null =>
        outcome.error ? (outcome.timedOut ? `Timed out: ${outcome.error}` : outcome.error) : null;

      const sourceStatuses = {
        urlhaus: silence(urlhausOutcome) ?? urlhausRes.status,
        safebrowsing: silence(safeBrowsingOutcome) ?? safeBrowsingRes.status,
        gemini: silence(geminiOutcome) ?? geminiRes.status,
        bluesky:
          silence(blueskyOutcome) ??
          (blueskyRes.rawPayload.sourceStatus === "available" ? "available" : "unavailable"),
        youtube: silence(youtubeOutcome) ?? (youtubeRes.rawPayload.error ? "unavailable" : "available"),
      };

      const safetyAnalysis = urlSafetyEngine.analyzeUrl(targetUrl);

      const normalizedEvidence = evidenceCollectorService.normalizeSignals({
        targetUrl,
        urlhausResult: urlhausRes,
        safeBrowsingResult: safeBrowsingRes,
        blueskyResult: blueskyRes,
        youtubeResult: youtubeRes,
        geminiResult: geminiRes,
        urlSafetyAnalysis: safetyAnalysis,
      });

      await evidenceCollectorService.recordEvidenceBatch(investigationId, normalizedEvidence);

      const riskEvaluation = riskScoringEngine.evaluate({
        evidenceItems: normalizedEvidence,
        geminiResult: geminiRes,
        heuristicRiskScore: detectionEval.compositeRiskScore,
        brandImpersonation,
      });

      const narrative = buildEvidenceNarrative({
        targetUrl,
        brandName,
        brandImpersonation,
        evidenceItems: normalizedEvidence,
        factors: riskEvaluation.factors,
        sourceStatuses,
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
          brand: brandName
            ? {
                id: brand?.id ?? dto.brandId ?? null,
                name: brandName,
                officialDomains: brandDomains,
              }
            : null,
          brandImpersonation,
          evidenceNarrative: narrative,
          coverage: riskEvaluation.coverage,
          escalation: riskEvaluation.escalation,
          sourceStatuses,
          aiAnalysis: {
            provider: "gemini",
            status: geminiRes.status,
            model: geminiRes.model,
            verdict: geminiRes.verdict,
            riskScore: geminiRes.riskScore,
            confidenceScore: geminiRes.confidenceScore,
          },
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
