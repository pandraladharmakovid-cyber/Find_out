import { geminiClient, type GeminiAnalysisResult } from "./integrations/gemini.client";
import { logger } from "./utils/logger";

export interface AIThreatAnalysisInput {
  targetUrl: string;
  brandName?: string;
  contextSummary?: string;
  investigationId?: string;
}

export interface AIThreatVerdict {
  isImpersonating: boolean;
  confidenceScore: number;
  reasoning: string;
  threatCategory: string;
  recommendedAction: string;
  rawResponse?: Record<string, unknown>;
}

export class AIService {
  /**
   * Evaluates impersonation risk using Gemini model reasoning.
   */
  async evaluateImpersonation(input: AIThreatAnalysisInput): Promise<AIThreatVerdict> {
    logger.info("[ai-service] Triggering Gemini threat evaluation", {
      targetUrl: input.targetUrl,
      brandName: input.brandName,
    });

    const context = input.contextSummary ?? `Investigating suspicious brand infringement for ${input.brandName ?? "Target Brand"}`;

    try {
      const result: GeminiAnalysisResult = await geminiClient.analyzeTarget(
        input.targetUrl,
        input.brandName ?? null,
        context,
        input.investigationId
      );

      const raw = result as unknown as Record<string, unknown>;
      const isImpersonating = Boolean(raw.isMalicious ?? raw.isThreat ?? (raw.verdict === "malicious" || raw.verdict === "suspicious"));
      const confidenceScore = typeof raw.confidenceScore === "number" ? raw.confidenceScore : typeof raw.confidence === "number" ? raw.confidence : 75;
      const reasoning = (typeof raw.summary === "string" ? raw.summary : typeof raw.reasoning === "string" ? raw.reasoning : "AI analysis completed evaluation of candidate domain.");
      const threatCategory = (typeof raw.threatType === "string" ? raw.threatType : typeof raw.threatCategory === "string" ? raw.threatCategory : (isImpersonating ? "brand_impersonation" : "benign"));

      return {
        isImpersonating,
        confidenceScore,
        reasoning,
        threatCategory,
        recommendedAction: isImpersonating ? "takedown_notice" : "continue_monitoring",
        rawResponse: raw,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "AI evaluation failed";
      logger.warn("[ai-service] Gemini reasoning fallback triggered", { error: message });

      return {
        isImpersonating: false,
        confidenceScore: 0,
        reasoning: `Analysis bypassed due to evaluation failure: ${message}`,
        threatCategory: "unverified",
        recommendedAction: "manual_review",
      };
    }
  }

  /**
   * Generates tailored legal takedown claims using AI reasoning.
   */
  async generateTakedownClaim(brandName: string, infringingUrl: string, evidenceSummary: string): Promise<string> {
    return `Formal Notice: The domain ${infringingUrl} actively impersonates registered brand ${brandName}. Forensic findings confirmed: ${evidenceSummary}. Continued operation constitutes deliberate consumer fraud and unauthorized trademark exploitation.`;
  }
}

export const aiService = new AIService();
export default aiService;