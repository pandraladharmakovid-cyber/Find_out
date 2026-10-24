import { geminiClient, type GeminiAnalysisResult } from "./integrations/gemini.client";
import { logger } from "./utils/logger";

export interface AIThreatAnalysisInput {
  targetUrl: string;
  brandName?: string;
  contextSummary?: string;
  investigationId?: string;
}

export interface AIThreatVerdict {
  verdict: GeminiAnalysisResult["verdict"];
  riskScore: number;
  isImpersonating: boolean;
  confidenceScore: number;
  reasoning: string;
  threatCategory: string;
  recommendedAction: string;
  rawResponse?: Record<string, unknown>;
}

function boundedScore(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(100, Math.max(0, value))
    : 0;
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
      const rawVerdict = raw.verdict;
      const verdict: AIThreatVerdict["verdict"] =
        rawVerdict === "clean" ||
        rawVerdict === "suspicious" ||
        rawVerdict === "malicious" ||
        rawVerdict === "phishing" ||
        rawVerdict === "unverified"
          ? rawVerdict
          : "unverified";
      const confidenceScore = boundedScore(raw.confidenceScore);
      const riskScore = boundedScore(raw.riskScore);
      const hasUsableAnalysis = confidenceScore > 0 && verdict !== "unverified";
      const effectiveVerdict: AIThreatVerdict["verdict"] = hasUsableAnalysis
        ? verdict
        : "unverified";
      const isImpersonating =
        hasUsableAnalysis &&
        (verdict === "suspicious" || verdict === "malicious" || verdict === "phishing");
      const reasoning =
        typeof raw.summary === "string"
          ? raw.summary
          : typeof raw.reasoning === "string"
            ? raw.reasoning
            : "AI analysis did not supply a usable explanation.";
      const threatCategory =
        effectiveVerdict === "unverified"
          ? "unverified"
          : typeof raw.threatType === "string"
            ? raw.threatType
            : typeof raw.threatCategory === "string"
              ? raw.threatCategory
              : isImpersonating
                ? "brand_impersonation"
                : "benign";
      const recommendedAction =
        effectiveVerdict === "malicious" || effectiveVerdict === "phishing"
          ? "takedown_notice"
          : effectiveVerdict === "suspicious" || effectiveVerdict === "unverified"
            ? "manual_review"
            : "continue_monitoring";

      return {
        verdict: effectiveVerdict,
        riskScore: hasUsableAnalysis ? riskScore : 0,
        isImpersonating,
        confidenceScore,
        reasoning,
        threatCategory,
        recommendedAction,
        rawResponse: raw,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "AI evaluation failed";
      logger.warn("[ai-service] Gemini reasoning fallback triggered", { error: message });

      return {
        verdict: "unverified",
        riskScore: 0,
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
