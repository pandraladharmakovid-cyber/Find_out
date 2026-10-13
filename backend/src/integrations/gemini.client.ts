import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export interface GeminiAnalysisResult {
  source: "gemini";
  riskScore: number;
  confidenceScore: number;
  verdict: "clean" | "suspicious" | "malicious" | "phishing" | "unverified";
  summary: string;
  keyFindings: string[];
  rawResponse: Record<string, unknown>;
}

export class GeminiClient {
  private readonly baseUrl = "https://generativelanguage.googleapis.com/v1beta/models";
  private readonly model = "gemini-1.5-pro";

  /**
   * Analyzes an investigation target and its collected context using the Gemini API.
   */
  async analyzeTarget(
    targetUrl: string | null,
    queryText: string | null,
    contextSummary: string,
    investigationId?: string
  ): Promise<GeminiAnalysisResult> {
    const startTime = Date.now();

    if (!config.GEMINI_API_KEY) {
      logger.info("[gemini] Gemini API key missing. Operating in degraded fallback mode.");
      return this.getFallbackResult("Gemini API key is not configured.");
    }

    try {
      logger.info("[gemini] Requesting AI threat analysis", { targetUrl, queryText });

      const prompt = `
You are a cybersecurity and threat intelligence analyzer. Evaluate the following entity or claim for fraud, phishing, brand impersonation, or malicious intent:

Target URL: ${targetUrl ?? "None"}
Claim / Description: ${queryText ?? "None"}
Additional Signals: ${contextSummary || "None"}

Respond strictly with valid JSON conforming to this structure:
{
  "riskScore": <number between 0 and 100>,
  "confidenceScore": <number between 0 and 100>,
  "verdict": "<clean | suspicious | malicious | phishing | unverified>",
  "summary": "<2-3 sentence technical assessment>",
  "keyFindings": ["<finding 1>", "<finding 2>"]
}
`;

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        config.REQUEST_TIMEOUT_MS
      );

      const endpoint = `${this.baseUrl}/${this.model}:generateContent?key=${config.GEMINI_API_KEY}`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.1,
            responseMimeType: "application/json",
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        throw new Error(`Gemini API returned HTTP status ${response.status}`);
      }

      const data = (await response.json()) as {
        candidates?: Array<{
          content?: {
            parts?: Array<{ text?: string }>;
          };
        }>;
      };

      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) {
        throw new Error("Empty candidate payload returned from Gemini");
      }

      const parsed = JSON.parse(rawText) as {
        riskScore: number;
        confidenceScore: number;
        verdict: "clean" | "suspicious" | "malicious" | "phishing" | "unverified";
        summary: string;
        keyFindings: string[];
      };

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "gemini",
        status: "success",
        latency_ms: latencyMs,
      });

      return {
        source: "gemini",
        riskScore: Math.min(100, Math.max(0, Number(parsed.riskScore) || 0)),
        confidenceScore: Math.min(100, Math.max(0, Number(parsed.confidenceScore) || 0)),
        verdict: parsed.verdict ?? "unverified",
        summary: parsed.summary ?? "AI analysis concluded without detailed remarks.",
        keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
        rawResponse: { rawText },
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : "Unknown error";

      logger.warn("[gemini] Analysis request failed", { error: errorMessage });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "gemini",
        status: "failed",
        latency_ms: latencyMs,
        error_message: errorMessage,
      });

      return this.getFallbackResult(errorMessage);
    }
  }

  private getFallbackResult(reason: string): GeminiAnalysisResult {
    return {
      source: "gemini",
      riskScore: 0,
      confidenceScore: 0,
      verdict: "unverified",
      summary: `AI evaluation unavailable: ${reason}`,
      keyFindings: ["Automated AI analysis skipped or unavailable."],
      rawResponse: { error: reason, fallback: true },
    };
  }
}

export const geminiClient = new GeminiClient();
export default geminiClient;