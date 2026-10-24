import { config, splitList } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export type GeminiVerdict = "clean" | "suspicious" | "malicious" | "phishing" | "unverified";

export interface GeminiAnalysisResult {
  source: "gemini";
  status: "available" | "unavailable" | "not_configured";
  model: string | null;
  riskScore: number;
  confidenceScore: number;
  verdict: GeminiVerdict;
  summary: string;
  keyFindings: string[];
  rawResponse: Record<string, unknown>;
}

const API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models";

/**
 * Gemini client.
 *
 * The previous implementation hard-coded `gemini-1.5-pro`, which Google has
 * retired; every call therefore returned HTTP 404 regardless of the API key.
 * The model is now configurable (GEMINI_MODEL) with a fallback chain, the key
 * is sent in the `x-goog-api-key` header instead of the query string, and a
 * model-level 404 is retried against the next model before failing.
 */
export class GeminiClient {
  get modelChain(): string[] {
    return [...new Set([config.GEMINI_MODEL, ...splitList(config.GEMINI_FALLBACK_MODELS)].filter(Boolean))];
  }

  get configured(): boolean {
    return Boolean(config.GEMINI_API_KEY);
  }

  /**
   * Lightweight model check used by diagnostics. Reports which configured model
   * actually answers, which is how a retired model (HTTP 404) is surfaced.
   */
  async probe(): Promise<{
    ok: boolean;
    model: string | null;
    latencyMs: number;
    message: string;
  }> {
    if (!this.configured) {
      return {
        ok: false,
        model: null,
        latencyMs: 0,
        message: "GEMINI_API_KEY is not configured.",
      };
    }

    const errors: string[] = [];
    const startedAt = Date.now();

    for (const model of this.modelChain) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(config.REQUEST_TIMEOUT_MS, 20_000));
      try {
        const response = await fetch(`${API_ROOT}/${encodeURIComponent(model)}:generateContent`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": config.GEMINI_API_KEY,
          },
          body: JSON.stringify({
            contents: [{ parts: [{ text: "Reply with the single word READY." }] }],
            generationConfig: { maxOutputTokens: 16, temperature: 0 },
          }),
          signal: controller.signal,
        });

        const body = await response.text();

        if (!response.ok) {
          errors.push(`${model}: ${summarizeGeminiError(response.status, body)}`);
          continue;
        }

        return {
          ok: true,
          model,
          latencyMs: Date.now() - startedAt,
          message: `${model} answered in ${Date.now() - startedAt} ms.`,
        };
      } catch (error) {
        errors.push(`${model}: ${error instanceof Error ? error.message : "request failed"}`);
      } finally {
        clearTimeout(timer);
      }
    }

    return {
      ok: false,
      model: null,
      latencyMs: Date.now() - startedAt,
      message: `No configured Gemini model answered. ${errors.join(" | ")}`,
    };
  }

  async analyzeTarget(
    targetUrl: string | null,
    queryText: string | null,
    contextSummary: string,
    investigationId?: string,
  ): Promise<GeminiAnalysisResult> {
    const startTime = Date.now();

    if (!this.configured) {
      logger.info("[gemini] Gemini API key missing. Operating in degraded mode.");
      await this.recordAudit(investigationId, "skipped", Date.now() - startTime, "GEMINI_API_KEY not configured");
      return this.fallback("Gemini API key is not configured.", "not_configured");
    }

    const prompt = `
You are a cybersecurity and threat-intelligence analyzer. Evaluate the following entity or claim for fraud, phishing, brand impersonation, or malicious intent:

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

    const errors: string[] = [];

    for (const model of this.modelChain) {
      const attemptStart = Date.now();

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);

        let response: Response;
        try {
          response = await fetch(`${API_ROOT}/${encodeURIComponent(model)}:generateContent`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
              "x-goog-api-key": config.GEMINI_API_KEY,
            },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: {
                temperature: 0.1,
                responseMimeType: "application/json",
              },
            }),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeout);
        }

        const rawBody = await response.text();

        if (!response.ok) {
          const message = summarizeGeminiError(response.status, rawBody);
          errors.push(`${model}: ${message}`);

          // A retired/unknown model must fall through to the next candidate.
          if (response.status === 404 || response.status === 400) {
            logger.warn("[gemini] Model rejected; trying the next configured model", {
              model,
              status: response.status,
              message,
            });
            continue;
          }

          throw new Error(message);
        }

        const data = JSON.parse(rawBody) as {
          candidates?: Array<{
            content?: { parts?: Array<{ text?: string }> };
          }>;
        };

        const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!rawText) {
          throw new Error("Gemini returned an empty candidate payload.");
        }

        const parsed = JSON.parse(rawText) as {
          riskScore?: unknown;
          confidenceScore?: unknown;
          verdict?: unknown;
          summary?: unknown;
          keyFindings?: unknown;
        };

        const result: GeminiAnalysisResult = {
          source: "gemini",
          status: "available",
          model,
          riskScore: clamp(Number(parsed.riskScore) || 0),
          confidenceScore: clamp(Number(parsed.confidenceScore) || 0),
          verdict: isVerdict(parsed.verdict) ? parsed.verdict : "unverified",
          summary:
            typeof parsed.summary === "string" && parsed.summary.trim()
              ? parsed.summary
              : "Gemini completed the analysis without a written summary.",
          keyFindings: Array.isArray(parsed.keyFindings)
            ? parsed.keyFindings.filter((entry): entry is string => typeof entry === "string").slice(0, 10)
            : [],
          rawResponse: { model, rawText },
        };

        await this.recordAudit(investigationId, "success", Date.now() - attemptStart);

        logger.info("[gemini] Analysis completed", {
          model,
          verdict: result.verdict,
          riskScore: result.riskScore,
          latencyMs: Date.now() - attemptStart,
        });

        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown Gemini error";
        errors.push(`${model}: ${message}`);
        logger.warn("[gemini] Attempt failed", { model, error: message });
      }
    }

    const reason = errors.join(" | ") || "All configured Gemini models failed.";
    await this.recordAudit(investigationId, "failed", Date.now() - startTime, reason.slice(0, 500));

    return this.fallback(
      `${reason} Add or update GEMINI_MODEL in backend/.env with a model that is currently available to this key.`,
      "unavailable",
    );
  }

  private fallback(reason: string, status: "unavailable" | "not_configured"): GeminiAnalysisResult {
    return {
      source: "gemini",
      status,
      model: null,
      riskScore: 0,
      confidenceScore: 0,
      verdict: "unverified",
      summary: `AI evaluation unavailable: ${reason}`,
      keyFindings: ["Automated AI analysis was skipped or unavailable."],
      rawResponse: { error: reason, fallback: true, status },
    };
  }

  private async recordAudit(
    investigationId: string | undefined,
    status: string,
    latencyMs: number,
    errorMessage?: string,
  ): Promise<void> {
    try {
      await AuditLogsRepository.recordLog({
        investigation_id: investigationId ?? null,
        source: "gemini",
        status,
        latency_ms: latencyMs,
        error_message: errorMessage ?? null,
      });
    } catch (error) {
      logger.warn("[gemini] Audit logging failed", {
        error: error instanceof Error ? error.message : "Unknown audit error",
      });
    }
  }
}

function clamp(value: number): number {
  return Math.min(100, Math.max(0, Math.round(value)));
}

function isVerdict(value: unknown): value is GeminiVerdict {
  return (
    value === "clean" ||
    value === "suspicious" ||
    value === "malicious" ||
    value === "phishing" ||
    value === "unverified"
  );
}

function summarizeGeminiError(status: number, body: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: { message?: string; status?: string } };
    if (parsed.error?.message) {
      return `HTTP ${status}: ${parsed.error.message}`;
    }
  } catch {
    // Fall through to a truncated body.
  }
  return `HTTP ${status}: ${body.slice(0, 200) || "no response body"}`;
}

export const geminiClient = new GeminiClient();
export default geminiClient;
