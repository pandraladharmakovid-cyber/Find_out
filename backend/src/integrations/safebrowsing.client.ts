
import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export interface SafeBrowsingMatch {
  threatType: string;
  platformType: string;
  threatEntryType: string;
}

export interface SafeBrowsingCheckResult {
  source: "safebrowsing";
  status: "available" | "unavailable";
  isThreat: boolean;
  threatTypes: string[];
  rawMatches: SafeBrowsingMatch[];
  confidence: number;
  error?: string;
}

export class SafeBrowsingClient {
  private readonly baseUrl =
    "https://safebrowsing.googleapis.com/v4/threatMatches:find";

  async checkUrl(
    targetUrl: string,
    investigationId?: string,
  ): Promise<SafeBrowsingCheckResult> {
    const startTime = Date.now();

    if (!config.GOOGLE_SAFE_BROWSING_API_KEY) {
      logger.warn(
        "[safebrowsing] API key missing; lookup was not performed.",
      );

      return {
        source: "safebrowsing",
        status: "unavailable",
        isThreat: false,
        threatTypes: [],
        rawMatches: [],
        confidence: 0,
        error: "Google Safe Browsing API key is not configured.",
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      config.REQUEST_TIMEOUT_MS,
    );

    try {
      const response = await fetch(
        `${this.baseUrl}?key=${encodeURIComponent(config.GOOGLE_SAFE_BROWSING_API_KEY)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: {
              clientId: "find-out-security-engine",
              clientVersion: "1.0.0",
            },
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: targetUrl }],
            },
          }),
          signal: controller.signal,
        },
      );

      if (!response.ok) {
        throw new Error(
          `Google Safe Browsing returned HTTP status ${response.status}`,
        );
      }

      const data = (await response.json()) as {
        matches?: SafeBrowsingMatch[];
      };

      const matches = data.matches ?? [];
      const threatTypes = [
        ...new Set(matches.map((match) => match.threatType)),
      ];

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "safebrowsing",
        status: "success",
        latency_ms: Date.now() - startTime,
      });

      return {
        source: "safebrowsing",
        status: "available",
        isThreat: matches.length > 0,
        threatTypes,
        rawMatches: matches,
        confidence: matches.length > 0 ? 95 : 90,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      logger.warn("[safebrowsing] Lookup failed or timed out", {
        error: errorMessage,
      });

      try {
        await AuditLogsRepository.recordLog({
          investigation_id: investigationId,
          source: "safebrowsing",
          status: "failed",
          latency_ms: Date.now() - startTime,
          error_message: errorMessage,
        });
      } catch (auditError) {
        logger.error("[safebrowsing] Failed to record audit log", {
          error:
            auditError instanceof Error
              ? auditError.message
              : "Unknown audit error",
        });
      }

      return {
        source: "safebrowsing",
        status: "unavailable",
        isThreat: false,
        threatTypes: [],
        rawMatches: [],
        confidence: 0,
        error: errorMessage,
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}

export const safeBrowsingClient = new SafeBrowsingClient();
export default safeBrowsingClient;
