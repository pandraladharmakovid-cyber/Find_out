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
  isThreat: boolean;
  threatTypes: string[];
  rawMatches: SafeBrowsingMatch[];
  confidence: number;
}

export class SafeBrowsingClient {
  private readonly baseUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

  /**
   * Checks a URL against Google Safe Browsing v4 threat lists (Malware, Social Engineering, Unwanted Software).
   */
  async checkUrl(
    targetUrl: string,
    investigationId?: string
  ): Promise<SafeBrowsingCheckResult> {
    const startTime = Date.now();

    // If API key is not configured, record graceful skip and return unflagged baseline
    if (!config.GOOGLE_SAFE_BROWSING_API_KEY) {
      logger.info("[safebrowsing] Google Safe Browsing API key missing. Skipping lookup.");
      return {
        source: "safebrowsing",
        isThreat: false,
        threatTypes: [],
        rawMatches: [],
        confidence: 0,
      };
    }

    try {
      logger.info("[safebrowsing] Querying Safe Browsing threat lists", { targetUrl });

      const requestBody = {
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
      };

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        config.REQUEST_TIMEOUT_MS
      );

      const response = await fetch(
        `${this.baseUrl}?key=${config.GOOGLE_SAFE_BROWSING_API_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        }
      );

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        throw new Error(`Google Safe Browsing returned HTTP status ${response.status}`);
      }

      const data = (await response.json()) as { matches?: SafeBrowsingMatch[] };
      const matches = data.matches ?? [];
      const isThreat = matches.length > 0;
      const threatTypes = [...new Set(matches.map((m) => m.threatType))];

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "safebrowsing",
        status: "success",
        latency_ms: latencyMs,
      });

      return {
        source: "safebrowsing",
        isThreat,
        threatTypes,
        rawMatches: matches,
        confidence: isThreat ? 95.0 : 90.0,
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      logger.warn("[safebrowsing] Lookup failed or timed out", {
        targetUrl,
        error: errorMessage,
      });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "safebrowsing",
        status: "failed",
        latency_ms: latencyMs,
        error_message: errorMessage,
      });

      // Graceful degraded mode
      return {
        source: "safebrowsing",
        isThreat: false,
        threatTypes: [],
        rawMatches: [],
        confidence: 0,
      };
    }
  }
}

export const safeBrowsingClient = new SafeBrowsingClient();
export default safeBrowsingClient;