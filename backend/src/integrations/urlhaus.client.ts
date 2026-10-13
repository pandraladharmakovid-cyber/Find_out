import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export interface UrlhausCheckResult {
  source: "urlhaus";
  isMalicious: boolean;
  threatType: string | null;
  status: "online" | "offline" | "unknown";
  confidence: number;
  rawPayload: Record<string, unknown>;
}

export class UrlhausClient {
  private readonly baseUrl = "https://urlhaus-api.abuse.ch/v1";

  /**
   * Scans a target URL against the URLhaus database for active malware/phishing payloads.
   */
  async checkUrl(
    targetUrl: string,
    investigationId?: string
  ): Promise<UrlhausCheckResult> {
    const startTime = Date.now();

    try {
      logger.info("[urlhaus] Querying URLhaus API", { targetUrl });

      const formBody = new URLSearchParams();
      formBody.append("url", targetUrl);

      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
      };

      if (config.URLHAUS_AUTH_KEY) {
        headers["Auth-Key"] = config.URLHAUS_AUTH_KEY;
      }

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        config.REQUEST_TIMEOUT_MS
      );

      const response = await fetch(`${this.baseUrl}/url/`, {
        method: "POST",
        headers,
        body: formBody,
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        throw new Error(`URLhaus returned HTTP status ${response.status}`);
      }

      const data = (await response.json()) as Record<string, unknown>;
      const queryStatus = data.query_status as string;

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "urlhaus",
        status: "success",
        latency_ms: latencyMs,
      });

      if (queryStatus === "ok") {
        const urlStatus = (data.url_status as string) || "unknown";
        const threat = (data.threat as string) || "malware_download";

        return {
          source: "urlhaus",
          isMalicious: true,
          threatType: threat,
          status: urlStatus === "online" ? "online" : "offline",
          confidence: 95.0,
          rawPayload: data,
        };
      }

      return {
        source: "urlhaus",
        isMalicious: false,
        threatType: null,
        status: "unknown",
        confidence: 85.0,
        rawPayload: data,
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      logger.warn("[urlhaus] Query failed or timed out", {
        targetUrl,
        error: errorMessage,
      });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "urlhaus",
        status: "failed",
        latency_ms: latencyMs,
        error_message: errorMessage,
      });

      // Graceful fallback for threat intelligence failure
      return {
        source: "urlhaus",
        isMalicious: false,
        threatType: null,
        status: "unknown",
        confidence: 0,
        rawPayload: { error: errorMessage, skipped: true },
      };
    }
  }
}

export const urlhausClient = new UrlhausClient();
export default urlhausClient;
