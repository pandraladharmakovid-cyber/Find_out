import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export type UrlhausSourceStatus = "available" | "unavailable" | "not_configured";

export interface UrlhausCheckResult {
  source: "urlhaus";
  status: UrlhausSourceStatus;
  isMalicious: boolean;
  threatType: string | null;
  urlStatus: "online" | "offline" | "unknown";
  confidence: number;
  error?: string;
  rawPayload: Record<string, unknown>;
}

interface UrlhausResponse {
  query_status?: string;
  url_status?: string;
  threat?: string;
  tags?: unknown;
  urls?: unknown;
  blacklists?: Record<string, unknown>;
  error?: string;
}

/**
 * URLhaus client.
 *
 * abuse.ch now requires an Auth-Key for the URLhaus API: unauthenticated calls
 * return HTTP 401. The previous client reported that as a generic failure and
 * still returned "not malicious", which produced conflicting availability
 * results between runs. The client now distinguishes:
 *
 *   not_configured - no URLHAUS_AUTH_KEY, so no call is made
 *   unavailable    - authentication/network/timeout failure, no conclusion
 *   available      - a real answer from URLhaus (match or no match)
 */
export class UrlhausClient {
  get configured(): boolean {
    return Boolean(config.URLHAUS_AUTH_KEY);
  }

  private get baseUrl(): string {
    return config.URLHAUS_API_URL.replace(/\/+$/, "");
  }

  async checkUrl(targetUrl: string, investigationId?: string): Promise<UrlhausCheckResult> {
    const startTime = Date.now();

    if (!this.configured) {
      logger.info("[urlhaus] No Auth-Key configured; lookup skipped.");
      await this.recordAudit(
        investigationId,
        "skipped",
        Date.now() - startTime,
        "URLHAUS_AUTH_KEY not configured; abuse.ch requires an Auth-Key.",
      );

      return {
        source: "urlhaus",
        status: "not_configured",
        isMalicious: false,
        threatType: null,
        urlStatus: "unknown",
        confidence: 0,
        error:
          "URLHAUS_AUTH_KEY is not configured. URLhaus (abuse.ch) requires an Auth-Key for API access since 2024.",
        rawPayload: { skipped: true, reason: "missing_auth_key" },
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);

    try {
      logger.info("[urlhaus] Querying URLhaus API", { targetUrl });

      const formBody = new URLSearchParams();
      formBody.append("url", targetUrl);

      const response = await fetch(`${this.baseUrl}/url/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Auth-Key": config.URLHAUS_AUTH_KEY,
          Accept: "application/json",
        },
        body: formBody,
        signal: controller.signal,
      });

      const rawBody = await response.text();
      const latencyMs = Date.now() - startTime;

      if (response.status === 401 || response.status === 403) {
        throw new UrlhausAuthError(
          "URLhaus rejected the configured Auth-Key (HTTP " +
            `${response.status}). Verify URLHAUS_AUTH_KEY at auth.abuse.ch.`,
        );
      }

      if (!response.ok) {
        throw new Error(`URLhaus returned HTTP ${response.status}: ${rawBody.slice(0, 160)}`);
      }

      let data: UrlhausResponse;
      try {
        data = JSON.parse(rawBody) as UrlhausResponse;
      } catch {
        throw new Error("URLhaus returned a non-JSON response.");
      }

      const queryStatus = String(data.query_status ?? "").toLowerCase();
      await this.recordAudit(investigationId, "success", latencyMs);

      if (queryStatus === "ok") {
        const urlStatus = data.url_status === "online" ? "online" : "offline";
        const threat = data.threat ?? "malware_download";

        return {
          source: "urlhaus",
          status: "available",
          isMalicious: true,
          threatType: threat,
          urlStatus,
          confidence: 95,
          rawPayload: { ...data },
        };
      }

      if (queryStatus === "no_results") {
        return {
          source: "urlhaus",
          status: "available",
          isMalicious: false,
          threatType: null,
          urlStatus: "unknown",
          confidence: 60,
          rawPayload: { ...data },
        };
      }

      // e.g. invalid_url / http_post_expected
      return {
        source: "urlhaus",
        status: "unavailable",
        isMalicious: false,
        threatType: null,
        urlStatus: "unknown",
        confidence: 0,
        error: `URLhaus did not complete the lookup (query_status: ${queryStatus || "unknown"}).`,
        rawPayload: { ...data },
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const isAuth = error instanceof UrlhausAuthError;
      const errorMessage =
        error instanceof Error
          ? error.name === "AbortError"
            ? `URLhaus did not respond within ${Math.round(config.REQUEST_TIMEOUT_MS / 1000)}s.`
            : error.message
          : "Unknown URLhaus error";

      logger.warn("[urlhaus] Query failed", { targetUrl, error: errorMessage, auth: isAuth });

      await this.recordAudit(investigationId, "failed", latencyMs, errorMessage);

      return {
        source: "urlhaus",
        status: "unavailable",
        isMalicious: false,
        threatType: null,
        urlStatus: "unknown",
        confidence: 0,
        error: errorMessage,
        rawPayload: { error: errorMessage, authFailure: isAuth, skipped: true },
      };
    } finally {
      clearTimeout(timeout);
    }
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
        source: "urlhaus",
        status,
        latency_ms: latencyMs,
        error_message: errorMessage ?? null,
      });
    } catch (error) {
      logger.warn("[urlhaus] Audit logging failed", {
        error: error instanceof Error ? error.message : "Unknown audit error",
      });
    }
  }
}

class UrlhausAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UrlhausAuthError";
  }
}

export const urlhausClient = new UrlhausClient();
export default urlhausClient;
