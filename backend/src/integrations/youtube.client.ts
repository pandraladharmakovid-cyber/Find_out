import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export interface YouTubeVideoFinding {
  videoId: string;
  channelId: string;
  title: string;
  description: string;
  channelTitle: string;
  publishedAt: string;
  videoUrl: string;
}

export interface YouTubeSearchResult {
  source: "youtube";
  query: string;
  totalFound: number;
  videos: YouTubeVideoFinding[];
  hasScamSignals: boolean;
  confidence: number;
  rawPayload: Record<string, unknown>;
}

export class YouTubeClient {
  private readonly baseUrl = "https://www.googleapis.com/youtube/v3/search";

  /**
   * Searches YouTube for videos promoting or exposing the target entity.
   */
  async searchVideos(
    searchQuery: string,
    investigationId?: string
  ): Promise<YouTubeSearchResult> {
    const startTime = Date.now();

    if (!config.YOUTUBE_API_KEY) {
      logger.info("[youtube] YouTube API key missing in .env. Returning clean baseline.");
      return {
        source: "youtube",
        query: searchQuery,
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { skipped: true, reason: "Missing API key" },
      };
    }

    try {
      logger.info("[youtube] Querying YouTube Data API", { searchQuery });

      const params = new URLSearchParams({
        part: "snippet",
        q: searchQuery,
        type: "video",
        maxResults: "10",
        key: config.YOUTUBE_API_KEY,
      });

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        config.REQUEST_TIMEOUT_MS
      );

      const response = await fetch(`${this.baseUrl}?${params.toString()}`, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        throw new Error(`YouTube API returned status ${response.status}`);
      }

      const json = (await response.json()) as {
        items?: Array<{
          id?: { videoId?: string };
          snippet?: {
            title?: string;
            description?: string;
            channelTitle?: string;
            channelId?: string;
            publishedAt?: string;
          };
        }>;
      };

      const items = json.items ?? [];
      const videos: YouTubeVideoFinding[] = items
        .filter((item) => item.id?.videoId)
        .map((item) => {
          const videoId = item.id?.videoId as string;
          return {
            videoId,
            channelId: item.snippet?.channelId ?? "",
            title: item.snippet?.title ?? "",
            description: (item.snippet?.description ?? "").substring(0, 1000),
            channelTitle: item.snippet?.channelTitle ?? "",
            publishedAt: item.snippet?.publishedAt ?? "",
            videoUrl: `https://www.youtube.com/watch?v=${videoId}`,
          };
        });

      // Scan for suspicious promotional keywords or warnings
      const suspiciousTerms = ["giveaway", "free money", "hack", "cracked", "scam review", "urgent warning", "crypto doubler"];
      const hasScamSignals = videos.some((v) => {
        const text = `${v.title} ${v.description}`.toLowerCase();
        return suspiciousTerms.some((term) => text.includes(term));
      });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "youtube",
        status: "success",
        latency_ms: latencyMs,
      });

      return {
        source: "youtube",
        query: searchQuery,
        totalFound: videos.length,
        videos,
        hasScamSignals,
        confidence: videos.length > 0 ? 80.0 : 50.0,
        rawPayload: { totalCount: videos.length, scamSignals: hasScamSignals },
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : "Unknown error";

      logger.warn("[youtube] Search failed or timed out", { error: errorMessage });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "youtube",
        status: "failed",
        latency_ms: latencyMs,
        error_message: errorMessage,
      });

      return {
        source: "youtube",
        query: searchQuery,
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { error: errorMessage },
      };
    }
  }
}

export const youtubeClient = new YouTubeClient();
export default youtubeClient;