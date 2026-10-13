import { config } from "../config";
import { logger } from "../utils/logger";
import { AuditLogsRepository } from "../repositories";

export interface RedditPostFinding {
  id: string;
  title: string;
  author: string;
  subreddit: string;
  permalink: string;
  score: number;
  createdUtc: number;
  selftext: string;
}

export interface RedditSearchResult {
  source: "reddit";
  query: string;
  totalFound: number;
  posts: RedditPostFinding[];
  hasScamSignals: boolean;
  confidence: number;
  rawPayload: Record<string, unknown>;
}

export class RedditClient {
  private readonly authUrl = "https://www.reddit.com/api/v1/access_token";
  private readonly apiBaseUrl = "https://oauth.reddit.com";
  private accessToken: string | null = null;
  private tokenExpiresAt = 0;

  /**
   * Acquires or reuses an OAuth2 Application-Only Bearer Token from Reddit.
   */
  private async getAccessToken(): Promise<string | null> {
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60000) {
      return this.accessToken;
    }

    if (!config.REDDIT_CLIENT_ID || !config.REDDIT_CLIENT_SECRET) {
      return null;
    }

    const credentials = Buffer.from(
      `${config.REDDIT_CLIENT_ID}:${config.REDDIT_CLIENT_SECRET}`
    ).toString("base64");

    const params = new URLSearchParams();
    params.append("grant_type", "client_credentials");

    const response = await fetch(this.authUrl, {
      method: "POST",
      headers: {
        Authorization: `Basic ${credentials}`,
        "User-Agent": config.REDDIT_USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    if (!response.ok) {
      throw new Error(`Reddit auth failed with HTTP ${response.status}`);
    }

    const data = (await response.json()) as {
      access_token: string;
      expires_in: number;
    };

    this.accessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + data.expires_in * 1000;
    return this.accessToken;
  }

  /**
   * Searches Reddit for mentions, community warnings, or scam discussions around a brand/URL.
   */
  async searchDiscussions(
    searchQuery: string,
    investigationId?: string
  ): Promise<RedditSearchResult> {
    const startTime = Date.now();

    if (!config.REDDIT_CLIENT_ID || !config.REDDIT_CLIENT_SECRET) {
      logger.info("[reddit] Reddit API credentials missing in .env. Returning clean baseline.");
      return {
        source: "reddit",
        query: searchQuery,
        totalFound: 0,
        posts: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { skipped: true, reason: "Missing credentials" },
      };
    }

    try {
      logger.info("[reddit] Searching Reddit discussions", { searchQuery });

      const token = await this.getAccessToken();
      if (!token) {
        throw new Error("Unable to obtain Reddit access token");
      }

      const encodedQuery = encodeURIComponent(searchQuery);
      const url = `${this.apiBaseUrl}/search?q=${encodedQuery}&sort=relevance&limit=15&type=link`;

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        config.REQUEST_TIMEOUT_MS
      );

      const response = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "User-Agent": config.REDDIT_USER_AGENT,
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        throw new Error(`Reddit API returned status ${response.status}`);
      }

      const json = (await response.json()) as {
        data?: {
          children?: Array<{
            data?: {
              id: string;
              title: string;
              author: string;
              subreddit: string;
              permalink: string;
              score: number;
              created_utc: number;
              selftext: string;
            };
          }>;
        };
      };

      const children = json.data?.children ?? [];
      const posts: RedditPostFinding[] = children.map((item) => ({
        id: item.data?.id ?? "",
        title: item.data?.title ?? "",
        author: item.data?.author ?? "",
        subreddit: item.data?.subreddit ?? "",
        permalink: `https://www.reddit.com${item.data?.permalink ?? ""}`,
        score: item.data?.score ?? 0,
        createdUtc: item.data?.created_utc ?? 0,
        selftext: (item.data?.selftext ?? "").substring(0, 1000),
      }));

      // Threat keyword detection in community threads
      const scamKeywords = ["scam", "fake", "phishing", "fraud", "stolen", "malware", "impersonator"];
      const hasScamSignals = posts.some((post) => {
        const fullText = `${post.title} ${post.selftext}`.toLowerCase();
        return scamKeywords.some((kw) => fullText.includes(kw));
      });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "reddit",
        status: "success",
        latency_ms: latencyMs,
      });

      return {
        source: "reddit",
        query: searchQuery,
        totalFound: posts.length,
        posts,
        hasScamSignals,
        confidence: posts.length > 0 ? 80.0 : 50.0,
        rawPayload: { postCount: posts.length, scamKeywordsDetected: hasScamSignals },
      };
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : "Unknown error";

      logger.warn("[reddit] Discussion search failed", { error: errorMessage });

      await AuditLogsRepository.recordLog({
        investigation_id: investigationId,
        source: "reddit",
        status: "failed",
        latency_ms: latencyMs,
        error_message: errorMessage,
      });

      return {
        source: "reddit",
        query: searchQuery,
        totalFound: 0,
        posts: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { error: errorMessage },
      };
    }
  }
}

export const redditClient = new RedditClient();
export default redditClient;