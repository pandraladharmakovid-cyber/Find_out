import { redditClient, type RedditSearchResult } from "./integrations/reddit.client";
import { youtubeClient, type YouTubeSearchResult } from "./integrations/youtube.client";
import { evidenceCollectorService, type NormalizedEvidenceItem } from "./evidence";
import { logger } from "./utils/logger";

export interface SocialMonitoringQuery {
  brandName: string;
  associatedDomain?: string;
  investigationId?: string;
}

export interface ImpersonationSignal {
  platform: "reddit" | "youtube";
  signalType: "unauthorized_giveaway" | "phishing_lure" | "credential_harvesting" | "negative_community_alert";
  confidence: number;
  snippet: string;
  url: string;
}

export interface SocialScanResult {
  brandName: string;
  scannedAt: string;
  totalFindings: number;
  impersonationDetected: boolean;
  overallThreatScore: number;
  signals: ImpersonationSignal[];
  sources: Array<{
    source: "reddit" | "youtube";
    status: "available" | "unavailable";
    error?: string;
    candidatesFound: number;
  }>;
  redditData: RedditSearchResult;
  youtubeData: YouTubeSearchResult;
}

export class SocialMonitoringService {
  /**
   * Scans social media networks for brand impersonation and threat campaigns.
   */
  async scanBrandMentions(query: SocialMonitoringQuery): Promise<SocialScanResult> {
    logger.info("[social] Initiating cross-platform social threat scan", {
      brandName: query.brandName,
      domain: query.associatedDomain,
    });

    const searchQuery = query.associatedDomain 
      ? `"${query.brandName}" OR "${query.associatedDomain}"`
      : `"${query.brandName}"`;

    // 1. Concurrently query Reddit and YouTube adapters
    const [redditData, youtubeData] = await Promise.all([
      redditClient.searchDiscussions(searchQuery, query.investigationId),
      youtubeClient.searchVideos(searchQuery, query.investigationId),
    ]);

    const signals: ImpersonationSignal[] = [];

    // 2. Analyze Reddit findings for brand impersonation and community reports
    for (const post of redditData.posts) {
      const text = `${post.title} ${post.selftext}`.toLowerCase();
      
      if (text.includes("fake") || text.includes("scam") || text.includes("phishing")) {
        signals.push({
          platform: "reddit",
          signalType: "negative_community_alert",
          confidence: 80,
          snippet: post.title,
          url: post.permalink,
        });
      }

      if (text.includes("giveaway") || text.includes("free bonus") || text.includes("airdrop")) {
        signals.push({
          platform: "reddit",
          signalType: "unauthorized_giveaway",
          confidence: 75,
          snippet: post.title,
          url: post.permalink,
        });
      }
    }

    // 3. Analyze YouTube findings
    for (const video of youtubeData.videos) {
      const text = `${video.title} ${video.description}`.toLowerCase();

      if (text.includes("hack") || text.includes("crack") || text.includes("free download")) {
        signals.push({
          platform: "youtube",
          signalType: "phishing_lure",
          confidence: 85,
          snippet: video.title,
          url: video.videoUrl,
        });
      }

      if (text.includes("login issue") || text.includes("customer service support number")) {
        signals.push({
          platform: "youtube",
          signalType: "credential_harvesting",
          confidence: 90,
          snippet: video.title,
          url: video.videoUrl,
        });
      }
    }

    // 4. Calculate Threat Score (0 - 100)
    let overallThreatScore = 0;
    if (signals.length > 0) {
      const baseWeight = Math.min(60, signals.length * 15);
      const scamBonus = (redditData.hasScamSignals ? 20 : 0) + (youtubeData.hasScamSignals ? 20 : 0);
      overallThreatScore = Math.min(100, baseWeight + scamBonus);
    }

    // 5. If an investigation is provided, pipe the normalized findings to evidence storage
    if (query.investigationId) {
      const normalizedItems: NormalizedEvidenceItem[] = evidenceCollectorService.normalizeSignals({
        redditResult: redditData,
        youtubeResult: youtubeData,
      });

      if (normalizedItems.length > 0) {
        await evidenceCollectorService.recordEvidenceBatch(query.investigationId, normalizedItems);
      }
    }

    return {
      brandName: query.brandName,
      scannedAt: new Date().toISOString(),
      totalFindings: redditData.totalFound + youtubeData.totalFound,
      impersonationDetected: signals.length > 0,
      overallThreatScore,
      signals,
      sources: [
        {
          source: "reddit",
          status: redditData.rawPayload.error || redditData.rawPayload.skipped ? "unavailable" : "available",
          ...(typeof redditData.rawPayload.error === "string"
            ? { error: redditData.rawPayload.error }
            : typeof redditData.rawPayload.reason === "string"
              ? { error: redditData.rawPayload.reason }
              : {}),
          candidatesFound: redditData.totalFound,
        },
        {
          source: "youtube",
          status: youtubeData.rawPayload.error || youtubeData.rawPayload.skipped ? "unavailable" : "available",
          ...(typeof youtubeData.rawPayload.error === "string"
            ? { error: youtubeData.rawPayload.error }
            : typeof youtubeData.rawPayload.reason === "string"
              ? { error: youtubeData.rawPayload.reason }
              : {}),
          candidatesFound: youtubeData.totalFound,
        },
      ],
      redditData,
      youtubeData,
    };
  }
}

export const socialMonitoringService = new SocialMonitoringService();
export default socialMonitoringService;
