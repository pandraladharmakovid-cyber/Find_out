import { blueskyClient, type BlueskySearchResult } from "./integrations/bluesky.client";
import { youtubeClient, type YouTubeSearchResult } from "./integrations/youtube.client";
import { evidenceCollectorService, type NormalizedEvidenceItem } from "./evidence";
import { logger } from "./utils/logger";

export interface SocialMonitoringQuery {
  brandName: string;
  associatedDomain?: string;
  investigationId?: string;
}

export interface ImpersonationSignal {
  platform: "bluesky" | "youtube";
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
    source: "bluesky" | "youtube";
    status: "available" | "unavailable";
    error?: string;
    candidatesFound: number;
  }>;
  blueskyData: BlueskySearchResult;
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

    // Concurrently query Bluesky and YouTube adapters.
    const [blueskyData, youtubeData] = await Promise.all([
      blueskyClient.searchDiscussions(searchQuery, query.investigationId),
      youtubeClient.searchVideos(searchQuery, query.investigationId),
    ]);

    const signals: ImpersonationSignal[] = [];

    // Analyze Bluesky findings for brand impersonation and community reports.
    for (const post of blueskyData.posts) {
      const text = post.text.toLowerCase();
      const snippet = post.text.slice(0, 280);

      if (text.includes("fake") || text.includes("scam") || text.includes("phishing")) {
        signals.push({
          platform: "bluesky",
          signalType: "negative_community_alert",
          confidence: 80,
          snippet,
          url: post.permalink,
        });
      }

      if (text.includes("giveaway") || text.includes("free bonus") || text.includes("airdrop")) {
        signals.push({
          platform: "bluesky",
          signalType: "unauthorized_giveaway",
          confidence: 75,
          snippet,
          url: post.permalink,
        });
      }
    }

    // Analyze YouTube findings without changing the existing provider behavior.
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

    // Preserve the existing transparent threat-score calculation.
    let overallThreatScore = 0;
    if (signals.length > 0) {
      const baseWeight = Math.min(60, signals.length * 15);
      const scamBonus = (blueskyData.hasScamSignals ? 20 : 0) + (youtubeData.hasScamSignals ? 20 : 0);
      overallThreatScore = Math.min(100, baseWeight + scamBonus);
    }

    // If an investigation is provided, pipe normalized findings to evidence storage.
    if (query.investigationId) {
      const normalizedItems: NormalizedEvidenceItem[] = evidenceCollectorService.normalizeSignals({
        blueskyResult: blueskyData,
        youtubeResult: youtubeData,
      });

      if (normalizedItems.length > 0) {
        await evidenceCollectorService.recordEvidenceBatch(query.investigationId, normalizedItems);
      }
    }

    return {
      brandName: query.brandName,
      scannedAt: new Date().toISOString(),
      totalFindings: blueskyData.totalFound + youtubeData.totalFound,
      impersonationDetected: signals.length > 0,
      overallThreatScore,
      signals,
      sources: [
        {
          source: "bluesky",
          status: blueskyData.rawPayload.sourceStatus === "available" ? "available" : "unavailable",
          ...(typeof blueskyData.rawPayload.error === "string"
            ? { error: blueskyData.rawPayload.error }
            : typeof blueskyData.rawPayload.reason === "string"
              ? { error: blueskyData.rawPayload.reason }
              : {}),
          candidatesFound: blueskyData.totalFound,
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
      blueskyData,
      youtubeData,
    };
  }
}

export const socialMonitoringService = new SocialMonitoringService();
export default socialMonitoringService;
