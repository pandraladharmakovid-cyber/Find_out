import { EvidenceRepository, type EvidenceRecord } from "./repositories";
import { logger } from "./utils/logger";
import type { UrlhausCheckResult } from "./integrations/urlhaus.client";
import type { SafeBrowsingCheckResult } from "./integrations/safebrowsing.client";
import type { RedditSearchResult } from "./integrations/reddit.client";
import type { YouTubeSearchResult } from "./integrations/youtube.client";
import type { UrlSafetyAnalysis } from "./url-safety";

export interface NormalizedEvidenceItem {
  source: "urlhaus" | "safebrowsing" | "gemini" | "reddit" | "youtube" | "app_store" | "manual";
  sourceUrl?: string | null;
  rawPayload: Record<string, unknown>;
  isVerified: boolean;
  reliabilityScore: number;
  extractedClaim: string | null;
}

export interface CollectedEvidenceSummary {
  investigationId: string;
  totalItems: number;
  highConfidenceThreats: number;
  sourcesSurveyed: string[];
  evidenceList: EvidenceRecord[];
}

export class EvidenceCollectorService {
  /**
   * Normalizes disparate source outputs into standard evidence records.
   */
  normalizeSignals(inputs: {
    targetUrl?: string | null;
    urlhausResult?: UrlhausCheckResult;
    safeBrowsingResult?: SafeBrowsingCheckResult;
    redditResult?: RedditSearchResult;
    youtubeResult?: YouTubeSearchResult;
    urlSafetyAnalysis?: UrlSafetyAnalysis;
  }): NormalizedEvidenceItem[] {
    const items: NormalizedEvidenceItem[] = [];

    // 1. Process URLhaus findings
    if (inputs.urlhausResult) {
      items.push({
        source: "urlhaus",
        sourceUrl: inputs.targetUrl ?? null,
        rawPayload: inputs.urlhausResult.rawPayload,
        isVerified: inputs.urlhausResult.isMalicious,
        reliabilityScore: inputs.urlhausResult.confidence,
        extractedClaim: inputs.urlhausResult.isMalicious
          ? `URLhaus confirmed active threat: ${inputs.urlhausResult.threatType ?? "Malware/Phishing"} (Status: ${inputs.urlhausResult.status})`
          : "URLhaus reported no active threat listings for target.",
      });
    }

    // 2. Process Google Safe Browsing findings
    if (inputs.safeBrowsingResult) {
      items.push({
        source: "safebrowsing",
        sourceUrl: inputs.targetUrl ?? null,
        rawPayload: { matches: inputs.safeBrowsingResult.rawMatches },
        isVerified: inputs.safeBrowsingResult.isThreat,
        reliabilityScore: inputs.safeBrowsingResult.confidence,
        extractedClaim: inputs.safeBrowsingResult.isThreat
          ? `Google Safe Browsing threat match detected: ${inputs.safeBrowsingResult.threatTypes.join(", ")}`
          : "Google Safe Browsing reported zero threat list matches.",
      });
    }

    // 3. Process Reddit social community signals
    if (inputs.redditResult && inputs.redditResult.posts.length > 0) {
      for (const post of inputs.redditResult.posts.slice(0, 5)) {
        items.push({
          source: "reddit",
          sourceUrl: post.permalink,
          rawPayload: { ...post },
          isVerified: false,
          reliabilityScore: inputs.redditResult.hasScamSignals ? 75.0 : 50.0,
          extractedClaim: `Community discussion on r/${post.subreddit}: "${post.title}" (Score: ${post.score})`,
        });
      }
    }

    // 4. Process YouTube video signals
    if (inputs.youtubeResult && inputs.youtubeResult.videos.length > 0) {
      for (const video of inputs.youtubeResult.videos.slice(0, 5)) {
        items.push({
          source: "youtube",
          sourceUrl: video.videoUrl,
          rawPayload: { ...video },
          isVerified: false,
          reliabilityScore: inputs.youtubeResult.hasScamSignals ? 70.0 : 45.0,
          extractedClaim: `YouTube video by ${video.channelTitle}: "${video.title}"`,
        });
      }
    }

    // 5. Process Heuristic URL Safety engine
    if (inputs.urlSafetyAnalysis) {
      items.push({
        source: "manual",
        sourceUrl: inputs.urlSafetyAnalysis.url,
        rawPayload: { ...inputs.urlSafetyAnalysis },
        isVerified: inputs.urlSafetyAnalysis.riskScore > 50,
        reliabilityScore: 85.0,
        extractedClaim: `Static URL heuristic analysis calculated risk ${inputs.urlSafetyAnalysis.riskScore}/100. Keywords detected: [${inputs.urlSafetyAnalysis.suspiciousKeywordsFound.join(", ")}]. Entropy: ${inputs.urlSafetyAnalysis.entropy}.`,
      });
    }

    return items;
  }

  /**
   * Persists normalized items into the evidence database and retrieves full investigation history.
   */
  async recordEvidenceBatch(
    investigationId: string,
    items: NormalizedEvidenceItem[]
  ): Promise<CollectedEvidenceSummary> {
    logger.info("[evidence] Persisting collected evidence batch", {
      investigationId,
      itemCount: items.length,
    });

    await EvidenceRepository.addBatch(
      investigationId,
      items.map((i) => ({
        source: i.source,
        source_url: i.sourceUrl ?? null,
        raw_payload: i.rawPayload,
        is_verified: i.isVerified,
        reliability_score: i.reliabilityScore,
        extracted_claim: i.extractedClaim,
      }))
    );

    const storedRecords = await EvidenceRepository.findByInvestigationId(investigationId);
    const sourcesSurveyed = [...new Set(storedRecords.map((r) => r.source))];
    const highConfidenceThreats = storedRecords.filter(
      (r) => r.is_verified && Number(r.reliability_score) >= 70
    ).length;

    return {
      investigationId,
      totalItems: storedRecords.length,
      highConfidenceThreats,
      sourcesSurveyed,
      evidenceList: storedRecords,
    };
  }
}

export const evidenceCollectorService = new EvidenceCollectorService();
export default evidenceCollectorService;