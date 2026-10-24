
import { EvidenceRepository, type EvidenceRecord } from "./repositories";
import { logger } from "./utils/logger";
import type { UrlhausCheckResult } from "./integrations/urlhaus.client";
import type { SafeBrowsingCheckResult } from "./integrations/safebrowsing.client";
import type { BlueskySearchResult } from "./integrations/bluesky.client";
import type { YouTubeSearchResult } from "./integrations/youtube.client";
import type { UrlSafetyAnalysis } from "./url-safety";
import type { GeminiAnalysisResult } from "./integrations/gemini.client";

export interface NormalizedEvidenceItem {
  source:
    | "urlhaus"
    | "safebrowsing"
    | "gemini"
    // Historical evidence remains readable; new social evidence uses Bluesky.
    | "reddit"
    | "bluesky"
    | "youtube"
    | "app_store"
    | "manual";
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
  normalizeSignals(inputs: {
    targetUrl?: string | null;
    urlhausResult?: UrlhausCheckResult;
    safeBrowsingResult?: SafeBrowsingCheckResult;
    blueskyResult?: BlueskySearchResult;
    youtubeResult?: YouTubeSearchResult;
    geminiResult?: GeminiAnalysisResult;
    urlSafetyAnalysis?: UrlSafetyAnalysis;
  }): NormalizedEvidenceItem[] {
    const items: NormalizedEvidenceItem[] = [];
    const targetUrl = inputs.targetUrl ?? null;
    let targetHost = "";
    let targetLabel = "";
    if (targetUrl) {
      try {
        targetHost = new URL(targetUrl).hostname.toLowerCase().replace(/^www\./, "");
        targetLabel = targetHost.split(".")[0] ?? "";
      } catch {
        targetHost = targetUrl.toLowerCase();
      }
    }
    const isGenericTarget = ["example.com", "localhost", "test.com"].includes(targetHost);

    const isRelevantText = (text: string): boolean => {
      if (!targetHost || isGenericTarget) return false;
      const lower = text.toLowerCase();
      return lower.includes(targetHost) || (targetLabel.length >= 5 && lower.includes(targetLabel));
    };

    // URLhaus: distinguish a confirmed match from no match or failure.
    if (inputs.urlhausResult) {
      const result = inputs.urlhausResult;
      const unavailable =
        result.status !== "available" ||
        result.confidence <= 0 ||
        result.rawPayload.skipped === true ||
        typeof result.rawPayload.error === "string";

      items.push({
        source: "urlhaus",
        sourceUrl: targetUrl,
        rawPayload: {
          ...result.rawPayload,
          sourceStatus: unavailable ? "unavailable" : "available",
        },
        isVerified: !unavailable && result.isMalicious,
        reliabilityScore: unavailable
          ? 0
          : result.isMalicious
            ? result.confidence
            : Math.min(result.confidence, 50),
        extractedClaim: unavailable
          ? "URLhaus lookup was unavailable; no conclusion can be drawn from this source."
          : result.isMalicious
            ? `URLhaus reported a threat: ${result.threatType ?? "unspecified threat"} (Status: ${result.status}).`
            : "URLhaus returned no active threat listing for this target; this does not prove the target is safe.",
      });
    }

    // Google Safe Browsing: preserve its explicit availability status.
    if (inputs.safeBrowsingResult) {
      const result = inputs.safeBrowsingResult;
      const available = result.status === "available";

      items.push({
        source: "safebrowsing",
        sourceUrl: targetUrl,
        rawPayload: {
          matches: result.rawMatches,
          sourceStatus: result.status,
          ...(result.error ? { error: result.error } : {}),
        },
        isVerified: available && result.isThreat,
        reliabilityScore: available
          ? result.isThreat
            ? result.confidence
            : Math.min(result.confidence, 50)
          : 0,
        extractedClaim: !available
          ? `Google Safe Browsing was unavailable: ${result.error ?? "reason not supplied"}. No conclusion can be drawn from this source.`
          : result.isThreat
            ? `Google Safe Browsing detected threat matches: ${result.threatTypes.join(", ")}.`
            : "Google Safe Browsing returned zero threat matches; this does not prove the target is safe.",
      });
    }

    // Bluesky: public posts are unverified leads, not confirmed threat intelligence.
    if (inputs.blueskyResult) {
      const result = inputs.blueskyResult;
      const available =
        result.rawPayload.sourceStatus === "available" &&
        result.rawPayload.skipped !== true &&
        typeof result.rawPayload.error !== "string";

      let blueskyTargetHost = "";
      if (targetUrl) {
        try {
          blueskyTargetHost = new URL(targetUrl).hostname
            .toLowerCase()
            .replace(/^www\./, "");
        } catch {
          // Without a valid target, posts are not promoted to target evidence.
        }
      }

      const blueskyTargetLabel = blueskyTargetHost.split(".")[0] ?? "";
      const genericBlueskyTarget = [
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "test.com",
      ].includes(blueskyTargetHost);
      const hasBlueskyTarget = Boolean(blueskyTargetHost);
      const isRelevantBlueskyText = (text: string): boolean => {
        if (!hasBlueskyTarget || genericBlueskyTarget) return false;
        const normalizedText = text.toLowerCase();
        const tokens: string[] = normalizedText.match(/[a-z0-9-]+/g) ?? [];
        return (
          normalizedText.includes(blueskyTargetHost) ||
          (blueskyTargetLabel.length >= 5 && tokens.includes(blueskyTargetLabel))
        );
      };

      if (!available) {
        const reason =
          typeof result.rawPayload.error === "string"
            ? result.rawPayload.error
            : typeof result.rawPayload.reason === "string"
              ? result.rawPayload.reason
              : "reason not supplied";
        items.push({
          source: "bluesky",
          sourceUrl: targetUrl,
          rawPayload: {
            ...result.rawPayload,
            sourceStatus: "unavailable",
            resultCount: 0,
          },
          isVerified: false,
          reliabilityScore: 0,
          extractedClaim: `Bluesky was unavailable: ${reason}. No conclusion can be drawn from this source.`,
        });
      } else {
        const relevantPosts = result.posts
          .filter((post) => isRelevantBlueskyText(post.text))
          .slice(0, 5);

        for (const post of relevantPosts) {
          const author = post.author ? `@${post.author}` : "an unknown author";
          const excerpt = post.text.replace(/\s+/g, " ").slice(0, 240) || "(no text)";
          items.push({
            source: "bluesky",
            sourceUrl: post.permalink || targetUrl,
            rawPayload: {
              ...post,
              sourceStatus: "available",
              relevantToTarget: true,
              relevanceMatch: "target-host-or-label",
            },
            isVerified: false,
            reliabilityScore: 25,
            extractedClaim:
              `Unverified Bluesky post by ${author}: "${excerpt}" (${post.likeCount} likes). ` +
              "This is a public discussion lead, not proof of impersonation or maliciousness.",
          });
        }

        if (relevantPosts.length === 0) {
          items.push({
            source: "bluesky",
            sourceUrl: targetUrl,
            rawPayload: {
              sourceStatus: "available",
              resultCount: result.totalFound,
              relevantResultCount: 0,
            },
            isVerified: false,
            reliabilityScore: 0,
            extractedClaim:
              !hasBlueskyTarget || genericBlueskyTarget
                ? "No specific non-generic investigation target was available; Bluesky posts were not treated as target evidence."
                : result.totalFound > 0
                  ? "Bluesky returned posts, but none mentioned the target host or label. They were not treated as target evidence."
                  : "Bluesky returned no posts for this query. This does not prove the target is safe.",
          });
        }
      }
    }

    // YouTube: search results are leads, not verified threat findings.
    if (inputs.youtubeResult) {
      const relevantVideos = inputs.youtubeResult.videos.filter((video) =>
        isRelevantText(`${video.title}${video.description}`)
      );

      for (const video of relevantVideos.slice(0, 5)) {
        items.push({
          source: "youtube",
          sourceUrl: video.videoUrl,
          rawPayload: { ...video, relevantToTarget: true },
          isVerified: false,
          reliabilityScore: 25,
          extractedClaim:
            `Unverified YouTube discussion by ${video.channelTitle}: "${video.title}". Relevance to the target requires verification.`,
        });
      }

      if (relevantVideos.length === 0) {
        items.push({
          source: "youtube",
          sourceUrl: targetUrl,
          rawPayload: { resultCount: inputs.youtubeResult.videos.length },
          isVerified: false,
          reliabilityScore: 0,
          extractedClaim:
            "No target-relevant YouTube discussions were returned. This is not evidence that the target is safe.",
        });
      }
    }

    // Gemini analysis is recorded as a model opinion, never as verified fact.
    if (inputs.geminiResult) {
      const result = inputs.geminiResult;
      const usable =
        result.status === "available" &&
        result.confidenceScore > 0 &&
        result.verdict !== "unverified";

      items.push({
        source: "gemini",
        sourceUrl: targetUrl,
        rawPayload: {
          sourceStatus: result.status,
          model: result.model,
          verdict: result.verdict,
          riskScore: result.riskScore,
          confidenceScore: result.confidenceScore,
          keyFindings: result.keyFindings,
          ...(result.status === "available" ? {} : { error: result.summary }),
        },
        isVerified: false,
        reliabilityScore: usable ? Math.min(60, result.confidenceScore) : 0,
        extractedClaim: usable
          ? `Gemini (${result.model}) assessed the target as "${result.verdict}" with risk ${result.riskScore}/100 and ${result.confidenceScore}% confidence. ` +
            `This is a model opinion, not a verified threat-intelligence match.`
          : `Gemini analysis was unavailable: ${result.summary}`,
      });
    }

    // Local heuristics are indicators, not external confirmation.
    if (inputs.urlSafetyAnalysis) {
      const analysis = inputs.urlSafetyAnalysis;

      items.push({
        source: "manual",
        sourceUrl: analysis.url,
        rawPayload: { ...analysis },
        isVerified: false,
        reliabilityScore: Math.min(analysis.riskScore, 70),
        extractedClaim:
          `Heuristic URL analysis calculated a risk score of ${analysis.riskScore}/100. ` +
          `Hostname keywords: [${analysis.suspiciousKeywordsFound.join(", ")}]. ` +
          `Entropy: ${analysis.entropy}. This is a heuristic signal, not a confirmed threat.`,
      });
    }

    return items;
  }

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
      items.map((item) => ({
        source: item.source,
        source_url: item.sourceUrl ?? null,
        raw_payload: item.rawPayload,
        is_verified: item.isVerified,
        reliability_score: item.reliabilityScore,
        extracted_claim: item.extractedClaim,
      }))
    );

    const storedRecords =
      await EvidenceRepository.findByInvestigationId(investigationId);

    const sourcesSurveyed = [
      ...new Set(storedRecords.map((record) => record.source)),
    ];

    const highConfidenceThreats = storedRecords.filter(
      (record) =>
        record.is_verified &&
        Number(record.reliability_score) >= 70
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
