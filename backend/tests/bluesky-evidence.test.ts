import { describe, expect, it, vi } from "vitest";

vi.mock("../src/repositories", () => ({
  EvidenceRepository: {
    addBatch: vi.fn().mockResolvedValue(undefined),
    findByInvestigationId: vi.fn().mockResolvedValue([]),
  },
  ExclusionRulesRepository: {},
}));

import { EvidenceCollectorService } from "../src/evidence";
import { matchesOfficialAsset } from "../src/exclusion-engine.service";
import { EvidenceRepository } from "../src/repositories";
import { RiskScoringEngine } from "../src/risk";
import type {
  BlueskyPostFinding,
  BlueskySearchResult,
} from "../src/integrations/bluesky.client";

function makePost(text: string, id = "abc123"): BlueskyPostFinding {
  return {
    id: `at://did:plc:author/app.bsky.feed.post/${id}`,
    text,
    author: "author.bsky.social",
    authorDid: "did:plc:author",
    displayName: "Example Author",
    permalink: `https://bsky.app/profile/author.bsky.social/post/${id}`,
    likeCount: 3,
    createdAt: "2026-10-23T10:00:00.000Z",
  };
}

function makeResult(
  posts: BlueskyPostFinding[],
  rawPayload: Record<string, unknown> = { sourceStatus: "available" },
): BlueskySearchResult {
  return {
    source: "bluesky",
    query: "nexuspay.io",
    totalFound: posts.length,
    posts,
    hasScamSignals: false,
    confidence: 0,
    rawPayload,
  };
}

describe("Bluesky evidence normalization", () => {
  it("retains only target-relevant posts as unverified leads", () => {
    const relevant = makePost("A suspicious login page references nexuspay.io", "relevant");
    const unrelated = makePost("A general discussion about an unrelated service", "unrelated");
    const items = new EvidenceCollectorService().normalizeSignals({
      targetUrl: "https://nexuspay.io/login",
      blueskyResult: makeResult([relevant, unrelated]),
    });

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      source: "bluesky",
      sourceUrl: relevant.permalink,
      isVerified: false,
      reliabilityScore: 25,
    });
    expect(items[0]?.rawPayload.relevantToTarget).toBe(true);
  });

  it("does not attach unrelated posts to a generic example target", () => {
    const items = new EvidenceCollectorService().normalizeSignals({
      targetUrl: "https://example.com/",
      blueskyResult: makeResult([makePost("NexusPay support discussion")]),
    });

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      source: "bluesky",
      isVerified: false,
      reliabilityScore: 0,
    });
    expect(items[0]?.rawPayload.sourceStatus).toBe("available");
    expect(items[0]?.rawPayload.relevantResultCount).toBe(0);
    expect(items[0]?.extractedClaim).toContain("No specific non-generic investigation target");
  });

  it("preserves an unavailable provider status instead of reporting a clean search", () => {
    const items = new EvidenceCollectorService().normalizeSignals({
      targetUrl: "https://nexuspay.io/",
      blueskyResult: makeResult([], {
        sourceStatus: "unavailable",
        error: "Bluesky authentication failed (HTTP 401).",
      }),
    });

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      source: "bluesky",
      isVerified: false,
      reliabilityScore: 0,
    });
    expect(items[0]?.rawPayload.sourceStatus).toBe("unavailable");
    expect(items[0]?.extractedClaim).toContain("Bluesky was unavailable");
  });

  it("stores Bluesky evidence and keeps its low-reliability lead below the risk threshold", async () => {
    const collector = new EvidenceCollectorService();
    const items = collector.normalizeSignals({
      targetUrl: "https://nexuspay.io/login",
      blueskyResult: makeResult([
        makePost("A suspicious login page references nexuspay.io"),
      ]),
    });

    await collector.recordEvidenceBatch("investigation-1", items);

    expect(EvidenceRepository.addBatch).toHaveBeenCalledWith(
      "investigation-1",
      [
        expect.objectContaining({
          source: "bluesky",
          is_verified: false,
          reliability_score: 25,
        }),
      ],
    );
    const evaluation = new RiskScoringEngine().evaluate({
      evidenceItems: items,
      heuristicRiskScore: 0,
    });
    expect(
      evaluation.factors.find((factor) => factor.code === "community_signals")?.score,
    ).toBe(0);
  });
});

describe("Bluesky official-asset exclusion", () => {
  it("matches only the exact verified handle or canonical profile URL", () => {
    const officialAsset = {
      id: "asset-bluesky",
      brand_id: "brand-1",
      asset_type: "social_profile",
      platform: "bluesky",
      identifier: "brand.bsky.social",
      value: "brand.bsky.social",
      canonical_url: "https://bsky.app/profile/brand.bsky.social",
      is_verified: true,
      metadata: {},
      created_at: "2026-10-23T10:00:00.000Z",
    } as any;

    expect(matchesOfficialAsset({
      platform: "bluesky",
      identifier: "@Brand.bsky.social",
      url: "https://bsky.app/profile/brand.bsky.social/",
    }, officialAsset)).toBe(true);

    expect(matchesOfficialAsset({
      platform: "bluesky",
      identifier: "brand-support.bsky.social",
      url: "https://bsky.app/profile/brand-support.bsky.social",
    }, officialAsset)).toBe(false);
  });
});
