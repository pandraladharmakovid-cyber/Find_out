import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  transactionQuery: vi.fn(),
  getBrand: vi.fn(),
  assets: vi.fn(),
  social: vi.fn(),
  apps: vi.fn(),
  alert: vi.fn(),
}));

vi.mock("../src/db", () => ({
  query: mocks.query,
  withTransaction: async (callback: (client: { query: typeof mocks.query }) => Promise<unknown>) =>
    callback({ query: mocks.query }),
}));
vi.mock("../src/brands", () => ({ brandService: { getBrandById: mocks.getBrand } }));
vi.mock("../src/repositories", () => ({
  BrandAssetsRepository: { findByBrandId: mocks.assets },
  ExclusionRulesRepository: { listActive: vi.fn() },
}));
vi.mock("../src/social", () => ({
  socialMonitoringService: { scanBrandMentions: mocks.social },
}));
vi.mock("../src/app-stores", () => ({
  appStoresMonitoringService: { scanAppStores: mocks.apps },
}));
vi.mock("../src/alerts", () => ({ alertsService: { createAlert: mocks.alert } }));

import { MonitoringService } from "../src/monitoring";

const blueskyPost = {
  id: "at://did:plc:author/app.bsky.feed.post/one",
  text: "General brand discussion",
  author: "author.bsky.social",
  authorDid: "did:plc:author",
  displayName: "Author",
  permalink: "https://bsky.app/profile/author.bsky.social/post/one",
  likeCount: 0,
  createdAt: "2026-10-23T10:00:00.000Z",
};

describe("Monitoring run reliability", () => {
  beforeEach(() => {
    mocks.query.mockReset();
    mocks.getBrand.mockReset();
    mocks.assets.mockReset();
    mocks.social.mockReset();
    mocks.apps.mockReset();
    mocks.alert.mockReset();
    mocks.assets.mockResolvedValue([]);
  });

  it("scopes candidate queries to both the selected brand and latest run", async () => {
    mocks.query.mockResolvedValue({ rows: [] });
    await new MonitoringService().getCandidates("brand-1", "run-1", { limit: 50, offset: 10 });

    const [sql, params] = mocks.query.mock.calls[0] ?? [];
    expect(String(sql)).toContain("WHERE c.brand_id = $1::uuid AND c.run_id = $2::uuid");
    expect(String(sql)).toContain("LIMIT $3 OFFSET $4");
    // Only the requested page is aggregated, which is what keeps the
    // findings page inside its latency budget.
    expect(String(sql)).toContain("WHERE ce.candidate_id IN (SELECT id FROM page)");
    expect(params).toEqual(["brand-1", "run-1", 50, 10]);
  });

  it("marks a run FAILED instead of leaving it IN_PROGRESS after a persistence error", async () => {
    mocks.getBrand.mockResolvedValue({
      id: "brand-1",
      name: "Brand",
      primary_domain: null,
      alternate_names: [],
    });
    mocks.social.mockResolvedValue({
      brandName: "Brand",
      scannedAt: new Date().toISOString(),
      totalFindings: 1,
      impersonationDetected: false,
      overallThreatScore: 0,
      signals: [],
      sources: [{ source: "bluesky", status: "available", candidatesFound: 1 }],
      blueskyData: {
        source: "bluesky",
        query: "Brand",
        totalFound: 1,
        posts: [blueskyPost],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { sourceStatus: "available" },
      },
      youtubeData: {
        source: "youtube",
        query: "Brand",
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: {},
      },
    });
    mocks.apps.mockResolvedValue({
      brandName: "Brand",
      officialDeveloperName: null,
      totalFound: 0,
      unauthorizedAppsCount: 0,
      findings: [],
      hasCriticalImpersonation: false,
      scannedAt: new Date().toISOString(),
      sources: [{ source: "apple_app_store", status: "available", candidatesFound: 0 }],
      logoComparisons: { compared: 0, unavailable: 0, notConfigured: 1 },
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("INSERT INTO monitoring_runs")) return { rows: [{ id: "run-1" }], rowCount: 1 };
      if (sql.includes("INSERT INTO discovered_candidates")) throw new Error("candidate insert failed");
      return { rows: [], rowCount: 1 };
    });

    await expect(new MonitoringService().runBrandScan("brand-1")).rejects.toThrow("candidate insert failed");

    const failureUpdate = mocks.query.mock.calls.find(([sql]) =>
      String(sql).includes("SET status = 'FAILED'"),
    );
    expect(failureUpdate).toBeDefined();
    expect(failureUpdate?.[1]?.[0]).toBe("run-1");
  });
});
