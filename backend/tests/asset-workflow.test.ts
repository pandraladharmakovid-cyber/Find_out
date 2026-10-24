import { beforeEach, describe, expect, it, vi } from "vitest";
import { hashVerificationToken } from "../src/asset-proof";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  clientQuery: vi.fn(),
  withTransaction: vi.fn(),
  addRule: vi.fn(),
  proofDomain: vi.fn(),
  proofManifest: vi.fn(),
  safeBrowsing: vi.fn(),
  urlhaus: vi.fn(),
}));

vi.mock("../src/db", () => ({
  query: mocks.query,
  withTransaction: mocks.withTransaction,
}));
vi.mock("../src/repositories", () => ({
  ExclusionRulesRepository: { addRule: mocks.addRule },
}));
vi.mock("../src/asset-proof", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/asset-proof")>();
  return {
    ...actual,
    assetProofService: {
      verifyDomainChallenge: mocks.proofDomain,
      verifyVerifiedDomainManifest: mocks.proofManifest,
    },
  };
});
vi.mock("../src/integrations/safebrowsing.client", () => ({
  safeBrowsingClient: { checkUrl: mocks.safeBrowsing },
}));
vi.mock("../src/integrations/urlhaus.client", () => ({
  urlhausClient: { checkUrl: mocks.urlhaus },
}));

import { AssetService, AssetVerificationError, type OfficialAssetRecord } from "../src/assets";

function asset(overrides: Record<string, unknown> = {}): OfficialAssetRecord {
  return {
    id: "asset-1",
    brand_id: "brand-1",
    asset_type: "domain",
    platform: "website",
    identifier: "example.com",
    value: "example.com",
    canonical_url: "https://example.com/",
    hash_signature: null,
    is_verified: false,
    verification_status: "PENDING_VERIFICATION",
    verification_method: null,
    verification_evidence: {},
    verified_at: null,
    verified_by: null,
    revoked_at: null,
    revocation_reason: null,
    safety_status: "NOT_ASSESSED",
    safety_evidence: {},
    metadata: {},
    created_at: "2026-10-23T10:00:00.000Z",
    updated_at: "2026-10-23T10:00:00.000Z",
    ...overrides,
  } as OfficialAssetRecord;
}

function challenge(expiresAt = new Date(Date.now() + 60_000).toISOString()) {
  return {
    id: "challenge-1",
    asset_id: "asset-1",
    method: "DNS_TXT",
    token_hash: hashVerificationToken("proof-token"),
    expires_at: expiresAt,
    consumed_at: null,
    superseded_at: null,
  };
}

describe("Server-enforced official asset workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.withTransaction.mockImplementation(async (callback) =>
      callback({ query: mocks.clientQuery }),
    );
    mocks.addRule.mockResolvedValue({ id: "rule-1" });
    mocks.safeBrowsing.mockResolvedValue({
      status: "available",
      isThreat: false,
      threatTypes: [],
    });
    mocks.urlhaus.mockResolvedValue({
      isMalicious: false,
      threatType: null,
      confidence: 85,
      rawPayload: {},
    });
  });

  it("stores new submissions as pending and creates no official exclusion", async () => {
    const pending = asset();
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT id FROM brands")) return { rows: [{ id: "brand-1" }] };
      if (sql.includes("INSERT INTO official_assets")) return { rows: [pending] };
      return { rows: [], rowCount: 0 };
    });

    const result = await new AssetService().registerAsset({
      brandId: "brand-1",
      assetType: "domain",
      platform: "website",
      value: "Example.com",
      canonicalUrl: "https://example.com/",
    });

    expect(result.created).toBe(true);
    expect(result.asset.verification_status).toBe("PENDING_VERIFICATION");
    expect(result.asset.is_verified).toBe(false);
    expect(mocks.addRule).not.toHaveBeenCalled();
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("'PENDING_VERIFICATION'"),
      expect.any(Array),
    );
  });

  it("verifies a correct domain challenge and links its exclusion transactionally", async () => {
    const pending = asset();
    const verified = asset({
      is_verified: true,
      verification_status: "VERIFIED",
      verification_method: "DNS_TXT",
      safety_status: "NO_THREAT_MATCH",
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT primary_domain FROM brands")) return { rows: [{ primary_domain: "example.com" }] };
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      return { rows: [pending] };
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      if (sql.includes("UPDATE official_assets")) return { rows: [verified] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [pending] };
      return { rows: [], rowCount: 1 };
    });
    mocks.proofDomain.mockResolvedValue({
      method: "DNS_TXT",
      domain: "example.com",
      checkedAt: new Date().toISOString(),
    });

    const result = await new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    });

    expect(result.verification_status).toBe("VERIFIED");
    expect(mocks.proofDomain).toHaveBeenCalledWith({
      domain: "example.com",
      method: "DNS_TXT",
      token: "proof-token",
    });
    expect(mocks.addRule).toHaveBeenCalledWith(
      "example.com",
      expect.any(String),
      "asset-1",
      "brand-1",
      expect.objectContaining({ query: mocks.clientQuery }),
    );
  });

  it("requires both domain control and a verified-brand declaration for an additional domain", async () => {
    const additional = asset({
      identifier: "cdn.example.com",
      value: "cdn.example.com",
      canonical_url: "https://cdn.example.com/",
    });
    const verified = asset({
      ...additional,
      is_verified: true,
      verification_status: "VERIFIED",
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT primary_domain FROM brands")) return { rows: [{ primary_domain: "example.com" }] };
      if (sql.includes("SELECT value FROM official_assets")) return { rows: [{ value: "example.com" }] };
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      return { rows: [additional] };
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      if (sql.includes("FOR SHARE")) return { rows: [{ id: "anchor-1" }] };
      if (sql.includes("UPDATE official_assets")) return { rows: [verified] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [additional] };
      return { rows: [], rowCount: 1 };
    });
    mocks.proofDomain.mockResolvedValue({
      method: "DNS_TXT",
      domain: "cdn.example.com",
      checkedAt: new Date().toISOString(),
    });
    mocks.proofManifest.mockResolvedValue({
      method: "VERIFIED_DOMAIN_MANIFEST",
      domain: "example.com",
      trustAnchorDomain: "example.com",
      checkedAt: new Date().toISOString(),
    });

    const result = await new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    });
    expect(result.verification_status).toBe("VERIFIED");
    expect(mocks.proofDomain).toHaveBeenCalled();
    expect(mocks.proofManifest).toHaveBeenCalledWith({
      asset: additional,
      verifiedDomains: ["example.com"],
    });
    expect(mocks.addRule).toHaveBeenCalledWith(
      "cdn.example.com",
      expect.any(String),
      "asset-1",
      "brand-1",
      expect.anything(),
    );
  });

  it("does not let control of an additional domain self-authorize its brand association", async () => {
    const additional = asset({ identifier: "evil.example.net", value: "evil.example.net" });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT primary_domain FROM brands")) return { rows: [{ primary_domain: "example.com" }] };
      if (sql.includes("SELECT value FROM official_assets")) return { rows: [] };
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      if (sql.includes("INSERT INTO asset_verification_events")) return { rows: [] };
      return { rows: [additional] };
    });

    await expect(new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    })).rejects.toMatchObject<Partial<AssetVerificationError>>({ code: "VERIFIED_DOMAIN_REQUIRED" });
    expect(mocks.proofDomain).not.toHaveBeenCalled();
    expect(mocks.proofManifest).not.toHaveBeenCalled();
  });

  it("does not call the proof provider for an expired challenge", async () => {
    const pending = asset();
    const expired = challenge("2020-01-01T00:00:00.000Z");
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [expired] };
      if (sql.includes("INSERT INTO asset_verification_events")) return { rows: [] };
      return { rows: [pending] };
    });

    await expect(new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    })).rejects.toMatchObject<Partial<AssetVerificationError>>({ code: "CHALLENGE_EXPIRED" });
    expect(mocks.proofDomain).not.toHaveBeenCalled();
  });

  it("verifies a social association without converting name similarity into proof", async () => {
    const pending = asset({
      asset_type: "social_profile",
      platform: "bluesky",
      identifier: "brand.bsky.social",
      value: "brand.bsky.social",
      canonical_url: null,
    });
    const verified = asset({
      ...pending,
      is_verified: true,
      verification_status: "VERIFIED",
      verification_method: "VERIFIED_DOMAIN_MANIFEST",
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT value FROM official_assets")) return { rows: [{ value: "example.com" }] };
      return { rows: [pending] };
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("FOR SHARE")) return { rows: [{ id: "domain-1" }] };
      if (sql.includes("UPDATE official_assets")) return { rows: [verified] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [pending] };
      return { rows: [], rowCount: 1 };
    });
    mocks.proofManifest.mockResolvedValue({
      method: "VERIFIED_DOMAIN_MANIFEST",
      domain: "example.com",
      trustAnchorDomain: "example.com",
      checkedAt: new Date().toISOString(),
    });

    const result = await new AssetService().verifyAssociation("brand-1", "asset-1");
    expect(result.verification_status).toBe("VERIFIED");
    expect(mocks.proofManifest).toHaveBeenCalledWith({
      asset: pending,
      verifiedDomains: ["example.com"],
    });
    expect(mocks.addRule).not.toHaveBeenCalled();
  });

  it("rejects a proof-matched asset when a reputation source reports a threat", async () => {
    const pending = asset();
    const rejected = asset({
      verification_status: "REJECTED",
      safety_status: "THREAT_DETECTED",
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT primary_domain FROM brands")) return { rows: [{ primary_domain: "example.com" }] };
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      return { rows: [pending] };
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      if (sql.includes("UPDATE official_assets")) return { rows: [rejected] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [pending] };
      return { rows: [], rowCount: 1 };
    });
    mocks.proofDomain.mockResolvedValue({
      method: "DNS_TXT",
      domain: "example.com",
      checkedAt: new Date().toISOString(),
    });
    mocks.safeBrowsing.mockResolvedValue({
      status: "available",
      isThreat: true,
      threatTypes: ["SOCIAL_ENGINEERING"],
    });

    await expect(new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    })).rejects.toMatchObject<Partial<AssetVerificationError>>({ code: "SAFETY_THREAT_DETECTED" });
    expect(mocks.addRule).not.toHaveBeenCalled();
  });

  it("revokes trust and deactivates linked exclusions while retaining audit history", async () => {
    const verified = asset({ is_verified: true, verification_status: "VERIFIED" });
    const revoked = asset({ verification_status: "REVOKED", is_verified: false });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("UPDATE official_assets") && sql.includes("trustAnchorDomain")) return { rows: [] };
      if (sql.includes("UPDATE official_assets")) return { rows: [revoked] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [verified] };
      return { rows: [], rowCount: 1 };
    });

    const result = await new AssetService().revokeAsset("brand-1", "asset-1", "Ownership changed");
    expect(result.verification_status).toBe("REVOKED");
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("UPDATE exclusion_rules SET is_active = FALSE"),
      ["asset-1"],
    );
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO asset_verification_events"),
      expect.arrayContaining(["ASSET_REVOKED", "REVOKED"]),
    );
  });
  it("rejects a proof if the asset changes while network verification is in flight", async () => {
    const pending = asset();
    const changed = asset({ canonical_url: "https://different.example.com/" });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT primary_domain FROM brands")) return { rows: [{ primary_domain: "example.com" }] };
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      return { rows: [pending] };
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM asset_verification_challenges")) return { rows: [challenge()] };
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [changed] };
      return { rows: [], rowCount: 1 };
    });
    mocks.proofDomain.mockResolvedValue({
      method: "DNS_TXT",
      domain: "example.com",
      checkedAt: new Date().toISOString(),
    });

    await expect(new AssetService().verifyDomainChallenge({
      brandId: "brand-1",
      assetId: "asset-1",
      challengeId: "challenge-1",
      token: "proof-token",
    })).rejects.toMatchObject<Partial<AssetVerificationError>>({
      code: "ASSET_CHANGED_DURING_VERIFICATION",
    });
    expect(mocks.addRule).not.toHaveBeenCalled();
  });

  it("does not let a legacy-only domain authorize a new manifest association", async () => {
    const pending = asset({
      asset_type: "social_profile",
      platform: "bluesky",
      identifier: "brand.bsky.social",
      value: "brand.bsky.social",
      canonical_url: null,
    });
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT value FROM official_assets")) return { rows: [] };
      return { rows: [pending] };
    });

    await expect(new AssetService().verifyAssociation("brand-1", "asset-1"))
      .rejects.toMatchObject<Partial<AssetVerificationError>>({ code: "VERIFIED_DOMAIN_REQUIRED" });
    const domainQuery = mocks.query.mock.calls.find(([sql]) =>
      String(sql).includes("SELECT value FROM official_assets"),
    )?.[0];
    expect(String(domainQuery)).toContain("verification_status = 'VERIFIED'");
    expect(String(domainQuery)).not.toContain("VERIFIED_LEGACY");
    expect(mocks.proofManifest).not.toHaveBeenCalled();
  });

  it("revokes manifest dependents when their verifying domain is revoked", async () => {
    const domain = asset({
      id: "domain-1",
      is_verified: true,
      verification_status: "VERIFIED",
    });
    const revokedDomain = asset({
      id: "domain-1",
      verification_status: "REVOKED",
      revocation_reason: "Domain control changed",
    });
    const revokedDependent = asset({
      id: "social-1",
      asset_type: "social_profile",
      platform: "bluesky",
      identifier: "brand.bsky.social",
      value: "brand.bsky.social",
      verification_status: "REVOKED",
      verification_method: "VERIFIED_DOMAIN_MANIFEST",
    });
    mocks.clientQuery.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT") && sql.includes("FROM official_assets")) return { rows: [domain] };
      if (sql.includes("UPDATE official_assets") && sql.includes("trustAnchorDomain")) {
        return { rows: [revokedDependent], rowCount: 1 };
      }
      if (sql.includes("UPDATE official_assets")) return { rows: [revokedDomain], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    });

    await new AssetService().revokeAsset("brand-1", "domain-1", "Domain control changed");
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("trustAnchorDomain"),
      ["brand-1", "domain-1", "example.com", "Domain control changed"],
    );
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO asset_verification_events"),
      expect.arrayContaining(["TRUST_ANCHOR_REVOKED", "social-1"]),
    );
  });

});
