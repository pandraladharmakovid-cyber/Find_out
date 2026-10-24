import { describe, expect, it, vi } from "vitest";
import {
  AssetProofService,
  createVerificationToken,
  hashVerificationToken,
  verificationTokensMatch,
} from "../src/asset-proof";
import { PinnedHttpsClient } from "../src/safe-https";
import { validateChallenge } from "../src/assets";
import { isTrustedOfficialAsset } from "../src/asset-trust";

function httpsReturning(body: string, status = 200): PinnedHttpsClient {
  return {
    get: vi.fn().mockResolvedValue({
      status,
      contentType: "application/json",
      body,
      url: "https://example.com/.well-known/findout-assets.json",
    }),
  } as unknown as PinnedHttpsClient;
}

describe("Official asset proof and trust boundaries", () => {
  it("uses unpredictable hashed challenge tokens and rejects incorrect tokens", () => {
    const first = createVerificationToken();
    const second = createVerificationToken();
    expect(first).not.toBe(second);
    expect(first.length).toBeGreaterThanOrEqual(43);
    expect(verificationTokensMatch(hashVerificationToken(first), first)).toBe(true);
    expect(verificationTokensMatch(hashVerificationToken(first), second)).toBe(false);
  });

  it("rejects expired challenges before accepting a proof attempt", () => {
    const token = createVerificationToken();
    expect(() => validateChallenge({
      token_hash: hashVerificationToken(token),
      expires_at: "2026-10-23T10:00:00.000Z",
      consumed_at: null,
      superseded_at: null,
    }, token, new Date("2026-10-23T10:31:00.000Z"))).toThrowError(
      expect.objectContaining({ code: "CHALLENGE_EXPIRED" }),
    );
  });

  it("rejects an incorrect challenge token", () => {
    expect(() => validateChallenge({
      token_hash: hashVerificationToken("correct-token"),
      expires_at: "2026-10-23T11:00:00.000Z",
      consumed_at: null,
      superseded_at: null,
    }, "wrong-token", new Date("2026-10-23T10:30:00.000Z"))).toThrowError(
      expect.objectContaining({ code: "TOKEN_MISMATCH" }),
    );
  });

  it("verifies an exact DNS TXT challenge", async () => {
    const service = new AssetProofService({
      resolveTxt: async (hostname) => {
        expect(hostname).toBe("_findout-verification.example.com");
        return [["findout-verification=proof-token"]];
      },
      https: httpsReturning(""),
    });
    const proof = await service.verifyDomainChallenge({
      domain: "example.com",
      method: "DNS_TXT",
      token: "proof-token",
    });
    expect(proof.method).toBe("DNS_TXT");
    expect(proof.proofLocation).toBe("_findout-verification.example.com");
  });

  it("does not verify when DNS contains a different token", async () => {
    const service = new AssetProofService({
      resolveTxt: async () => [["findout-verification=wrong-token"]],
      https: httpsReturning(""),
    });
    await expect(service.verifyDomainChallenge({
      domain: "example.com",
      method: "DNS_TXT",
      token: "proof-token",
    })).rejects.toThrow("does not contain the challenge token");
  });

  it("verifies a social asset only through an exact verified-domain manifest declaration", async () => {
    const manifest = JSON.stringify({
      assets: [{
        type: "social_profile",
        platform: "bluesky",
        identifier: "brand.bsky.social",
        url: "https://bsky.app/profile/brand.bsky.social",
      }],
    });
    const service = new AssetProofService({ https: httpsReturning(manifest) });
    const proof = await service.verifyVerifiedDomainManifest({
      asset: {
        asset_type: "social_profile",
        platform: "bluesky",
        identifier: "brand.bsky.social",
        value: "brand.bsky.social",
        canonical_url: "https://bsky.app/profile/brand.bsky.social",
      },
      verifiedDomains: ["example.com"],
    });
    expect(proof.method).toBe("VERIFIED_DOMAIN_MANIFEST");
  });

  it("accepts an exact additional-domain declaration from the verified primary domain", async () => {
    const service = new AssetProofService({
      https: httpsReturning(JSON.stringify({
        assets: [{ type: "domain", identifier: "cdn.example.com" }],
      })),
    });
    const proof = await service.verifyVerifiedDomainManifest({
      asset: {
        asset_type: "domain",
        platform: "website",
        identifier: "cdn.example.com",
        value: "cdn.example.com",
        canonical_url: "https://cdn.example.com/",
      },
      verifiedDomains: ["example.com"],
    });
    expect(proof.domain).toBe("example.com");
    expect(proof.trustAnchorDomain).toBe("example.com");
  });

  it("does not treat a matching name or public URL alone as ownership proof", async () => {
    const service = new AssetProofService({
      https: httpsReturning(JSON.stringify({ assets: [{
        type: "social_profile",
        platform: "bluesky",
        identifier: "different-account.bsky.social",
      }] })),
    });
    await expect(service.verifyVerifiedDomainManifest({
      asset: {
        asset_type: "social_profile",
        platform: "bluesky",
        identifier: "brand.bsky.social",
        value: "brand.bsky.social",
        canonical_url: "https://bsky.app/profile/brand.bsky.social",
      },
      verifiedDomains: ["example.com"],
    })).rejects.toThrow("No verified-domain manifest exactly declares this asset");
  });

  it("blocks a DNS rebinding attempt with mixed public and private answers before HTTP", async () => {
    const request = vi.fn();
    const client = new PinnedHttpsClient({
      lookup: async () => [
        { address: "8.8.8.8", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ],
      request: request as never,
    });
    await expect(client.get("https://public.example.com/.well-known/findout-verification.txt"))
      .rejects.toThrow("private, reserved, or mixed");
    expect(request).not.toHaveBeenCalled();
  });

  it("never trusts a pending/revoked asset even if its boolean is forged", () => {
    const base = { is_verified: true } as const;
    expect(isTrustedOfficialAsset({ ...base, verification_status: "PENDING_VERIFICATION" })).toBe(false);
    expect(isTrustedOfficialAsset({ ...base, verification_status: "REVOKED" })).toBe(false);
    expect(isTrustedOfficialAsset({ ...base, verification_status: "VERIFIED" })).toBe(true);
    expect(isTrustedOfficialAsset({ ...base, verification_status: "VERIFIED_LEGACY" })).toBe(true);
    expect(isTrustedOfficialAsset({ is_verified: false, verification_status: "VERIFIED" })).toBe(false);
  });
});
