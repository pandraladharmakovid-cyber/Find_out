import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolveTxt as defaultResolveTxt } from "node:dns/promises";
import { PinnedHttpsClient, pinnedHttpsClient } from "./safe-https";
import { normalizeTargetUrl, urlSafetyEngine } from "./url-safety";
import {
  isAppAssetType,
  isDomainAssetType,
  isSocialAssetType,
} from "./asset-trust";

export type DomainChallengeMethod = "DNS_TXT" | "WELL_KNOWN";

export interface ProofAssetIdentity {
  asset_type: string;
  platform: string;
  identifier?: string;
  value: string;
  canonical_url: string | null;
}

export interface AssetProofEvidence extends Record<string, unknown> {
  method: DomainChallengeMethod | "VERIFIED_DOMAIN_MANIFEST";
  domain: string;
  checkedAt: string;
}

type ResolveTxt = (hostname: string) => Promise<string[][]>;

export function createVerificationToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashVerificationToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function verificationTokensMatch(expectedHash: string, token: string): boolean {
  const expected = Buffer.from(expectedHash, "hex");
  const supplied = Buffer.from(hashVerificationToken(token), "hex");
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

export function normalizeVerificationDomain(value: string): string {
  const normalized = normalizeTargetUrl(value);
  const validation = urlSafetyEngine.validateTargetUrl(normalized);
  if (!validation.isAllowed) {
    throw new Error(validation.reason ?? "Domain is not eligible for verification.");
  }
  return validation.hostname;
}

export function domainChallengeInstructions(
  domain: string,
  method: DomainChallengeMethod,
): { dnsName: string; wellKnownUrl: string } {
  return {
    dnsName: `_findout-verification.${domain}`,
    wellKnownUrl: `https://${domain}/.well-known/findout-verification.txt`,
  };
}

function canonicalType(assetType: string): string {
  const type = assetType.toLowerCase();
  if (isDomainAssetType(type)) return "domain";
  if (isSocialAssetType(type)) return "social_profile";
  if (isAppAssetType(type)) return "mobile_app";
  return type;
}

function canonicalPlatform(platform: string): string {
  const value = platform.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (["appleappstore", "appstore", "ios"].includes(value)) return "appstore";
  if (["website", "web", "domain"].includes(value)) return "web";
  return value;
}

function canonicalIdentifier(value: string): string {
  return value
    .normalize("NFKC")
    .trim()
    .replace(/^@/, "")
    .replace(/\/+$/, "")
    .toLowerCase();
}

function canonicalUrl(value: string | null | undefined): string {
  if (!value) return "";
  try {
    const url = new URL(value);
    const port = url.port ? `:${url.port}` : "";
    return `${url.protocol.toLowerCase()}//${url.hostname.toLowerCase()}${port}${url.pathname.replace(/\/+$/, "")}${url.search}`;
  } catch {
    return canonicalIdentifier(value);
  }
}

function manifestEntryMatches(
  entry: Record<string, unknown>,
  asset: ProofAssetIdentity,
): boolean {
  const entryType = typeof entry.type === "string" ? entry.type : "";
  const entryPlatform = typeof entry.platform === "string" ? entry.platform : "";
  if (canonicalType(entryType) !== canonicalType(asset.asset_type)) return false;
  if (
    !isDomainAssetType(asset.asset_type) &&
    canonicalPlatform(entryPlatform) !== canonicalPlatform(asset.platform)
  ) {
    return false;
  }

  const entryIdentifier =
    typeof entry.identifier === "string" ? canonicalIdentifier(entry.identifier) : "";
  const assetIdentifier = canonicalIdentifier(asset.identifier || asset.value);
  if (entryIdentifier && entryIdentifier === assetIdentifier) return true;

  const entryUrl = canonicalUrl(typeof entry.url === "string" ? entry.url : null);
  const assetUrl = canonicalUrl(asset.canonical_url);
  return Boolean(entryUrl && assetUrl && entryUrl === assetUrl);
}

export class AssetProofService {
  private readonly resolveTxt: ResolveTxt;
  private readonly https: PinnedHttpsClient;

  constructor(options?: {
    resolveTxt?: ResolveTxt;
    https?: PinnedHttpsClient;
  }) {
    this.resolveTxt = options?.resolveTxt ?? defaultResolveTxt;
    this.https = options?.https ?? pinnedHttpsClient;
  }

  async verifyDomainChallenge(params: {
    domain: string;
    method: DomainChallengeMethod;
    token: string;
  }): Promise<AssetProofEvidence> {
    const domain = normalizeVerificationDomain(params.domain);
    const { dnsName, wellKnownUrl } = domainChallengeInstructions(
      domain,
      params.method,
    );
    const expectedValues = new Set([
      params.token,
      `findout-verification=${params.token}`,
    ]);

    if (params.method === "DNS_TXT") {
      const records = await this.resolveTxt(dnsName);
      const values = records.map((chunks) => chunks.join("").trim());
      if (!values.some((value) => expectedValues.has(value))) {
        throw new Error(`The DNS TXT record at ${dnsName} does not contain the challenge token.`);
      }
    } else {
      const response = await this.https.get(wellKnownUrl, {
        accept: "text/plain",
        maxBytes: 16 * 1024,
      });
      const body = response.body.trim();
      if (response.status !== 200 || !expectedValues.has(body)) {
        throw new Error(`The verification file at ${wellKnownUrl} does not contain the challenge token.`);
      }
    }

    return {
      method: params.method,
      domain,
      checkedAt: new Date().toISOString(),
      proofLocation: params.method === "DNS_TXT" ? dnsName : wellKnownUrl,
    };
  }

  /**
   * Verifies a non-domain asset only when an exact declaration is hosted on a
   * domain that has already passed a Find_out ownership challenge.
   */
  async verifyVerifiedDomainManifest(params: {
    asset: ProofAssetIdentity;
    verifiedDomains: string[];
  }): Promise<AssetProofEvidence> {
    if (params.verifiedDomains.length === 0) {
      throw new Error("Verify a brand domain before verifying associated assets.");
    }

    const attempted: string[] = [];
    for (const suppliedDomain of params.verifiedDomains) {
      const domain = normalizeVerificationDomain(suppliedDomain);
      const manifestUrl = `https://${domain}/.well-known/findout-assets.json`;
      attempted.push(manifestUrl);
      try {
        const response = await this.https.get(manifestUrl, {
          accept: "application/json",
          maxBytes: 128 * 1024,
        });
        if (response.status !== 200) continue;
        const parsed = JSON.parse(response.body) as unknown;
        if (!parsed || typeof parsed !== "object") continue;
        const entries = (parsed as Record<string, unknown>).assets;
        if (!Array.isArray(entries) || entries.length > 100) continue;
        const matched = entries.some(
          (entry): entry is Record<string, unknown> =>
            Boolean(entry && typeof entry === "object") &&
            manifestEntryMatches(entry as Record<string, unknown>, params.asset),
        );
        if (matched) {
          return {
            method: "VERIFIED_DOMAIN_MANIFEST",
            domain,
            checkedAt: new Date().toISOString(),
            manifestUrl,
            trustAnchorDomain: domain,
          };
        }
      } catch {
        // Try another already verified brand domain; never treat failure as proof.
      }
    }

    throw new Error(
      `No verified-domain manifest exactly declares this asset. Checked: ${attempted.join(", ")}`,
    );
  }
}

export const assetProofService = new AssetProofService();
