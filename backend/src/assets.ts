import type { PoolClient, QueryResultRow } from "pg";
import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import { ExclusionRulesRepository } from "./repositories";
import { logoSimilarityService } from "./logo-similarity.service";
import {
  assetProofService,
  createVerificationToken,
  domainChallengeInstructions,
  hashVerificationToken,
  normalizeVerificationDomain,
  verificationTokensMatch,
  type AssetProofEvidence,
  type DomainChallengeMethod,
} from "./asset-proof";
import { isDomainAssetType, isTrustedOfficialAsset } from "./asset-trust";
import { normalizeTargetUrl, urlSafetyEngine } from "./url-safety";
import { safeBrowsingClient } from "./integrations/safebrowsing.client";
import { urlhausClient } from "./integrations/urlhaus.client";

export type AssetType =
  | "domain"
  | "subdomain"
  | "website"
  | "logo"
  | "trademark"
  | "social_handle"
  | "social_account"
  | "social_profile"
  | "mobile_app"
  | "app_store_id";

export type AssetVerificationStatus =
  | "PENDING_VERIFICATION"
  | "VERIFIED"
  | "VERIFIED_LEGACY"
  | "REJECTED"
  | "REVOKED";

export type AssetSafetyStatus =
  | "NOT_ASSESSED"
  | "NO_THREAT_MATCH"
  | "THREAT_DETECTED";

export interface OfficialAssetRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  asset_type: AssetType;
  platform: string;
  identifier: string;
  value: string;
  canonical_url: string | null;
  hash_signature: string | null;
  is_verified: boolean;
  verification_status: AssetVerificationStatus;
  verification_method: string | null;
  verification_evidence: Record<string, unknown>;
  verified_at: string | null;
  verified_by: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  safety_status: AssetSafetyStatus;
  safety_evidence: Record<string, unknown>;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface RegisterAssetDTO {
  brandId: string;
  assetType: AssetType;
  value: string;
  platform?: string;
  canonicalUrl?: string | null;
  assetContent?: string;
  imageData?: Buffer | null;
  hashSignature?: string | null;
  metadata?: Record<string, unknown>;
}

interface AssetChallengeRecord extends QueryResultRow {
  id: string;
  asset_id: string;
  method: DomainChallengeMethod;
  token_hash: string;
  expires_at: string;
  consumed_at: string | null;
  superseded_at: string | null;
}

interface SafetyAssessment {
  status: AssetSafetyStatus;
  threatDetected: boolean;
  evidence: Record<string, unknown>;
}

export class AssetVerificationError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AssetVerificationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const ASSET_COLUMNS = `
  id, brand_id, asset_type, platform, identifier, value, canonical_url,
  hash_signature, is_verified, verification_status, verification_method,
  verification_evidence, verified_at, verified_by, revoked_at,
  revocation_reason, safety_status, safety_evidence, metadata, created_at, updated_at
`;

function sanitizeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  const clean = { ...(metadata ?? {}) };
  for (const key of [
    "is_verified",
    "verified",
    "verification_status",
    "verification_method",
    "verified_at",
    "verified_by",
    "safety_status",
  ]) {
    delete clean[key];
  }
  return clean;
}

function normalizeOptionalAssetUrl(
  value: string | null | undefined,
  assetType: AssetType,
): string | null {
  if (!value?.trim()) return null;
  let normalized: string;
  try {
    normalized = normalizeTargetUrl(value);
  } catch (error) {
    throw new AssetVerificationError(
      400,
      "INVALID_ASSET_URL",
      error instanceof Error ? error.message : "Invalid asset URL.",
    );
  }
  const validation = urlSafetyEngine.validateTargetUrl(normalized);
  if (!validation.isAllowed) {
    throw new AssetVerificationError(
      400,
      "UNSAFE_ASSET_URL",
      validation.reason ?? "Private or internal asset URLs are not allowed.",
    );
  }
  if (assetType === "logo" && validation.protocol !== "https:") {
    throw new AssetVerificationError(
      400,
      "UNSAFE_ASSET_URL",
      "Logo verification URLs must use HTTPS.",
    );
  }
  return normalized;
}

export function validateChallenge(
  challenge: Pick<
    AssetChallengeRecord,
    "token_hash" | "expires_at" | "consumed_at" | "superseded_at"
  >,
  token: string,
  now = new Date(),
): void {
  if (challenge.consumed_at || challenge.superseded_at) {
    throw new AssetVerificationError(
      409,
      "CHALLENGE_NOT_ACTIVE",
      "This verification challenge is no longer active. Create a new challenge.",
    );
  }
  if (new Date(challenge.expires_at).getTime() <= now.getTime()) {
    throw new AssetVerificationError(
      410,
      "CHALLENGE_EXPIRED",
      "This verification challenge has expired. Create a new challenge.",
    );
  }
  if (!token || !verificationTokensMatch(challenge.token_hash, token)) {
    throw new AssetVerificationError(
      403,
      "TOKEN_MISMATCH",
      "The supplied verification token does not match this challenge.",
    );
  }
}

export class AssetService {
  async registerAsset(
    dto: RegisterAssetDTO,
  ): Promise<{ asset: OfficialAssetRecord; created: boolean }> {
    const assetType = dto.assetType.toLowerCase() as AssetType;
    const cleanValue = isDomainAssetType(assetType)
      ? normalizeVerificationDomain(dto.value)
      : dto.value.normalize("NFKC").trim();
    if (!cleanValue || cleanValue.length > 1000) {
      throw new AssetVerificationError(
        400,
        "INVALID_ASSET_IDENTIFIER",
        "Asset identifier must contain between 1 and 1000 characters.",
      );
    }
    const canonicalUrl = normalizeOptionalAssetUrl(dto.canonicalUrl, assetType);
    const platform = dto.platform?.trim().toLowerCase() || "unknown";
    let imageData = dto.imageData ?? null;
    let hashSignature = dto.hashSignature ?? null;

    if (dto.assetContent) {
      imageData = Buffer.from(dto.assetContent, "base64");
      if (!imageData.length) {
        throw new AssetVerificationError(
          400,
          "INVALID_LOGO",
          "Logo image data must be non-empty base64.",
        );
      }
    }
    if (imageData && !hashSignature) {
      hashSignature = await logoSimilarityService.computeImageHash(imageData);
    }

    return await withTransaction(async (client) => {
      const brand = await client.query(
        `SELECT id FROM brands WHERE id = $1 FOR UPDATE;`,
        [dto.brandId],
      );
      if (!brand.rows[0]) {
        throw new AssetVerificationError(404, "BRAND_NOT_FOUND", "Brand not found.");
      }

      const existingResult = await client.query<OfficialAssetRecord>(
        `SELECT ${ASSET_COLUMNS} FROM official_assets
         WHERE brand_id = $1 AND asset_type = $2 AND platform = $3 AND identifier = $4
         FOR UPDATE;`,
        [dto.brandId, assetType, platform, cleanValue],
      );
      const existing = existingResult.rows[0];
      if (existing) {
        if (isTrustedOfficialAsset(existing) || existing.verification_status === "REVOKED") {
          await this.recordEvent(
            existing.id,
            "DUPLICATE_SUBMISSION_IGNORED",
            "UNCHANGED",
            null,
            "public-submission",
            { reason: "Trusted or revoked assets cannot be overwritten by a submission." },
            null,
            client,
          );
          return { asset: existing, created: false };
        }

        const updated = await client.query<OfficialAssetRecord>(
          `UPDATE official_assets
           SET value = $3, canonical_url = $4, hash_signature = $5, image_data = $6,
               metadata = $7, is_verified = FALSE,
               verification_status = 'PENDING_VERIFICATION', verification_method = NULL,
               verification_evidence = '{}'::jsonb, verified_at = NULL, verified_by = NULL,
               revoked_at = NULL, revocation_reason = NULL,
               safety_status = 'NOT_ASSESSED', safety_evidence = '{}'::jsonb,
               updated_at = NOW()
           WHERE id = $1 AND brand_id = $2
           RETURNING ${ASSET_COLUMNS};`,
          [
            existing.id,
            dto.brandId,
            cleanValue,
            canonicalUrl,
            hashSignature,
            imageData,
            JSON.stringify(sanitizeMetadata(dto.metadata)),
          ],
        );
        const asset = updated.rows[0]!;
        await this.recordEvent(
          asset.id,
          "ASSET_RESUBMITTED",
          "PENDING_VERIFICATION",
          null,
          "public-submission",
          { assetType, platform },
          null,
          client,
        );
        return { asset, created: false };
      }

      const inserted = await client.query<OfficialAssetRecord>(
        `INSERT INTO official_assets (
           brand_id, asset_type, platform, identifier, value, canonical_url,
           hash_signature, image_data, is_verified, verification_status,
           verification_evidence, safety_status, safety_evidence, metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, FALSE,
           'PENDING_VERIFICATION', '{}'::jsonb, 'NOT_ASSESSED', '{}'::jsonb, $9
         )
         RETURNING ${ASSET_COLUMNS};`,
        [
          dto.brandId,
          assetType,
          platform,
          cleanValue,
          cleanValue,
          canonicalUrl,
          hashSignature,
          imageData,
          JSON.stringify(sanitizeMetadata(dto.metadata)),
        ],
      );
      const asset = inserted.rows[0];
      if (!asset) {
        throw new Error("Failed to persist asset submission.");
      }
      await this.recordEvent(
        asset.id,
        "ASSET_SUBMITTED",
        "PENDING_VERIFICATION",
        null,
        "public-submission",
        { assetType, platform },
        null,
        client,
      );
      logger.info("[assets] Asset stored as pending verification", {
        assetId: asset.id,
        brandId: dto.brandId,
        assetType,
      });
      return { asset, created: true };
    });
  }

  async listAssetsByBrand(brandId: string): Promise<OfficialAssetRecord[]> {
    const result = await query<OfficialAssetRecord>(
      `SELECT ${ASSET_COLUMNS} FROM official_assets
       WHERE brand_id = $1 ORDER BY created_at ASC;`,
      [brandId],
    );
    return result.rows;
  }

  async getAssetsByType(
    brandId: string,
    assetType: AssetType,
  ): Promise<OfficialAssetRecord[]> {
    const result = await query<OfficialAssetRecord>(
      `SELECT ${ASSET_COLUMNS} FROM official_assets
       WHERE brand_id = $1 AND asset_type = $2 ORDER BY created_at ASC;`,
      [brandId, assetType],
    );
    return result.rows;
  }

  async createDomainChallenge(
    brandId: string,
    assetId: string,
    method: DomainChallengeMethod,
  ) {
    if (!["DNS_TXT", "WELL_KNOWN"].includes(method)) {
      throw new AssetVerificationError(
        400,
        "INVALID_VERIFICATION_METHOD",
        "Use DNS_TXT or WELL_KNOWN domain verification.",
      );
    }
    const asset = await this.getAsset(brandId, assetId);
    if (!isDomainAssetType(asset.asset_type)) {
      throw new AssetVerificationError(
        400,
        "NOT_A_DOMAIN_ASSET",
        "Only domain assets use DNS or well-known file challenges.",
      );
    }

    const domain = normalizeVerificationDomain(asset.value);
    const token = createVerificationToken();
    const tokenHash = hashVerificationToken(token);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    let challengeId: string | null = null;
    await withTransaction(async (client) => {
      await client.query(
        `UPDATE asset_verification_challenges
         SET superseded_at = NOW()
         WHERE asset_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL;`,
        [assetId],
      );
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO asset_verification_challenges (
           asset_id, method, token_hash, expires_at
         ) VALUES ($1, $2, $3, $4) RETURNING id;`,
        [assetId, method, tokenHash, expiresAt.toISOString()],
      );
      challengeId = inserted.rows[0]?.id ?? null;
      await this.recordEvent(
        assetId,
        "CHALLENGE_ISSUED",
        asset.verification_status,
        method,
        "public-submission",
        { domain, expiresAt: expiresAt.toISOString() },
        null,
        client,
      );
    });

    if (!challengeId) throw new Error("Failed to create the verification challenge.");
    const locations = domainChallengeInstructions(domain, method);
    return {
      challengeId,
      token,
      method,
      expiresAt: expiresAt.toISOString(),
      domain,
      ...locations,
      dnsValue: `findout-verification=${token}`,
      fileContents: `findout-verification=${token}`,
    };
  }

  async verifyDomainChallenge(params: {
    brandId: string;
    assetId: string;
    challengeId: string;
    token: string;
  }): Promise<OfficialAssetRecord> {
    const asset = await this.getAsset(params.brandId, params.assetId);
    if (!isDomainAssetType(asset.asset_type)) {
      throw new AssetVerificationError(400, "NOT_A_DOMAIN_ASSET", "Not a domain asset.");
    }
    const challenge = await this.getChallenge(params.assetId, params.challengeId);
    try {
      validateChallenge(challenge, params.token);
    } catch (error) {
      await this.recordVerificationFailure(asset, challenge.method, error);
      throw error;
    }

    const primaryDomain = await this.getPrimaryDomain(params.brandId);
    const isPrimaryDomain =
      normalizeVerificationDomain(asset.value) === normalizeVerificationDomain(primaryDomain);
    let verifiedAnchorDomains: string[] = [];
    if (!isPrimaryDomain) {
      verifiedAnchorDomains = await this.listFreshVerifiedDomains(params.brandId, asset.id);
      if (verifiedAnchorDomains.length === 0) {
        const error = new AssetVerificationError(
          412,
          "VERIFIED_DOMAIN_REQUIRED",
          "Verify the brand primary domain first. An additional domain also needs an exact declaration on that verified domain.",
        );
        await this.recordVerificationFailure(asset, challenge.method, error);
        throw error;
      }
    }

    let domainProof: AssetProofEvidence;
    try {
      domainProof = await assetProofService.verifyDomainChallenge({
        domain: asset.value,
        method: challenge.method,
        token: params.token,
      });
    } catch (error) {
      await this.recordVerificationFailure(asset, challenge.method, error);
      throw new AssetVerificationError(
        422,
        "OWNERSHIP_PROOF_NOT_FOUND",
        error instanceof Error ? error.message : "Domain control proof was not found.",
      );
    }

    let proof = domainProof;
    if (!isPrimaryDomain) {
      try {
        const association = await assetProofService.verifyVerifiedDomainManifest({
          asset,
          verifiedDomains: verifiedAnchorDomains,
        });
        proof = {
          ...domainProof,
          association,
          trustAnchorDomain: association.domain,
        };
      } catch (error) {
        await this.recordVerificationFailure(asset, "VERIFIED_DOMAIN_MANIFEST", error);
        throw new AssetVerificationError(
          422,
          "ASSET_ASSOCIATION_NOT_PROVEN",
          "Domain control matched, but no verified brand domain exactly declares this additional domain.",
        );
      }
    }

    const safety = await this.assessSafety(asset);
    const updated = await this.finalizeVerification({
      asset,
      proof,
      safety,
      challenge,
      suppliedToken: params.token,
    });
    this.throwIfSafetyRejected(updated);
    return updated;
  }

  async verifyAssociation(
    brandId: string,
    assetId: string,
  ): Promise<OfficialAssetRecord> {
    const asset = await this.getAsset(brandId, assetId);
    if (isDomainAssetType(asset.asset_type)) {
      throw new AssetVerificationError(
        400,
        "DOMAIN_CHALLENGE_REQUIRED",
        "Use a DNS TXT or well-known file challenge for domain assets.",
      );
    }
    if (!["logo", "social_handle", "social_account", "social_profile", "mobile_app", "app_store_id"].includes(asset.asset_type)) {
      throw new AssetVerificationError(
        400,
        "AUTHORIZED_REVIEW_REQUIRED",
        "This asset type requires a separate authorized brand-identity review.",
      );
    }

    const verifiedDomains = await this.listFreshVerifiedDomains(brandId);
    if (verifiedDomains.length === 0) {
      throw new AssetVerificationError(
        412,
        "VERIFIED_DOMAIN_REQUIRED",
        "Verify a brand domain before verifying associated social, app, or logo assets.",
      );
    }

    let proof: AssetProofEvidence;
    try {
      proof = await assetProofService.verifyVerifiedDomainManifest({
        asset,
        verifiedDomains,
      });
    } catch (error) {
      await this.recordVerificationFailure(asset, "VERIFIED_DOMAIN_MANIFEST", error);
      throw new AssetVerificationError(
        422,
        "ASSET_ASSOCIATION_NOT_PROVEN",
        error instanceof Error ? error.message : "Asset association was not proven.",
      );
    }

    const safety = await this.assessSafety(asset);
    const updated = await this.finalizeVerification({ asset, proof, safety });
    this.throwIfSafetyRejected(updated);
    return updated;
  }

  async revokeAsset(
    brandId: string,
    assetId: string,
    reason = "Ownership or authorization revoked.",
  ): Promise<OfficialAssetRecord> {
    return await withTransaction(async (client) => {
      const current = await client.query<OfficialAssetRecord>(
        `SELECT ${ASSET_COLUMNS} FROM official_assets
         WHERE id = $1 AND brand_id = $2 FOR UPDATE;`,
        [assetId, brandId],
      );
      if (!current.rows[0]) {
        throw new AssetVerificationError(404, "ASSET_NOT_FOUND", "Asset not found.");
      }
      const updated = await client.query<OfficialAssetRecord>(
        `UPDATE official_assets
         SET is_verified = FALSE, verification_status = 'REVOKED',
             revoked_at = NOW(), revocation_reason = $3, updated_at = NOW()
         WHERE id = $1 AND brand_id = $2
         RETURNING ${ASSET_COLUMNS};`,
        [assetId, brandId, reason.trim().slice(0, 500) || "Revoked by registry user."],
      );
      await client.query(
        `UPDATE exclusion_rules SET is_active = FALSE WHERE asset_id = $1;`,
        [assetId],
      );
      const asset = updated.rows[0]!;
      await this.revokeManifestDependents(
        client,
        asset,
        asset.revocation_reason ?? "The verifying domain was revoked.",
      );
      await this.recordEvent(
        assetId,
        "ASSET_REVOKED",
        "REVOKED",
        asset.verification_method,
        "registry-operator",
        { reason: asset.revocation_reason },
        null,
        client,
      );
      return asset;
    });
  }

  async deleteAsset(id: string): Promise<void> {
    const asset = await query<OfficialAssetRecord>(
      `SELECT ${ASSET_COLUMNS} FROM official_assets WHERE id = $1;`,
      [id],
    );
    if (!asset.rows[0]) {
      throw new AssetVerificationError(404, "ASSET_NOT_FOUND", "Asset not found.");
    }
    await this.revokeAsset(
      asset.rows[0].brand_id,
      id,
      "Asset deletion requested; retained as a revocation audit record.",
    );
  }

  async listVerificationEvents(brandId: string, assetId: string) {
    const result = await query(
      `SELECT e.id, e.asset_id, e.event_type, e.status, e.method, e.actor,
              e.evidence, e.error_message, e.created_at
       FROM asset_verification_events e
       INNER JOIN official_assets a ON a.id = e.asset_id
       WHERE e.asset_id = $1 AND a.brand_id = $2
       ORDER BY e.created_at DESC LIMIT 100;`,
      [assetId, brandId],
    );
    return result.rows;
  }

  private async getPrimaryDomain(brandId: string): Promise<string> {
    const result = await query<{ primary_domain: string }>(
      `SELECT primary_domain FROM brands WHERE id = $1;`,
      [brandId],
    );
    const domain = result.rows[0]?.primary_domain;
    if (!domain) {
      throw new AssetVerificationError(404, "BRAND_NOT_FOUND", "Brand not found.");
    }
    return domain;
  }

  private async listFreshVerifiedDomains(
    brandId: string,
    excludeAssetId?: string,
  ): Promise<string[]> {
    const result = await query<{ value: string }>(
      `SELECT value FROM official_assets
       WHERE brand_id = $1 AND is_verified = TRUE
         AND verification_status = 'VERIFIED'
         AND asset_type IN ('domain', 'subdomain', 'website')
         AND (verification_evidence #>> '{ownership,trustAnchorDomain}') IS NULL
         AND ($2::uuid IS NULL OR id <> $2::uuid)
       ORDER BY verified_at DESC NULLS LAST, created_at ASC
       LIMIT 10;`,
      [brandId, excludeAssetId ?? null],
    );
    return result.rows.map((row) => row.value);
  }

  private async getAsset(
    brandId: string,
    assetId: string,
  ): Promise<OfficialAssetRecord> {
    const result = await query<OfficialAssetRecord>(
      `SELECT ${ASSET_COLUMNS} FROM official_assets
       WHERE id = $1 AND brand_id = $2;`,
      [assetId, brandId],
    );
    const asset = result.rows[0];
    if (!asset) {
      throw new AssetVerificationError(404, "ASSET_NOT_FOUND", "Asset not found for this brand.");
    }
    return asset;
  }

  private async getChallenge(
    assetId: string,
    challengeId: string,
  ): Promise<AssetChallengeRecord> {
    const result = await query<AssetChallengeRecord>(
      `SELECT * FROM asset_verification_challenges
       WHERE id = $1 AND asset_id = $2;`,
      [challengeId, assetId],
    );
    const challenge = result.rows[0];
    if (!challenge) {
      throw new AssetVerificationError(404, "CHALLENGE_NOT_FOUND", "Verification challenge not found.");
    }
    return challenge;
  }

  private async assessSafety(asset: OfficialAssetRecord): Promise<SafetyAssessment> {
    const target = asset.canonical_url ??
      (isDomainAssetType(asset.asset_type) ? `https://${asset.value}/` : null);
    if (!target) {
      return {
        status: "NOT_ASSESSED",
        threatDetected: false,
        evidence: { note: "No public URL was available for reputation checks." },
      };
    }

    const [safeBrowsing, urlhaus] = await Promise.allSettled([
      safeBrowsingClient.checkUrl(target),
      urlhausClient.checkUrl(target),
    ]);
    const sb = safeBrowsing.status === "fulfilled" ? safeBrowsing.value : null;
    const uh = urlhaus.status === "fulfilled" ? urlhaus.value : null;
    const sbThreat = sb?.isThreat === true;
    const uhThreat = uh?.isMalicious === true;
    const available =
      sb?.status === "available" ||
      Boolean(uh && uh.confidence > 0 && !uh.rawPayload.skipped && !uh.rawPayload.error);
    const threatDetected = sbThreat || uhThreat;

    return {
      status: threatDetected
        ? "THREAT_DETECTED"
        : available
          ? "NO_THREAT_MATCH"
          : "NOT_ASSESSED",
      threatDetected,
      evidence: {
        target,
        safeBrowsing: sb
          ? { status: sb.status, isThreat: sb.isThreat, threatTypes: sb.threatTypes }
          : { status: "unavailable" },
        urlhaus: uh
          ? { isMalicious: uh.isMalicious, threatType: uh.threatType, confidence: uh.confidence }
          : { status: "unavailable" },
        note: "A lack of threat matches is not a guarantee of safety.",
      },
    };
  }

  private async finalizeVerification(params: {
    asset: OfficialAssetRecord;
    proof: AssetProofEvidence;
    safety: SafetyAssessment;
    challenge?: AssetChallengeRecord;
    suppliedToken?: string;
  }): Promise<OfficialAssetRecord> {
    return await withTransaction(async (client) => {
      const locked = await client.query<OfficialAssetRecord>(
        `SELECT ${ASSET_COLUMNS} FROM official_assets
         WHERE id = $1 AND brand_id = $2 FOR UPDATE;`,
        [params.asset.id, params.asset.brand_id],
      );
      const asset = locked.rows[0];
      if (!asset) {
        throw new AssetVerificationError(404, "ASSET_NOT_FOUND", "Asset not found.");
      }
      const snapshotChanged =
        asset.asset_type !== params.asset.asset_type ||
        asset.platform !== params.asset.platform ||
        asset.identifier !== params.asset.identifier ||
        asset.value !== params.asset.value ||
        asset.canonical_url !== params.asset.canonical_url ||
        new Date(asset.updated_at).getTime() !== new Date(params.asset.updated_at).getTime();
      if (snapshotChanged) {
        throw new AssetVerificationError(
          409,
          "ASSET_CHANGED_DURING_VERIFICATION",
          "The asset changed while proof was being checked. Submit or review it again before verifying.",
        );
      }
      if (typeof params.proof.trustAnchorDomain === "string") {
        const proofDomain = normalizeVerificationDomain(params.proof.trustAnchorDomain);
        const anchor = await client.query(
          `SELECT id FROM official_assets
           WHERE brand_id = $1 AND value = $2 AND id <> $3 AND is_verified = TRUE
             AND verification_status = 'VERIFIED'
             AND asset_type IN ('domain', 'subdomain', 'website')
             AND (verification_evidence #>> '{ownership,trustAnchorDomain}') IS NULL
           FOR SHARE;`,
          [asset.brand_id, proofDomain, asset.id],
        );
        if (!anchor.rows[0]) {
          throw new AssetVerificationError(
            409,
            "VERIFIED_DOMAIN_REQUIRED",
            "The verifying domain is no longer freshly verified. Re-verify it before proving this association.",
          );
        }
      }
      if (params.challenge && params.suppliedToken !== undefined) {
        const active = await client.query<AssetChallengeRecord>(
          `SELECT * FROM asset_verification_challenges
           WHERE id = $1 AND asset_id = $2 FOR UPDATE;`,
          [params.challenge.id, asset.id],
        );
        if (!active.rows[0]) {
          throw new AssetVerificationError(404, "CHALLENGE_NOT_FOUND", "Challenge not found.");
        }
        validateChallenge(active.rows[0], params.suppliedToken);
      }

      const rejected = params.safety.threatDetected;
      const combinedEvidence = {
        ownership: params.proof,
        safety: params.safety.evidence,
        legalIdentityNote:
          "Domain control or asset association does not prove the legal identity or authorization of a company.",
      };
      const updated = await client.query<OfficialAssetRecord>(
        rejected
          ? `UPDATE official_assets
             SET is_verified = FALSE, verification_status = 'REJECTED',
                 verification_method = $3, verification_evidence = $4,
                 verified_at = NULL, verified_by = NULL,
                 safety_status = 'THREAT_DETECTED', safety_evidence = $5,
                 revoked_at = NULL, revocation_reason = NULL, updated_at = NOW()
             WHERE id = $1 AND brand_id = $2 RETURNING ${ASSET_COLUMNS};`
          : `UPDATE official_assets
             SET is_verified = TRUE, verification_status = 'VERIFIED',
                 verification_method = $3, verification_evidence = $4,
                 verified_at = NOW(), verified_by = $6,
                 safety_status = $7, safety_evidence = $5,
                 revoked_at = NULL, revocation_reason = NULL, updated_at = NOW()
             WHERE id = $1 AND brand_id = $2 RETURNING ${ASSET_COLUMNS};`,
        rejected
          ? [
              asset.id,
              asset.brand_id,
              params.proof.method,
              JSON.stringify(combinedEvidence),
              JSON.stringify(params.safety.evidence),
            ]
          : [
              asset.id,
              asset.brand_id,
              params.proof.method,
              JSON.stringify(combinedEvidence),
              JSON.stringify(params.safety.evidence),
              `system:${params.proof.method.toLowerCase()}`,
              params.safety.status,
            ],
      );
      const result = updated.rows[0]!;

      if (params.challenge) {
        await client.query(
          `UPDATE asset_verification_challenges SET consumed_at = NOW() WHERE id = $1;`,
          [params.challenge.id],
        );
      }
      if (rejected) {
        await client.query(
          `UPDATE exclusion_rules SET is_active = FALSE WHERE asset_id = $1;`,
          [asset.id],
        );
        await this.revokeManifestDependents(
          client,
          asset,
          "The verifying domain was rejected during re-verification.",
        );
      } else if (isDomainAssetType(asset.asset_type)) {
        await ExclusionRulesRepository.addRule(
          asset.value,
          `Domain proof verified for asset ${asset.id}`,
          asset.id,
          asset.brand_id,
          client,
        );
      }
      await this.recordEvent(
        asset.id,
        rejected ? "VERIFICATION_REJECTED" : "VERIFICATION_SUCCEEDED",
        rejected ? "REJECTED" : "VERIFIED",
        params.proof.method,
        `system:${params.proof.method.toLowerCase()}`,
        combinedEvidence,
        rejected ? "A configured reputation source reported a threat." : null,
        client,
      );
      return result;
    });
  }

  private async revokeManifestDependents(
    client: PoolClient,
    domainAsset: OfficialAssetRecord,
    reason: string,
  ): Promise<void> {
    if (!isDomainAssetType(domainAsset.asset_type)) return;
    const domain = normalizeVerificationDomain(domainAsset.value);
    const dependencyFilter = `
      brand_id = $1 AND id <> $2 AND is_verified = TRUE
      AND verification_status = 'VERIFIED'
      AND verification_evidence #>> '{ownership,trustAnchorDomain}' = $3
    `;
    await client.query(
      `UPDATE exclusion_rules SET is_active = FALSE
       WHERE asset_id IN (SELECT id FROM official_assets WHERE ${dependencyFilter});`,
      [domainAsset.brand_id, domainAsset.id, domain],
    );
    const dependents = await client.query<OfficialAssetRecord>(
      `UPDATE official_assets
       SET is_verified = FALSE, verification_status = 'REVOKED',
           revoked_at = NOW(), revocation_reason = $4, updated_at = NOW()
       WHERE ${dependencyFilter}
       RETURNING ${ASSET_COLUMNS};`,
      [domainAsset.brand_id, domainAsset.id, domain, reason.slice(0, 500)],
    );
    for (const dependent of dependents.rows) {
      await this.recordEvent(
        dependent.id,
        "TRUST_ANCHOR_REVOKED",
        "REVOKED",
        dependent.verification_method,
        "system:trust-anchor-revoked",
        { domain, parentAssetId: domainAsset.id, reason },
        null,
        client,
      );
    }
  }

  private throwIfSafetyRejected(asset: OfficialAssetRecord): void {
    if (asset.verification_status === "REJECTED" && asset.safety_status === "THREAT_DETECTED") {
      throw new AssetVerificationError(
        422,
        "SAFETY_THREAT_DETECTED",
        "Ownership evidence matched, but a reputation source reported a threat. The asset was not trusted.",
        { assetId: asset.id },
      );
    }
  }

  private async recordVerificationFailure(
    asset: OfficialAssetRecord,
    method: string,
    error: unknown,
  ): Promise<void> {
    await this.recordEvent(
      asset.id,
      "VERIFICATION_ATTEMPT_FAILED",
      asset.verification_status,
      method,
      "system:verification",
      {},
      error instanceof Error ? error.message : "Verification failed.",
    );
  }

  private async recordEvent(
    assetId: string,
    eventType: string,
    status: string,
    method: string | null,
    actor: string,
    evidence: Record<string, unknown>,
    errorMessage: string | null,
    client?: PoolClient,
  ): Promise<void> {
    const text = `INSERT INTO asset_verification_events (
      asset_id, event_type, status, method, actor, evidence, error_message
    ) VALUES ($1, $2, $3, $4, $5, $6, $7);`;
    const values = [
      assetId,
      eventType,
      status,
      method,
      actor,
      JSON.stringify(evidence),
      errorMessage,
    ];
    if (client) await client.query(text, values);
    else await query(text, values);
  }
}

export const assetService = new AssetService();
export default assetService;
