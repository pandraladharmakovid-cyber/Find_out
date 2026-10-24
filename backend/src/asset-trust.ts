import type { BrandAssetRecord } from "./repositories";

export const TRUSTED_ASSET_STATUSES = ["VERIFIED", "VERIFIED_LEGACY"] as const;

export type TrustedAssetStatus = (typeof TRUSTED_ASSET_STATUSES)[number];

/**
 * Central trust decision used by exclusions, app-store comparisons, and logo checks.
 * Missing status is accepted only for legacy in-memory/legacy-database records that
 * predate verification_status; all newly migrated database rows have an explicit state.
 */
export function isTrustedOfficialAsset(
  asset: Pick<BrandAssetRecord, "is_verified" | "verification_status">,
): boolean {
  if (!asset.is_verified) return false;
  if (asset.verification_status === undefined) return true;
  return TRUSTED_ASSET_STATUSES.includes(
    asset.verification_status as TrustedAssetStatus,
  );
}

export function isDomainAssetType(assetType: string): boolean {
  return ["domain", "subdomain", "website"].includes(assetType.toLowerCase());
}

export function isSocialAssetType(assetType: string): boolean {
  return ["social_account", "social_profile", "social_handle"].includes(
    assetType.toLowerCase(),
  );
}

export function isAppAssetType(assetType: string): boolean {
  return ["mobile_app", "app_store_id"].includes(assetType.toLowerCase());
}
