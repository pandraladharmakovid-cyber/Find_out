import { config } from "./config";
import { logger } from "./utils/logger";
import { AuditLogsRepository, BrandAssetsRepository, type BrandAssetRecord } from "./repositories";
import { lookalikeDetectionService, normalizeComparableName } from "./lookalike.service";
import { logoSimilarityService } from "./logo-similarity.service";

export interface MobileAppFinding {
  store: "apple_app_store";
  appId: string;
  title: string;
  developer: string;
  description: string;
  iconUrl: string;
  storeUrl: string;
  rating?: number;
  reviewCount?: number;
  isOfficialDeveloper: boolean;
  isExcludedOfficial: boolean;
  lookalikeSimilarity: number;
  logoSimilarity: number | null;
  logoComparisonStatus: "not_assessed" | "compared" | "unavailable";
  riskScore: number;
  evidence: string[];
}

export interface AppStoreSourceStatus {
  source: "apple_app_store";
  status: "available" | "unavailable";
  error?: string;
  candidatesFound: number;
}

export interface AppStoreScanResult {
  brandName: string;
  officialDeveloperName: string | null;
  totalFound: number;
  unauthorizedAppsCount: number;
  findings: MobileAppFinding[];
  hasCriticalImpersonation: boolean;
  scannedAt: string;
  sources: AppStoreSourceStatus[];
  logoComparisons: {
    compared: number;
    unavailable: number;
    notConfigured: number;
  };
}

type AppleListing = {
  trackId?: number;
  bundleId?: string;
  trackName?: string;
  sellerName?: string;
  description?: string;
  artworkUrl100?: string;
  trackViewUrl?: string;
  averageUserRating?: number;
  userRatingCount?: number;
};

function normalized(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/[\W_]+/g, "");
}

function assetValue(asset: BrandAssetRecord): string {
  return asset.value || asset.identifier || "";
}

function isOfficialListing(listing: AppleListing, assets: BrandAssetRecord[]): boolean {
  const identifiers = [listing.bundleId, listing.trackId === undefined ? "" : String(listing.trackId)]
    .filter(Boolean)
    .map((value) => normalized(value as string));
  const listingUrl = listing.trackViewUrl?.toLowerCase().replace(/\/+$/, "");

  return assets.some((asset) => {
    if (!asset.is_verified) return false;
    const type = asset.asset_type.toLowerCase();
    if (!["mobile_app", "app_store_id"].includes(type)) return false;
    const platform = normalized(asset.platform);
    if (!["appstore", "appleappstore", "ios"].includes(platform)) return false;

    const registeredIdentifier = normalized(assetValue(asset));
    const registeredUrl = asset.canonical_url?.toLowerCase().replace(/\/+$/, "");
    return (
      identifiers.includes(registeredIdentifier) ||
      Boolean(listingUrl && registeredUrl && listingUrl === registeredUrl)
    );
  });
}

function evaluateListing(
  listing: AppleListing,
  brandName: string,
  alternateNames: string[],
  assets: BrandAssetRecord[],
): MobileAppFinding | null {
  const appId = listing.bundleId || (listing.trackId === undefined ? "" : String(listing.trackId));
  const title = listing.trackName?.trim();
  const storeUrl = listing.trackViewUrl?.trim();
  if (!appId || !title || !storeUrl) return null;

  const registeredNames = [brandName, ...alternateNames].map(normalizeComparableName).filter(Boolean);
  const normalizedTitle = normalizeComparableName(title);
  const nameSimilarity = Math.max(
    0,
    ...registeredNames.map((name) => {
      if (normalizedTitle.includes(name)) return 1;
      return lookalikeDetectionService.similarityRatio(name, normalizedTitle);
    }),
  );
  const officialAssets = assets.filter(
    (asset) => asset.is_verified && ["mobile_app", "app_store_id"].includes(asset.asset_type.toLowerCase()),
  );
  const officialPublishers = officialAssets
    .map((asset) => asset.metadata?.publisher)
    .filter((publisher): publisher is string => typeof publisher === "string" && publisher.trim().length > 0)
    .map(normalized);
  const developer = listing.sellerName?.trim() || "Publisher not supplied";
  const publisherMismatch =
    officialPublishers.length > 0 &&
    !officialPublishers.includes(normalized(developer));
  const description = (listing.description ?? "").slice(0, 1000);
  const mentionsBrand = registeredNames.some((name) => normalized(description).includes(name));
  const official = isOfficialListing(listing, assets);

  const evidence: string[] = [];
  if (nameSimilarity >= 0.65) {
    evidence.push(`App name resembles a registered brand name (${Math.round(nameSimilarity * 100)}% similarity).`);
  }
  if (publisherMismatch) evidence.push("Publisher differs from the registered official app publisher.");
  if (mentionsBrand) evidence.push("App description uses a registered brand name.");

  const riskScore = Math.min(
    100,
    (nameSimilarity >= 0.85 ? 35 : nameSimilarity >= 0.65 ? 20 : 0) +
      (publisherMismatch && nameSimilarity >= 0.65 ? 30 : 0) +
      (mentionsBrand ? 15 : 0),
  );

  return {
    store: "apple_app_store",
    appId,
    title,
    developer,
    description,
    iconUrl: listing.artworkUrl100 ?? "",
    storeUrl,
    ...(typeof listing.averageUserRating === "number" ? { rating: listing.averageUserRating } : {}),
    ...(typeof listing.userRatingCount === "number" ? { reviewCount: listing.userRatingCount } : {}),
    isOfficialDeveloper: !publisherMismatch,
    isExcludedOfficial: official,
    lookalikeSimilarity: nameSimilarity,
    logoSimilarity: null,
    logoComparisonStatus: "not_assessed",
    riskScore: official ? 0 : riskScore,
    evidence: official ? ["Exact application ID or official store URL matched the registered asset registry."] : evidence,
  };
}

export class AppStoresMonitoringService {
  async scanAppStores(params: {
    brandName: string;
    brandId?: string;
    alternateNames?: string[];
    officialDeveloperName?: string;
    investigationId?: string;
  }): Promise<AppStoreScanResult> {
    const startTime = Date.now();
    const findings: MobileAppFinding[] = [];
    const assets = params.brandId
      ? await BrandAssetsRepository.findByBrandId(params.brandId, true)
      : [];
    const officialDeveloperName =
      params.officialDeveloperName ??
      assets
        .map((asset) => asset.metadata?.publisher)
        .find((publisher): publisher is string => typeof publisher === "string") ??
      null;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
    let logoComparisons: AppStoreScanResult["logoComparisons"] = {
      compared: 0,
      unavailable: 0,
      notConfigured: 0,
    };
    let sourceStatus: AppStoreSourceStatus;

    try {
      const url = new URL("https://itunes.apple.com/search");
      url.searchParams.set("term", params.brandName);
      url.searchParams.set("entity", "software");
      url.searchParams.set("limit", "50");
      url.searchParams.set("country", "us");
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Apple App Store search returned HTTP ${response.status}`);

      const payload = (await response.json()) as { results?: AppleListing[] };
      const listings = Array.isArray(payload.results) ? payload.results : [];
      for (const listing of listings) {
        const finding = evaluateListing(
          listing,
          params.brandName,
          params.alternateNames ?? [],
          assets,
        );
        if (finding) findings.push(finding);
      }
      const logoAssets = assets.filter(
        (asset) =>
          asset.is_verified &&
          asset.asset_type.toLowerCase() === "logo" &&
          ((typeof asset.canonical_url === "string" && asset.canonical_url.length > 0) ||
            (Buffer.isBuffer(asset.image_data) && asset.image_data.length > 0)),
      );
      logoComparisons = { compared: 0, unavailable: 0, notConfigured: logoAssets.length === 0 ? 1 : 0 };
      const logoCandidates = findings
        .filter((finding) => !finding.isExcludedOfficial && finding.lookalikeSimilarity >= 0.65 && finding.iconUrl)
        .slice(0, 3);
      if (logoAssets.length > 0) {
        await Promise.all(logoCandidates.map(async (finding) => {
          try {
            const comparisons = await Promise.all(
              logoAssets.slice(0, 3).map((asset) => {
                if (Buffer.isBuffer(asset.image_data)) {
                  return logoSimilarityService.compareImageUrlToBuffer({
                    targetImageUri: finding.iconUrl,
                    referenceImage: asset.image_data,
                    referenceAssetUri: asset.canonical_url ?? "registered-logo-upload",
                  });
                }
                if (!asset.canonical_url) {
                  throw new Error("Registered logo has no readable image.");
                }
                return logoSimilarityService.compareImageUrls({
                  targetImageUri: finding.iconUrl,
                  referenceAssetUri: asset.canonical_url,
                });
              }),
            );
            const best = comparisons.reduce((current, comparison) =>
              comparison.similarityScore > current.similarityScore ? comparison : current,
            );
            finding.logoSimilarity = best.similarityScore;
            finding.logoComparisonStatus = "compared";
            finding.evidence.push(
              `App icon similarity to a registered logo: ${Math.round(best.similarityScore * 100)}% (64-pixel average-hash comparison).`,
            );
            if (best.similarityScore >= 0.82) {
              finding.riskScore = Math.min(100, finding.riskScore + 25);
            }
            logoComparisons.compared++;
          } catch (error) {
            finding.logoComparisonStatus = "unavailable";
            finding.evidence.push(
              `Logo similarity was not assessed: ${error instanceof Error ? error.message : "Image source unavailable"}`,
            );
            logoComparisons.unavailable++;
          }
        }));
      }
      sourceStatus = { source: "apple_app_store", status: "available", candidatesFound: findings.length };

      await AuditLogsRepository.recordLog({
        investigation_id: params.investigationId,
        source: "apple_app_store",
        status: "success",
        latency_ms: Date.now() - startTime,
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown source error";
      sourceStatus = {
        source: "apple_app_store",
        status: "unavailable",
        error: errorMessage,
        candidatesFound: 0,
      };
      logger.warn("[app-stores] Apple App Store source unavailable", { error: errorMessage });
      await AuditLogsRepository.recordLog({
        investigation_id: params.investigationId,
        source: "apple_app_store",
        status: "failed",
        latency_ms: Date.now() - startTime,
        error_message: errorMessage,
      });
      logoComparisons = { compared: 0, unavailable: 0, notConfigured: 0 };
    } finally {
      clearTimeout(timeout);
    }

    const unauthorized = findings.filter((finding) => !finding.isExcludedOfficial);
    return {
      brandName: params.brandName,
      officialDeveloperName,
      totalFound: findings.length,
      unauthorizedAppsCount: unauthorized.length,
      findings,
      hasCriticalImpersonation: unauthorized.some(
        (finding) => finding.riskScore >= 65 && finding.lookalikeSimilarity >= 0.85,
      ),
      scannedAt: new Date().toISOString(),
      sources: [sourceStatus],
      logoComparisons,
    };
  }
}

export const appStoresMonitoringService = new AppStoresMonitoringService();
export default appStoresMonitoringService;
