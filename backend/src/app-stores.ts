import { config } from "./config";
import { logger } from "./utils/logger";
import { runWithDeadline } from "./utils/timeout";
import { AuditLogsRepository, BrandAssetsRepository, type BrandAssetRecord } from "./repositories";
import { lookalikeDetectionService, normalizeComparableName } from "./lookalike.service";
import { logoSimilarityService } from "./logo-similarity.service";
import { isTrustedOfficialAsset } from "./asset-trust";
import {
  googlePlayClient,
  type PlayStoreListing,
} from "./integrations/google-play.client";

export type AppStorePlatform = "apple_app_store" | "google_play";

export interface MobileAppFinding {
  store: AppStorePlatform;
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
  source: AppStorePlatform;
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

type NormalizedListing = {
  appId: string;
  title: string;
  developer: string;
  description: string;
  iconUrl: string;
  storeUrl: string;
  rating?: number;
  reviewCount?: number;
};

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

const APPLE_PLATFORM_ALIASES = ["appstore", "appleappstore", "apple", "ios"];
const PLAY_PLATFORM_ALIASES = ["playstore", "googleplay", "google", "android"];

function normalized(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/[\W_]+/g, "");
}

function assetValue(asset: BrandAssetRecord): string {
  return asset.value || asset.identifier || "";
}

function platformAliases(store: AppStorePlatform): string[] {
  return store === "apple_app_store" ? APPLE_PLATFORM_ALIASES : PLAY_PLATFORM_ALIASES;
}

function isOfficialListing(
  listing: NormalizedListing,
  store: AppStorePlatform,
  assets: BrandAssetRecord[],
): boolean {
  const identifiers = [listing.appId].filter(Boolean).map((value) => normalized(value));
  const listingUrl = listing.storeUrl.toLowerCase().replace(/\/+$/, "");
  const aliases = platformAliases(store);

  return assets.some((asset) => {
    if (!isTrustedOfficialAsset(asset)) return false;
    const type = asset.asset_type.toLowerCase();
    if (!["mobile_app", "app_store_id"].includes(type)) return false;
    if (!aliases.includes(normalized(asset.platform))) return false;

    const registeredIdentifier = normalized(assetValue(asset));
    const registeredUrl = asset.canonical_url?.toLowerCase().replace(/\/+$/, "");
    return (
      (registeredIdentifier.length > 0 && identifiers.includes(registeredIdentifier)) ||
      Boolean(listingUrl && registeredUrl && listingUrl === registeredUrl)
    );
  });
}

function evaluateListing(
  listing: NormalizedListing,
  store: AppStorePlatform,
  brandName: string,
  alternateNames: string[],
  assets: BrandAssetRecord[],
): MobileAppFinding | null {
  const { appId, title, storeUrl } = listing;
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
    (asset) => isTrustedOfficialAsset(asset) && ["mobile_app", "app_store_id"].includes(asset.asset_type.toLowerCase()),
  );
  const officialPublishers = officialAssets
    .map((asset) => asset.metadata?.publisher)
    .filter((publisher): publisher is string => typeof publisher === "string" && publisher.trim().length > 0)
    .map(normalized);
  const developerName = listing.developer.trim();
  const developer = developerName || "Publisher not supplied";
  const normalizedDeveloper = normalized(developerName);
  const publisherMatches =
    officialPublishers.length > 0 && officialPublishers.includes(normalizedDeveloper);
  const publisherMismatch =
    officialPublishers.length > 0 &&
    Boolean(normalizedDeveloper) &&
    !publisherMatches;
  const description = listing.description.slice(0, 1000);
  const mentionsBrand = registeredNames.some((name) => normalized(description).includes(name));
  const official = isOfficialListing(listing, store, assets);
  const relevantToBrand = official || nameSimilarity >= 0.65 || mentionsBrand;
  if (!relevantToBrand) return null;

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
    store,
    appId,
    title,
    developer,
    description,
    iconUrl: listing.iconUrl,
    storeUrl,
    ...(typeof listing.rating === "number" ? { rating: listing.rating } : {}),
    ...(typeof listing.reviewCount === "number" ? { reviewCount: listing.reviewCount } : {}),
    isOfficialDeveloper: official || publisherMatches,
    isExcludedOfficial: official,
    lookalikeSimilarity: nameSimilarity,
    logoSimilarity: null,
    logoComparisonStatus: "not_assessed",
    riskScore: official ? 0 : riskScore,
    evidence: official ? ["Exact application ID or official store URL matched the registered asset registry."] : evidence,
  };
}

function fromApple(listing: AppleListing): NormalizedListing | null {
  const appId = listing.bundleId || (listing.trackId === undefined ? "" : String(listing.trackId));
  const title = listing.trackName?.trim() ?? "";
  const storeUrl = listing.trackViewUrl?.trim() ?? "";
  if (!appId || !title || !storeUrl) return null;

  return {
    appId,
    title,
    developer: listing.sellerName?.trim() ?? "",
    description: listing.description ?? "",
    iconUrl: listing.artworkUrl100 ?? "",
    storeUrl,
    ...(typeof listing.averageUserRating === "number" ? { rating: listing.averageUserRating } : {}),
    ...(typeof listing.userRatingCount === "number" ? { reviewCount: listing.userRatingCount } : {}),
  };
}

function fromPlay(listing: PlayStoreListing): NormalizedListing {
  return {
    appId: listing.packageId,
    title: listing.title,
    developer: listing.developer,
    description: listing.description,
    iconUrl: listing.iconUrl,
    storeUrl: listing.storeUrl,
    ...(typeof listing.rating === "number" ? { rating: listing.rating } : {}),
    ...(typeof listing.reviewCount === "number" ? { reviewCount: listing.reviewCount } : {}),
  };
}

export class AppStoresMonitoringService {
  private async searchApple(
    brandName: string,
    timeoutMs: number,
  ): Promise<{ listings: NormalizedListing[]; status: AppStoreSourceStatus }> {
    const outcome = await runWithDeadline(
      async () => {
        const url = new URL("https://itunes.apple.com/search");
        url.searchParams.set("term", brandName);
        url.searchParams.set("entity", "software");
        url.searchParams.set("limit", String(config.APP_STORE_RESULT_LIMIT));
        url.searchParams.set("country", config.APPLE_STORE_COUNTRY);

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const response = await fetch(url, {
            headers: { Accept: "application/json" },
            signal: controller.signal,
          });
          if (!response.ok) {
            throw new Error(`Apple App Store search returned HTTP ${response.status}`);
          }
          const payload = (await response.json()) as { results?: AppleListing[] };
          const listings = Array.isArray(payload.results) ? payload.results : [];
          return listings
            .map((listing) => fromApple(listing))
            .filter((listing): listing is NormalizedListing => listing !== null);
        } finally {
          clearTimeout(timer);
        }
      },
      timeoutMs,
      "Apple App Store search",
    );

    if (!outcome.value) {
      return {
        listings: [],
        status: {
          source: "apple_app_store",
          status: "unavailable",
          error: outcome.error ?? "Apple App Store search failed",
          candidatesFound: 0,
        },
      };
    }

    return {
      listings: outcome.value,
      status: {
        source: "apple_app_store",
        status: "available",
        candidatesFound: outcome.value.length,
      },
    };
  }

  private async searchPlay(
    brandName: string,
    timeoutMs: number,
  ): Promise<{ listings: NormalizedListing[]; status: AppStoreSourceStatus }> {
    const result = await googlePlayClient.search(brandName, {
      limit: config.APP_STORE_RESULT_LIMIT,
      timeoutMs,
    });

    if (result.status !== "available") {
      return {
        listings: [],
        status: {
          source: "google_play",
          status: "unavailable",
          error: result.error ?? "Google Play search failed",
          candidatesFound: 0,
        },
      };
    }

    return {
      listings: result.listings.map(fromPlay),
      status: {
        source: "google_play",
        status: "available",
        candidatesFound: result.listings.length,
      },
    };
  }

  async scanAppStores(params: {
    brandName: string;
    brandId?: string;
    alternateNames?: string[];
    officialDeveloperName?: string;
    investigationId?: string;
  }): Promise<AppStoreScanResult> {
    const startTime = Date.now();
    const assets = params.brandId
      ? await BrandAssetsRepository.findByBrandId(params.brandId, true)
      : [];
    const officialDeveloperName =
      params.officialDeveloperName ??
      assets
        .filter((asset) =>
          isTrustedOfficialAsset(asset) &&
          ["mobile_app", "app_store_id"].includes(asset.asset_type.toLowerCase()),
        )
        .map((asset) => asset.metadata?.publisher)
        .find((publisher): publisher is string => typeof publisher === "string") ??
      null;

    const timeoutMs = config.MONITORING_SOURCE_TIMEOUT_MS;

    // Apple and Google Play are queried in parallel; a failure in one store
    // never hides results from the other.
    const [apple, play] = await Promise.all([
      this.searchApple(params.brandName, timeoutMs),
      this.searchPlay(params.brandName, timeoutMs),
    ]);

    const findings: MobileAppFinding[] = [];
    const seen = new Set<string>();

    for (const listing of [...apple.listings, ...play.listings]) {
      const store: AppStorePlatform = apple.listings.includes(listing)
        ? "apple_app_store"
        : "google_play";
      const key = `${store}:${listing.appId}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const finding = evaluateListing(
        listing,
        store,
        params.brandName,
        params.alternateNames ?? [],
        assets,
      );
      if (finding) findings.push(finding);
    }

    // Play Search results carry titles and publishers but not descriptions or
    // icons for every card. Enrich only the candidates that matter for review.
    const playNeedingDetail = findings.filter(
      (finding) =>
        finding.store === "google_play" &&
        !finding.isExcludedOfficial &&
        finding.lookalikeSimilarity >= 0.65 &&
        (!finding.iconUrl || !finding.description),
    );
    if (playNeedingDetail.length > 0) {
      const enriched = await googlePlayClient.enrichListings(
        playNeedingDetail.map((finding) => ({
          packageId: finding.appId,
          title: finding.title,
          developer: finding.developer,
          description: finding.description,
          iconUrl: finding.iconUrl,
          storeUrl: finding.storeUrl,
        })),
        { limit: 5, timeoutMs },
      );
      for (const detail of enriched) {
        const target = findings.find(
          (finding) => finding.store === "google_play" && finding.appId === detail.packageId,
        );
        if (!target) continue;
        target.description = detail.description || target.description;
        target.iconUrl = detail.iconUrl || target.iconUrl;
      }
    }

    let logoComparisons: AppStoreScanResult["logoComparisons"] = {
      compared: 0,
      unavailable: 0,
      notConfigured: 0,
    };

    const logoAssets = assets.filter(
      (asset) =>
        isTrustedOfficialAsset(asset) &&
        asset.asset_type.toLowerCase() === "logo" &&
        ((typeof asset.canonical_url === "string" && asset.canonical_url.length > 0) ||
          (Buffer.isBuffer(asset.image_data) && asset.image_data.length > 0)),
    );
    logoComparisons = {
      compared: 0,
      unavailable: 0,
      notConfigured: logoAssets.length === 0 ? 1 : 0,
    };

    const logoCandidates = findings
      .filter((finding) => !finding.isExcludedOfficial && finding.lookalikeSimilarity >= 0.65 && finding.iconUrl)
      .slice(0, 3);

    if (logoAssets.length > 0) {
      await Promise.all(
        logoCandidates.map(async (finding) => {
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
            logoComparisons.compared += 1;
          } catch (error) {
            finding.logoComparisonStatus = "unavailable";
            finding.evidence.push(
              `Logo similarity was not assessed: ${error instanceof Error ? error.message : "Image source unavailable"}`,
            );
            logoComparisons.unavailable += 1;
          }
        }),
      );
    }

    const unauthorized = findings.filter((finding) => !finding.isExcludedOfficial);

    try {
      await AuditLogsRepository.recordLog({
        investigation_id: params.investigationId,
        source: "app_store",
        status:
          apple.status.status === "available" || play.status.status === "available"
            ? "success"
            : "failed",
        latency_ms: Date.now() - startTime,
        error_message:
          apple.status.error || play.status.error
            ? [apple.status.error, play.status.error].filter(Boolean).join(" | ")
            : null,
      });
    } catch (error) {
      logger.warn("[app-stores] Audit logging failed", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }

    logger.info("[app-stores] App-store scan completed", {
      brandName: params.brandName,
      appleStatus: apple.status.status,
      playStatus: play.status.status,
      findings: findings.length,
      latencyMs: Date.now() - startTime,
    });

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
      sources: [apple.status, play.status],
      logoComparisons,
    };
  }
}

export const appStoresMonitoringService = new AppStoresMonitoringService();
export default appStoresMonitoringService;
