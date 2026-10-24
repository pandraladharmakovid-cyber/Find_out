import { ExclusionRulesRepository, type ExclusionRuleRecord } from "./repositories";
import { logger } from "./utils/logger";
import type { BrandAssetRecord } from "./repositories";
import { isDomainAssetType, isTrustedOfficialAsset } from "./asset-trust";

export interface OfficialCandidateIdentity {
  platform: string;
  identifier: string;
  url: string;
}

function normalizeIdentifier(value: string): string {
  return value.normalize("NFKC").trim().replace(/^@/, "").toLowerCase();
}

function normalizeAssetUrl(value: string | null | undefined): string {
  if (!value) return "";
  try {
    const url = new URL(value);
    const port = url.port ? `:${url.port}` : "";
    return `${url.protocol.toLowerCase()}//${url.hostname.toLowerCase()}${port}${url.pathname.replace(/\/+$/, "")}${url.search}`;
  } catch {
    return value.trim().replace(/\/+$/, "").toLowerCase();
  }
}

export function matchesOfficialAsset(
  candidate: OfficialCandidateIdentity,
  asset: BrandAssetRecord,
): boolean {
  if (!isTrustedOfficialAsset(asset)) return false;
  const type = asset.asset_type.toLowerCase();
  const isSocialAsset = ["social_account", "social_profile", "social_handle"].includes(type);
  const isAppAsset = ["mobile_app", "app_store_id"].includes(type);
  const platform = candidate.platform.toLowerCase().replace(/[^a-z0-9]/g, "");
  if ((platform === "reddit" || platform === "bluesky" || platform === "youtube") && !isSocialAsset) return false;
  if (platform.includes("appstore") && !isAppAsset) return false;

  const assetPlatform = asset.platform.toLowerCase().replace(/[^a-z0-9]/g, "");
  const platformMatches =
    assetPlatform === platform ||
    (platform === "appleappstore" && ["appstore", "ios"].includes(assetPlatform));
  if (!platformMatches) return false;

  const identifier = normalizeIdentifier(candidate.identifier);
  const registeredIdentifier = normalizeIdentifier(asset.identifier || asset.value);
  if (identifier && identifier === registeredIdentifier) return true;
  return normalizeAssetUrl(candidate.url) === normalizeAssetUrl(asset.canonical_url);
}

export function exactDomainExclusionMatch(targetUrl: string, registeredDomain: string): boolean {
  try {
    const target = new URL(/^[a-z][a-z0-9+.-]*:/i.test(targetUrl.trim())
      ? targetUrl.trim()
      : `https://${targetUrl.trim()}`);
    const registered = new URL(/^[a-z][a-z0-9+.-]*:/i.test(registeredDomain.trim())
      ? registeredDomain.trim()
      : `https://${registeredDomain.trim()}`);
    if (!["http:", "https:"].includes(target.protocol) || !["http:", "https:"].includes(registered.protocol)) {
      return false;
    }
    const hostname = target.hostname.toLowerCase().replace(/\.$/, "");
    const officialHostname = registered.hostname.toLowerCase().replace(/\.$/, "");
    return Boolean(hostname && officialHostname && hostname === officialHostname);
  } catch {
    return false;
  }
}

export interface ExclusionCheckResult {
  isExcluded: boolean;
  matchedRule: ExclusionRuleRecord | null;
  reason: string | null;
  evaluatedUrl: string;
}

export class ExclusionEngineService {
  /**
   * Evaluates an unknown target against registered regex patterns and literal substring exclusions.
   */
  async checkExclusion(targetUrl: string, brandId?: string): Promise<ExclusionCheckResult> {
    if (!brandId) {
      return { isExcluded: false, matchedRule: null, reason: null, evaluatedUrl: targetUrl };
    }
    const activeRules = await ExclusionRulesRepository.listActive(brandId);
    const normalizedTarget = targetUrl.toLowerCase().trim();

    for (const rule of activeRules) {
      if (!rule.pattern) continue;

      const patternStr = rule.pattern.trim();

      if (rule.asset_type && isDomainAssetType(rule.asset_type)) {
        if (rule.asset_value && exactDomainExclusionMatch(targetUrl, rule.asset_value)) {
          logger.info("[exclusion-engine] Target matched an exact verified domain", {
            targetUrl,
            domain: rule.asset_value,
          });
          return {
            isExcluded: true,
            matchedRule: rule,
            reason: rule.reason ?? `Exact verified domain: ${rule.asset_value}`,
            evaluatedUrl: targetUrl,
          };
        }
        // A verified domain never suppresses lookalikes, subdomains, or regex-like strings.
        continue;
      }

      // Test regex pattern if wrapped or contains regex characters
      try {
        const regex = new RegExp(patternStr, "i");
        if (regex.test(normalizedTarget)) {
          logger.info("[exclusion-engine] Target matched active exclusion pattern regex", {
            targetUrl,
            pattern: rule.pattern,
          });

          return {
            isExcluded: true,
            matchedRule: rule,
            reason: rule.reason ?? `Matched regex pattern: ${rule.pattern}`,
            evaluatedUrl: targetUrl,
          };
        }
      } catch {
        // Fallback to literal domain/substring matching if pattern is not valid regex
        if (normalizedTarget.includes(patternStr.toLowerCase())) {
          logger.info("[exclusion-engine] Target matched active literal exclusion pattern", {
            targetUrl,
            pattern: rule.pattern,
          });

          return {
            isExcluded: true,
            matchedRule: rule,
            reason: rule.reason ?? `Matched literal pattern: ${rule.pattern}`,
            evaluatedUrl: targetUrl,
          };
        }
      }
    }

    return {
      isExcluded: false,
      matchedRule: null,
      reason: null,
      evaluatedUrl: targetUrl,
    };
  }

  /**
   * Adds and activates a new exclusion pattern.
   */
  async registerExclusion(
    pattern: string,
    reason: string | undefined,
    assetId: string,
    brandId: string,
  ): Promise<ExclusionRuleRecord> {
    logger.info("[exclusion-engine] Registering exclusion for a verified asset", {
      pattern,
      reason,
      assetId,
      brandId,
    });
    return await ExclusionRulesRepository.addRule(pattern, reason, assetId, brandId);
  }
}

export const exclusionEngineService = new ExclusionEngineService();
export default exclusionEngineService;
