import { ExclusionRulesRepository, type ExclusionRuleRecord } from "./repositories";
import { logger } from "./utils/logger";
import type { BrandAssetRecord } from "./repositories";

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
    return `${url.protocol.toLowerCase()}//${url.hostname.toLowerCase()}${url.pathname.replace(/\/+$/, "")}${url.search}`;
  } catch {
    return value.trim().replace(/\/+$/, "").toLowerCase();
  }
}

export function matchesOfficialAsset(
  candidate: OfficialCandidateIdentity,
  asset: BrandAssetRecord,
): boolean {
  if (!asset.is_verified) return false;
  const type = asset.asset_type.toLowerCase();
  const isSocialAsset = ["social_account", "social_profile", "social_handle"].includes(type);
  const isAppAsset = ["mobile_app", "app_store_id"].includes(type);
  const platform = candidate.platform.toLowerCase().replace(/[^a-z0-9]/g, "");
  if ((platform === "reddit" || platform === "youtube") && !isSocialAsset) return false;
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
  async checkExclusion(targetUrl: string): Promise<ExclusionCheckResult> {
    const activeRules = await ExclusionRulesRepository.listActive();
    const normalizedTarget = targetUrl.toLowerCase().trim();

    for (const rule of activeRules) {
      if (!rule.pattern) continue;

      const patternStr = rule.pattern.trim();

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
  async registerExclusion(pattern: string, reason?: string): Promise<ExclusionRuleRecord> {
    logger.info("[exclusion-engine] Registering new exclusion rule", { pattern, reason });
    return await ExclusionRulesRepository.addRule(pattern, reason);
  }
}

export const exclusionEngineService = new ExclusionEngineService();
export default exclusionEngineService;