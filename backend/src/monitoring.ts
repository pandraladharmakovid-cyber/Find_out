import { query } from "./db";
import { logger } from "./utils/logger";
import { brandService } from "./brands";
import { lookalikeDetectionService, normalizeComparableName } from "./lookalike.service";
import { socialMonitoringService, type SocialScanResult } from "./social";
import { appStoresMonitoringService, type AppStoreScanResult } from "./app-stores";
import { matchesOfficialAsset } from "./exclusion-engine.service";
import { alertsService } from "./alerts";
import { BrandAssetsRepository, type BrandAssetRecord } from "./repositories";
import type { QueryResultRow } from "pg";

export interface MonitoringJobRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  job_type: "domain" | "social" | "app_store" | "full_scan";
  status: "pending" | "running" | "completed" | "failed";
  findings_count: number;
  threats_detected: number;
  details: Record<string, unknown>;
  started_at: string;
  completed_at: string | null;
}

export interface MonitoringSourceStatus {
  source: string;
  status: "available" | "unavailable" | "not_configured";
  candidatesFound: number;
  error?: string;
}

interface StoredCandidateInput {
  platform: string;
  identifier: string;
  url: string;
  name: string;
  publisher?: string;
  description?: string;
  iconUrl?: string;
  riskScore: number;
  confidence: number;
  excluded: boolean;
  matchAsset?: BrandAssetRecord;
  evidence: Array<{
    type: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    details: Record<string, unknown>;
    similarity?: number;
  }>;
}

export interface MonitoringScanSummary {
  brandId: string;
  brandName: string;
  runId: string;
  domainsEvaluated: number;
  suspiciousDomains: string[];
  socialThreats: number;
  unauthorizedApps: number;
  investigationsTriggered: string[];
  alertsGenerated: number;
  candidatesFound: number;
  excludedOfficialAssets: number;
  sourceStatuses: MonitoringSourceStatus[];
}

function normalized(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/[\W_]+/g, "");
}

function isScamContent(value: string): boolean {
  return /\b(scam|fake|phishing|fraud|giveaway|free money|airdrop|urgent support|login now|verify account|customer service)\b/i.test(value);
}

function findOfficialMatch(
  candidate: { platform: string; identifier: string; url: string },
  assets: BrandAssetRecord[],
): BrandAssetRecord | undefined {
  return assets.find((asset) => matchesOfficialAsset(candidate, asset));
}

function socialCandidates(
  result: SocialScanResult,
  brandName: string,
  alternateNames: string[],
  assets: BrandAssetRecord[],
): StoredCandidateInput[] {
  const brandNames = [brandName, ...alternateNames].map(normalizeComparableName).filter(Boolean);
  const candidates: StoredCandidateInput[] = [];

  for (const post of result.redditData.posts) {
    const profileUrl = `https://www.reddit.com/user/${encodeURIComponent(post.author)}/`;
    const author = post.author || "Unknown Reddit account";
    const similarity = Math.max(
      0,
      ...brandNames.map((brand) => {
        const account = normalizeComparableName(author);
        return account.includes(brand)
          ? 1
          : lookalikeDetectionService.similarityRatio(brand, account);
      }),
    );
    const text = `${post.title} ${post.selftext}`;
    const suspicious = isScamContent(text);
    const matchAsset = findOfficialMatch(
      { platform: "reddit", identifier: author, url: profileUrl },
      assets,
    );
    const evidence: StoredCandidateInput["evidence"] = [
      {
        type: "SOCIAL_SEARCH_RESULT",
        severity: "LOW",
        details: {
          source: "Reddit public discussion search",
          statement: "A matching public discussion was found; this alone does not establish account impersonation.",
          title: post.title,
          subreddit: post.subreddit,
          permalink: post.permalink,
        },
      },
    ];
    if (similarity >= 0.65) {
      evidence.push({
        type: "NAME_LOOKALIKE",
        severity: similarity >= 0.85 ? "MEDIUM" : "LOW",
        similarity,
        details: { accountName: author, matchedBrandName: brandName, similarity },
      });
    }
    if (suspicious) {
      evidence.push({
        type: "SUSPICIOUS_CONTENT",
        severity: "HIGH",
        details: { keywordsMatched: true, context: text.slice(0, 500) },
      });
    }
    if (matchAsset) {
      evidence.push({
        type: "OFFICIAL_ASSET_MATCH",
        severity: "LOW",
        details: { assetId: matchAsset.id, reason: "Exact registered account identifier or URL match." },
      });
    }
    candidates.push({
      platform: "reddit",
      identifier: author,
      url: profileUrl,
      name: author,
      description: text.slice(0, 1000),
      riskScore: matchAsset ? 0 : Math.min(100, (similarity >= 0.85 ? 35 : similarity >= 0.65 ? 20 : 0) + (suspicious ? 40 : 0)),
      confidence: suspicious && similarity >= 0.65 ? 0.75 : 0.45,
      excluded: Boolean(matchAsset),
      ...(matchAsset ? { matchAsset } : {}),
      evidence,
    });
  }

  for (const video of result.youtubeData.videos) {
    const channelName = video.channelTitle || video.title;
    const channelUrl = video.channelId
      ? `https://www.youtube.com/channel/${encodeURIComponent(video.channelId)}`
      : video.videoUrl;
    const similarity = Math.max(
      0,
      ...brandNames.map((brand) => {
        const channel = normalizeComparableName(channelName);
        return channel.includes(brand)
          ? 1
          : lookalikeDetectionService.similarityRatio(brand, channel);
      }),
    );
    const text = `${video.title} ${video.description}`;
    const suspicious = isScamContent(text);
    const matchAsset = findOfficialMatch(
      { platform: "youtube", identifier: video.channelId || video.videoId, url: channelUrl },
      assets,
    );
    const evidence: StoredCandidateInput["evidence"] = [
      {
        type: "SOCIAL_SEARCH_RESULT",
        severity: "LOW",
        details: {
          source: "YouTube public video search",
          statement: "A matching public video was found; the channel identity requires human review.",
          title: video.title,
          videoUrl: video.videoUrl,
        },
      },
    ];
    if (similarity >= 0.65) {
      evidence.push({
        type: "NAME_LOOKALIKE",
        severity: similarity >= 0.85 ? "MEDIUM" : "LOW",
        similarity,
        details: { channelName, matchedBrandName: brandName, similarity },
      });
    }
    if (suspicious) {
      evidence.push({
        type: "SUSPICIOUS_CONTENT",
        severity: "HIGH",
        details: { keywordsMatched: true, context: text.slice(0, 500) },
      });
    }
    if (matchAsset) {
      evidence.push({
        type: "OFFICIAL_ASSET_MATCH",
        severity: "LOW",
        details: { assetId: matchAsset.id, reason: "Exact registered channel identifier or URL match." },
      });
    }
    candidates.push({
      platform: "youtube",
      identifier: video.channelId || video.videoId,
      url: channelUrl,
      name: channelName,
      description: text.slice(0, 1000),
      riskScore: matchAsset ? 0 : Math.min(100, (similarity >= 0.85 ? 35 : similarity >= 0.65 ? 20 : 0) + (suspicious ? 40 : 0)),
      confidence: suspicious && similarity >= 0.65 ? 0.75 : 0.45,
      excluded: Boolean(matchAsset),
      ...(matchAsset ? { matchAsset } : {}),
      evidence,
    });
  }
  return candidates;
}

export class MonitoringService {
  private async persistCandidate(runId: string, brandId: string, candidate: StoredCandidateInput): Promise<string> {
    const inserted = await query<{ id: string }>(
      `INSERT INTO discovered_candidates (
        run_id, brand_id, platform, candidate_identifier, candidate_url,
        display_name, developer_publisher, description, icon_or_logo_url, is_excluded_official
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id;`,
      [
        runId,
        brandId,
        candidate.platform,
        candidate.identifier,
        candidate.url,
        candidate.name,
        candidate.publisher ?? null,
        candidate.description ?? null,
        candidate.iconUrl ?? null,
        candidate.excluded,
      ],
    );
    const id = inserted.rows[0]?.id;
    if (!id) throw new Error("Monitoring candidate was not persisted");

    for (const evidence of candidate.evidence) {
      await query(
        `INSERT INTO candidate_evidence (candidate_id, evidence_type, severity, details, similarity_score)
         VALUES ($1, $2, $3, $4, $5);`,
        [id, evidence.type, evidence.severity, JSON.stringify(evidence.details), evidence.similarity ?? null],
      );
    }
    await query(
      `INSERT INTO risk_assessments (candidate_id, risk_level, risk_score, confidence_score, primary_reasons, status)
       VALUES ($1, $2, $3, $4, $5, $6);`,
      [
        id,
        candidate.excluded ? "BENIGN" : candidate.riskScore >= 75 ? "HIGH" : candidate.riskScore >= 40 ? "MEDIUM" : "LOW",
        candidate.riskScore,
        candidate.confidence,
        candidate.evidence.map((evidence) => evidence.type),
        candidate.excluded ? "RESOLVED" : "UNRESOLVED",
      ],
    );
    if (candidate.matchAsset) {
      await query(
        `INSERT INTO official_asset_matches (candidate_id, asset_id, matched_by)
         VALUES ($1, $2, $3);`,
        [id, candidate.matchAsset.id, candidate.platform === "apple_app_store" ? "APP_ID_OR_URL" : "EXACT_IDENTIFIER_OR_URL"],
      );
    }
    return id;
  }

  async runBrandScan(brandId: string): Promise<MonitoringScanSummary> {
    const brand = await brandService.getBrandById(brandId);
    if (!brand) throw new Error(`Cannot run monitoring scan: brand ${brandId} not found`);
    const assets = await BrandAssetsRepository.findByBrandId(brand.id);
    const runResult = await query<{ id: string }>(
      `INSERT INTO monitoring_runs (brand_id, target_type, status)
       VALUES ($1, 'SOCIAL_AND_APP', 'IN_PROGRESS') RETURNING id;`,
      [brand.id],
    );
    const runId = runResult.rows[0]?.id;
    if (!runId) throw new Error("Failed to create monitoring run");
    const startedAt = new Date();

    const summary: MonitoringScanSummary = {
      brandId: brand.id,
      brandName: brand.name,
      runId,
      domainsEvaluated: 0,
      suspiciousDomains: [],
      socialThreats: 0,
      unauthorizedApps: 0,
      investigationsTriggered: [],
      alertsGenerated: 0,
      candidatesFound: 0,
      excludedOfficialAssets: 0,
      sourceStatuses: [],
    };

    const [socialResult, appResult] = await Promise.allSettled([
      socialMonitoringService.scanBrandMentions({
        brandName: brand.name,
        associatedDomain: brand.primary_domain,
      }),
      appStoresMonitoringService.scanAppStores({
        brandId: brand.id,
        brandName: brand.name,
        alternateNames: brand.alternate_names ?? [],
      }),
    ]);

    const sourceCandidates: StoredCandidateInput[] = [];
    if (socialResult.status === "fulfilled") {
      const social = socialResult.value;
      summary.socialThreats = social.signals.length;
      summary.sourceStatuses.push(...social.sources);
      sourceCandidates.push(...socialCandidates(social, brand.name, brand.alternate_names ?? [], assets));
      if (social.impersonationDetected && social.overallThreatScore >= 65) {
        const alert = await alertsService.createAlert({
          brandId: brand.id,
          severity: social.overallThreatScore >= 85 ? "critical" : "high",
          title: `Potential social impersonation activity for ${brand.name}`,
          description: `Public social search returned ${social.signals.length} suspicious-content indicators. Account identity is not confirmed by this result.`,
          evidenceSnapshot: { signals: social.signals },
        });
        if (alert) summary.alertsGenerated++;
      }
    } else {
      summary.sourceStatuses.push({
        source: "social_search",
        status: "unavailable",
        candidatesFound: 0,
        error: socialResult.reason instanceof Error ? socialResult.reason.message : "Social source failed",
      });
    }

    if (appResult.status === "fulfilled") {
      const apps: AppStoreScanResult = appResult.value;
      summary.unauthorizedApps = apps.unauthorizedAppsCount;
      summary.sourceStatuses.push(...apps.sources);
      summary.sourceStatuses.push({
        source: "registered_logo_comparison",
        status: apps.logoComparisons.notConfigured > 0
          ? "not_configured"
          : apps.logoComparisons.unavailable > 0
            ? "unavailable"
            : "available",
        candidatesFound: apps.logoComparisons.compared,
        ...(apps.logoComparisons.unavailable > 0
          ? { error: `${apps.logoComparisons.unavailable} image comparison(s) could not be completed.` }
          : apps.logoComparisons.notConfigured > 0
            ? { error: "Register a verified logo URL to enable image comparison." }
            : {}),
      });
      for (const finding of apps.findings) {
        const matchAsset = findOfficialMatch(
          { platform: finding.store, identifier: finding.appId, url: finding.storeUrl },
          assets,
        );
        sourceCandidates.push({
          platform: finding.store,
          identifier: finding.appId,
          url: finding.storeUrl,
          name: finding.title,
          publisher: finding.developer,
          description: finding.description,
          iconUrl: finding.iconUrl,
          riskScore: matchAsset ? 0 : finding.riskScore,
          confidence: finding.lookalikeSimilarity >= 0.85 ? 0.8 : 0.55,
          excluded: Boolean(matchAsset) || finding.isExcludedOfficial,
          ...(matchAsset ? { matchAsset } : {}),
          evidence: [
            {
              type: "APP_NAME_SIMILARITY",
              severity: finding.lookalikeSimilarity >= 0.85 ? "MEDIUM" : "LOW",
              similarity: finding.lookalikeSimilarity,
              details: { similarity: finding.lookalikeSimilarity, title: finding.title },
            },
            ...(finding.evidence.map((reason) => ({
              type: reason.includes("Publisher") ? "PUBLISHER_MISMATCH" : "APP_LISTING_EVIDENCE",
              severity: reason.includes("Publisher") ? "MEDIUM" as const : "LOW" as const,
              details: { reason },
            }))),
            ...(finding.logoSimilarity === null
              ? []
              : [{
                  type: "LOGO_SIMILARITY",
                  severity: finding.logoSimilarity >= 0.82 ? "HIGH" as const : "LOW" as const,
                  similarity: finding.logoSimilarity,
                  details: {
                    similarity: finding.logoSimilarity,
                    method: "8x8 grayscale average hash",
                  },
                }]),
            ...(finding.logoComparisonStatus === "unavailable"
              ? [{
                  type: "LOGO_ASSESSMENT_UNAVAILABLE",
                  severity: "LOW" as const,
                  details: { reason: "The registered logo or app icon could not be retrieved safely." },
                }]
              : []),
            ...(matchAsset
              ? [{
                  type: "OFFICIAL_ASSET_MATCH",
                  severity: "LOW" as const,
                  details: { assetId: matchAsset.id, reason: "Exact registered application ID or official store URL." },
                }]
              : []),
          ],
        });
      }
      if (apps.hasCriticalImpersonation) {
        const alert = await alertsService.createAlert({
          brandId: brand.id,
          severity: "critical",
          title: `Potential app-store impersonation for ${brand.name}`,
          description: "A listing has multiple elevated indicators. Confirm the publisher and listing before treating it as malicious.",
          evidenceSnapshot: { findings: apps.findings.filter((finding) => finding.riskScore >= 65) },
        });
        if (alert) summary.alertsGenerated++;
      }
    } else {
      summary.sourceStatuses.push({
        source: "app_store",
        status: "unavailable",
        candidatesFound: 0,
        error: appResult.reason instanceof Error ? appResult.reason.message : "App-store source failed",
      });
    }

    for (const candidate of sourceCandidates) {
      await this.persistCandidate(runId, brand.id, candidate);
      summary.candidatesFound++;
      if (candidate.excluded) summary.excludedOfficialAssets++;
    }
    summary.sourceStatuses = summary.sourceStatuses.map((source) => ({ ...source }));
    const sourceErrors = summary.sourceStatuses
      .filter((source) => source.status === "unavailable")
      .map(({ source, error }) => ({ source, error: error ?? "Source unavailable" }));

    await query(
      `UPDATE monitoring_runs
       SET status = 'COMPLETED', source_errors = $2, summary = $3, completed_at = NOW()
       WHERE id = $1;`,
      [runId, JSON.stringify(sourceErrors), JSON.stringify(summary)],
    );
    await query(
      `INSERT INTO monitoring_jobs (
        brand_id, job_type, status, findings_count, threats_detected, details, started_at, completed_at
       ) VALUES ($1, 'full_scan', 'completed', $2, $3, $4, $5, NOW());`,
      [
        brand.id,
        summary.candidatesFound,
        summary.candidatesFound - summary.excludedOfficialAssets,
        JSON.stringify(summary),
        startedAt,
      ],
    );

    logger.info("[monitoring] Brand monitoring run completed", { summary });
    return summary;
  }

  async getCandidates(brandId?: string): Promise<Record<string, unknown>[]> {
    const values: string[] = [];
    const brandFilter = brandId ? "WHERE c.brand_id = $1" : "";
    if (brandId) values.push(brandId);
    const result = await query(
      `SELECT
         c.id, c.brand_id, c.platform, c.candidate_identifier AS identifier,
         c.candidate_url AS url, c.display_name AS name,
         c.developer_publisher AS publisher, c.description, c.icon_or_logo_url,
         c.is_excluded_official AS is_official_excluded, c.discovered_at AS created_at,
         CASE
           WHEN c.platform IN ('reddit', 'youtube') THEN 'social'
           WHEN c.platform = 'apple_app_store' THEN 'app_store'
           ELSE c.platform
         END AS source_type,
         COALESCE(ra.risk_level, 'UNASSESSED') AS risk_level,
         COALESCE(ra.risk_score, 0)::float AS risk_score,
         COALESCE(ra.confidence_score, 0) AS confidence_score,
         COALESCE(ra.primary_reasons, ARRAY[]::TEXT[]) AS risk_reasons,
         jsonb_build_object(
           'name_similarity', (
             SELECT MAX(similarity_score)::float FROM candidate_evidence
             WHERE candidate_id = c.id AND evidence_type IN ('NAME_LOOKALIKE', 'APP_NAME_SIMILARITY')
           ),
           'logo_similarity', (
             SELECT MAX(similarity_score)::float FROM candidate_evidence
             WHERE candidate_id = c.id AND evidence_type = 'LOGO_SIMILARITY'
           ),
           'publisher_mismatch', EXISTS (
             SELECT 1 FROM candidate_evidence
             WHERE candidate_id = c.id AND evidence_type = 'PUBLISHER_MISMATCH'
           ),
           'lookalike_technique', (
             SELECT evidence_type FROM candidate_evidence
             WHERE candidate_id = c.id AND evidence_type IN ('NAME_LOOKALIKE', 'APP_NAME_SIMILARITY')
             ORDER BY recorded_at DESC LIMIT 1
           )
         ) AS evidence,
         COALESCE(
           (SELECT jsonb_agg(jsonb_build_object(
              'type', evidence_type, 'severity', severity, 'details', details
            ) ORDER BY recorded_at ASC)
            FROM candidate_evidence WHERE candidate_id = c.id),
           '[]'::jsonb
         ) AS source_evidence
       FROM discovered_candidates c
       LEFT JOIN LATERAL (
         SELECT risk_level, risk_score, confidence_score, primary_reasons
         FROM risk_assessments
         WHERE candidate_id = c.id
         ORDER BY assessed_at DESC LIMIT 1
       ) ra ON TRUE
       LEFT JOIN candidate_evidence ce ON ce.candidate_id = c.id
       ${brandFilter}
       GROUP BY c.id, ra.risk_level, ra.risk_score, ra.confidence_score, ra.primary_reasons
       ORDER BY c.discovered_at DESC
       LIMIT 500;`,
      values,
    );
    return result.rows;
  }

  async getLatestRun(brandId: string): Promise<Record<string, unknown> | null> {
    const result = await query(
      `SELECT id, brand_id, target_type, status, source_errors, summary, started_at, completed_at
       FROM monitoring_runs WHERE brand_id = $1
       ORDER BY started_at DESC LIMIT 1;`,
      [brandId],
    );
    return result.rows[0] ?? null;
  }

  async runAllActiveMonitors(): Promise<MonitoringScanSummary[]> {
    const activeBrands = await brandService.listBrands(100, 0);
    const results: MonitoringScanSummary[] = [];
    for (const brand of activeBrands) {
      if (brand.status !== "active") continue;
      try {
        results.push(await this.runBrandScan(brand.id));
      } catch (error) {
        logger.error("[monitoring] Brand monitoring run failed", {
          brandId: brand.id,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }
    return results;
  }
}

export const monitoringService = new MonitoringService();
export default monitoringService;
