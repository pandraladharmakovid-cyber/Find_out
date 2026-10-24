import { randomUUID } from "node:crypto";
import { query, withTransaction } from "./db";
import { runWithDeadline } from "./utils/timeout";
import { config } from "./config";
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

  for (const post of result.blueskyData.posts) {
    const handle = post.author || post.authorDid;
    const author = post.displayName || handle || "Unknown Bluesky account";
    const profileUrl = handle
      ? `https://bsky.app/profile/${encodeURIComponent(handle)}`
      : post.permalink;
    const similarity = Math.max(
      0,
      ...[author, handle].flatMap((accountName) =>
        brandNames.map((brand) => {
          const account = normalizeComparableName(accountName);
          if (!account) return 0;
          return account.includes(brand)
            ? 1
            : lookalikeDetectionService.similarityRatio(brand, account);
        }),
      ),
    );
    const text = post.text;
    const suspicious = isScamContent(text);
    const matchAsset = findOfficialMatch(
      { platform: "bluesky", identifier: handle, url: profileUrl },
      assets,
    );
    const evidence: StoredCandidateInput["evidence"] = [
      {
        type: "SOCIAL_SEARCH_RESULT",
        severity: "LOW",
        details: {
          source: "Bluesky public post search",
          statement: "A matching public discussion was found; this alone does not establish account impersonation.",
          text: post.text.slice(0, 1000),
          handle,
          postUrl: post.permalink,
          createdAt: post.createdAt,
          likeCount: post.likeCount,
        },
      },
    ];
    if (similarity >= 0.65) {
      evidence.push({
        type: "NAME_LOOKALIKE",
        severity: similarity >= 0.85 ? "MEDIUM" : "LOW",
        similarity,
        details: { accountName: author, accountHandle: handle, matchedBrandName: brandName, similarity },
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
      platform: "bluesky",
      identifier: handle || post.id,
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
  /**
   * Persists a whole scan in one transaction with set-based inserts. The old
   * per-row loop issued 3-4 round-trips per candidate, which is what made large
   * findings pages slow to accumulate.
   */
  private async persistCandidates(
    runId: string,
    brandId: string,
    candidates: StoredCandidateInput[],
  ): Promise<void> {
    if (candidates.length === 0) return;

    const rows = candidates.map((candidate) => {
      const riskLevel = candidate.excluded
        ? "BENIGN"
        : candidate.riskScore >= 75
          ? "HIGH"
          : candidate.riskScore >= 40
            ? "MEDIUM"
            : "LOW";

      return {
        id: randomUUID(),
        run_id: runId,
        brand_id: brandId,
        platform: candidate.platform,
        candidate_identifier: candidate.identifier,
        candidate_url: candidate.url,
        display_name: candidate.name,
        developer_publisher: candidate.publisher ?? null,
        description: candidate.description ?? null,
        icon_or_logo_url: candidate.iconUrl ?? null,
        is_excluded_official: candidate.excluded,
        risk_level: riskLevel,
        risk_score: candidate.riskScore,
        confidence_score: candidate.confidence,
        primary_reasons: candidate.evidence.map((evidence) => evidence.type),
        status: candidate.excluded ? "RESOLVED" : "UNRESOLVED",
        severity: riskLevel === "BENIGN" ? "LOW" : riskLevel,
        asset_id: candidate.matchAsset?.id ?? null,
        matched_by:
          candidate.platform === "apple_app_store" || candidate.platform === "google_play"
            ? "APP_ID_OR_URL"
            : "EXACT_IDENTIFIER_OR_URL",
      };
    });

    const evidenceRows = candidates.flatMap((candidate, index) =>
      candidate.evidence.map((evidence) => ({
        candidate_id: rows[index]?.id ?? "",
        evidence_type: evidence.type,
        severity: evidence.severity,
        details: evidence.details,
        similarity_score: evidence.similarity ?? null,
      })),
    );

    await withTransaction(async (client) => {
      await client.query(
        `INSERT INTO discovered_candidates (
           id, run_id, brand_id, platform, candidate_identifier, candidate_url,
           display_name, developer_publisher, description, icon_or_logo_url, is_excluded_official
         )
         SELECT id, run_id, brand_id, platform, candidate_identifier, candidate_url,
                display_name, developer_publisher, description, icon_or_logo_url, is_excluded_official
         FROM jsonb_to_recordset($1::jsonb) AS x(
           id uuid, run_id uuid, brand_id uuid, platform text, candidate_identifier text,
           candidate_url text, display_name text, developer_publisher text, description text,
           icon_or_logo_url text, is_excluded_official boolean
         );`,
        [JSON.stringify(rows)],
      );

      if (evidenceRows.length > 0) {
        await client.query(
          `INSERT INTO candidate_evidence (candidate_id, evidence_type, severity, details, similarity_score)
           SELECT candidate_id, evidence_type, severity, details, similarity_score
           FROM jsonb_to_recordset($1::jsonb) AS x(
             candidate_id uuid, evidence_type text, severity text, details jsonb, similarity_score numeric
           );`,
          [JSON.stringify(evidenceRows)],
        );
      }

      await client.query(
        `INSERT INTO risk_assessments (
           candidate_id, risk_level, risk_score, overall_score, severity, confidence_score, primary_reasons, status
         )
         SELECT candidate_id, risk_level, risk_score, risk_score, severity, confidence_score,
                ARRAY(SELECT jsonb_array_elements_text(primary_reasons)), status
         FROM jsonb_to_recordset($1::jsonb) AS x(
           candidate_id uuid, risk_level text, risk_score numeric, severity text,
           confidence_score numeric, primary_reasons jsonb, status text
         );`,
        [
          JSON.stringify(
            rows.map((row) => ({
              candidate_id: row.id,
              risk_level: row.risk_level,
              risk_score: row.risk_score,
              severity: row.severity,
              confidence_score: row.confidence_score,
              primary_reasons: row.primary_reasons,
              status: row.status,
            })),
          ),
        ],
      );

      const matches = rows.filter((row) => row.asset_id);
      if (matches.length > 0) {
        await client.query(
          `INSERT INTO official_asset_matches (candidate_id, asset_id, matched_by)
           SELECT candidate_id, asset_id, matched_by
           FROM jsonb_to_recordset($1::jsonb) AS x(
             candidate_id uuid, asset_id uuid, matched_by text
           );`,
          [
            JSON.stringify(
              matches.map((row) => ({
                candidate_id: row.id,
                asset_id: row.asset_id,
                matched_by: row.matched_by,
              })),
            ),
          ],
        );
      }
    });
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

    try {
      // Every source runs under its own deadline. A slow provider now yields a
      // partial scan with an explicit "unavailable" status instead of blocking
      // the request until the HTTP layer times out.
      const sourceTimeoutMs = config.MONITORING_SOURCE_TIMEOUT_MS;
      const [socialOutcome, appOutcome] = await Promise.all([
        runWithDeadline(
          () =>
            socialMonitoringService.scanBrandMentions({
              brandName: brand.name,
              associatedDomain: brand.primary_domain,
            }),
          sourceTimeoutMs,
          "Social monitoring",
        ),
        runWithDeadline(
          () =>
            appStoresMonitoringService.scanAppStores({
              brandId: brand.id,
              brandName: brand.name,
              alternateNames: brand.alternate_names ?? [],
            }),
          sourceTimeoutMs,
          "App-store monitoring",
        ),
      ]);

      const socialResult = socialOutcome.value
        ? ({ status: "fulfilled", value: socialOutcome.value } as const)
        : ({ status: "rejected", reason: new Error(socialOutcome.error ?? "Social source failed") } as const);
      const appResult = appOutcome.value
        ? ({ status: "fulfilled", value: appOutcome.value } as const)
        : ({ status: "rejected", reason: new Error(appOutcome.error ?? "App-store source failed") } as const);

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

      const persistStartedAt = Date.now();
      await this.persistCandidates(runId, brand.id, sourceCandidates);
      summary.candidatesFound = sourceCandidates.length;
      summary.excludedOfficialAssets = sourceCandidates.filter((candidate) => candidate.excluded).length;
      logger.info("[monitoring] Candidates persisted", {
        runId,
        candidates: sourceCandidates.length,
        persistMs: Date.now() - persistStartedAt,
      });
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
    } catch (error) {
      const message = error instanceof Error ? error.message : "Monitoring run failed";
      summary.sourceStatuses.push({
        source: "monitoring_run",
        status: "unavailable",
        candidatesFound: 0,
        error: message,
      });
      try {
        await query(
          `UPDATE monitoring_runs
           SET status = 'FAILED', source_errors = $2, summary = $3, completed_at = NOW()
           WHERE id = $1;`,
          [
            runId,
            JSON.stringify([{ source: "monitoring_run", error: message }]),
            JSON.stringify(summary),
          ],
        );
      } catch (statusError) {
        logger.error("[monitoring] Failed to mark monitoring run as failed", {
          runId,
          error: statusError instanceof Error ? statusError.message : "Unknown error",
        });
      }
      throw error;
    }
  }

  /**
   * Returns candidates for a brand/run. The previous implementation joined
   * candidate_evidence to the candidate list and then ran three correlated
   * subqueries per row, which multiplied rows and exceeded the 20 s UI budget
   * at 500 candidates. This version pages first, then aggregates only the
   * evidence belonging to that page.
   */
  async getCandidates(
    brandId?: string,
    runId?: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<Record<string, unknown>[]> {
    const limit = Math.max(1, Math.min(options.limit ?? 200, 500));
    const offset = Math.max(0, options.offset ?? 0);
    const values: Array<string | number> = [];
    const filters: string[] = [];

    if (brandId) {
      values.push(brandId);
      filters.push(`c.brand_id = $${values.length}::uuid`);
    }
    if (runId) {
      values.push(runId);
      filters.push(`c.run_id = $${values.length}::uuid`);
    }

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
    values.push(limit);
    const limitParam = `$${values.length}`;
    values.push(offset);
    const offsetParam = `$${values.length}`;

    const result = await query(
      `WITH page AS (
         SELECT c.id, c.brand_id, c.run_id, c.platform, c.candidate_identifier,
                c.candidate_url, c.display_name, c.developer_publisher,
                c.description, c.icon_or_logo_url, c.is_excluded_official, c.discovered_at
         FROM discovered_candidates c
         ${whereClause}
         ORDER BY c.discovered_at DESC
         LIMIT ${limitParam} OFFSET ${offsetParam}
       ),
       evidence AS (
         SELECT ce.candidate_id,
                MAX(ce.similarity_score) FILTER (
                  WHERE ce.evidence_type IN ('NAME_LOOKALIKE', 'APP_NAME_SIMILARITY')
                )::float AS name_similarity,
                MAX(ce.similarity_score) FILTER (
                  WHERE ce.evidence_type = 'LOGO_SIMILARITY'
                )::float AS logo_similarity,
                BOOL_OR(ce.evidence_type = 'PUBLISHER_MISMATCH') AS publisher_mismatch,
                (ARRAY_AGG(ce.evidence_type ORDER BY ce.recorded_at DESC) FILTER (
                  WHERE ce.evidence_type IN ('NAME_LOOKALIKE', 'APP_NAME_SIMILARITY')
                ))[1] AS lookalike_technique,
                jsonb_agg(
                  jsonb_build_object('type', ce.evidence_type, 'severity', ce.severity, 'details', ce.details)
                  ORDER BY ce.recorded_at ASC
                ) AS source_evidence
         FROM candidate_evidence ce
         WHERE ce.candidate_id IN (SELECT id FROM page)
         GROUP BY ce.candidate_id
       ),
       latest_risk AS (
         SELECT DISTINCT ON (ra.candidate_id)
                ra.candidate_id, ra.risk_level, ra.risk_score, ra.confidence_score, ra.primary_reasons
         FROM risk_assessments ra
         WHERE ra.candidate_id IN (SELECT id FROM page)
         ORDER BY ra.candidate_id, ra.assessed_at DESC
       )
       SELECT
         p.id,
         p.brand_id,
         p.run_id,
         p.platform,
         p.candidate_identifier AS identifier,
         p.candidate_url AS url,
         p.display_name AS name,
         p.developer_publisher AS publisher,
         p.description,
         p.icon_or_logo_url,
         p.is_excluded_official AS is_official_excluded,
         p.discovered_at AS created_at,
         CASE
           -- Keep historical Reddit candidate rows in the social category.
           WHEN p.platform IN ('reddit', 'bluesky', 'youtube') THEN 'social'
           WHEN p.platform IN ('apple_app_store', 'google_play', 'play_store') THEN 'app_store'
           ELSE p.platform
         END AS source_type,
         COALESCE(lr.risk_level, 'UNASSESSED') AS risk_level,
         COALESCE(lr.risk_score, 0)::float AS risk_score,
         COALESCE(lr.confidence_score, 0) AS confidence_score,
         COALESCE(lr.primary_reasons, ARRAY[]::TEXT[]) AS risk_reasons,
         jsonb_build_object(
           'name_similarity', e.name_similarity,
           'logo_similarity', e.logo_similarity,
           'publisher_mismatch', COALESCE(e.publisher_mismatch, false),
           'lookalike_technique', e.lookalike_technique
         ) AS evidence,
         COALESCE(e.source_evidence, '[]'::jsonb) AS source_evidence
       FROM page p
       LEFT JOIN evidence e ON e.candidate_id = p.id
       LEFT JOIN latest_risk lr ON lr.candidate_id = p.id
       ORDER BY p.discovered_at DESC;`,
      values,
    );

    return result.rows;
  }

  /**
   * Fast counters used by dashboards and the agent, so a 500-row findings page
   * does not need to be rendered just to learn the totals.
   */
  async getCandidatesSummary(brandId?: string): Promise<{
    total: number;
    excluded: number;
    highRisk: number;
    mediumRisk: number;
    unassessed: number;
    byPlatform: Record<string, number>;
  }> {
    const values: string[] = [];
    const whereClause = brandId ? `WHERE c.brand_id = $1::uuid` : "";
    if (brandId) values.push(brandId);

    const result = await query<{
      total: string;
      excluded: string;
      high_risk: string;
      medium_risk: string;
      unassessed: string;
      by_platform?: Record<string, number> | null;
    }>(
      `WITH latest_risk AS (
         SELECT DISTINCT ON (candidate_id) candidate_id, risk_level
         FROM risk_assessments
         ORDER BY candidate_id, assessed_at DESC
       ),
       totals AS (
         SELECT
           COUNT(*)::text AS total,
           COUNT(*) FILTER (WHERE c.is_excluded_official)::text AS excluded,
           COUNT(*) FILTER (WHERE COALESCE(lr.risk_level, 'UNASSESSED') IN ('HIGH', 'CRITICAL'))::text AS high_risk,
           COUNT(*) FILTER (WHERE COALESCE(lr.risk_level, 'UNASSESSED') = 'MEDIUM')::text AS medium_risk,
           COUNT(*) FILTER (WHERE COALESCE(lr.risk_level, 'UNASSESSED') = 'UNASSESSED')::text AS unassessed
         FROM discovered_candidates c
         LEFT JOIN latest_risk lr ON lr.candidate_id = c.id
         ${whereClause}
       ),
       platforms AS (
         SELECT COALESCE(jsonb_object_agg(platform, count_value), '{}'::jsonb) AS by_platform
         FROM (
           SELECT c.platform, COUNT(*)::int AS count_value
           FROM discovered_candidates c
           ${whereClause}
           GROUP BY c.platform
         ) grouped
       )
       SELECT totals.*, platforms.by_platform
       FROM totals, platforms;`,
      values,
    );

    const row = result.rows[0];
    return {
      total: Number(row?.total ?? 0),
      excluded: Number(row?.excluded ?? 0),
      highRisk: Number(row?.high_risk ?? 0),
      mediumRisk: Number(row?.medium_risk ?? 0),
      unassessed: Number(row?.unassessed ?? 0),
      byPlatform: (row?.by_platform ?? {}) as Record<string, number>,
    };
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
