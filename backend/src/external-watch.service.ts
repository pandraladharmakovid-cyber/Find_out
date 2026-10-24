import { query, withTransaction } from "./db";
import { config } from "./config";
import { brandService, type BrandRecord } from "./brands";
import { monitoringService } from "./monitoring";
import {
  ctLogClient,
  type CtLogDiscoveryClient,
  type DiscoveredExternalDomain,
  type ExternalSourceCheckStatus,
} from "./integrations/ct-log.client";
import { exclusionEngineService } from "./exclusion-engine.service";
import { investigationService } from "./investigations";
import { evaluateBrandImpersonation } from "./brand-impersonation.service";
import { detectionRecordService } from "./detection-records.service";
import { alertsService, type AlertSeverity } from "./alerts";
import { isResendConfigured, sendResendEmail } from "./integrations/resend.client";
import { logger } from "./utils/logger";
import type { QueryResultRow } from "pg";

/**
 * Automatic Internet-Wide Brand Impersonation Detection ("External Brand Watch")
 *
 * Continuously monitors public external sources outside Find_out for registered
 * Brand Profiles, combining:
 *   - Public Certificate Transparency logs (`crt.sh`) & live public DNS look-alike probes
 *   - Social & video discovery (`Bluesky`, `YouTube`, `Reddit` status)
 *   - Mobile app marketplace discovery (`Apple App Store`, `Google Play` status)
 *   - Threat-intelligence enrichment (`Google Safe Browsing`, `URLhaus`) via `InvestigationService`
 *
 * Core safeguards:
 *   1. Official assets (`primary_domain`, `associated_domains`, `website`, verified
 *      `official_assets`, `exclusion_rules`) are excluded before alerting.
 *   2. Similarity of name or logo alone is NEVER treated as proof of fraud —
 *      automatic alerts require corroborating abuse signals.
 *   3. Alerts & official brand e-mails are deduplicated via `external_watch_notifications`
 *      so unchanged findings never spam analysts or brand contacts.
 *   4. Find_out NEVER auto-submits third-party takedown requests or contacts
 *      external registrars/hosts/platforms without explicit analyst action.
 */

export type WatchTriggerType = "scheduled" | "manual" | "brand_registered";

export interface ExternalWatchScheduleRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  brand_name?: string;
  primary_domain?: string;
  contact_email?: string | null;
  is_enabled: boolean;
  interval_minutes: number;
  alert_risk_threshold: number;
  last_run_at: string | null;
  next_run_at: string;
  last_status: string;
  created_at: string;
  updated_at: string;
}

export interface ExternalWatchRunRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  brand_name?: string;
  trigger_type: WatchTriggerType;
  status: "IN_PROGRESS" | "COMPLETED" | "PARTIAL" | "FAILED";
  monitoring_run_id: string | null;
  sources_checked: ExternalSourceCheckStatus[];
  candidates_discovered: number;
  new_candidates_count: number;
  changed_candidates_count: number;
  high_risk_count: number;
  alerts_created: number;
  emails_sent: number;
  deduplicated_alerts_skipped: number;
  error_summary: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface ExternalSeenAssetRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  brand_name?: string;
  platform: string;
  canonical_id: string;
  target_url: string;
  display_name: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_candidate_id: string | null;
  last_investigation_id: string | null;
  last_risk_score: number;
  last_risk_level: string;
  previous_risk_score: number | null;
  change_state: "new" | "escalated" | "unchanged";
  times_seen: number;
  corroborating_signals: string[];
  evidence_summary: Record<string, unknown>;
  detection_record_id?: string | null;
  analyst_status?: string | null;
}

export interface ExternalWatchNotificationRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  brand_name?: string;
  dedupe_key: string;
  platform: string;
  canonical_id: string;
  target_url: string;
  risk_score: number;
  risk_level: string;
  alert_id: string | null;
  recipient_email: string | null;
  email_status: "sent" | "failed" | "not_configured" | "no_recipient";
  resend_message_id: string | null;
  email_error: string | null;
  created_at: string;
}

export interface ExternalWatchOverview {
  scheduler: {
    enabled: boolean;
    running: boolean;
    tickMs: number;
    defaultIntervalMinutes: number;
    defaultAlertThreshold: number;
    resendConfigured: boolean;
  };
  summary: {
    monitoredBrands: number;
    totalRuns: number;
    newlyDiscoveredCount: number;
    highRiskCount: number;
    confirmedThreatsCount: number;
    alertsSentCount: number;
    emailsDeliveredCount: number;
  };
  schedules: ExternalWatchScheduleRecord[];
  recentRuns: ExternalWatchRunRecord[];
  externalCandidates: ExternalSeenAssetRecord[];
  notifications: ExternalWatchNotificationRecord[];
}

interface CandidateSnapshotRow extends QueryResultRow {
  id: string;
  brand_id: string;
  platform: string;
  candidate_identifier: string;
  candidate_url: string;
  display_name: string | null;
  developer_publisher: string | null;
  description: string | null;
  is_excluded_official: boolean;
  risk_level: string;
  risk_score: number;
  confidence_score: number;
  primary_reasons: string[];
  ai_summary: string | null;
  evidence_types: string[];
  evidence_items: Array<{
    type: string;
    severity: string;
    similarity_score: number | null;
    details: Record<string, unknown>;
  }>;
}

const CORROBORATING_EVIDENCE_TYPES = new Set([
  "DECEPTIVE_AFFIX",
  "SUSPICIOUS_TLD",
  "THREAT_INTEL_MATCH",
  "SUSPICIOUS_CONTENT",
  "PUBLISHER_MISMATCH",
  "CREDENTIAL_HARVEST_INDICATOR",
  "DOMAIN_IMPERSONATION_SIGNAL",
]);

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function canonicalizeAssetId(platform: string, identifier: string, url: string): string {
  const cleanId = identifier.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  if (cleanId) return cleanId.slice(0, 255);
  try {
    const parsed = new URL(url);
    return `${parsed.hostname.toLowerCase()}${parsed.pathname.replace(/\/+$/, "")}`.slice(0, 255);
  } catch {
    return url.trim().toLowerCase().slice(0, 255);
  }
}

/**
 * Evaluates whether a candidate has corroborating abuse indicators beyond
 * bare name or logo similarity alone.
 */
export function extractCorroboratingSignals(candidate: {
  platform: string;
  evidenceTypes: string[];
  primaryReasons: string[];
  evidenceItems?: Array<{
    type: string;
    severity: string;
    details?: Record<string, unknown>;
  }>;
}): string[] {
  const signals = new Set<string>();

  for (const evType of candidate.evidenceTypes) {
    if (CORROBORATING_EVIDENCE_TYPES.has(evType)) {
      signals.add(evType);
    }
  }

  for (const item of candidate.evidenceItems ?? []) {
    if (CORROBORATING_EVIDENCE_TYPES.has(item.type)) {
      signals.add(item.type);
    }
    const reasonText = String(item.details?.reason ?? item.details?.statement ?? "").toLowerCase();
    if (
      reasonText.includes("publisher") ||
      reasonText.includes("phishing") ||
      reasonText.includes("malicious") ||
      reasonText.includes("deceptive") ||
      reasonText.includes("credential")
    ) {
      signals.add(item.type || "CORROBORATING_INDICATOR");
    }
  }

    for (const reason of candidate.primaryReasons) {
    const lower = reason.toLowerCase();
    if (
      lower.includes("deceptive") ||
      lower.includes("phishing") ||
      lower.includes("malicious") ||
      lower.includes("safe browsing") ||
      lower.includes("urlhaus") ||
      lower.includes("publisher") ||
      lower.includes("suspicious_content") ||
      lower.includes("high-abuse tld") ||
      lower.includes("suspicious tld")
    ) {
      signals.add(reason.slice(0, 120));
    }
  }

  return Array.from(signals);
}

export class ExternalBrandWatchService {
  private tablesEnsured = false;
  private schedulerTimer: ReturnType<typeof setInterval> | null = null;
  private tickInProgress = false;
  private readonly activeBrandRuns = new Set<string>();
  private readonly domainDiscovery: CtLogDiscoveryClient;

  constructor(options?: { domainDiscovery?: CtLogDiscoveryClient }) {
    this.domainDiscovery = options?.domainDiscovery ?? ctLogClient;
  }

  async ensureTables(): Promise<void> {
    if (this.tablesEnsured) return;
    await query(`
      CREATE TABLE IF NOT EXISTS external_watch_schedules (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        brand_id UUID NOT NULL UNIQUE REFERENCES brands(id) ON DELETE CASCADE,
        is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        alert_risk_threshold NUMERIC(5, 2) NOT NULL DEFAULT 65.00,
        last_run_at TIMESTAMPTZ,
        next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS external_watch_runs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
        trigger_type VARCHAR(32) NOT NULL DEFAULT 'scheduled',
        status VARCHAR(32) NOT NULL DEFAULT 'IN_PROGRESS',
        monitoring_run_id UUID REFERENCES monitoring_runs(id) ON DELETE SET NULL,
        sources_checked JSONB NOT NULL DEFAULT '[]'::jsonb,
        candidates_discovered INTEGER NOT NULL DEFAULT 0,
        new_candidates_count INTEGER NOT NULL DEFAULT 0,
        changed_candidates_count INTEGER NOT NULL DEFAULT 0,
        high_risk_count INTEGER NOT NULL DEFAULT 0,
        alerts_created INTEGER NOT NULL DEFAULT 0,
        emails_sent INTEGER NOT NULL DEFAULT 0,
        deduplicated_alerts_skipped INTEGER NOT NULL DEFAULT 0,
        error_summary TEXT,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS external_watch_seen_assets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
        platform VARCHAR(64) NOT NULL,
        canonical_id VARCHAR(255) NOT NULL,
        target_url TEXT NOT NULL,
        display_name VARCHAR(255),
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_candidate_id UUID REFERENCES discovered_candidates(id) ON DELETE SET NULL,
        last_investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
        last_risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
        last_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
        previous_risk_score NUMERIC(5, 2),
        change_state VARCHAR(24) NOT NULL DEFAULT 'new',
        times_seen INTEGER NOT NULL DEFAULT 1,
        corroborating_signals JSONB NOT NULL DEFAULT '[]'::jsonb,
        evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
        UNIQUE (brand_id, platform, canonical_id)
      );
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS external_watch_notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
        dedupe_key VARCHAR(320) NOT NULL UNIQUE,
        platform VARCHAR(64) NOT NULL,
        canonical_id VARCHAR(255) NOT NULL,
        target_url TEXT NOT NULL,
        risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
        risk_level VARCHAR(20) NOT NULL DEFAULT 'HIGH',
        alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
        recipient_email TEXT,
        email_status VARCHAR(32) NOT NULL DEFAULT 'not_configured',
        resend_message_id TEXT,
        email_error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    this.tablesEnsured = true;
  }

  /**
   * Enrolls or updates continuous external monitoring for a registered brand.
   */
  async enrollBrand(
    brandId: string,
    options?: {
      isEnabled?: boolean;
      intervalMinutes?: number;
      alertRiskThreshold?: number;
    },
  ): Promise<ExternalWatchScheduleRecord> {
    await this.ensureTables();

    const interval = Math.max(
      5,
      Math.min(1440, options?.intervalMinutes ?? config.EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES),
    );
    const threshold = Math.max(
      35,
      Math.min(99, options?.alertRiskThreshold ?? config.EXTERNAL_WATCH_ALERT_THRESHOLD),
    );
    const enabled = options?.isEnabled ?? true;

    const res = await query<ExternalWatchScheduleRecord>(
      `INSERT INTO external_watch_schedules (
         brand_id, is_enabled, interval_minutes, alert_risk_threshold, next_run_at, last_status, updated_at
       ) VALUES ($1, $2, $3, $4, NOW(), 'SCHEDULED', NOW())
       ON CONFLICT (brand_id) DO UPDATE SET
         is_enabled = COALESCE($5, external_watch_schedules.is_enabled),
         interval_minutes = COALESCE($6, external_watch_schedules.interval_minutes),
         alert_risk_threshold = COALESCE($7, external_watch_schedules.alert_risk_threshold),
         updated_at = NOW()
       RETURNING *;`,
      [
        brandId,
        enabled,
        interval,
        threshold,
        options?.isEnabled ?? null,
        options?.intervalMinutes ? interval : null,
        options?.alertRiskThreshold !== undefined ? threshold : null,
      ],
    );

    const row = res.rows[0];
    if (!row) {
      throw new Error(`Failed to enroll brand ${brandId} into External Brand Watch`);
    }
    return {
      ...row,
      alert_risk_threshold: Number(row.alert_risk_threshold),
    };
  }

  async ensureAllActiveBrandsEnrolled(): Promise<void> {
    await this.ensureTables();
    await query(
      `INSERT INTO external_watch_schedules (
         brand_id, is_enabled, interval_minutes, alert_risk_threshold, next_run_at, last_status
       )
       SELECT
         b.id,
         TRUE,
         $1,
         $2,
         NOW(),
         'SCHEDULED'
       FROM brands b
       WHERE b.status = 'active'
         AND NOT EXISTS (
           SELECT 1 FROM external_watch_schedules s WHERE s.brand_id = b.id
         )
       ON CONFLICT (brand_id) DO NOTHING;`,
      [config.EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES, config.EXTERNAL_WATCH_ALERT_THRESHOLD],
    );
  }

  /**
   * Non-blocking hook invoked when a new official Brand Profile is created.
   * Skips background execution in unit-test mode (`NODE_ENV === "test"`) so
   * mocked-DB route tests remain deterministic; use `handleBrandRegistration`
   * directly when testing enrollment + auto-scan behavior.
   */
  onBrandRegistered(brandId: string): void {
    if (process.env.NODE_ENV === "test") return;

    void this.handleBrandRegistration(brandId, {
      runImmediateScan: config.EXTERNAL_WATCH_AUTO_SCAN_ON_REGISTER,
    }).catch((error) => {
      logger.warn("[external-watch] Background brand registration hook failed", {
        brandId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
    });
  }

  async handleBrandRegistration(
    brandId: string,
    options?: { runImmediateScan?: boolean },
  ): Promise<{ schedule: ExternalWatchScheduleRecord; run: ExternalWatchRunRecord | null }> {
    const schedule = await this.enrollBrand(brandId);
    let run: ExternalWatchRunRecord | null = null;
    if (options?.runImmediateScan ?? config.EXTERNAL_WATCH_AUTO_SCAN_ON_REGISTER) {
      run = await this.runBrandWatch(brandId, "brand_registered");
    }
    return { schedule, run };
  }

  /**
   * Executes one end-to-end external internet brand watch cycle for `brandId`:
   *   1. Discovers external social accounts, video channels, and app store listings
   *      via `MonitoringService.runBrandScan`
   *   2. Discovers live external look-alike domains via Certificate Transparency
   *      (`crt.sh`) and public DNS resolution (`ctLogClient`)
   *   3. Filters out verified official brand domains & assets
   *   4. Enriches external domains through `InvestigationService` + `evaluateBrandImpersonation`,
   *      requiring corroborating signals before treating a look-alike as high-risk fraud
   *   5. Syncs findings into `detection_records` (`Findings & Evidence`)
   *   6. Tracks newly appearing & escalated external assets across runs
   *   7. Emits deduplicated in-app alerts + Resend e-mails to `brand.contact_email`
   */
  async runBrandWatch(
    brandId: string,
    triggerType: WatchTriggerType = "manual",
  ): Promise<ExternalWatchRunRecord> {
    await this.ensureTables();

    if (this.activeBrandRuns.has(brandId)) {
      throw new Error(`An External Brand Watch scan is already running for brand ${brandId}.`);
    }

    this.activeBrandRuns.add(brandId);

    try {
      const brand = await brandService.getBrandById(brandId);
      if (!brand) {
        throw new Error(`Brand ${brandId} not found`);
      }

      const schedule = await this.enrollBrand(brand.id);
      const runInsert = await query<ExternalWatchRunRecord>(
        `INSERT INTO external_watch_runs (
           brand_id, trigger_type, status, started_at
         ) VALUES ($1, $2, 'IN_PROGRESS', NOW())
         RETURNING *;`,
        [brand.id, triggerType],
      );
      const watchRun = runInsert.rows[0]!;

      await query(
        `UPDATE external_watch_schedules
         SET last_status = 'RUNNING', updated_at = NOW()
         WHERE brand_id = $1;`,
        [brand.id],
      );

      const sourcesChecked: ExternalSourceCheckStatus[] = [];
      const errors: string[] = [];

      const websiteHostname = (() => {
        if (!brand.website) return null;
        try {
          return new URL(brand.website).hostname.toLowerCase();
        } catch {
          return null;
        }
      })();

      const officialDomains = Array.from(
        new Set(
          [
            brand.primary_domain,
            ...(brand.associated_domains ?? []),
            ...(websiteHostname ? [websiteHostname] : []),
          ].filter((d): d is string => Boolean(d && d.trim())),
        ),
      );

      // Run social/app monitoring + external CT/DNS domain discovery concurrently
      const [monitoringOutcome, domainOutcome] = await Promise.allSettled([
        monitoringService.runBrandScan(brand.id),
        this.domainDiscovery.discoverExternalDomains({
          brandName: brand.name,
          alternateNames: brand.alternate_names ?? [],
          primaryDomain: brand.primary_domain,
          associatedDomains: officialDomains,
          keywords: brand.keywords ?? [],
        }),
      ]);

      let monitoringRunId: string | null = null;
      if (monitoringOutcome.status === "fulfilled") {
        monitoringRunId = monitoringOutcome.value.runId;
        for (const src of monitoringOutcome.value.sourceStatuses) {
          sourcesChecked.push({
            source: src.source,
            status: src.status,
            candidatesFound: src.candidatesFound,
            ...(src.error ? { error: src.error } : {}),
          });
        }
      } else {
        const msg =
          monitoringOutcome.reason instanceof Error
            ? monitoringOutcome.reason.message
            : "Social/app monitoring failed";
        errors.push(msg);
        sourcesChecked.push({
          source: "social_and_app_monitoring",
          status: "unavailable",
          candidatesFound: 0,
          error: msg,
        });
      }

      let discoveredDomains: DiscoveredExternalDomain[] = [];
      if (domainOutcome.status === "fulfilled") {
        discoveredDomains = domainOutcome.value.domains;
        sourcesChecked.push(...domainOutcome.value.sources);
      } else {
        const msg =
          domainOutcome.reason instanceof Error
            ? domainOutcome.reason.message
            : "External domain discovery failed";
        errors.push(msg);
        sourcesChecked.push({
          source: "external_domain_discovery",
          status: "unavailable",
          candidatesFound: 0,
          error: msg,
        });
      }

      // Record honest threat-intelligence & Reddit OAuth availability
      sourcesChecked.push(
        {
          source: "google_safe_browsing",
          status: config.GOOGLE_SAFE_BROWSING_API_KEY ? "available" : "not_configured",
          candidatesFound: 0,
          ...(config.GOOGLE_SAFE_BROWSING_API_KEY
            ? {}
            : { error: "GOOGLE_SAFE_BROWSING_API_KEY not configured; URL reputation skipped." }),
        },
        {
          source: "urlhaus_threat_feed",
          status: config.URLHAUS_AUTH_KEY ? "available" : "not_configured",
          candidatesFound: 0,
          ...(config.URLHAUS_AUTH_KEY
            ? {}
            : { error: "URLHAUS_AUTH_KEY not configured; malware feed enrichment skipped." }),
        },
        {
          source: "reddit_oauth",
          status:
            process.env.REDDIT_CLIENT_ID && process.env.REDDIT_CLIENT_SECRET
              ? "available"
              : "not_configured",
          candidatesFound: 0,
          ...(process.env.REDDIT_CLIENT_ID && process.env.REDDIT_CLIENT_SECRET
            ? {}
            : { error: "Official Reddit OAuth API credentials not configured." }),
        },
      );

      // Ensure we have a `monitoring_runs` row if `monitoringService.runBrandScan` failed
      // so external domain candidates can still be persisted into `discovered_candidates`.
      if (!monitoringRunId && discoveredDomains.length > 0) {
        const fallbackRun = await query<{ id: string }>(
          `INSERT INTO monitoring_runs (brand_id, target_type, status, summary, completed_at)
           VALUES ($1, 'EXTERNAL_DOMAIN_WATCH', 'COMPLETED', '{}'::jsonb, NOW())
           RETURNING id;`,
          [brand.id],
        );
        monitoringRunId = fallbackRun.rows[0]?.id ?? null;
      }

      // Persist & investigate newly discovered external domains
      const investigationMap = new Map<string, string>();
      if (monitoringRunId && discoveredDomains.length > 0) {
        const domainsToInspect = discoveredDomains.slice(
          0,
          config.EXTERNAL_WATCH_MAX_INVESTIGATIONS_PER_RUN,
        );

        for (const extDomain of domainsToInspect) {
          const persisted = await this.inspectAndPersistExternalDomain(
            monitoringRunId,
            brand,
            officialDomains,
            extDomain,
          );
          if (persisted?.investigationId) {
            investigationMap.set(
              canonicalizeAssetId("domain", extDomain.domain, extDomain.url),
              persisted.investigationId,
            );
          }
        }
      }

      // Project all discovered candidates into Rulebook v2 `detection_records`
      await detectionRecordService.sync().catch((syncErr) => {
        logger.warn("[external-watch] DetectionRecordService sync warning", {
          brandId: brand.id,
          error: syncErr instanceof Error ? syncErr.message : "Unknown sync error",
        });
      });

      // Evaluate run candidates for change tracking & deduplicated alerting
      const candidates = monitoringRunId
        ? await this.loadRunCandidateSnapshots(monitoringRunId)
        : [];

      let newCandidatesCount = 0;
      let changedCandidatesCount = 0;
      let highRiskCount = 0;
      let alertsCreated = 0;
      let emailsSent = 0;
      let deduplicatedAlertsSkipped = 0;

      for (const candidate of candidates) {
        if (candidate.is_excluded_official) continue;

        const canonicalId = canonicalizeAssetId(
          candidate.platform,
          candidate.candidate_identifier,
          candidate.candidate_url,
        );
        const corroboratingSignals = extractCorroboratingSignals({
          platform: candidate.platform,
          evidenceTypes: candidate.evidence_types,
          primaryReasons: candidate.primary_reasons,
          evidenceItems: candidate.evidence_items,
        });

        // Enforce Evidence-Based Risk Scoring rule:
        // Similarity of name or logo alone must NOT trigger fraud classification/alerts
        // without corroborating signals.
        const effectiveScore =
          corroboratingSignals.length > 0
            ? Number(candidate.risk_score)
            : Math.min(Number(candidate.risk_score), 55);

        const effectiveLevel =
          effectiveScore >= 85
            ? "CRITICAL"
            : effectiveScore >= 65
              ? "HIGH"
              : effectiveScore >= 40
                ? "MEDIUM"
                : "LOW";

        if (effectiveScore >= 65 && corroboratingSignals.length > 0) {
          highRiskCount += 1;
        }

        const existingAssetRes = await query<ExternalSeenAssetRecord>(
          `SELECT * FROM external_watch_seen_assets
           WHERE brand_id = $1 AND platform = $2 AND canonical_id = $3
           LIMIT 1;`,
          [brand.id, candidate.platform, canonicalId],
        );
        const existingAsset = existingAssetRes.rows[0] ?? null;

        let changeState: "new" | "escalated" | "unchanged" = "unchanged";
        if (!existingAsset) {
          changeState = "new";
          newCandidatesCount += 1;
        } else {
          const prevScore = Number(existingAsset.last_risk_score ?? 0);
          const crossedHigh =
            prevScore < Number(schedule.alert_risk_threshold) &&
            effectiveScore >= Number(schedule.alert_risk_threshold);
          if (effectiveScore - prevScore >= 15 || crossedHigh) {
            changeState = "escalated";
            changedCandidatesCount += 1;
          }
        }

        const investigationId = investigationMap.get(canonicalId) ?? existingAsset?.last_investigation_id ?? null;

        await query(
          `INSERT INTO external_watch_seen_assets (
             brand_id, platform, canonical_id, target_url, display_name,
             first_seen_at, last_seen_at, last_candidate_id, last_investigation_id,
             last_risk_score, last_risk_level, previous_risk_score,
             change_state, times_seen, corroborating_signals, evidence_summary
           ) VALUES (
             $1, $2, $3, $4, $5,
             NOW(), NOW(), $6, $7,
             $8, $9, $10,
             $11, 1, $12::jsonb, $13::jsonb
           )
           ON CONFLICT (brand_id, platform, canonical_id) DO UPDATE SET
             target_url = EXCLUDED.target_url,
             display_name = COALESCE(EXCLUDED.display_name, external_watch_seen_assets.display_name),
             last_seen_at = NOW(),
             last_candidate_id = EXCLUDED.last_candidate_id,
             last_investigation_id = COALESCE(EXCLUDED.last_investigation_id, external_watch_seen_assets.last_investigation_id),
             previous_risk_score = external_watch_seen_assets.last_risk_score,
             last_risk_score = EXCLUDED.last_risk_score,
             last_risk_level = EXCLUDED.last_risk_level,
             change_state = EXCLUDED.change_state,
             times_seen = external_watch_seen_assets.times_seen + 1,
             corroborating_signals = EXCLUDED.corroborating_signals,
             evidence_summary = EXCLUDED.evidence_summary;`,
          [
            brand.id,
            candidate.platform,
            canonicalId,
            candidate.candidate_url,
            candidate.display_name,
            candidate.id,
            investigationId,
            effectiveScore,
            effectiveLevel,
            existingAsset ? Number(existingAsset.last_risk_score) : null,
            changeState,
            JSON.stringify(corroboratingSignals),
            JSON.stringify({
              summary: candidate.ai_summary,
              reasons: candidate.primary_reasons,
              evidenceTypes: candidate.evidence_types,
              corroborated: corroboratingSignals.length > 0,
            }),
          ],
        );

        // Deduplicated Alert + Official Brand Email Notification
        const threshold = Number(schedule.alert_risk_threshold ?? config.EXTERNAL_WATCH_ALERT_THRESHOLD);
        if (effectiveScore >= threshold && corroboratingSignals.length > 0) {
          const riskBand = effectiveScore >= 85 ? "critical" : "high";
          const dedupeKey = `${brand.id}:${candidate.platform}:${canonicalId}:${riskBand}`;

          const alreadyNotified = await query<{ id: string }>(
            `SELECT id FROM external_watch_notifications WHERE dedupe_key = $1 LIMIT 1;`,
            [dedupeKey],
          );

          if (alreadyNotified.rows.length > 0) {
            deduplicatedAlertsSkipped += 1;
          } else {
            const dispatched = await this.dispatchImpersonationAlert({
              brand,
              candidate,
              canonicalId,
              dedupeKey,
              effectiveScore,
              effectiveLevel,
              severity: riskBand as AlertSeverity,
              corroboratingSignals,
              investigationId,
            });
            if (dispatched.alertCreated) alertsCreated += 1;
            if (dispatched.emailDelivered) emailsSent += 1;
          }
        }
      }

      const unavailableCount = sourcesChecked.filter((s) => s.status === "unavailable").length;
      const availableCount = sourcesChecked.filter((s) => s.status === "available").length;
      const finalStatus: ExternalWatchRunRecord["status"] =
        availableCount === 0 && unavailableCount > 0
          ? "FAILED"
          : unavailableCount > 0
            ? "PARTIAL"
            : "COMPLETED";

      const nonExcludedTotal = candidates.filter((c) => !c.is_excluded_official).length;
      const errorSummary = errors.length > 0 ? errors.join(" | ").slice(0, 1000) : null;

      const updatedRunRes = await query<ExternalWatchRunRecord>(
        `UPDATE external_watch_runs
         SET status = $2,
             monitoring_run_id = $3,
             sources_checked = $4::jsonb,
             candidates_discovered = $5,
             new_candidates_count = $6,
             changed_candidates_count = $7,
             high_risk_count = $8,
             alerts_created = $9,
             emails_sent = $10,
             deduplicated_alerts_skipped = $11,
             error_summary = $12,
             completed_at = NOW()
         WHERE id = $1
         RETURNING *;`,
        [
          watchRun.id,
          finalStatus,
          monitoringRunId,
          JSON.stringify(sourcesChecked),
          nonExcludedTotal,
          newCandidatesCount,
          changedCandidatesCount,
          highRiskCount,
          alertsCreated,
          emailsSent,
          deduplicatedAlertsSkipped,
          errorSummary,
        ],
      );

      await query(
        `UPDATE external_watch_schedules
         SET last_run_at = NOW(),
             next_run_at = NOW() + ($2::text || ' minutes')::interval,
             last_status = $3,
             updated_at = NOW()
         WHERE brand_id = $1;`,
        [brand.id, schedule.interval_minutes, finalStatus],
      );

      return updatedRunRes.rows[0]!;
    } catch (error) {
      const message = error instanceof Error ? error.message : "External watch scan failed";
      logger.error("[external-watch] Brand watch run failed", { brandId, error: message });
      await query(
        `UPDATE external_watch_schedules
         SET last_run_at = NOW(),
             next_run_at = NOW() + (interval_minutes::text || ' minutes')::interval,
             last_status = 'FAILED',
             updated_at = NOW()
         WHERE brand_id = $1;`,
        [brandId],
      ).catch(() => undefined);
      throw error;
    } finally {
      this.activeBrandRuns.delete(brandId);
    }
  }

  private async inspectAndPersistExternalDomain(
    monitoringRunId: string,
    brand: BrandRecord,
    officialDomains: string[],
    extDomain: DiscoveredExternalDomain,
  ): Promise<{ candidateId: string; investigationId: string | null } | null> {
    const exclusion = await exclusionEngineService.checkExclusion(extDomain.url, brand.id);
    if (exclusion.isExcluded) {
      return null;
    }

    const impersonation = evaluateBrandImpersonation({
      targetUrl: extDomain.url,
      brandName: brand.name,
      brandDomains: officialDomains,
    });

    let investigationId: string | null = null;
    let investigationRiskScore = 0;
    let investigationConfidence = 0.6;
    let investigationVerdict = "unverified";
    let investigationSummary: string | null = null;

    try {
      const inv = await investigationService.runInvestigation({
        title: `External Watch: ${extDomain.domain} vs ${brand.name}`,
        targetUrl: extDomain.url,
        brandId: brand.id,
        brandName: brand.name,
      });
      investigationId = inv.id;
      investigationRiskScore = Number(inv.risk_score ?? 0);
      investigationConfidence = Number(inv.confidence_score ?? 0.6);
      investigationVerdict = inv.verdict;
      investigationSummary = inv.summary;
    } catch (invErr) {
      logger.warn("[external-watch] Domain investigation degraded gracefully; using structural evaluation", {
        domain: extDomain.domain,
        error: invErr instanceof Error ? invErr.message : "Investigation error",
      });
    }

    const suspiciousTldSignal = impersonation.signals.some((s) => s.code === "suspicious_tld");
    const deceptiveSignal =
      extDomain.hasDeceptiveAffix ||
      impersonation.signals.some(
        (s) => s.code === "deceptive_affix" || s.code === "deceptive_keyword" || s.code === "credential_path",
      );
    const threatIntelHit = investigationVerdict === "malicious";
    const ctLoggedRecently = extDomain.discoveredVia === "crt_sh_ct_logs";

    const corroboratingReasons: string[] = [];
    if (deceptiveSignal) {
      corroboratingReasons.push(
        `Deceptive credential/brand affix in external domain (${extDomain.deceptiveTokens.join(", ") || "impersonation token"})`,
      );
    }
    if (suspiciousTldSignal) {
      corroboratingReasons.push("High-abuse TLD mismatch relative to official brand domain");
    }
    if (threatIntelHit) {
      corroboratingReasons.push("Flagged malicious by URL threat intelligence / investigation engine");
    }

    const combinedRawScore = Math.max(
      impersonation.score,
      investigationRiskScore,
      Math.round(extDomain.similarity * 55) +
        (deceptiveSignal ? 28 : 0) +
        (suspiciousTldSignal ? 15 : 0) +
        (ctLoggedRecently ? 10 : 0),
    );

    // Crucial Rule: similarity alone without corroborating signals cannot exceed MEDIUM (55)
    const finalRiskScore =
      corroboratingReasons.length > 0
        ? Math.min(100, combinedRawScore)
        : Math.min(55, Math.max(25, Math.round(extDomain.similarity * 50)));

    const riskLevel =
      finalRiskScore >= 85
        ? "CRITICAL"
        : finalRiskScore >= 65
          ? "HIGH"
          : finalRiskScore >= 40
            ? "MEDIUM"
            : "LOW";

    const confidenceNormalized = Math.max(
      0.35,
      Math.min(
        0.98,
        investigationConfidence > 1 ? investigationConfidence / 100 : investigationConfidence,
      ),
    );

    const primaryReasons = [
      `External domain ${extDomain.domain} resolves to public IP (${extDomain.resolvedIps.slice(0, 3).join(", ")}) outside ${brand.name}'s official domains.`,
      ...(extDomain.detectedTechnique
        ? [`Look-alike technique: ${extDomain.detectedTechnique} (similarity ${(extDomain.similarity * 100).toFixed(0)}%).`]
        : []),
      ...corroboratingReasons,
      ...(corroboratingReasons.length === 0
        ? [
            "Name similarity alone is not proof of fraud; queued for human analyst review before any enforcement.",
          ]
        : []),
    ];

    const summaryText =
      investigationSummary ??
      (corroboratingReasons.length > 0
        ? `External domain ${extDomain.domain} resembles ${brand.name} and exhibits corroborating risk signals (${corroboratingReasons.join("; ")}).`
        : `External domain ${extDomain.domain} shares lexical similarity with ${brand.name}, without corroborating fraud indicators yet. Analyst verification required.`);

    const candidateId = await withTransaction(async (client) => {
      const candRes = await client.query<{ id: string }>(
        `INSERT INTO discovered_candidates (
           run_id, brand_id, platform, candidate_identifier, candidate_url,
           display_name, developer_publisher, description, is_excluded_official
         ) VALUES ($1, $2, 'domain', $3, $4, $5, $6, $7, FALSE)
         RETURNING id;`,
        [
          monitoringRunId,
          brand.id,
          extDomain.domain,
          extDomain.url,
          extDomain.domain,
          extDomain.ctIssuer ?? "External DNS / Certificate Registry",
          summaryText,
        ],
      );
      const id = candRes.rows[0]!.id;

      // Evidence 1: Name / Domain Lookalike
      await client.query(
        `INSERT INTO candidate_evidence (
           candidate_id, evidence_type, severity, details, similarity_score
         ) VALUES ($1, 'NAME_LOOKALIKE', $2, $3::jsonb, $4);`,
        [
          id,
          extDomain.similarity >= 0.85 ? "MEDIUM" : "LOW",
          JSON.stringify({
            domain: extDomain.domain,
            officialPrimaryDomain: brand.primary_domain,
            technique: extDomain.detectedTechnique,
            resolvedIps: extDomain.resolvedIps,
            discoveredVia: extDomain.discoveredVia,
          }),
          extDomain.similarity,
        ],
      );

      // Evidence 2: Certificate Transparency record when discovered via CT
      if (ctLoggedRecently) {
        await client.query(
          `INSERT INTO candidate_evidence (
             candidate_id, evidence_type, severity, details
           ) VALUES ($1, 'CERTIFICATE_TRANSPARENCY_LOG', $2, $3::jsonb);`,
          [
            id,
            deceptiveSignal || suspiciousTldSignal ? "HIGH" : "MEDIUM",
            JSON.stringify({
              source: "crt.sh Certificate Transparency",
              issuer: extDomain.ctIssuer,
              loggedAt: extDomain.ctLoggedAt,
              resolvedIps: extDomain.resolvedIps,
            }),
          ],
        );
      }

      // Evidence 3: Deceptive affix corroboration
      if (deceptiveSignal) {
        await client.query(
          `INSERT INTO candidate_evidence (
             candidate_id, evidence_type, severity, details
           ) VALUES ($1, 'DECEPTIVE_AFFIX', 'HIGH', $2::jsonb);`,
          [
            id,
            JSON.stringify({
              tokens: extDomain.deceptiveTokens,
              reason: "Hostname combines brand stem with deceptive login/security/verification wording.",
            }),
          ],
        );
      }

      // Evidence 4: Suspicious TLD corroboration
      if (suspiciousTldSignal) {
        await client.query(
          `INSERT INTO candidate_evidence (
             candidate_id, evidence_type, severity, details
           ) VALUES ($1, 'SUSPICIOUS_TLD', 'MEDIUM', $2::jsonb);`,
          [
            id,
            JSON.stringify({
              domain: extDomain.domain,
              officialDomain: brand.primary_domain,
              reason: "External domain uses a high-abuse TLD distinct from the official brand domain.",
            }),
          ],
        );
      }

      // Evidence 5: Threat intel hit
      if (threatIntelHit) {
        await client.query(
          `INSERT INTO candidate_evidence (
             candidate_id, evidence_type, severity, details
           ) VALUES ($1, 'THREAT_INTEL_MATCH', 'HIGH', $2::jsonb);`,
          [
            id,
            JSON.stringify({
              investigationId,
              verdict: investigationVerdict,
              reason: "External threat intelligence / investigation verdict flagged malicious indicators.",
            }),
          ],
        );
      }

      await client.query(
        `INSERT INTO risk_assessments (
           candidate_id, risk_level, risk_score, overall_score, severity,
           confidence_score, primary_reasons, ai_summary, status
         ) VALUES ($1, $2, $3, $3, $4, $5, $6, $7, 'UNRESOLVED');`,
        [
          id,
          riskLevel,
          finalRiskScore,
          riskLevel.toLowerCase(),
          confidenceNormalized,
          primaryReasons,
          summaryText,
        ],
      );

      return id;
    });

    return { candidateId, investigationId };
  }

  private async loadRunCandidateSnapshots(runId: string): Promise<CandidateSnapshotRow[]> {
    const res = await query<CandidateSnapshotRow>(
      `WITH latest_risk AS (
         SELECT DISTINCT ON (ra.candidate_id)
           ra.candidate_id,
           ra.risk_level,
           ra.risk_score::float AS risk_score,
           ra.confidence_score::float AS confidence_score,
           ra.primary_reasons,
           ra.ai_summary
         FROM risk_assessments ra
         ORDER BY ra.candidate_id, ra.assessed_at DESC
       ),
       ev AS (
         SELECT
           ce.candidate_id,
           ARRAY_AGG(DISTINCT ce.evidence_type) AS evidence_types,
           jsonb_agg(
             jsonb_build_object(
               'type', ce.evidence_type,
               'severity', ce.severity,
               'similarity_score', ce.similarity_score,
               'details', ce.details
             )
             ORDER BY ce.recorded_at ASC
           ) AS evidence_items
         FROM candidate_evidence ce
         GROUP BY ce.candidate_id
       )
       SELECT
         dc.id,
         dc.brand_id,
         dc.platform,
         dc.candidate_identifier,
         dc.candidate_url,
         dc.display_name,
         dc.developer_publisher,
         dc.description,
         dc.is_excluded_official,
         COALESCE(lr.risk_level, 'LOW') AS risk_level,
         COALESCE(lr.risk_score, 0)::float AS risk_score,
         COALESCE(lr.confidence_score, 0.5)::float AS confidence_score,
         COALESCE(lr.primary_reasons, ARRAY[]::text[]) AS primary_reasons,
         lr.ai_summary,
         COALESCE(ev.evidence_types, ARRAY[]::text[]) AS evidence_types,
         COALESCE(ev.evidence_items, '[]'::jsonb) AS evidence_items
       FROM discovered_candidates dc
       LEFT JOIN latest_risk lr ON lr.candidate_id = dc.id
       LEFT JOIN ev ON ev.candidate_id = dc.id
       WHERE dc.run_id = $1
       ORDER BY COALESCE(lr.risk_score, 0) DESC;`,
      [runId],
    );
    return res.rows;
  }

  private async dispatchImpersonationAlert(params: {
    brand: BrandRecord;
    candidate: CandidateSnapshotRow;
    canonicalId: string;
    dedupeKey: string;
    effectiveScore: number;
    effectiveLevel: string;
    severity: AlertSeverity;
    corroboratingSignals: string[];
    investigationId: string | null;
  }): Promise<{ alertCreated: boolean; emailDelivered: boolean }> {
    const {
      brand,
      candidate,
      canonicalId,
      dedupeKey,
      effectiveScore,
      effectiveLevel,
      severity,
      corroboratingSignals,
      investigationId,
    } = params;

    const platformLabel =
      candidate.platform === "domain"
        ? "External Website / Domain"
        : `External ${candidate.platform.replace(/_/g, " ")}`;

    const alertTitle = `${platformLabel} impersonation risk for ${brand.name}: ${candidate.candidate_identifier}`;
    const alertDescription = [
      `Find_out External Brand Watch detected a suspected external impersonation asset (${candidate.candidate_url}) targeting ${brand.name} (${brand.primary_domain}).`,
      `Risk score: ${effectiveScore.toFixed(0)}/100 (${effectiveLevel}).`,
      `Corroborating signals: ${corroboratingSignals.join(", ")}.`,
      `Recommended next steps: Review captured evidence in Findings & Evidence, confirm or dismiss as false positive, and if confirmed prepare an authorized takedown/abuse report. No external takedown has been submitted automatically.`,
    ].join(" ");

    const alert = await alertsService.createAlert({
      brandId: brand.id,
      investigationId,
      severity,
      title: alertTitle,
      description: alertDescription,
      evidenceSnapshot: {
        module: "external_brand_watch",
        platform: candidate.platform,
        suspectedIdentifier: candidate.candidate_identifier,
        targetUrl: candidate.candidate_url,
        riskScore: effectiveScore,
        riskLevel: effectiveLevel,
        corroboratingSignals,
        reasons: candidate.primary_reasons,
        recommendedNextSteps: [
          "Inspect evidence & domain/account details in Find_out Findings & Evidence.",
          "Verify with internal brand/marketing teams that this external asset is unauthorized.",
          "Mark finding CONFIRMED or FALSE_POSITIVE in the analyst queue.",
          "If confirmed, generate a human-authorized registrar/host/platform complaint.",
        ],
      },
    });

    let emailStatus: ExternalWatchNotificationRecord["email_status"] = "no_recipient";
    let resendMessageId: string | null = null;
    let emailError: string | null = null;
    const recipient = brand.contact_email?.trim() || null;

    if (!recipient) {
      emailStatus = "no_recipient";
      emailError = "Brand profile has no official contact_email configured.";
    } else if (!isResendConfigured()) {
      emailStatus = "not_configured";
      emailError = "RESEND_API_KEY is not configured on backend.";
    } else {
      const reasonsHtml = candidate.primary_reasons
        .slice(0, 6)
        .map((r) => `<li style="margin-bottom:4px;">${escapeHtml(r)}</li>`)
        .join("");

      const html = `
        <div style="font-family:Inter,Segoe UI,Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;color:#0f172a;">
          <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#dc2626;margin-bottom:8px;">
            Find_out External Brand Watch Alert
          </div>
          <h2 style="margin:0 0 12px;font-size:20px;">Suspected External Brand Impersonation Detected</h2>
          <p style="margin:0 0 16px;font-size:14px;line-height:1.55;color:#334155;">
            Continuous external monitoring identified an unverified public asset outside <strong>${escapeHtml(brand.name)}</strong>'s registered official domains and accounts that exhibits corroborating impersonation signals.
          </p>
          <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;">
            <tr><td style="padding:6px 0;color:#64748b;width:160px;">Protected Brand</td><td style="padding:6px 0;font-weight:600;">${escapeHtml(brand.name)} (${escapeHtml(brand.primary_domain)})</td></tr>
            <tr><td style="padding:6px 0;color:#64748b;">Source Channel</td><td style="padding:6px 0;">${escapeHtml(platformLabel)}</td></tr>
            <tr><td style="padding:6px 0;color:#64748b;">Suspected Asset</td><td style="padding:6px 0;font-family:monospace;">${escapeHtml(candidate.candidate_identifier)}</td></tr>
            <tr><td style="padding:6px 0;color:#64748b;">Observed URL</td><td style="padding:6px 0;word-break:break-all;">${escapeHtml(candidate.candidate_url)}</td></tr>
            <tr><td style="padding:6px 0;color:#64748b;">Risk Assessment</td><td style="padding:6px 0;font-weight:700;color:#b91c1c;">${effectiveScore.toFixed(0)}/100 (${escapeHtml(effectiveLevel)})</td></tr>
            <tr><td style="padding:6px 0;color:#64748b;">Corroborating Signals</td><td style="padding:6px 0;">${escapeHtml(corroboratingSignals.join(", "))}</td></tr>
          </table>
          <div style="background:#f8fafc;border-radius:8px;padding:12px 16px;margin-bottom:16px;">
            <div style="font-size:12px;font-weight:700;color:#475569;margin-bottom:6px;">Captured Evidence Summary</div>
            <ul style="margin:0;padding-left:18px;font-size:13px;color:#1e293b;">${reasonsHtml}</ul>
          </div>
          <div style="font-size:13px;line-height:1.5;color:#334155;">
            <strong>Recommended Next Steps:</strong>
            <ol style="margin:6px 0 0;padding-left:18px;">
              <li>Open Find_out &rarr; External Brand Watch or Findings &amp; Evidence to inspect full technical evidence.</li>
              <li>Confirm whether your organization recently registered this external domain/account.</li>
              <li>Mark the finding as <strong>Confirmed</strong> or <strong>False Positive</strong>. Find_out never submits third-party takedowns without explicit human authorization.</li>
            </ol>
          </div>
        </div>
      `;

      const sendOutcome = await sendResendEmail({
        to: [recipient],
        subject: `[Find_out Alert] ${effectiveLevel} External Impersonation Risk (${effectiveScore.toFixed(0)}/100) — ${candidate.candidate_identifier}`,
        html,
        text: `${alertTitle}\n\n${alertDescription}`,
      });

      if (sendOutcome.delivered) {
        emailStatus = "sent";
        resendMessageId = sendOutcome.id;
      } else {
        emailStatus = "failed";
        emailError = sendOutcome.error ?? "Resend delivery failed";
      }
    }

    await query(
      `INSERT INTO external_watch_notifications (
         brand_id, dedupe_key, platform, canonical_id, target_url,
         risk_score, risk_level, alert_id, recipient_email,
         email_status, resend_message_id, email_error
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (dedupe_key) DO NOTHING;`,
      [
        brand.id,
        dedupeKey,
        candidate.platform,
        canonicalId,
        candidate.candidate_url,
        effectiveScore,
        effectiveLevel,
        alert.id,
        recipient,
        emailStatus,
        resendMessageId,
        emailError,
      ],
    );

    return {
      alertCreated: true,
      emailDelivered: emailStatus === "sent",
    };
  }

  /**
   * Executes due scheduled watches sequentially with full error isolation.
   */
  async runDueWatches(): Promise<{ triggered: number; failed: number }> {
    if (this.tickInProgress) {
      return { triggered: 0, failed: 0 };
    }
    this.tickInProgress = true;

    let triggered = 0;
    let failed = 0;

    try {
      await this.ensureAllActiveBrandsEnrolled();
      const dueRes = await query<{ brand_id: string }>(
        `SELECT s.brand_id
         FROM external_watch_schedules s
         JOIN brands b ON b.id = s.brand_id
         WHERE s.is_enabled = TRUE
           AND b.status = 'active'
           AND s.next_run_at <= NOW()
         ORDER BY s.next_run_at ASC
         LIMIT 3;`,
      );

      for (const row of dueRes.rows) {
        try {
          await this.runBrandWatch(row.brand_id, "scheduled");
          triggered += 1;
        } catch (error) {
          failed += 1;
          logger.warn("[external-watch] Scheduled watch run failed for brand", {
            brandId: row.brand_id,
            error: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }
    } finally {
      this.tickInProgress = false;
    }

    return { triggered, failed };
  }

  startScheduler(): void {
    if (this.schedulerTimer || !config.EXTERNAL_WATCH_SCHEDULER_ENABLED || process.env.NODE_ENV === "test") {
      return;
    }

    const tickMs = Math.max(15_000, config.EXTERNAL_WATCH_TICK_MS);
    this.schedulerTimer = setInterval(() => {
      void this.runDueWatches().catch((error) => {
        logger.error("[external-watch] Scheduler tick error", {
          error: error instanceof Error ? error.message : "Unknown scheduler error",
        });
      });
    }, tickMs);

    if (typeof this.schedulerTimer.unref === "function") {
      this.schedulerTimer.unref();
    }

    // Enroll existing active brands immediately on boot without blocking HTTP startup
    void this.ensureAllActiveBrandsEnrolled().catch((error) => {
      logger.warn("[external-watch] Initial brand enrollment warning", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
    });

    logger.info("[external-watch] Continuous external brand watch scheduler active", {
      tickMs,
      defaultIntervalMinutes: config.EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES,
    });
  }

  stopScheduler(): void {
    if (this.schedulerTimer) {
      clearInterval(this.schedulerTimer);
      this.schedulerTimer = null;
    }
  }

  isSchedulerRunning(): boolean {
    return this.schedulerTimer !== null;
  }

  /**
   * Comprehensive dashboard & status payload for External Brand Watch.
   */
  async getOverview(brandId?: string): Promise<ExternalWatchOverview> {
    await this.ensureAllActiveBrandsEnrolled();

    const params: string[] = [];
    const brandFilter = brandId ? `WHERE s.brand_id = $1::uuid` : "";
    const runFilter = brandId ? `WHERE r.brand_id = $1::uuid` : "";
    const assetFilter = brandId ? `WHERE a.brand_id = $1::uuid` : "";
    const notifFilter = brandId ? `WHERE n.brand_id = $1::uuid` : "";
    if (brandId) params.push(brandId);

    const [schedulesRes, runsRes, assetsRes, notifsRes, confirmedRes] = await Promise.all([
      query<ExternalWatchScheduleRecord>(
        `SELECT
           s.*,
           b.name AS brand_name,
           b.primary_domain,
           b.contact_email
         FROM external_watch_schedules s
         JOIN brands b ON b.id = s.brand_id
         ${brandFilter}
         ORDER BY b.created_at DESC;`,
        params,
      ),
      query<ExternalWatchRunRecord>(
        `SELECT
           r.*,
           b.name AS brand_name
         FROM external_watch_runs r
         JOIN brands b ON b.id = r.brand_id
         ${runFilter}
         ORDER BY r.started_at DESC
         LIMIT 25;`,
        params,
      ),
      query<ExternalSeenAssetRecord>(
        `SELECT
           a.*,
           b.name AS brand_name,
           dr.id AS detection_record_id,
           dr.status AS analyst_status
         FROM external_watch_seen_assets a
         JOIN brands b ON b.id = a.brand_id
         LEFT JOIN detection_records dr ON dr.candidate_id = a.last_candidate_id
         ${assetFilter}
         ORDER BY a.last_risk_score DESC, a.last_seen_at DESC
         LIMIT 60;`,
        params,
      ),
      query<ExternalWatchNotificationRecord>(
        `SELECT
           n.*,
           b.name AS brand_name
         FROM external_watch_notifications n
         JOIN brands b ON b.id = n.brand_id
         ${notifFilter}
         ORDER BY n.created_at DESC
         LIMIT 30;`,
        params,
      ),
      query<{ count: string }>(
        `SELECT COUNT(*)::text AS count
         FROM detection_records dr
         WHERE dr.status = 'CONFIRMED'
           ${brandId ? `AND dr.brand_id = $1::uuid` : ""};`,
        params,
      ),
    ]);

    const schedules = schedulesRes.rows.map((s) => ({
      ...s,
      alert_risk_threshold: Number(s.alert_risk_threshold),
    }));

    const externalCandidates = assetsRes.rows.map((a) => ({
      ...a,
      last_risk_score: Number(a.last_risk_score),
      previous_risk_score: a.previous_risk_score !== null ? Number(a.previous_risk_score) : null,
      corroborating_signals: Array.isArray(a.corroborating_signals) ? a.corroborating_signals : [],
    }));

    const notifications = notifsRes.rows.map((n) => ({
      ...n,
      risk_score: Number(n.risk_score),
    }));

    return {
      scheduler: {
        enabled: config.EXTERNAL_WATCH_SCHEDULER_ENABLED,
        running: this.isSchedulerRunning(),
        tickMs: config.EXTERNAL_WATCH_TICK_MS,
        defaultIntervalMinutes: config.EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES,
        defaultAlertThreshold: config.EXTERNAL_WATCH_ALERT_THRESHOLD,
        resendConfigured: isResendConfigured(),
      },
      summary: {
        monitoredBrands: schedules.filter((s) => s.is_enabled).length,
        totalRuns: runsRes.rows.length,
        newlyDiscoveredCount: externalCandidates.filter((a) => a.change_state === "new").length,
        highRiskCount: externalCandidates.filter(
          (a) =>
            a.last_risk_score >= config.EXTERNAL_WATCH_ALERT_THRESHOLD &&
            a.corroborating_signals.length > 0 &&
            a.analyst_status !== "FALSE_POSITIVE",
        ).length,
        confirmedThreatsCount: Number.parseInt(confirmedRes.rows[0]?.count ?? "0", 10),
        alertsSentCount: notifications.filter((n) => Boolean(n.alert_id)).length,
        emailsDeliveredCount: notifications.filter((n) => n.email_status === "sent").length,
      },
      schedules,
      recentRuns: runsRes.rows,
      externalCandidates,
      notifications,
    };
  }
}

export const externalBrandWatchService = new ExternalBrandWatchService();
export default externalBrandWatchService;
