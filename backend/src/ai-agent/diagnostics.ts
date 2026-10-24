import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import sharp from "sharp";

import { config } from "../config";
import { query } from "../db";
import { logger } from "../utils/logger";
import { runWithDeadline } from "../utils/timeout";
import { aiProvider } from "./provider";
import { geminiClient } from "../integrations/gemini.client";
import { urlhausClient } from "../integrations/urlhaus.client";
import { threatFeedService } from "../integrations/threat-feed.client";
import { complaintDispatchService } from "../complaints-dispatch.service";
import { safeBrowsingClient } from "../integrations/safebrowsing.client";
import { youtubeClient } from "../integrations/youtube.client";
import { blueskyClient } from "../integrations/bluesky.client";
import { googlePlayClient } from "../integrations/google-play.client";
import { logoSimilarityService } from "../logo-similarity.service";
import { lookalikeDetectionService } from "../lookalike.service";

export type ModuleStatus = "ok" | "degraded" | "not_configured" | "error";

export interface ModuleDiagnostic {
  id: string;
  name: string;
  category: "ai" | "threat-intel" | "social" | "app-store" | "data" | "product" | "platform";
  status: ModuleStatus;
  configured: boolean;
  latencyMs: number;
  detail: string;
  remediation?: string;
  metrics?: Record<string, number | string | boolean>;
}

export interface SystemDiagnostics {
  generatedAt: string;
  durationMs: number;
  deep: boolean;
  overall: ModuleStatus;
  ready: boolean;
  counts: { ok: number; degraded: number; notConfigured: number; error: number };
  blockers: ModuleDiagnostic[];
  warnings: ModuleDiagnostic[];
  modules: ModuleDiagnostic[];
  ai: {
    configured: boolean;
    primaryModel: string;
    modelChain: string[];
    transportPreference: string;
    usableRoute: { model: string; transport: string } | null;
    lastError: { code: string; message: string } | null;
  };
}

type Check = () => Promise<ModuleDiagnostic>;

const MODULE_TIMEOUT_MS = 30_000;

function base(
  partial: Omit<ModuleDiagnostic, "latencyMs"> & { latencyMs?: number },
): ModuleDiagnostic {
  return { latencyMs: 0, ...partial };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

function hasTableScript(tables: string[]): string {
  return tables
    .map((table) => `to_regclass('public.${table}') IS NOT NULL AS ${table}`)
    .join(", ");
}

export class DiagnosticsService {
  async run(options: { deep?: boolean } = {}): Promise<SystemDiagnostics> {
    const deep = options.deep ?? true;
    const startedAt = Date.now();

    const checks: Check[] = [
      () => this.checkDatabase(),
      () => this.checkSchema(),
      () => this.checkAiProvider(deep),
      () => this.checkGemini(deep),
      () => this.checkUrlhaus(deep),
      () => this.checkSafeBrowsing(deep),
      () => this.checkYouTube(deep),
      () => this.checkBluesky(deep),
      () => this.checkAppleStore(deep),
      () => this.checkGooglePlay(deep),
      () => this.checkLogoEngine(),
      () => this.checkLookalikeEngine(),
      () => this.checkRiskEngine(),
      () => this.checkInvestigationPipeline(),
      () => this.checkAlertsAndComplaints(),
      () => this.checkThreatFeed(),
      () => this.checkComplaintDelivery(),
      () => this.checkLocalization(),
    ];

    const modules: ModuleDiagnostic[] = [];

    for (const check of checks) {
      const outcome = await runWithDeadline(check, MODULE_TIMEOUT_MS, "Diagnostic check");
      if (outcome.value) {
        modules.push(outcome.value);
      } else {
        modules.push(
          base({
            id: "unknown",
            name: "Diagnostic check",
            category: "platform",
            status: "error",
            configured: true,
            detail: outcome.error ?? "The diagnostic check failed.",
            latencyMs: outcome.durationMs,
          }),
        );
      }
    }

    const counts = {
      ok: modules.filter((module) => module.status === "ok").length,
      degraded: modules.filter((module) => module.status === "degraded").length,
      notConfigured: modules.filter((module) => module.status === "not_configured").length,
      error: modules.filter((module) => module.status === "error").length,
    };

    const blockers = modules.filter((module) => module.status === "error");
    const warnings = modules.filter(
      (module) => module.status === "degraded" || module.status === "not_configured",
    );

    const overall: ModuleStatus =
      counts.error > 0 ? "error" : counts.degraded > 0 ? "degraded" : counts.notConfigured > 0 ? "not_configured" : "ok";

    const diagnostics: SystemDiagnostics = {
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      deep,
      overall,
      ready: counts.error === 0,
      counts,
      blockers,
      warnings,
      modules,
      ai: {
        configured: aiProvider.configured,
        primaryModel: config.OPENAI_MODEL,
        modelChain: aiProvider.modelChain,
        transportPreference: config.OPENAI_TRANSPORT,
        usableRoute: aiProvider.status.lastSuccessfulRoute,
        lastError: aiProvider.status.lastError,
      },
    };

    logger.info("[diagnostics] System sweep completed", {
      deep,
      overall,
      ok: counts.ok,
      degraded: counts.degraded,
      notConfigured: counts.notConfigured,
      errors: counts.error,
      durationMs: diagnostics.durationMs,
    });

    return diagnostics;
  }

  private async checkDatabase(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      await query("SELECT 1");
      const version = await query<{ version: string }>("SELECT version() AS version");
      return base({
        id: "database",
        name: "PostgreSQL",
        category: "data",
        status: "ok",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `${version.rows[0]?.version?.split(",")[0] ?? "PostgreSQL"} responded in ${Date.now() - startedAt} ms.`,
      });
    } catch (error) {
      return base({
        id: "database",
        name: "PostgreSQL",
        category: "data",
        status: "error",
        configured: Boolean(config.DATABASE_URL),
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
        remediation:
          "Start PostgreSQL (docker compose up -d postgres) and confirm DATABASE_URL in backend/.env.",
      });
    }
  }

  private async checkSchema(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    const required = [
      "brands",
      "official_assets",
      "monitoring_runs",
      "discovered_candidates",
      "candidate_evidence",
      "risk_assessments",
      "investigations",
      "evidence_items",
      "alerts",
      "complaints",
      "reports",
      "agent_runs",
    ];

    try {
      const result = await query<Record<string, boolean>>(
        `SELECT ${hasTableScript(required)};`,
      );
      const row = result.rows[0] ?? {};
      const absent = required.filter((table) => row[table] !== true);

      return base({
        id: "schema",
        name: "Database schema",
        category: "data",
        status: absent.length === 0 ? "ok" : "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail:
          absent.length === 0
            ? `All ${required.length} required tables are present.`
            : `Missing tables: ${absent.join(", ")}`,
        remediation: "Restart the backend so initializeSchema() can apply the schema.",
        metrics: { requiredTables: required.length, missingTables: absent.length },
      });
    } catch (error) {
      return base({
        id: "schema",
        name: "Database schema",
        category: "data",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
      });
    }
  }

  private async checkAiProvider(deep: boolean): Promise<ModuleDiagnostic> {
    const configured = aiProvider.configured;

    if (!configured) {
      return base({
        id: "ai_agent",
        name: "AI agent gateway (OpenAI-compatible)",
        category: "ai",
        status: "not_configured",
        configured: false,
        detail:
          "OPENAI_BASE_URL / OPENAI_API_KEY are not set. The agent still runs, but answers come from the deterministic evidence engine.",
        remediation:
          "Add OPENAI_BASE_URL=https://api.aicredits.in/v1 and OPENAI_API_KEY to backend/.env.",
      });
    }

    if (!deep) {
      // Configured and in use by the chat box; the deep probe is what turns this
      // into a verified "ok". Calling it "degraded" made a working gateway look
      // broken on the dashboard.
      return base({
        id: "ai_agent",
        name: "AI agent gateway (OpenAI-compatible)",
        category: "ai",
        status: "ok",
        configured: true,
        detail: `Configured with OPENAI_MODEL=${config.OPENAI_MODEL}. Deep check not run in this sweep.`,
        metrics: { model: config.OPENAI_MODEL, baseUrl: config.OPENAI_BASE_URL.replace(/\/\/.*@/, "//") },
      });
    }

    const startedAt = Date.now();
    const models = await aiProvider.listModels(15_000);
    const probe = await aiProvider.probe(60_000);

    if (probe.ok) {
      return base({
        id: "ai_agent",
        name: "AI agent gateway (OpenAI-compatible)",
        category: "ai",
        status: "ok",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: probe.message,
        metrics: {
          modelsListed: models.count,
          usableModel: probe.model ?? "",
          transport: probe.transport ?? "",
        },
      });
    }

    return base({
      id: "ai_agent",
      name: "AI agent gateway (OpenAI-compatible)",
      category: "ai",
      status: "error",
      configured: true,
      latencyMs: Date.now() - startedAt,
      detail: probe.message,
      remediation:
        "The key authenticates but no configured model answered. Confirm which models this key is permitted to use (GET /v1/models), then set OPENAI_MODEL and OPENAI_FALLBACK_MODELS. Chat Completions is blocked on some keys; the agent already retries through /v1/responses.",
      metrics: {
        modelsListed: models.count,
        probeCode: probe.code ?? "",
      },
    });
  }

  private async checkGemini(deep: boolean): Promise<ModuleDiagnostic> {
    if (!geminiClient.configured) {
      return base({
        id: "gemini",
        name: "Gemini threat reasoning",
        category: "ai",
        status: "not_configured",
        configured: false,
        detail: "GEMINI_API_KEY is not set; risk scoring runs without model reasoning.",
        remediation: "Set GEMINI_API_KEY in backend/.env (optional, independent of the AI agent).",
      });
    }

    if (!deep) {
      return base({
        id: "gemini",
        name: "Gemini threat reasoning",
        category: "ai",
        status: "degraded",
        configured: true,
        detail: `Configured with model chain: ${geminiClient.modelChain.join(" → ")}.`,
      });
    }

    const probe = await geminiClient.probe();
    return base({
      id: "gemini",
      name: "Gemini threat reasoning",
      category: "ai",
      status: probe.ok ? "ok" : "error",
      configured: true,
      latencyMs: probe.latencyMs,
      detail: probe.message,
      remediation: probe.ok
        ? undefined
        : "Set GEMINI_MODEL to a currently available model (e.g. gemini-2.5-flash). Retired names such as gemini-1.5-pro return HTTP 404.",
      metrics: { model: probe.model ?? "" },
    });
  }

  private async checkUrlhaus(deep: boolean): Promise<ModuleDiagnostic> {
    if (!urlhausClient.configured) {
      return base({
        id: "urlhaus",
        name: "URLhaus (abuse.ch)",
        category: "threat-intel",
        status: "not_configured",
        configured: false,
        detail:
          "URLHAUS_AUTH_KEY is not set. abuse.ch rejects unauthenticated API calls with HTTP 401, so this source is skipped rather than reported as a false negative.",
        remediation:
          "Create a free Auth-Key at https://auth.abuse.ch/ and set URLHAUS_AUTH_KEY in backend/.env.",
      });
    }

    if (!deep) {
      return base({
        id: "urlhaus",
        name: "URLhaus (abuse.ch)",
        category: "threat-intel",
        status: "degraded",
        configured: true,
        detail: "Auth-Key is configured. Run a deep check to verify it.",
      });
    }

    const result = await urlhausClient.checkUrl("https://example.com/");
    return base({
      id: "urlhaus",
      name: "URLhaus (abuse.ch)",
      category: "threat-intel",
      status: result.status === "available" ? "ok" : "error",
      configured: true,
      detail:
        result.status === "available"
          ? "URLhaus answered a live lookup."
          : result.error ?? "URLhaus lookup failed.",
      remediation:
        result.status === "available"
          ? undefined
          : "Verify URLHAUS_AUTH_KEY at https://auth.abuse.ch/ — expired or revoked keys return 401.",
    });
  }

  private async checkSafeBrowsing(deep: boolean): Promise<ModuleDiagnostic> {
    if (!config.GOOGLE_SAFE_BROWSING_API_KEY) {
      return base({
        id: "safebrowsing",
        name: "Google Safe Browsing",
        category: "threat-intel",
        status: "not_configured",
        configured: false,
        detail: "GOOGLE_SAFE_BROWSING_API_KEY is not set.",
        remediation: "Enable the Safe Browsing API and set GOOGLE_SAFE_BROWSING_API_KEY.",
      });
    }

    if (!deep) {
      return base({
        id: "safebrowsing",
        name: "Google Safe Browsing",
        category: "threat-intel",
        status: "degraded",
        configured: true,
        detail: "API key configured. Run a deep check to verify.",
      });
    }

    const result = await safeBrowsingClient.checkUrl("https://example.com/");
    return base({
      id: "safebrowsing",
      name: "Google Safe Browsing",
      category: "threat-intel",
      status: result.status === "available" ? "ok" : "error",
      configured: true,
      detail:
        result.status === "available"
          ? `Safe Browsing answered (${result.rawMatches.length} matches for the probe URL).`
          : result.error ?? "Safe Browsing lookup failed.",
      remediation:
        result.status === "available"
          ? undefined
          : "Confirm the API key is allowed to call safebrowsing.googleapis.com/v4/threatMatches:find.",
    });
  }

  private async checkYouTube(deep: boolean): Promise<ModuleDiagnostic> {
    if (!config.YOUTUBE_API_KEY) {
      return base({
        id: "youtube",
        name: "YouTube Data API",
        category: "social",
        status: "not_configured",
        configured: false,
        detail: "YOUTUBE_API_KEY is not set.",
        remediation: "Set YOUTUBE_API_KEY to include YouTube in social monitoring.",
      });
    }

    if (!deep) {
      return base({
        id: "youtube",
        name: "YouTube Data API",
        category: "social",
        status: "degraded",
        configured: true,
        detail: "API key configured. Run a deep check to verify.",
      });
    }

    const result = await youtubeClient.searchVideos("cyber security");
    const ok = !result.rawPayload.error && result.rawPayload.skipped !== true;

    return base({
      id: "youtube",
      name: "YouTube Data API",
      category: "social",
      status: ok ? "ok" : "error",
      configured: true,
      detail: ok
        ? `YouTube answered with ${result.totalFound} results.`
        : String(result.rawPayload.error ?? "YouTube search failed."),
      remediation: ok ? undefined : "Verify the key and quota in Google Cloud Console.",
    });
  }

  private async checkBluesky(deep: boolean): Promise<ModuleDiagnostic> {
    if (!config.BLUESKY_HANDLE || !config.BLUESKY_APP_PASSWORD) {
      return base({
        id: "bluesky",
        name: "Bluesky public search",
        category: "social",
        status: "not_configured",
        configured: false,
        detail: "BLUESKY_HANDLE / BLUESKY_APP_PASSWORD are not set.",
        remediation:
          "Generate an app password in Bluesky settings and set BLUESKY_HANDLE + BLUESKY_APP_PASSWORD.",
      });
    }

    if (!deep) {
      return base({
        id: "bluesky",
        name: "Bluesky public search",
        category: "social",
        status: "degraded",
        configured: true,
        detail: "Credentials configured. Run a deep check to verify the session.",
      });
    }

    const probe = await blueskyClient.probe();
    return base({
      id: "bluesky",
      name: "Bluesky public search",
      category: "social",
      status: probe.ok ? "ok" : "error",
      configured: true,
      latencyMs: probe.latencyMs,
      detail: probe.message,
      remediation: probe.ok
        ? undefined
        : "App passwords are separate from the account password; regenerate one in Bluesky → Settings → App Passwords.",
    });
  }

  private async checkAppleStore(deep: boolean): Promise<ModuleDiagnostic> {
    if (!deep) {
      return base({
        id: "apple_app_store",
        name: "Apple App Store",
        category: "app-store",
        status: "degraded",
        configured: true,
        detail: "Public iTunes Search API. Run a deep check to verify connectivity.",
      });
    }

    const startedAt = Date.now();
    try {
      const url = new URL("https://itunes.apple.com/search");
      url.searchParams.set("term", "banking");
      url.searchParams.set("entity", "software");
      url.searchParams.set("limit", "3");
      url.searchParams.set("country", config.APPLE_STORE_COUNTRY);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12_000);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);

      if (!response.ok) throw new Error(`iTunes Search returned HTTP ${response.status}`);
      const payload = (await response.json()) as { results?: unknown[] };

      return base({
        id: "apple_app_store",
        name: "Apple App Store",
        category: "app-store",
        status: "ok",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `iTunes Search answered with ${payload.results?.length ?? 0} probe results.`,
      });
    } catch (error) {
      return base({
        id: "apple_app_store",
        name: "Apple App Store",
        category: "app-store",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
        remediation: "Check outbound HTTPS access to itunes.apple.com.",
      });
    }
  }

  private async checkGooglePlay(deep: boolean): Promise<ModuleDiagnostic> {
    if (!deep) {
      return base({
        id: "google_play",
        name: "Google Play Store",
        category: "app-store",
        status: "degraded",
        configured: true,
        detail: "Public Play Store search parser. Run a deep check to verify the markup.",
      });
    }

    const result = await googlePlayClient.search("banking", { limit: 5, timeoutMs: 20_000 });

    return base({
      id: "google_play",
      name: "Google Play Store",
      category: "app-store",
      status: result.status === "available" ? "ok" : "error",
      configured: true,
      latencyMs: result.latencyMs,
      detail:
        result.status === "available"
          ? `Play Store search parsed ${result.listings.length} listings.`
          : result.error ?? "Play Store search failed.",
      remediation:
        result.status === "available"
          ? undefined
          : "Google frequently changes Play Store markup. Outbound access to play.google.com is required; the parser degrades to 'unavailable' rather than inventing results.",
      metrics: { listings: result.listings.length },
    });
  }

  private async checkLogoEngine(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      const image = await sharp({
        create: { width: 32, height: 32, channels: 3, background: { r: 12, g: 44, b: 90 } },
      })
        .png()
        .toBuffer();

      const hashA = await logoSimilarityService.computeImageHash(image);
      const hashB = await logoSimilarityService.computeImageHash(image);
      const distance = logoSimilarityService.hammingDistance(hashA, hashB);

      return base({
        id: "logo_similarity",
        name: "Logo similarity engine",
        category: "product",
        status: distance === 0 ? "ok" : "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail:
          distance === 0
            ? "Average-hash pipeline is deterministic (0 bits differ on identical images)."
            : `Hash self-check produced ${distance} differing bits.`,
        metrics: { hashBits: hashA.length },
      });
    } catch (error) {
      return base({
        id: "logo_similarity",
        name: "Logo similarity engine",
        category: "product",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `sharp/logo engine unavailable: ${errorMessage(error)}`,
        remediation: "Reinstall backend dependencies (npm ci --prefix backend) so sharp's native binary is present.",
      });
    }
  }

  private async checkLookalikeEngine(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      const variants = lookalikeDetectionService.generatePermutations("findout", "com");
      const evaluation = lookalikeDetectionService.evaluateLookalike("find0ut.com", "findout");

      const ok = variants.length > 0 && evaluation.isLookalike;

      return base({
        id: "lookalike_engine",
        name: "Look-alike name engine",
        category: "product",
        status: ok ? "ok" : "degraded",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `Generated ${variants.length} variants; homoglyph self-test similarity ${evaluation.similarityRatio}.`,
        metrics: { variants: variants.length, similarity: evaluation.similarityRatio },
      });
    } catch (error) {
      return base({
        id: "lookalike_engine",
        name: "Look-alike name engine",
        category: "product",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
      });
    }
  }

  private async checkRiskEngine(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      const { riskScoringEngine } = await import("../risk.js");
      const evaluation = riskScoringEngine.evaluate({
        evidenceItems: [
          {
            source: "urlhaus",
            rawPayload: { sourceStatus: "available" },
            isVerified: true,
            reliabilityScore: 95,
            extractedClaim: "URLhaus reported a threat.",
          },
        ],
        heuristicRiskScore: 60,
      });

      const ok = evaluation.verdict === "malicious" && evaluation.compositeRiskScore >= 80;

      return base({
        id: "risk_engine",
        name: "Risk & verdict engine",
        category: "product",
        status: ok ? "ok" : "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `Synthetic verified threat → score ${evaluation.compositeRiskScore}, verdict ${evaluation.verdict}.`,
        metrics: {
          score: evaluation.compositeRiskScore,
          confidence: evaluation.confidenceScore,
        },
      });
    } catch (error) {
      return base({
        id: "risk_engine",
        name: "Risk & verdict engine",
        category: "product",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
      });
    }
  }

  private async checkInvestigationPipeline(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      const result = await query<{ investigations: string; evidence: string }>(
        `SELECT
           (SELECT COUNT(*)::text FROM investigations) AS investigations,
           (SELECT COUNT(*)::text FROM evidence_items) AS evidence;`,
      );
      const row = result.rows[0];

      return base({
        id: "investigations",
        name: "Investigation pipeline",
        category: "product",
        status: "ok",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `${row?.investigations ?? 0} investigations and ${row?.evidence ?? 0} evidence rows are stored.`,
        metrics: {
          investigations: Number(row?.investigations ?? 0),
          evidenceItems: Number(row?.evidence ?? 0),
        },
      });
    } catch (error) {
      return base({
        id: "investigations",
        name: "Investigation pipeline",
        category: "product",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
      });
    }
  }

  /**
   * The old build had no live feed at all: alerts were only internal rows.
   * This check proves the CISA KEV catalogue is actually reachable and parsed.
   */
  private async checkThreatFeed(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    const result = await threatFeedService.status();

    if (result.status === "not_configured") {
      return base({
        id: "threat_feed",
        name: "Live threat feed (CISA KEV)",
        category: "threat-intel",
        status: "not_configured",
        configured: false,
        latencyMs: Date.now() - startedAt,
        detail: result.detail,
        remediation: "Set THREAT_FEED_ENABLED=true to include the live CISA catalogue.",
      });
    }

    return base({
      id: "threat_feed",
      name: "Live threat feed (CISA KEV)",
      category: "threat-intel",
      status: result.status === "available" ? "ok" : "degraded",
      configured: true,
      latencyMs: Date.now() - startedAt,
      detail:
        result.status === "available"
          ? `${result.items} known-exploited vulnerabilities, fetched ${result.fetchedAt}.`
          : result.detail,
      remediation:
        result.status === "available"
          ? undefined
          : "CISA may be unreachable from this network. The feed is cached for 15 minutes and the UI shows the last error instead of inventing alerts.",
      metrics: { items: result.items },
    });
  }

  /** Proves whether a takedown notice can actually leave the platform. */
  private async checkComplaintDelivery(): Promise<ModuleDiagnostic> {
    const status = complaintDispatchService.status();
    return base({
      id: "complaint_delivery",
      name: "Takedown notice delivery",
      category: "product",
      status: status.configured ? "ok" : "not_configured",
      configured: status.configured,
      latencyMs: 0,
      detail: status.detail,
      remediation: status.configured
        ? undefined
        : "Configure SMTP_HOST + COMPLAINT_FROM_EMAIL (+ SMTP_USER/SMTP_PASS) or COMPLAINT_WEBHOOK_URL. Until then notices are stored, never marked as sent.",
      metrics: { transport: status.transport },
    });
  }

  private async checkAlertsAndComplaints(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    try {
      const result = await query<{ alerts: string; complaints: string; reports: string }>(
        `SELECT
           (SELECT COUNT(*)::text FROM alerts) AS alerts,
           (SELECT COUNT(*)::text FROM complaints) AS complaints,
           (SELECT COUNT(*)::text FROM reports) AS reports;`,
      );
      const row = result.rows[0];

      return base({
        id: "alerts_complaints",
        name: "Alerts, complaints & reports",
        category: "product",
        status: "ok",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `${row?.alerts ?? 0} alerts, ${row?.complaints ?? 0} complaints, ${row?.reports ?? 0} reports.`,
        metrics: {
          alerts: Number(row?.alerts ?? 0),
          complaints: Number(row?.complaints ?? 0),
          reports: Number(row?.reports ?? 0),
        },
      });
    } catch (error) {
      return base({
        id: "alerts_complaints",
        name: "Alerts, complaints & reports",
        category: "product",
        status: "error",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: errorMessage(error),
      });
    }
  }

  /**
   * The backend can be started from any working directory (and the compiled
   * output may live outside the repository in a container). Resolve the locale
   * folder from several candidates instead of assuming one layout, otherwise
   * the localization module falsely reports "degraded".
   */
  private resolveLocaleDir(): string | null {
    const candidates = [
      path.resolve(__dirname, "../../../frontend/src/locales"),
      path.resolve(__dirname, "../../frontend/src/locales"),
      path.resolve(process.cwd(), "frontend/src/locales"),
      path.resolve(process.cwd(), "../frontend/src/locales"),
      path.resolve(process.cwd(), "src/locales"),
    ];

    for (const candidate of candidates) {
      if (existsSync(path.join(candidate, "en.json"))) return candidate;
    }

    // Walk up from the current directory as a last resort.
    let current = process.cwd();
    for (let depth = 0; depth < 5; depth += 1) {
      const candidate = path.join(current, "frontend", "src", "locales");
      if (existsSync(path.join(candidate, "en.json"))) return candidate;
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }

    return null;
  }

  private async checkLocalization(): Promise<ModuleDiagnostic> {
    const startedAt = Date.now();
    const localeDir = this.resolveLocaleDir();

    if (!localeDir) {
      return base({
        id: "localization",
        name: "Localization (EN/HI/TE)",
        category: "platform",
        status: "degraded",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail:
          "Locale files were not found next to the backend. Deploy frontend/src/locales with the backend or set the working directory to the repository root.",
      });
    }

    try {
      const [en, hi, te] = await Promise.all([
        readFile(path.join(localeDir, "en.json"), "utf8"),
        readFile(path.join(localeDir, "hi.json"), "utf8"),
        readFile(path.join(localeDir, "te.json"), "utf8"),
      ]);

      const enKeys = flattenKeys(JSON.parse(en));
      const hiKeys = new Set(flattenKeys(JSON.parse(hi)));
      const teKeys = new Set(flattenKeys(JSON.parse(te)));

      const missingHi = enKeys.filter((key) => !hiKeys.has(key));
      const missingTe = enKeys.filter((key) => !teKeys.has(key));
      const complete = missingHi.length === 0 && missingTe.length === 0;

      return base({
        id: "localization",
        name: "Localization (EN/HI/TE)",
        category: "platform",
        status: complete ? "ok" : "degraded",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: complete
          ? `All ${enKeys.length} keys are present in English, Hindi and Telugu.`
          : `Hindi missing ${missingHi.length} keys, Telugu missing ${missingTe.length} keys.`,
        remediation: complete ? undefined : "Add the missing keys to frontend/src/locales/*.json.",
        metrics: {
          keys: enKeys.length,
          missingHindi: missingHi.length,
          missingTelugu: missingTe.length,
        },
      });
    } catch (error) {
      return base({
        id: "localization",
        name: "Localization (EN/HI/TE)",
        category: "platform",
        status: "degraded",
        configured: true,
        latencyMs: Date.now() - startedAt,
        detail: `Locale coverage could not be measured: ${errorMessage(error)}`,
      });
    }
  }
}

function flattenKeys(value: unknown, prefix = ""): string[] {
  if (typeof value !== "object" || value === null) return [];
  const keys: string[] = [];

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof child === "object" && child !== null) {
      keys.push(...flattenKeys(child, path));
    } else {
      keys.push(path);
    }
  }

  return keys;
}

export const diagnosticsService = new DiagnosticsService();
export default diagnosticsService;
