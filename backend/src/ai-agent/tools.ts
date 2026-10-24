import { brandService } from "../brands";
import { monitoringService } from "../monitoring";
import { investigationService } from "../investigations";
import { alertsService } from "../alerts";
import { threatFeedService } from "../integrations/threat-feed.client";
import { complaintDispatchService } from "../complaints-dispatch.service";
import { reportsService } from "../reports";
import { lookalikeDetectionService } from "../lookalike.service";
import { logoSimilarityService } from "../logo-similarity.service";
import { EvidenceRepository, BrandAssetsRepository } from "../repositories";
import { diagnosticsService } from "./diagnostics";
import { logger } from "../utils/logger";
import { runWithDeadline } from "../utils/timeout";
import { config } from "../config";
import { query } from "../db";

/**
 * Tool registry for the Find_out agent.
 *
 * Every tool reads or writes through the real application services, so an agent
 * answer is always traceable to stored data. Tools never fabricate results: a
 * failed source is returned as `status: "unavailable"` with the underlying error.
 */

export interface AgentToolResult {
  ok: boolean;
  tool: string;
  summary: string;
  data?: unknown;
  error?: string;
  durationMs: number;
}

export interface AgentToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  readOnly: boolean;
  execute: (args: Record<string, unknown>) => Promise<AgentToolResult>;
}

const MAX_RESULT_CHARS = 12_000;

function str(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  return typeof value === "string" ? value.trim() : "";
}

function bool(args: Record<string, unknown>, key: string): boolean {
  return args[key] === true || args[key] === "true";
}

function num(args: Record<string, unknown>, key: string, fallback: number): number {
  const value = args[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return fallback;
}

function truncatePayload(value: unknown): unknown {
  const serialized = safeStringify(value);
  if (serialized.length <= MAX_RESULT_CHARS) return value;

  return {
    truncated: true,
    originalLength: serialized.length,
    preview: `${serialized.slice(0, MAX_RESULT_CHARS)}…`,
  };
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return String(value);
  }
}

async function runTool(
  name: string,
  action: () => Promise<{ summary: string; data: unknown }>,
  timeoutMs = 60_000,
): Promise<AgentToolResult> {
  const startedAt = Date.now();
  const outcome = await runWithDeadline(action, timeoutMs, `Tool ${name}`);

  if (!outcome.value) {
    return {
      ok: false,
      tool: name,
      summary: outcome.error ?? "The tool failed.",
      error: outcome.error ?? "Unknown tool error",
      durationMs: Date.now() - startedAt,
    };
  }

  return {
    ok: true,
    tool: name,
    summary: outcome.value.summary,
    data: truncatePayload(outcome.value.data),
    durationMs: Date.now() - startedAt,
  };
}

function brandIdOrError(args: Record<string, unknown>): string {
  const brandId = str(args, "brandId");
  if (!brandId) throw new Error("brandId is required. Call list_brands first.");
  return brandId;
}

export const agentTools: AgentToolDefinition[] = [
  {
    name: "system_diagnostics",
    description:
      "Connects to every module (database, AI gateway, Gemini, URLhaus, Safe Browsing, YouTube, Bluesky, Apple App Store, Google Play, logo engine, look-alike engine, risk engine, localization) and reports which modules work, which are misconfigured, and why.",
    parameters: {
      type: "object",
      properties: {
        deep: {
          type: "boolean",
          description: "When true, makes live network calls to each integration (slower but authoritative).",
        },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool(
        "system_diagnostics",
        async () => {
          const diagnostics = await diagnosticsService.run({ deep: bool(args, "deep") });
          return {
            summary: `Overall status ${diagnostics.overall.toUpperCase()}: ${diagnostics.counts.ok} ok, ${diagnostics.counts.degraded} degraded, ${diagnostics.counts.notConfigured} not configured, ${diagnostics.counts.error} failing.`,
            data: diagnostics,
          };
        },
        120_000,
      ),
  },
  {
    name: "list_brands",
    description: "Lists the registered brand profiles (id, name, domain, status, alternates).",
    parameters: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Maximum brands to return (default 25)." },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("list_brands", async () => {
        const limit = Math.max(1, Math.min(num(args, "limit", 25), 100));
        const brands = await brandService.listBrands(limit, 0);
        return {
          summary: `${brands.length} brand profile(s) available.`,
          data: brands.map((brand) => ({
            id: brand.id,
            name: brand.name,
            primaryDomain: brand.primary_domain,
            alternateNames: brand.alternate_names ?? [],
            status: brand.status,
            industry: brand.industry,
          })),
        };
      }),
  },
  {
    name: "get_brand_overview",
    description:
      "Reads one brand profile together with its official assets, latest monitoring run and findings counters.",
    parameters: {
      type: "object",
      properties: { brandId: { type: "string", description: "Brand UUID." } },
      required: ["brandId"],
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("get_brand_overview", async () => {
        const brandId = brandIdOrError(args);
        const brand = await brandService.getBrandById(brandId);
        if (!brand) throw new Error(`Brand ${brandId} was not found.`);

        const [assets, latestRun, summary] = await Promise.all([
          BrandAssetsRepository.findByBrandId(brandId),
          monitoringService.getLatestRun(brandId),
          monitoringService.getCandidatesSummary(brandId),
        ]);

        return {
          summary: `${brand.name} has ${assets.length} registered assets, ${summary.total} candidates (${summary.highRisk} high risk) and ${latestRun ? `a ${String(latestRun.status)} monitoring run` : "no monitoring run yet"}.`,
          data: {
            brand,
            assets: assets.map((asset) => ({
              id: asset.id,
              type: asset.asset_type,
              platform: asset.platform,
              identifier: asset.identifier,
              canonicalUrl: asset.canonical_url,
              verificationStatus: asset.verification_status,
              isVerified: asset.is_verified,
            })),
            latestRun,
            findings: summary,
          },
        };
      }),
  },
  {
    name: "run_monitoring_scan",
    description:
      "Runs a full monitoring scan for a brand (Bluesky, YouTube, Apple App Store, Google Play, logo comparison) and stores the findings.",
    parameters: {
      type: "object",
      properties: { brandId: { type: "string", description: "Brand UUID." } },
      required: ["brandId"],
      additionalProperties: false,
    },
    readOnly: false,
    execute: (args) =>
      runTool(
        "run_monitoring_scan",
        async () => {
          const brandId = brandIdOrError(args);
          const summary = await monitoringService.runBrandScan(brandId);
          const unavailable = summary.sourceStatuses.filter((source) => source.status === "unavailable");
          return {
            summary:
              `Scan finished: ${summary.candidatesFound} candidates (${summary.excludedOfficialAssets} official exclusions), ` +
              `${summary.alertsGenerated} alert(s). Sources unavailable: ${unavailable.length}.`,
            data: summary,
          };
        },
        config.MONITORING_RUN_DEADLINE_MS + 15_000,
      ),
  },
  {
    name: "list_findings",
    description: "Returns stored monitoring findings with risk scores and evidence.",
    parameters: {
      type: "object",
      properties: {
        brandId: { type: "string", description: "Optional brand UUID filter." },
        limit: { type: "number", description: "Maximum findings (default 25, max 100)." },
        onlyRisk: { type: "boolean", description: "Return only non-excluded candidates." },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("list_findings", async () => {
        const brandId = str(args, "brandId") || undefined;
        const limit = Math.max(1, Math.min(num(args, "limit", 25), 100));
        const rows = await monitoringService.getCandidates(brandId, undefined, { limit, offset: 0 });
        const filtered = bool(args, "onlyRisk")
          ? rows.filter((row) => row.is_official_excluded !== true)
          : rows;

        return {
          summary: `${filtered.length} finding(s) returned${brandId ? " for this brand" : ""}.`,
          data: filtered.map((row) => ({
            id: row.id,
            name: row.name,
            platform: row.platform,
            sourceType: row.source_type,
            url: row.url,
            publisher: row.publisher,
            riskScore: row.risk_score,
            riskLevel: row.risk_level,
            excluded: row.is_official_excluded,
            evidence: row.evidence,
          })),
        };
      }),
  },
  {
    name: "findings_summary",
    description: "Returns fast counters for findings instead of full rows (total, high/medium risk, exclusions).",
    parameters: {
      type: "object",
      properties: { brandId: { type: "string", description: "Optional brand UUID filter." } },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("findings_summary", async () => {
        const summary = await monitoringService.getCandidatesSummary(str(args, "brandId") || undefined);
        return {
          summary: `${summary.total} candidates, ${summary.highRisk} high risk, ${summary.excluded} official exclusions.`,
          data: summary,
        };
      }),
  },
  {
    name: "investigate_target",
    description:
      "Runs the full investigation pipeline for a URL or domain: URL heuristics, URLhaus, Google Safe Browsing, Gemini reasoning, Bluesky and YouTube evidence, then the risk engine verdict.",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "URL or domain to investigate." },
        brandId: { type: "string", description: "Optional brand UUID for exclusion checks." },
        brandName: { type: "string", description: "Optional brand name used for AI context." },
      },
      required: ["target"],
      additionalProperties: false,
    },
    readOnly: false,
    execute: (args) =>
      runTool(
        "investigate_target",
        async () => {
          const target = str(args, "target");
          if (!target) throw new Error("target is required.");
          const investigation = await investigationService.runInvestigation({
            targetUrl: target,
            brandId: str(args, "brandId") || undefined,
            brandName: str(args, "brandName") || undefined,
          });
          const evidence = await EvidenceRepository.findByInvestigationId(investigation.id);

          return {
            summary: `Verdict ${investigation.verdict.toUpperCase()} — risk ${investigation.risk_score}/100 at ${investigation.confidence_score}% confidence, ${evidence.length} evidence rows.`,
            data: {
              investigation: {
                id: investigation.id,
                target: investigation.target_url,
                status: investigation.status,
                verdict: investigation.verdict,
                riskScore: investigation.risk_score,
                confidenceScore: investigation.confidence_score,
                summary: investigation.summary,
                metadata: investigation.metadata,
              },
              evidence: evidence.map((item) => ({
                source: item.source,
                verified: item.is_verified,
                reliability: item.reliability_score,
                claim: item.extracted_claim,
                url: item.source_url,
              })),
            },
          };
        },
        120_000,
      ),
  },
  {
    name: "get_investigation",
    description: "Loads a stored investigation with its full evidence ledger and generated dossier.",
    parameters: {
      type: "object",
      properties: { investigationId: { type: "string", description: "Investigation UUID." } },
      required: ["investigationId"],
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("get_investigation", async () => {
        const investigationId = str(args, "investigationId");
        if (!investigationId) throw new Error("investigationId is required.");

        const investigation = await investigationService.getInvestigationById(investigationId);
        if (!investigation) throw new Error(`Investigation ${investigationId} was not found.`);

        const dossier = await reportsService.buildDossier(investigationId).catch(() => null);

        return {
          summary: `Investigation ${investigation.verdict.toUpperCase()} with risk ${investigation.risk_score}/100.`,
          data: { investigation, dossier },
        };
      }),
  },
  {
    name: "generate_lookalikes",
    description:
      "Generates look-alike domain permutations for a brand (omission, insertion, transposition, homoglyph, prefix/suffix) with similarity scores.",
    parameters: {
      type: "object",
      properties: {
        brandName: { type: "string", description: "Brand or product name." },
        tld: { type: "string", description: "TLD without a dot (default com)." },
      },
      required: ["brandName"],
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("generate_lookalikes", async () => {
        const brandName = str(args, "brandName");
        if (!brandName) throw new Error("brandName is required.");
        const tld = (str(args, "tld") || "com").replace(/^\./, "");
        const permutations = lookalikeDetectionService.generatePermutations(brandName, tld);

        return {
          summary: `${permutations.length} look-alike domains generated for ${brandName}.`,
          data: permutations.slice(0, 60),
        };
      }),
  },
  {
    name: "evaluate_lookalike",
    description:
      "Compares a suspect domain against a brand name and explains the detected technique (edit distance, similarity, keyword embedding).",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Suspect domain or URL." },
        brandName: { type: "string", description: "Official brand name." },
      },
      required: ["domain", "brandName"],
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("evaluate_lookalike", async () => {
        const domain = str(args, "domain");
        const brandName = str(args, "brandName");
        if (!domain || !brandName) throw new Error("domain and brandName are required.");
        const evaluation = lookalikeDetectionService.evaluateLookalike(domain, brandName);

        return {
          summary: evaluation.isLookalike
            ? `${domain} is a likely look-alike of ${brandName} (${evaluation.detectedTechnique}, similarity ${evaluation.similarityRatio}).`
            : `${domain} did not match the look-alike rules for ${brandName} (similarity ${evaluation.similarityRatio}).`,
          data: evaluation,
        };
      }),
  },
  {
    name: "compare_logos",
    description:
      "Perceptually compares two images (registered logo vs suspect icon) using an 8x8 average hash. Accepts HTTPS URLs or base64 data.",
    parameters: {
      type: "object",
      properties: {
        referenceUrl: { type: "string", description: "HTTPS URL of the registered logo." },
        referenceBase64: { type: "string", description: "Base64 image data for the registered logo." },
        targetUrl: { type: "string", description: "HTTPS URL of the suspect icon." },
        targetBase64: { type: "string", description: "Base64 image data for the suspect icon." },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool(
        "compare_logos",
        async () => {
          const referenceUrl = str(args, "referenceUrl");
          const targetUrl = str(args, "targetUrl");
          const referenceBase64 = str(args, "referenceBase64");
          const targetBase64 = str(args, "targetBase64");

          const toBuffer = (value: string): Buffer => {
            const payload = value.includes(",") ? value.slice(value.indexOf(",") + 1) : value;
            return Buffer.from(payload, "base64");
          };

          let reference: Buffer | string = referenceUrl;
          let target: Buffer | string = targetUrl;
          if (referenceBase64) reference = toBuffer(referenceBase64);
          if (targetBase64) target = toBuffer(targetBase64);

          if (!reference || !target) {
            throw new Error("Provide a reference image and a target image (URL or base64).");
          }

          const result =
            typeof reference === "string" && typeof target === "string"
              ? await logoSimilarityService.compareImageUrls({
                  targetImageUri: target,
                  referenceAssetUri: reference,
                })
              : await logoSimilarityService.compareImageBuffers({
                  targetImage: typeof target === "string" ? Buffer.alloc(0) : target,
                  referenceImage: typeof reference === "string" ? Buffer.alloc(0) : reference,
                });

          return {
            summary: `Logo similarity ${Math.round(result.similarityScore * 100)}% (${result.isImpersonating ? "above" : "below"} the 82% threshold).`,
            data: result,
          };
        },
        40_000,
      ),
  },
  {
    name: "list_alerts",
    description: "Lists security alerts, optionally filtered by status.",
    parameters: {
      type: "object",
      properties: {
        status: {
          type: "string",
          description: "open | acknowledged | resolved | dismissed",
        },
        brandId: { type: "string", description: "Optional brand UUID." },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("list_alerts", async () => {
        const status = str(args, "status");
        const alerts = await alertsService.listAlerts(
          str(args, "brandId") || undefined,
          status ? (status as "open" | "acknowledged" | "resolved" | "dismissed") : undefined,
        );

        return {
          summary: `${alerts.length} alert(s) returned.`,
          data: alerts.slice(0, 50),
        };
      }),
  },
  {
    name: "live_threat_feed",
    description:
      "Reads the live CISA Known Exploited Vulnerabilities feed and returns the newest entries, optionally filtered by a vendor/product/technique keyword.",
    parameters: {
      type: "object",
      properties: {
        search: { type: "string", description: "Optional keyword such as a vendor or product." },
        limit: { type: "number", description: "How many entries to return (1-25)." },
      },
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool(
        "live_threat_feed",
        async () => {
          const search = str(args, "search");
          const limit = Math.max(1, Math.min(Math.round(num(args, "limit", 10)), 25));
          const feed = await threatFeedService.getFeed({ limit, search });

          return {
            summary:
              feed.status === "available"
                ? `${feed.count} live entries from CISA KEV${search ? ` matching "${search}"` : ""}.`
                : `The live feed is ${feed.status}: ${feed.detail}`,
            data: {
              status: feed.status,
              detail: feed.detail,
              fetchedAt: feed.fetchedAt,
              totalAvailable: feed.totalAvailable,
              items: feed.items.map((item) => ({
                id: item.id,
                title: item.title,
                vendor: item.vendor,
                product: item.product,
                severity: item.severity,
                dateAdded: item.dateAdded,
                knownRansomware: item.knownRansomware,
              })),
            },
          };
        },
        25_000,
      ),
  },
  {
    name: "complaint_delivery_status",
    description:
      "Reports whether takedown notices can actually be submitted (SMTP or webhook configured) and how many complaints are stored with each status.",
    parameters: { type: "object", properties: {}, additionalProperties: false },
    readOnly: true,
    execute: () =>
      runTool("complaint_delivery_status", async () => {
        const status = complaintDispatchService.status();
        const stats = await query<{ status: string; count: string }>(
          `SELECT status, COUNT(*)::text AS count FROM complaints GROUP BY status ORDER BY status;`,
        );
        return {
          summary: status.configured
            ? `Delivery is configured via ${status.transport}.`
            : "No outbound delivery transport is configured: notices are drafted but cannot be submitted.",
          data: {
            ...status,
            byStatus: Object.fromEntries(
              stats.rows.map((row: { status: string; count: string }) => [row.status, Number(row.count)]),
            ),
          },
        };
      }),
  },
  {
    name: "draft_takedown_notice",
    description:
      "Produces a factual takedown/complaint draft for a target using supplied evidence. It never sends the complaint anywhere.",
    parameters: {
      type: "object",
      properties: {
        brandName: { type: "string", description: "Brand being impersonated." },
        targetUrl: { type: "string", description: "Infringing URL or profile." },
        platform: { type: "string", description: "Hosting platform (optional)." },
        evidenceSummary: { type: "string", description: "Verified evidence points to cite." },
      },
      required: ["brandName", "targetUrl"],
      additionalProperties: false,
    },
    readOnly: true,
    execute: (args) =>
      runTool("draft_takedown_notice", async () => {
        const brandName = str(args, "brandName");
        const targetUrl = str(args, "targetUrl");
        const platform = str(args, "platform") || "the hosting platform";
        const evidence = str(args, "evidenceSummary") || "See the attached evidence ledger.";

        const notice = [
          `Subject: Notice of trademark infringement and fraudulent impersonation — ${targetUrl}`,
          "",
          `To: ${platform} Trust & Safety / Abuse team`,
          "",
          `I am authorised to act on behalf of ${brandName}. The resource at ${targetUrl} misuses the ${brandName} name and/or marks without authorisation and is being presented to users as an official ${brandName} property.`,
          "",
          "Evidence collected by the Find_out investigation platform:",
          evidence
            .split("\n")
            .filter(Boolean)
            .map((line) => `- ${line}`)
            .join("\n"),
          "",
          `Requested action: remove or disable access to ${targetUrl}, preserve associated records, and confirm the action taken.`,
          "",
          "This notice is provided for platform and registrar abuse handling. It is not a legal opinion; consult counsel before formal proceedings.",
        ].join("\n");

        return {
          summary: `Draft takedown notice prepared for ${targetUrl}.`,
          data: { notice, platform, targetUrl, brandName },
        };
      }),
  },
];

const toolMap = new Map(agentTools.map((tool) => [tool.name, tool]));

export function getTool(name: string): AgentToolDefinition | undefined {
  return toolMap.get(name);
}

export function toolCatalogForPrompt(): string {
  return agentTools
    .map(
      (tool) =>
        `- ${tool.name}: ${tool.description}\n  parameters: ${JSON.stringify(tool.parameters)}`,
    )
    .join("\n");
}

export async function executeTool(
  name: string,
  args: Record<string, unknown>,
): Promise<AgentToolResult> {
  const tool = getTool(name);
  if (!tool) {
    return {
      ok: false,
      tool: name,
      summary: `Unknown tool "${name}". Available tools: ${agentTools.map((entry) => entry.name).join(", ")}.`,
      error: "unknown_tool",
      durationMs: 0,
    };
  }

  try {
    logger.info("[agent-tool] Executing", { tool: name, args });
    return await tool.execute(args);
  } catch (error) {
    return {
      ok: false,
      tool: name,
      summary: error instanceof Error ? error.message : "The tool failed.",
      error: error instanceof Error ? error.message : "unknown_error",
      durationMs: 0,
    };
  }
}
