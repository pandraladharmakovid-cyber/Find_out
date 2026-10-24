import { randomUUID } from "node:crypto";

import { config } from "../config";
import { query } from "../db";
import { logger } from "../utils/logger";
import { aiProvider, AIProviderError, extractJson, type AIAttempt, type AIMessage } from "./provider";
import { executeTool, toolCatalogForPrompt, type AgentToolResult } from "./tools";
import { diagnosticsService, type ModuleDiagnostic, type SystemDiagnostics } from "./diagnostics";
import { brandService } from "../brands";
import { monitoringService } from "../monitoring";
import { investigationService } from "../investigations";

export type AgentVerdict = "clean" | "suspicious" | "malicious" | "phishing" | "unverified";

export interface AgentRequest {
  goal: string;
  brandId?: string;
  targetUrl?: string;
  maxSteps?: number;
  language?: "en" | "hi" | "te";
  mode?: "investigate" | "ask" | "audit";
}

export interface AgentStepTrace {
  step: number;
  thought: string;
  tool: string | null;
  args: Record<string, unknown>;
  ok: boolean;
  summary: string;
  durationMs: number;
}

export interface AgentReport {
  goal: string;
  mode: "investigate" | "ask" | "audit";
  answer: string;
  verdict: AgentVerdict;
  riskScore: number;
  confidenceScore: number;
  summary: string;
  keyFindings: string[];
  moduleStatus: Array<{
    id: string;
    name: string;
    status: string;
    detail: string;
    remediation?: string;
  }>;
  recommendedActions: string[];
  limitations: string[];
  engine: "llm" | "deterministic";
  model: string | null;
  transport: string | null;
  fallbackUsed: boolean;
  toolsUsed: string[];
  diagnostics: SystemDiagnostics | null;
}

export interface AgentRunResult {
  id: string;
  status: "completed" | "failed";
  durationMs: number;
  report: AgentReport;
  trace: AgentStepTrace[];
  attempts: AIAttempt[];
  error?: string;
}

const HARD_MAX_STEPS = 12;
const TOOL_RESULT_CHAR_LIMIT = 6000;
const MESSAGE_CHAR_LIMIT = 20_000;

function clampScore(value: unknown): number {
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.min(100, Math.max(0, Math.round(numeric)));
}

function isVerdict(value: unknown): value is AgentVerdict {
  return (
    value === "clean" ||
    value === "suspicious" ||
    value === "malicious" ||
    value === "phishing" ||
    value === "unverified"
  );
}

function asStringArray(value: unknown, limit = 12): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    .map((entry) => entry.trim())
    .slice(0, limit);
}

function describeToolResult(result: AgentToolResult): string {
  const payload = JSON.stringify(
    { ok: result.ok, summary: result.summary, data: result.data ?? null },
    null,
    0,
  );
  return payload.length > TOOL_RESULT_CHAR_LIMIT
    ? `${payload.slice(0, TOOL_RESULT_CHAR_LIMIT)}… [truncated]`
    : payload;
}

const LANGUAGE_NAMES: Record<string, string> = {
  en: "English",
  hi: "Hindi (Devanagari)",
  te: "Telugu",
};

export class AIAgentService {
  /**
   * Runs a bounded tool-using investigation. The model plans, calls real
   * application tools, and finally returns a structured report. If the model is
   * unavailable, the deterministic engine still produces a report from stored
   * data so the module never returns an empty screen.
   */
  async run(request: AgentRequest): Promise<AgentRunResult> {
    const startedAt = Date.now();
    const runId = randomUUID();
    const mode = request.mode ?? "investigate";
    const maxSteps = Math.max(1, Math.min(request.maxSteps ?? config.AI_AGENT_MAX_STEPS, HARD_MAX_STEPS));
    const language = request.language ?? "en";
    const trace: AgentStepTrace[] = [];
    const attempts: AIAttempt[] = [];

    logger.info("[agent] Run started", {
      runId,
      mode,
      goal: request.goal.slice(0, 200),
      brandId: request.brandId,
      targetUrl: request.targetUrl,
      maxSteps,
    });

    await this.persistRunStart(runId, request, mode);

    // Shallow diagnostics are cheap (no network calls) and give the model the
    // current module truth before it decides what to do.
    let diagnostics: SystemDiagnostics | null = null;
    try {
      diagnostics = await diagnosticsService.run({ deep: false });
    } catch (error) {
      logger.warn("[agent] Shallow diagnostics failed", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }

    let report: AgentReport;
    let error: string | undefined;

    if (!aiProvider.configured) {
      report = await this.deterministicReport(request, diagnostics, {
        reason:
          "The AI gateway is not configured (OPENAI_BASE_URL / OPENAI_API_KEY). This report was assembled directly from stored evidence.",
      });
    } else {
      try {
        report = await this.runWithModel({
          runId,
          request,
          mode,
          language,
          maxSteps,
          diagnostics,
          trace,
          attempts,
        });
      } catch (failure) {
        error =
          failure instanceof AIProviderError
            ? `${failure.code}: ${failure.message}`
            : failure instanceof Error
              ? failure.message
              : "Unknown agent error";

        logger.warn("[agent] LLM orchestration failed; using deterministic engine", {
          runId,
          error,
        });

        report = await this.deterministicReport(request, diagnostics, { reason: error });
      }
    }

    const durationMs = Date.now() - startedAt;
    const status = report.engine === "llm" || report.keyFindings.length > 0 ? "completed" : "failed";

    await this.persistRunComplete(runId, report, trace, durationMs, status, error);

    return {
      id: runId,
      status,
      durationMs,
      report,
      trace,
      attempts,
      ...(error ? { error } : {}),
    };
  }

  /**
   * Chat-style question answering with the same tool access. Used by the
   * "Ask the copilot" panel.
   */
  /**
   * Fast single-shot answer for the dashboard chat box.
   *
   * Unlike `run()`, this makes exactly one model call with a compact snapshot of
   * the workspace, so the widget answers in a few seconds instead of walking a
   * tool loop. It still degrades to a deterministic answer.
   */
  async chat(
    message: string,
    options: {
      brandId?: string;
      language?: "en" | "hi" | "te";
      history?: Array<{ role: "user" | "assistant"; content: string }>;
    } = {},
  ): Promise<{
    answer: string;
    keyPoints: string[];
    suggestedActions: string[];
    engine: "llm" | "deterministic";
    model: string | null;
    transport: string | null;
    latencyMs: number;
    context: Record<string, unknown>;
    notice: string | null;
  }> {
    const startedAt = Date.now();
    const language = options.language ?? "en";

    const context = await this.buildChatContext(options.brandId);

    if (!aiProvider.configured) {
      return {
        answer: this.deterministicChatAnswer(context),
        keyPoints: context.highlights,
        suggestedActions: context.nextSteps,
        engine: "deterministic",
        model: null,
        transport: null,
        latencyMs: Date.now() - startedAt,
        context,
        notice:
          "The AI gateway is not configured, so this answer is assembled directly from stored platform data.",
      };
    }

    const history = (options.history ?? [])
      .filter((entry) => entry && typeof entry.content === "string" && entry.content.trim())
      .slice(-6)
      .map((entry) => `${entry.role === "assistant" ? "Assistant" : "User"}: ${entry.content.slice(0, 800)}`)
      .join("\n");

    try {
      const result = await aiProvider.generate({
        purpose: "copilot-chat",
        temperature: 0.2,
        maxOutputTokens: 900,
        messages: [
          {
            role: "system",
            content: [
              "You are Find_out Copilot, the assistant inside a digital-risk-protection platform for brand impersonation.",
              `Answer in ${language === "hi" ? "Hindi" : language === "te" ? "Telugu" : "English"}.`,
              "Use ONLY the PLATFORM CONTEXT below. Never invent counts, brands, domains or module names.",
              "When a module is unavailable or not configured, say so plainly; never present it as working or as 'safe'.",
              "Be concrete and brief: 2-5 short sentences plus bullet points.",
              "When you quote a count of modules, use moduleCounts verbatim; never estimate or recount the list.",
              'Reply as strict JSON: {"answer": string, "keyPoints": string[], "suggestedActions": string[]}.',
            ].join("\n"),
          },
          {
            role: "user",
            content: `PLATFORM CONTEXT\n${JSON.stringify(context, null, 2)}\n\n${history ? `CONVERSATION SO FAR\n${history}\n\n` : ""}QUESTION: ${message}`,
          },
        ],
        jsonSchema: {
          name: "copilot_chat",
          strict: false,
          schema: {
            type: "object",
            properties: {
              answer: { type: "string" },
              keyPoints: { type: "array", items: { type: "string" } },
              suggestedActions: { type: "array", items: { type: "string" } },
            },
            required: ["answer"],
            additionalProperties: false,
          },
        },
      });

      const parsed = (result.parsed ?? extractJson(result.text)) as
        | { answer?: unknown; keyPoints?: unknown; suggestedActions?: unknown }
        | null;

      const answer =
        parsed && typeof parsed.answer === "string" && parsed.answer.trim()
          ? parsed.answer.trim()
          : result.text.trim().slice(0, 2000);

      return {
        answer: answer || this.deterministicChatAnswer(context),
        keyPoints: asStringArray(parsed?.keyPoints).slice(0, 6),
        suggestedActions: asStringArray(parsed?.suggestedActions).slice(0, 6),
        engine: "llm",
        model: result.model,
        transport: result.transport,
        latencyMs: Date.now() - startedAt,
        context,
        notice: result.fallbackUsed
          ? `Requested model was unavailable; answered with ${result.model}.`
          : null,
      };
    } catch (error) {
      const notice =
        error instanceof AIProviderError
          ? `The AI gateway rejected the request (${error.code}): ${error.message}`
          : error instanceof Error
            ? error.message
            : "The AI gateway could not be reached.";

      logger.warn("[agent] Copilot chat fell back to the deterministic answer", { notice });

      return {
        answer: this.deterministicChatAnswer(context),
        keyPoints: context.highlights,
        suggestedActions: context.nextSteps,
        engine: "deterministic",
        model: null,
        transport: null,
        latencyMs: Date.now() - startedAt,
        context,
        notice,
      };
    }
  }

  /** Compact, real snapshot used by the chat box. */
  private async buildChatContext(brandId?: string): Promise<{
    platform: string;
    brands: number;
    officialAssets: number;
    candidates: number;
    highRisk: number;
    excluded: number;
    topFindings: Array<{ name: string; source: string; risk: number; status: string }>;
    modules: Array<{ name: string; status: string; detail: string }>;
    moduleCounts: { total: number; working: number; notConfigured: number; failing: number };
    failingModules: string[];
    highlights: string[];
    nextSteps: string[];
  }> {
    const context = {
      platform: "Find_out digital risk protection",
      brands: 0,
      officialAssets: 0,
      candidates: 0,
      highRisk: 0,
      excluded: 0,
      topFindings: [] as Array<{ name: string; source: string; risk: number; status: string }>,
      modules: [] as Array<{ name: string; status: string; detail: string }>,
      moduleCounts: { total: 0, working: 0, notConfigured: 0, failing: 0 },
      failingModules: [] as string[],
      highlights: [] as string[],
      nextSteps: [] as string[],
    };

    try {
      const brands = await brandService.listBrands(100, 0);
      context.brands = brands.length;
      context.officialAssets = brands.reduce((total, brand) => {
        const assets = (brand as unknown as { assets?: unknown[] }).assets;
        return total + (Array.isArray(assets) ? assets.length : 0);
      }, 0);
    } catch {
      // Leave the counts at zero; the answer states that storage was unreadable.
    }

    try {
      const summary = await monitoringService.getCandidatesSummary(brandId);
      context.candidates = summary.total;
      context.highRisk = summary.highRisk;
      context.excluded = summary.excluded;

      const findings = await monitoringService.getCandidates(brandId, undefined, { limit: 5 });
      context.topFindings = findings.map((row) => ({
        name: String(row.name ?? row.identifier ?? "Unnamed"),
        source: String(row.source_type ?? row.platform ?? "unknown"),
        risk: Number(row.risk_score ?? 0),
        status: String(row.risk_level ?? "UNASSESSED"),
      }));
    } catch {
      // Same as above.
    }

    try {
      const diagnostics = await diagnosticsService.run({ deep: false });
      context.modules = diagnostics.modules.map((module) => ({
        name: module.name,
        status: module.status,
        detail: module.detail,
      }));
      // "degraded" covers two very different situations: configured but not yet
      // probed in this (shallow) sweep, and actually failing. Say which one, so
      // the model never reports a working source as broken.
      context.moduleCounts = {
        total: diagnostics.modules.length,
        working: diagnostics.modules.filter((module) => module.status === "ok").length,
        notConfigured: diagnostics.modules.filter((module) => module.status === "not_configured").length,
        failing: diagnostics.modules.filter((module) => module.status === "error").length,
      };

      context.failingModules = diagnostics.modules
        .filter((module) => module.status !== "ok")
        .map((module) => {
          const unprobed = /run a deep check/i.test(module.detail);
          return module.status === "degraded" && unprobed
            ? `${module.name} (configured, not probed in this sweep)`
            : `${module.name} (${module.status})`;
        });
    } catch {
      context.failingModules = ["System diagnostics could not be collected."];
    }

    context.highlights = [
      `${context.candidates} monitored candidate(s) stored, ${context.highRisk} high or critical, ${context.excluded} excluded as official.`,
      `${context.brands} brand profile(s) and ${context.officialAssets} registered official asset(s).`,
      context.failingModules.length > 0
        ? `Modules that are not fully working: ${context.failingModules.slice(0, 6).join(", ")}.`
        : "Every diagnostics module reported OK.",
    ];

    context.nextSteps = [];
    if (context.highRisk > 0) {
      context.nextSteps.push("Open Findings & Evidence and triage the high-risk candidates first.");
    }
    if (context.failingModules.some((module) => module.includes("not_configured"))) {
      context.nextSteps.push("Add the missing API keys in backend/.env so unconfigured sources can report.");
    }
    if (context.brands === 0) {
      context.nextSteps.push("Register a brand profile so monitoring and look-alike scoring have a reference.");
    }
    if (context.nextSteps.length === 0) {
      context.nextSteps.push("Run a monitoring scan to refresh the detection queue.");
    }

    return context;
  }

  private deterministicChatAnswer(context: {
    brands: number;
    officialAssets: number;
    candidates: number;
    highRisk: number;
    excluded: number;
    failingModules: string[];
  }): string {
    const parts = [
      `Right now the workspace holds ${context.candidates} monitored candidate(s) (${context.highRisk} high or critical, ${context.excluded} excluded as official) across ${context.brands} brand profile(s) with ${context.officialAssets} registered asset(s).`,
    ];

    if (context.failingModules.length > 0) {
      parts.push(`These modules are not fully working: ${context.failingModules.slice(0, 6).join(", ")}.`);
    } else {
      parts.push("Every diagnostics module reported OK on the last sweep.");
    }

    parts.push(
      "This answer was assembled from stored platform data because the AI gateway is not configured.",
    );

    return parts.join(" ");
  }

  async ask(question: string, options: { brandId?: string; language?: "en" | "hi" | "te" } = {}) {
    return this.run({
      goal: question,
      brandId: options.brandId,
      language: options.language ?? "en",
      mode: "ask",
      maxSteps: 4,
    });
  }

  private buildSystemPrompt(request: AgentRequest, language: string): string {
    return [
      "You are Find_out Copilot, the senior digital-risk analyst for the Find_out platform.",
      "You reason over real data returned by tools. You never invent findings, domains, or numbers.",
      "",
      "Operating rules:",
      "1. Call tools to gather evidence before concluding. Prefer system_diagnostics, list_brands, get_brand_overview, findings_summary and list_findings before making claims.",
      "2. If a source is unavailable or unconfigured, say so explicitly and mark the verdict 'unverified'. Never convert missing data into 'clean'.",
      "3. A 'clean' verdict requires that the threat-intelligence sources actually answered.",
      "4. Cite concrete evidence (names, URLs, scores, counts) in your findings.",
      "5. When the user asks about module health, use system_diagnostics and report every failing module with its remediation.",
      "6. Only call run_monitoring_scan or investigate_target when they are needed for the question; they are slow.",
      "7. Respond in " + (LANGUAGE_NAMES[language] ?? "English") + " for user-facing text, but keep JSON keys in English.",
      "",
      "Available tools:",
      toolCatalogForPrompt(),
      "",
      "Response protocol — reply with a single JSON object, no markdown:",
      "{",
      '  "thought": "short reasoning about the next step",',
      '  "tool": "tool_name or null",',
      '  "args": { },',
      '  "done": false,',
      '  "final": null',
      "}",
      "When you have enough evidence set done=true and provide:",
      "{",
      '  "done": true,',
      '  "final": {',
      '    "answer": "direct answer to the user",',
      '    "verdict": "clean|suspicious|malicious|phishing|unverified",',
      '    "riskScore": 0-100,',
      '    "confidenceScore": 0-100,',
      '    "summary": "2-4 sentence assessment",',
      '    "keyFindings": ["..."],',
      '    "recommendedActions": ["..."],',
      '    "limitations": ["..."]',
      "  }",
      "}",
    ].join("\n");
  }

  private initialUserMessage(request: AgentRequest, diagnostics: SystemDiagnostics | null): string {
    const context: string[] = [`Goal: ${request.goal}`];

    if (request.mode === "audit") {
      context.push(
        "Mode: full platform audit. Start with system_diagnostics (deep=true), then summarise every module that fails and exactly how to fix it.",
      );
    }
    if (request.brandId) context.push(`Brand id supplied by the user: ${request.brandId}`);
    if (request.targetUrl) context.push(`Target supplied by the user: ${request.targetUrl}`);

    if (diagnostics) {
      context.push(
        "",
        "Current shallow diagnostics (no network calls):",
        diagnostics.modules
          .map((module) => `- ${module.id}: ${module.status} — ${module.detail}`)
          .join("\n"),
      );
    }

    return context.join("\n");
  }

  private async runWithModel(params: {
    runId: string;
    request: AgentRequest;
    mode: "investigate" | "ask" | "audit";
    language: string;
    maxSteps: number;
    diagnostics: SystemDiagnostics | null;
    trace: AgentStepTrace[];
    attempts: AIAttempt[];
  }): Promise<AgentReport> {
    const { runId, request, mode, language, maxSteps, diagnostics, trace, attempts } = params;

    const messages: AIMessage[] = [
      { role: "system", content: this.buildSystemPrompt(request, language) },
      { role: "user", content: this.initialUserMessage(request, diagnostics) },
    ];

    let usedTools: string[] = [];

    for (let step = 1; step <= maxSteps; step += 1) {
      const result = await aiProvider.generate({
        messages,
        purpose: `agent-step-${step}`,
        temperature: 0.1,
        jsonSchema: {
          name: "agent_step",
          strict: false,
          schema: {
            type: "object",
            properties: {
              // Empty string / empty object mean "not used". Union type
              // arrays break the gateway's JSON Schema validator.
              thought: { type: "string" },
              tool: { type: "string", description: "Tool name, or an empty string when finished." },
              args: { type: "object", additionalProperties: true },
              done: { type: "boolean" },
              final: {
                type: "object",
                additionalProperties: true,
                description: "Final report payload, or an empty object while still working.",
              },
            },
            required: ["thought", "done"],
            additionalProperties: true,
          },
        },
      });

      attempts.push(...result.attempts);

      const plan = (result.parsed ?? extractJson(result.text)) as
        | {
            thought?: unknown;
            tool?: unknown;
            args?: unknown;
            done?: unknown;
            final?: unknown;
          }
        | null;

      if (!plan || typeof plan !== "object") {
        messages.push({ role: "assistant", content: result.text.slice(0, 2000) });
        messages.push({
          role: "user",
          content:
            "Your previous reply was not valid JSON. Reply again with the JSON protocol only.",
        });
        continue;
      }

      const thought = typeof plan.thought === "string" ? plan.thought : "";
      const done = plan.done === true;
      const toolName = typeof plan.tool === "string" && plan.tool.trim() ? plan.tool.trim() : null;
      const args =
        plan.args && typeof plan.args === "object" && !Array.isArray(plan.args)
          ? (plan.args as Record<string, unknown>)
          : {};

      if (done) {
        const report = this.reportFromFinal({
          request,
          mode,
          final: plan.final,
          diagnostics,
          trace,
          usedTools,
          model: result.model,
          transport: result.transport,
          fallbackUsed: result.fallbackUsed,
        });

        await this.persistMessage(runId, step, "assistant", result.text, null, null);
        return report;
      }

      if (!toolName) {
        messages.push({ role: "assistant", content: JSON.stringify({ thought }) });
        messages.push({
          role: "user",
          content: "No tool was requested and done=false. Either call a tool now or finish with done=true.",
        });
        continue;
      }

      const toolResult = await executeTool(toolName, args);
      usedTools = [...new Set([...usedTools, toolName])];

      trace.push({
        step,
        thought,
        tool: toolName,
        args,
        ok: toolResult.ok,
        summary: toolResult.summary,
        durationMs: toolResult.durationMs,
      });

      await this.persistMessage(runId, step, "tool", thought, toolName, toolResult);

      messages.push({
        role: "assistant",
        content: JSON.stringify({ thought, tool: toolName, args, done: false }),
      });
      messages.push({
        role: "user",
        content: `TOOL RESULT (${toolName}):\n${describeToolResult(toolResult)}\n\nContinue. Call another tool or finish with done=true.`,
      });

      if (messages.length > 24) {
        // Keep the system prompt plus the most recent exchanges.
        messages.splice(1, messages.length - 18);
      }
    }

    // Step budget exhausted: ask for a final report from what has been gathered.
    messages.push({
      role: "user",
      content:
        "Step budget exhausted. Do not call more tools. Return your final JSON report now using the evidence already collected, and list what remains unverified in limitations.",
    });

    const finalResult = await aiProvider.generate({
      messages,
      purpose: "agent-final",
      temperature: 0,
      jsonSchema: {
        name: "agent_final",
        strict: false,
        schema: {
          type: "object",
          properties: {
            done: { type: "boolean" },
            final: { type: "object" },
          },
          required: ["final"],
          additionalProperties: true,
        },
      },
    });

    attempts.push(...finalResult.attempts);
    const finalPlan = (finalResult.parsed ?? extractJson(finalResult.text)) as
      | { final?: unknown }
      | null;

    return this.reportFromFinal({
      request,
      mode,
      final: finalPlan?.final,
      diagnostics,
      trace,
      usedTools,
      model: finalResult.model,
      transport: finalResult.transport,
      fallbackUsed: finalResult.fallbackUsed,
    });
  }

  private reportFromFinal(params: {
    request: AgentRequest;
    mode: "investigate" | "ask" | "audit";
    final: unknown;
    diagnostics: SystemDiagnostics | null;
    trace: AgentStepTrace[];
    usedTools: string[];
    model: string;
    transport: string;
    fallbackUsed: boolean;
  }): AgentReport {
    const final =
      params.final && typeof params.final === "object"
        ? (params.final as Record<string, unknown>)
        : {};

    const verdict = isVerdict(final.verdict) ? final.verdict : "unverified";
    const modules = this.moduleStatus(params.diagnostics);
    const failing = modules.filter((module) => module.status === "error");
    const notConfigured = modules.filter((module) => module.status === "not_configured");
    const degraded = modules.filter((module) => module.status === "degraded");

    // A model can return done=true with an empty payload. Never surface an
    // empty report: rebuild the narrative from the diagnostics it was given.
    const synthesized: string[] = [];
    if (modules.length > 0) {
      synthesized.push(
        `${modules.filter((module) => module.status === "ok").length}/${modules.length} modules are healthy, ` +
          `${degraded.length} degraded, ${notConfigured.length} not configured, ${failing.length} failing.`,
      );
      for (const module of [...failing, ...degraded]) {
        synthesized.push(`${module.name}: ${module.status} — ${module.detail}`);
      }
      for (const module of notConfigured) {
        synthesized.push(`${module.name}: not configured — ${module.detail}`);
      }
    }
    const toolSummary = params.trace
      .filter((step) => step.tool)
      .map((step) => `${step.tool}: ${step.ok ? "ok" : "failed"}`);

    const keyFindings =
      asStringArray(final.keyFindings).length > 0
        ? asStringArray(final.keyFindings)
        : synthesized.slice(0, 8);

    const answer =
      typeof final.answer === "string" && final.answer.trim()
        ? final.answer.trim()
        : typeof final.summary === "string" && final.summary.trim()
          ? final.summary.trim()
          : synthesized.length > 0
            ? synthesized.join("\n")
            : "The agent completed its analysis but the model returned no narrative.";

    return {
      goal: params.request.goal,
      mode: params.mode,
      answer,
      verdict,
      riskScore: clampScore(final.riskScore),
      confidenceScore: clampScore(final.confidenceScore),
      summary:
        typeof final.summary === "string" && final.summary.trim()
          ? final.summary.trim()
          : (synthesized[0] ?? "No summary was supplied by the model."),
      keyFindings,
      moduleStatus: this.moduleStatus(params.diagnostics),
      recommendedActions: asStringArray(final.recommendedActions),
      limitations:
        asStringArray(final.limitations).length > 0
          ? asStringArray(final.limitations)
          : this.defaultLimitations(params.diagnostics),
      engine: "llm",
      model: params.model,
      transport: params.transport,
      fallbackUsed: params.fallbackUsed,
      toolsUsed: params.usedTools.length > 0 ? params.usedTools : toolSummary,
      diagnostics: params.diagnostics,
    };
  }

  private moduleStatus(diagnostics: SystemDiagnostics | null): AgentReport["moduleStatus"] {
    if (!diagnostics) return [];
    return diagnostics.modules.map((module: ModuleDiagnostic) => ({
      id: module.id,
      name: module.name,
      status: module.status,
      detail: module.detail,
      ...(module.remediation ? { remediation: module.remediation } : {}),
    }));
  }

  private defaultLimitations(diagnostics: SystemDiagnostics | null): string[] {
    const limitations: string[] = [];

    if (!diagnostics) {
      limitations.push("Module diagnostics could not be collected during this run.");
    } else {
      for (const module of diagnostics.modules) {
        if (module.status === "error" || module.status === "not_configured") {
          limitations.push(`${module.name}: ${module.detail}`);
        }
      }
    }

    limitations.push(
      "Public social posts and marketplace listings are unverified leads until a human confirms ownership.",
    );

    return limitations.slice(0, 10);
  }

  /**
   * Rule-based report built from stored evidence. Used when the model cannot be
   * reached, so the UI always receives something defensible.
   */
  private async deterministicReport(
    request: AgentRequest,
    diagnostics: SystemDiagnostics | null,
    options: { reason: string },
  ): Promise<AgentReport> {
    const keyFindings: string[] = [];
    const limitations: string[] = [options.reason];
    const toolsUsed: string[] = [];
    let verdict: AgentVerdict = "unverified";
    let riskScore = 0;
    let confidenceScore = 0;
    let summary = "";

    try {
      if (request.brandId) {
        const brand = await brandService.getBrandById(request.brandId);
        if (brand) {
          const counters = await monitoringService.getCandidatesSummary(request.brandId);
          keyFindings.push(
            `Brand "${brand.name}" has ${counters.total} stored candidates, ${counters.highRisk} high-risk, ${counters.excluded} official exclusions.`,
          );
          riskScore = counters.highRisk > 0 ? 70 : riskScore;
          verdict = counters.highRisk > 0 ? "suspicious" : "unverified";
          confidenceScore = counters.total > 0 ? 45 : 20;
          toolsUsed.push("findings_summary");
        } else {
          limitations.push(`Brand ${request.brandId} was not found.`);
        }
      }

      if (request.targetUrl) {
        // The protected brand is resolved inside runInvestigation from brandId.
        // Never pass the user's goal as a brand name: doing so silently scored
        // the target against a sentence.
        const investigation = await investigationService.runInvestigation({
          targetUrl: request.targetUrl,
          ...(request.brandId ? { brandId: request.brandId } : {}),
        });
        toolsUsed.push("investigate_target");
        verdict = isVerdict(investigation.verdict) ? investigation.verdict : "unverified";
        riskScore = Number(investigation.risk_score) || 0;
        confidenceScore = Number(investigation.confidence_score) || 0;
        keyFindings.push(
          `Investigation of ${request.targetUrl}: verdict ${investigation.verdict.toUpperCase()}, risk ${investigation.risk_score}/100, confidence ${investigation.confidence_score}%.`,
        );
        if (investigation.summary) summary = investigation.summary;
      }
    } catch (error) {
      limitations.push(
        `Deterministic analysis could not complete: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }

    if (diagnostics) {
      const failing = diagnostics.modules.filter(
        (module) => module.status === "error" || module.status === "not_configured",
      );
      for (const module of failing.slice(0, 8)) {
        keyFindings.push(`${module.name}: ${module.status} — ${module.detail}`);
      }
      if (failing.length > 0) toolsUsed.push("system_diagnostics");
    }

    if (!summary) {
      summary =
        keyFindings.length > 0
          ? `Deterministic assessment produced ${keyFindings.length} evidence point(s). The AI model could not be used: ${options.reason}`
          : `No evidence could be assembled. ${options.reason}`;
    }

    if (verdict === "clean") {
      // A deterministic run can never assert safety.
      verdict = "unverified";
    }

    return {
      goal: request.goal,
      mode: request.mode ?? "investigate",
      answer: summary,
      verdict,
      riskScore: clampScore(riskScore),
      confidenceScore: clampScore(confidenceScore),
      summary,
      keyFindings,
      moduleStatus: this.moduleStatus(diagnostics),
      recommendedActions: [
        "Review the failing modules listed in the findings and apply the suggested remediation.",
        "Re-run the investigation once the AI gateway or missing source keys are configured.",
      ],
      limitations,
      engine: "deterministic",
      model: null,
      transport: null,
      fallbackUsed: true,
      toolsUsed: [...new Set(toolsUsed)],
      diagnostics,
    };
  }

  private async persistRunStart(
    runId: string,
    request: AgentRequest,
    mode: string,
  ): Promise<void> {
    try {
      await query(
        `INSERT INTO agent_runs (id, goal, mode, status, brand_id, target)
         VALUES ($1, $2, $3, 'running', $4, $5);`,
        [
          runId,
          request.goal.slice(0, 4000),
          mode,
          request.brandId ?? null,
          request.targetUrl ?? null,
        ],
      );
    } catch (error) {
      logger.warn("[agent] Could not persist run start", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  private async persistMessage(
    runId: string,
    step: number,
    role: string,
    content: string,
    toolName: string | null,
    toolResult: AgentToolResult | null,
  ): Promise<void> {
    try {
      await query(
        `INSERT INTO agent_messages (run_id, step, role, content, tool_name, tool_result)
         VALUES ($1, $2, $3, $4, $5, $6);`,
        [
          runId,
          step,
          role,
          content.slice(0, MESSAGE_CHAR_LIMIT),
          toolName,
          toolResult ? JSON.stringify(toolResult) : null,
        ],
      );
    } catch (error) {
      logger.warn("[agent] Could not persist message", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  private async persistRunComplete(
    runId: string,
    report: AgentReport,
    trace: AgentStepTrace[],
    durationMs: number,
    status: string,
    error?: string,
  ): Promise<void> {
    try {
      await query(
        `UPDATE agent_runs
         SET status = $2,
             model = $3,
             transport = $4,
             steps = $5,
             duration_ms = $6,
             verdict = $7,
             risk_score = $8,
             confidence = $9,
             engine = $10,
             report = $11,
             trace = $12,
             error = $13,
             completed_at = NOW()
         WHERE id = $1;`,
        [
          runId,
          status,
          report.model,
          report.transport,
          trace.length,
          durationMs,
          report.verdict,
          report.riskScore,
          report.confidenceScore,
          report.engine,
          JSON.stringify(report),
          JSON.stringify(trace),
          error ?? null,
        ],
      );
    } catch (persistError) {
      logger.warn("[agent] Could not persist run completion", {
        error: persistError instanceof Error ? persistError.message : "unknown",
      });
    }
  }

  async listRuns(limit = 20): Promise<Array<Record<string, unknown>>> {
    const result = await query(
      `SELECT id, goal, mode, status, model, transport, engine, verdict, risk_score,
              confidence, steps, duration_ms, created_at, completed_at
       FROM agent_runs ORDER BY created_at DESC LIMIT $1;`,
      [Math.max(1, Math.min(limit, 100))],
    );
    return result.rows;
  }

  async getRun(id: string): Promise<Record<string, unknown> | null> {
    const result = await query(`SELECT * FROM agent_runs WHERE id = $1;`, [id]);
    const row = result.rows[0];
    if (!row) return null;

    const messages = await query(
      `SELECT step, role, content, tool_name, tool_result, created_at
       FROM agent_messages WHERE run_id = $1 ORDER BY step ASC, created_at ASC;`,
      [id],
    );

    return { ...row, messages: messages.rows };
  }
}

export const aiAgentService = new AIAgentService();
export default aiAgentService;
