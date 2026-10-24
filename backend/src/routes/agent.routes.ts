import { Router, type Request, type Response } from "express";

import { aiAgentService } from "../ai-agent/agent";
import { aiProvider } from "../ai-agent/provider";
import { diagnosticsService } from "../ai-agent/diagnostics";
import { agentTools } from "../ai-agent/tools";
import { logger } from "../utils/logger";
import { rateLimiter } from "../middleware";
import { config } from "../config";

export const agentRouter = Router();

const agentLimiter = rateLimiter(20, 60_000);

function readString(body: unknown, key: string, max = 4000): string {
  if (typeof body !== "object" || body === null) return "";
  const value = (body as Record<string, unknown>)[key];
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

agentRouter.get("/status", async (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      enabled: config.AI_AGENT_ENABLED,
      agent: {
        provider: aiProvider.status,
        maxSteps: config.AI_AGENT_MAX_STEPS,
        timeoutMs: config.AI_AGENT_TIMEOUT_MS,
        maxOutputTokens: config.AI_AGENT_MAX_OUTPUT_TOKENS,
      },
      tools: agentTools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        readOnly: tool.readOnly,
      })),
    },
  });
});

agentRouter.get("/diagnostics", agentLimiter, async (req: Request, res: Response) => {
  const deep = req.query.deep !== "0";
  try {
    const diagnostics = await diagnosticsService.run({ deep });
    res.json({ success: true, data: diagnostics });
  } catch (error) {
    logger.error("[agent.routes] Diagnostics failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Diagnostics failed.",
    });
  }
});

agentRouter.post("/run", agentLimiter, async (req: Request, res: Response) => {
  const goal = readString(req.body, "goal", 2000);
  if (!goal) {
    res.status(400).json({
      success: false,
      error: "A goal is required, for example: 'Audit the platform and tell me what is broken'.",
    });
    return;
  }

  if (!config.AI_AGENT_ENABLED) {
    res.status(503).json({
      success: false,
      error: "The AI agent is disabled (AI_AGENT_ENABLED=false).",
    });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  const mode = body.mode === "ask" || body.mode === "audit" ? body.mode : "investigate";
  const language = body.language === "hi" || body.language === "te" ? body.language : "en";
  const maxSteps =
    typeof body.maxSteps === "number" && Number.isFinite(body.maxSteps)
      ? Math.max(1, Math.min(Math.round(body.maxSteps), 12))
      : undefined;

  try {
    const result = await aiAgentService.run({
      goal,
      mode,
      language,
      ...(readString(req.body, "brandId", 64) ? { brandId: readString(req.body, "brandId", 64) } : {}),
      ...(readString(req.body, "targetUrl", 2048)
        ? { targetUrl: readString(req.body, "targetUrl", 2048) }
        : {}),
      ...(maxSteps ? { maxSteps } : {}),
    });

    res.status(result.status === "completed" ? 200 : 500).json({
      success: result.status === "completed",
      data: result,
    });
  } catch (error) {
    logger.error("[agent.routes] Agent run failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Agent run failed.",
    });
  }
});

/**
 * Dashboard chat box. One fast model call over a live platform snapshot; falls
 * back to a deterministic answer and always reports which engine answered.
 */
agentRouter.post("/chat", agentLimiter, async (req: Request, res: Response) => {
  const message = readString(req.body, "message", 2000) || readString(req.body, "question", 2000);
  if (!message) {
    res.status(400).json({ success: false, error: "A message is required." });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  const language = body.language === "hi" || body.language === "te" ? body.language : "en";
  const history = Array.isArray(body.history)
    ? (body.history as unknown[])
        .filter(
          (entry): entry is { role: "user" | "assistant"; content: string } =>
            typeof entry === "object" &&
            entry !== null &&
            (((entry as Record<string, unknown>).role === "user") ||
              ((entry as Record<string, unknown>).role === "assistant")) &&
            typeof (entry as Record<string, unknown>).content === "string",
        )
        .slice(-8)
    : [];

  try {
    const result = await aiAgentService.chat(message, {
      language,
      history: history.map((entry) => ({
        role: entry.role,
        content: entry.content.slice(0, 2000),
      })),
      ...(readString(req.body, "brandId", 64) ? { brandId: readString(req.body, "brandId", 64) } : {}),
    });

    res.json({ success: true, data: { ...result, engine: result.engine } });
  } catch (error) {
    logger.error("[agent.routes] Copilot chat failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "The assistant could not answer.",
    });
  }
});

agentRouter.post("/ask", agentLimiter, async (req: Request, res: Response) => {
  const question = readString(req.body, "question", 2000);
  if (!question) {
    res.status(400).json({ success: false, error: "A question is required." });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  const language = body.language === "hi" || body.language === "te" ? body.language : "en";

  try {
    const result = await aiAgentService.ask(question, {
      language,
      ...(readString(req.body, "brandId", 64) ? { brandId: readString(req.body, "brandId", 64) } : {}),
    });

    res.json({ success: true, data: result });
  } catch (error) {
    logger.error("[agent.routes] Agent question failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Agent question failed.",
    });
  }
});

agentRouter.get("/runs", async (req: Request, res: Response) => {
  try {
    const limit = typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 20;
    const runs = await aiAgentService.listRuns(Number.isFinite(limit) ? limit : 20);
    res.json({ success: true, count: runs.length, data: runs });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not list agent runs.",
    });
  }
});

agentRouter.get("/runs/:id", async (req: Request, res: Response) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!id) {
    res.status(400).json({ success: false, error: "A run id is required." });
    return;
  }

  try {
    const run = await aiAgentService.getRun(id);
    if (!run) {
      res.status(404).json({ success: false, error: "Agent run not found." });
      return;
    }
    res.json({ success: true, data: run });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not load the agent run.",
    });
  }
});

export default agentRouter;
