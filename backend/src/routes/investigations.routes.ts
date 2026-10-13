import { Router, type Request, type Response } from "express";
import { investigationService } from "../investigations";
import { aiService } from "../ai";
import { reportsService } from "../reports";
import { logger } from "../utils/logger";
import { query } from "../db";
import { urlSafetyEngine } from "../url-safety";
import { EvidenceRepository } from "../repositories";

export const investigationsRouter = Router();

investigationsRouter.post("/inspect", async (req: Request, res: Response) => {
  const suppliedTarget = typeof req.body?.target === "string" ? req.body.target.trim() : "";
  if (!suppliedTarget || suppliedTarget.length > 2048) {
    res.status(400).json({
      success: false,
      error: "A target URL or domain (up to 2048 characters) is required.",
    });
    return;
  }

  const target = /^https?:\/\//i.test(suppliedTarget)
    ? suppliedTarget
    : `https://${suppliedTarget}`;
  const validation = urlSafetyEngine.validateTargetUrl(target);
  if (validation.blocked) {
    res.status(400).json({
      success: false,
      error: validation.reason ?? "This target is not allowed.",
    });
    return;
  }

  try {
    const investigation = await investigationService.runInvestigation({
      targetUrl: target,
      title: `User-submitted investigation: ${validation.hostname}`,
    });
    const evidence = await EvidenceRepository.findByInvestigationId(investigation.id);
    const verdict = investigation.verdict.toLowerCase();
    res.status(201).json({
      success: true,
      data: {
        id: investigation.id,
        target: investigation.target_url,
        target_type: "web",
        verdict: verdict === "clean" ? "SAFE" : verdict.toUpperCase(),
        risk_score: investigation.risk_score,
        confidence_score: investigation.confidence_score,
        summary: investigation.summary,
        safe_browsing_status: "See source evidence; unavailable sources are not treated as clean.",
        urlhaus_status: "See source evidence; unavailable sources are not treated as clean.",
        details: { metadata: investigation.metadata, evidence },
      },
    });
  } catch (error) {
    logger.error("[investigations.routes] User-submitted investigation failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Investigation failed.",
    });
  }
});

// ==========================================
// 1. Investigation Lifecycle Management
// ==========================================

investigationsRouter.post("/", async (req: Request, res: Response) => {
  try {
    const { brandId, targetUrl, title } = req.body;

    if (!brandId || !targetUrl) {
      res.status(400).json({
        success: false,
        error: "Missing required parameters: 'brandId' and 'targetUrl' are mandatory",
      });
      return;
    }

    // Executes the pipeline investigation lifecycle
    const investigation = await investigationService.runInvestigation({
      brandId: String(brandId),
      targetUrl: String(targetUrl).trim(),
      title: title ? String(title).trim() : undefined,
    });

    res.status(201).json({
      success: true,
      data: investigation,
    });
  } catch (error) {
    logger.error("[investigations.routes] Failed to initiate investigation", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to run investigation",
    });
  }
});

investigationsRouter.get("/", async (req: Request, res: Response) => {
  try {
    const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 50;
    const offset = typeof req.query.offset === "string" ? parseInt(req.query.offset, 10) : 0;

    const investigations = await investigationService.listInvestigations(limit, offset);
    res.json({
      success: true,
      count: investigations.length,
      data: investigations,
    });
  } catch (error) {
    logger.error("[investigations.routes] Failed to list investigations", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve investigations",
    });
  }
});

investigationsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Investigation ID is required" });
      return;
    }

    const investigation = await investigationService.getInvestigationById(String(id));
    if (!investigation) {
      res.status(404).json({ success: false, error: "Investigation not found" });
      return;
    }

    res.json({
      success: true,
      data: investigation,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve investigation",
    });
  }
});

investigationsRouter.patch("/:id/verdict", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { verdict, riskScore, confidenceScore, summary } = req.body;

    if (!id || !verdict) {
      res.status(400).json({
        success: false,
        error: "Investigation ID and verdict are required",
      });
      return;
    }

    const resDb = await query(
      `UPDATE investigations
       SET verdict = $2,
           risk_score = COALESCE($3, risk_score),
           confidence_score = COALESCE($4, confidence_score),
           summary = COALESCE($5, summary),
           status = 'completed',
           updated_at = NOW()
       WHERE id = $1
       RETURNING *;`,
      [
        String(id),
        String(verdict),
        typeof riskScore === "number" ? riskScore : null,
        typeof confidenceScore === "number" ? confidenceScore : null,
        summary ? String(summary) : null,
      ]
    );

    const updated = resDb.rows[0];
    if (!updated) {
      res.status(404).json({ success: false, error: "Investigation not found" });
      return;
    }

    res.json({
      success: true,
      data: updated,
    });
  } catch (error) {
    logger.error("[investigations.routes] Failed to update verdict", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to update verdict",
    });
  }
});

// ==========================================
// 2. AI Threat Analysis & Evidence Endpoints
// ==========================================

investigationsRouter.post("/:id/ai-analyze", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Investigation ID is required" });
      return;
    }

    const investigation = await investigationService.getInvestigationById(String(id));
    if (!investigation) {
      res.status(404).json({ success: false, error: "Investigation not found" });
      return;
    }

    if (!investigation.target_url) {
      res.status(400).json({
        success: false,
        error: "Cannot run AI threat analysis: target URL is not defined",
      });
      return;
    }

    const aiVerdict = await aiService.evaluateImpersonation({
      targetUrl: investigation.target_url,
      investigationId: investigation.id,
      contextSummary: investigation.summary ?? undefined,
    });

    const resDb = await query(
      `UPDATE investigations
       SET verdict = $2,
           risk_score = $3,
           confidence_score = $4,
           summary = $5,
           status = 'completed',
           updated_at = NOW()
       WHERE id = $1
       RETURNING *;`,
      [
        investigation.id,
        aiVerdict.isImpersonating ? "malicious" : "clean",
        aiVerdict.isImpersonating ? aiVerdict.confidenceScore : 10,
        aiVerdict.confidenceScore,
        aiVerdict.reasoning,
      ]
    );

    res.json({
      success: true,
      data: {
        investigation: resDb.rows[0],
        aiVerdict,
      },
    });
  } catch (error) {
    logger.error("[investigations.routes] AI analysis trigger failed", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "AI evaluation execution failed",
    });
  }
});

investigationsRouter.get("/:id/evidence", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Investigation ID is required" });
      return;
    }

    const result = await query(
      `SELECT * FROM evidence_items WHERE investigation_id = $1 ORDER BY created_at ASC;`,
      [String(id)]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to fetch evidence items",
    });
  }
});

investigationsRouter.get("/:id/dossier", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Investigation ID is required" });
      return;
    }

    const dossier = await reportsService.buildDossier(String(id));
    res.json({
      success: true,
      data: dossier,
    });
  } catch (error) {
    res.status(404).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to compile dossier",
    });
  }
});

export default investigationsRouter;