import { Router, type Request, type Response } from "express";
import { investigationService } from "../investigations";
import { aiService } from "../ai";
import { reportsService } from "../reports";
import { logger } from "../utils/logger";
import { query } from "../db";
import {
  normalizeTargetUrl,
  urlSafetyEngine,
} from "../url-safety";
import { EvidenceRepository } from "../repositories";

export const investigationsRouter = Router();

investigationsRouter.post("/inspect", async (req: Request, res: Response) => {
  const suppliedTarget =
    typeof req.body?.target === "string" ? req.body.target.trim() : "";

  if (!suppliedTarget || suppliedTarget.length > 2048) {
    res.status(400).json({
      success: false,
      error: "A target URL or domain (up to 2048 characters) is required.",
    });
    return;
  }

  let target: string;

  try {
    target = normalizeTargetUrl(suppliedTarget);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : "Invalid target URL.",
    });
    return;
  }

  const validation = urlSafetyEngine.validateTargetUrl(target);

  if (validation.blocked) {
    res.status(400).json({
      success: false,
      error: validation.reason ?? "This target is not allowed.",
    });
    return;
  }

  const brandId = typeof req.body?.brandId === "string" && req.body.brandId.trim()
    ? req.body.brandId.trim()
    : undefined;
  const brandName = typeof req.body?.brandName === "string" && req.body.brandName.trim()
    ? req.body.brandName.trim()
    : undefined;

  try {
    const investigation = await investigationService.runInvestigation({
      targetUrl: target,
      title: `User-submitted investigation: ${validation.hostname}`,
      ...(brandId ? { brandId } : {}),
      ...(brandName ? { brandName } : {}),
    });

    const evidence = await EvidenceRepository.findByInvestigationId(
      investigation.id
    );

    const metadata = (investigation.metadata ?? {}) as Record<string, unknown>;
    const verdict = investigation.verdict.toLowerCase();
    const sbEvidence = evidence.find((e) => e.source === "safebrowsing");
    const uhEvidence = evidence.find((e) => e.source === "urlhaus");

    const formatSourceStatus = (item: typeof sbEvidence, label: string) => {
      if (!item) return `${label}: Not queried (target excluded or skipped).`;
      const status = item.raw_payload?.sourceStatus;
      if (status === "unavailable") {
        return `${label}: Unavailable (${item.extracted_claim ?? "source unreachable"}).`;
      }
      return item.is_verified
        ? `${label}: Threat match detected.`
        : `${label}: Available — 0 threat matches returned.`;
    };

    res.status(201).json({
      success: true,
      data: {
        id: investigation.id,
        target: investigation.target_url,
        target_type: "web",
        verdict: verdict === "clean" ? "SAFE" : verdict.toUpperCase(),
        // The single number an analyst reads first.
        overall_risk_score: Number(investigation.risk_score ?? 0),
        risk_score: investigation.risk_score,
        confidence_score: investigation.confidence_score,
        summary: investigation.summary,
        // Plain-English, ordered statements derived from stored evidence.
        evidence_narrative: Array.isArray(metadata.evidenceNarrative)
          ? metadata.evidenceNarrative
          : [],
        risk_factors: Array.isArray(metadata.factors) ? metadata.factors : [],
        brand_impersonation: metadata.brandImpersonation ?? null,
        high_risk_flags: Array.isArray(metadata.highRiskFlags) ? metadata.highRiskFlags : [],
        coverage: typeof metadata.coverage === "number" ? metadata.coverage : null,
        escalation: typeof metadata.escalation === "string" ? metadata.escalation : null,
        source_statuses: metadata.sourceStatuses ?? {},
        safe_browsing_status: formatSourceStatus(
          sbEvidence,
          "Google Safe Browsing"
        ),
        urlhaus_status: formatSourceStatus(uhEvidence, "URLhaus"),
        details: {
          metadata: investigation.metadata,
          evidence,
        },
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

// Investigation lifecycle management
investigationsRouter.post("/", async (req: Request, res: Response) => {
  try {
    const { brandId, targetUrl, title } = req.body ?? {};

    if (
      !brandId ||
      typeof targetUrl !== "string" ||
      !targetUrl.trim()
    ) {
      res.status(400).json({
        success: false,
        error:
          "Missing required parameters: 'brandId' and 'targetUrl' are mandatory.",
      });
      return;
    }

    let normalizedTarget: string;

    try {
      normalizedTarget = normalizeTargetUrl(targetUrl);
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : "Invalid target URL.",
      });
      return;
    }

    const validation =
      urlSafetyEngine.validateTargetUrl(normalizedTarget);

    if (validation.blocked) {
      res.status(400).json({
        success: false,
        error: validation.reason ?? "This target is not allowed.",
      });
      return;
    }

    const investigation = await investigationService.runInvestigation({
      brandId: String(brandId),
      targetUrl: normalizedTarget,
      title: title ? String(title).trim() : undefined,
    });

    res.status(201).json({
      success: true,
      data: investigation,
    });
  } catch (error) {
    logger.error(
      "[investigations.routes] Failed to initiate investigation",
      {
        error: error instanceof Error ? error.message : "Unknown error",
      }
    );

    res.status(500).json({
      success: false,
      error:
        error instanceof Error ? error.message : "Failed to run investigation",
    });
  }
});

investigationsRouter.get("/", async (req: Request, res: Response) => {
  try {
    const limit =
      typeof req.query.limit === "string"
        ? parseInt(req.query.limit, 10)
        : 50;

    const offset =
      typeof req.query.offset === "string"
        ? parseInt(req.query.offset, 10)
        : 0;

    const investigations = await investigationService.listInvestigations(
      limit,
      offset
    );

    res.json({
      success: true,
      count: investigations.length,
      data: investigations,
    });
  } catch (error) {
    logger.error("[investigations.routes] Failed to list investigations", {
      error: error instanceof Error ? error.message : "Unknown error",
    });

    res.status(500).json({
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Failed to retrieve investigations",
    });
  }
});

investigationsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id)
      ? req.params.id[0]
      : req.params.id;

    if (!id) {
      res.status(400).json({
        success: false,
        error: "Investigation ID is required",
      });
      return;
    }

    const investigation =
      await investigationService.getInvestigationById(String(id));

    if (!investigation) {
      res.status(404).json({
        success: false,
        error: "Investigation not found",
      });
      return;
    }

    // Include the analysis the UI renders: overall score, factors, readable
    // evidence. Everything comes from the stored investigation metadata.
    const meta = (investigation.metadata ?? {}) as Record<string, unknown>;

    res.json({
      success: true,
      data: {
        ...investigation,
        overall_risk_score: Number(investigation.risk_score ?? 0),
        evidence_narrative: Array.isArray(meta.evidenceNarrative) ? meta.evidenceNarrative : [],
        risk_factors: Array.isArray(meta.factors) ? meta.factors : [],
        brand_impersonation: meta.brandImpersonation ?? null,
        high_risk_flags: Array.isArray(meta.highRiskFlags) ? meta.highRiskFlags : [],
        source_statuses: meta.sourceStatuses ?? {},
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Failed to retrieve investigation",
    });
  }
});

investigationsRouter.patch(
  "/:id/verdict",
  async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id)
        ? req.params.id[0]
        : req.params.id;

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
        res.status(404).json({
          success: false,
          error: "Investigation not found",
        });
        return;
      }

      res.json({
        success: true,
        data: updated,
      });
    } catch (error) {
      logger.error("[investigations.routes] Failed to update verdict", {
        error: error instanceof Error ? error.message : "Unknown error",
      });

      res.status(500).json({
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Failed to update verdict",
      });
    }
  }
);

// AI threat analysis
investigationsRouter.post(
  "/:id/ai-analyze",
  async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id)
        ? req.params.id[0]
        : req.params.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: "Investigation ID is required",
        });
        return;
      }

      const investigation =
        await investigationService.getInvestigationById(String(id));

      if (!investigation) {
        res.status(404).json({
          success: false,
          error: "Investigation not found",
        });
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
          aiVerdict.verdict,
          aiVerdict.riskScore,
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
      logger.error("[investigations.routes] AI analysis trigger failed", {
        error: error instanceof Error ? error.message : "Unknown error",
      });

      res.status(500).json({
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "AI evaluation execution failed",
      });
    }
  }
);

investigationsRouter.get(
  "/:id/evidence",
  async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id)
        ? req.params.id[0]
        : req.params.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: "Investigation ID is required",
        });
        return;
      }

      const result = await query(
        `SELECT * FROM evidence_items
         WHERE investigation_id = $1
         ORDER BY created_at ASC;`,
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
        error:
          error instanceof Error
            ? error.message
            : "Failed to fetch evidence items",
      });
    }
  }
);

investigationsRouter.get(
  "/:id/dossier",
  async (req: Request, res: Response) => {
    try {
      const id = Array.isArray(req.params.id)
        ? req.params.id[0]
        : req.params.id;

      if (!id) {
        res.status(400).json({
          success: false,
          error: "Investigation ID is required",
        });
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
        error:
          error instanceof Error
            ? error.message
            : "Failed to compile dossier",
      });
    }
  }
);

export default investigationsRouter;
