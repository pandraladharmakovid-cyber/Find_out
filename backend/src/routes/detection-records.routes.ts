import { Router, type Request, type Response } from "express";

import {
  detectionRecordService,
  DETECTION_STATUSES,
  type DetectionStatus,
} from "../detection-records.service";
import { logger } from "../utils/logger";
import { rateLimiter } from "../middleware";

export const detectionRecordsRouter = Router();

const writeLimiter = rateLimiter(60, 60_000);

function idParam(req: Request): string {
  const raw = req.params.id;
  return String(Array.isArray(raw) ? raw[0] : raw ?? "");
}

function actorFrom(req: Request): string {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const header = req.header("x-analyst-name") ?? req.header("x-analyst-id");
  const bodyActor = typeof body.actor === "string" ? body.actor : "";
  return (bodyActor || header || "demo-analyst").trim().slice(0, 120);
}

/**
 * GET /api/detection-records
 * The Rulebook-v2 work queue: Source, Suspected asset, Evidence, Score, Status.
 */
detectionRecordsRouter.get("/", async (req: Request, res: Response) => {
  try {
    const sync = req.query.sync === "0" ? { created: 0 } : await detectionRecordService.sync();

    const status = typeof req.query.status === "string" ? req.query.status.toUpperCase() : "";
    const priority = typeof req.query.priority === "string" ? req.query.priority.toUpperCase() : "";

    const result = await detectionRecordService.list({
      ...(DETECTION_STATUSES.includes(status as DetectionStatus)
        ? { status: status as DetectionStatus }
        : {}),
      ...(["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(priority)
        ? { priority: priority as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }
        : {}),
      ...(typeof req.query.brandId === "string" && req.query.brandId
        ? { brandId: req.query.brandId }
        : {}),
      ...(typeof req.query.search === "string" && req.query.search.trim()
        ? { search: req.query.search.trim() }
        : {}),
      limit: typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 100,
      offset: typeof req.query.offset === "string" ? Number.parseInt(req.query.offset, 10) : 0,
    });

    res.json({
      success: true,
      data: {
        ...result,
        priorityQueue: await detectionRecordService.priorityQueue(8),
        statuses: DETECTION_STATUSES,
        syncedNow: sync.created,
      },
    });
  } catch (error) {
    logger.error("[detection-records] List failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not load detection records.",
    });
  }
});

detectionRecordsRouter.get("/alerts", async (_req: Request, res: Response) => {
  try {
    const alerts = await detectionRecordService.listAlerts();
    res.json({ success: true, count: alerts.length, data: alerts });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not load high-risk alerts.",
    });
  }
});

detectionRecordsRouter.post("/alerts/:id/acknowledge", writeLimiter, async (req: Request, res: Response) => {
  try {
    const ok = await detectionRecordService.acknowledgeAlert(idParam(req), actorFrom(req));
    if (!ok) {
      res.status(404).json({ success: false, error: "Alert not found." });
      return;
    }
    res.json({ success: true, data: { acknowledged: true } });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not acknowledge the alert.",
    });
  }
});

detectionRecordsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const found = await detectionRecordService.get(idParam(req));
    if (!found) {
      res.status(404).json({ success: false, error: "Detection record not found." });
      return;
    }
    res.json({ success: true, data: found });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not load the detection record.",
    });
  }
});

/**
 * POST /api/detection-records/:id/decision
 * Analyst confirms or dismisses a detection. The actor is recorded so the
 * history shows who made the call.
 */
detectionRecordsRouter.post("/:id/decision", writeLimiter, async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const raw = typeof body.status === "string" ? body.status.toUpperCase().replace(/\s+/g, "_") : "";

  if (!DETECTION_STATUSES.includes(raw as DetectionStatus)) {
    res.status(400).json({
      success: false,
      error: `status must be one of ${DETECTION_STATUSES.join(", ")}.`,
    });
    return;
  }

  try {
    const updated = await detectionRecordService.decide({
      id: idParam(req),
      status: raw as DetectionStatus,
      actor: actorFrom(req),
      note: typeof body.note === "string" ? body.note : "",
    });

    res.json({ success: true, data: updated });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not record the decision.";
    const status = /not found/i.test(message) ? 404 : 400;
    res.status(status).json({ success: false, error: message });
  }
});

detectionRecordsRouter.get("/:id/takedown-draft", async (req: Request, res: Response) => {
  try {
    const draft = await detectionRecordService.takedownDraft(idParam(req));
    if (!draft) {
      res.status(404).json({ success: false, error: "Detection record not found." });
      return;
    }
    res.json({ success: true, data: draft });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not build the takedown draft.",
    });
  }
});

export default detectionRecordsRouter;
