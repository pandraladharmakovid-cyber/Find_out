import { Router, type Request, type Response } from "express";
import { monitoringService } from "../monitoring";
import { logger } from "../utils/logger";

const monitoringRouter = Router();

async function startScan(req: Request, res: Response): Promise<void> {
  const brandId = typeof req.body?.brandId === "string" ? req.body.brandId.trim() : "";
  if (!brandId) {
    res.status(400).json({ success: false, error: "A brandId is required to start monitoring." });
    return;
  }

  try {
    const result = await monitoringService.runBrandScan(brandId);
    res.status(200).json({ success: true, data: result });
  } catch (error) {
    logger.error("[monitoring.routes] Monitoring run failed", {
      brandId,
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Monitoring run failed.",
    });
  }
}

monitoringRouter.post("/scan", startScan);
monitoringRouter.post("/run", startScan);

monitoringRouter.get("/candidates", async (req: Request, res: Response): Promise<void> => {
  try {
    const brandId = typeof req.query.brandId === "string" ? req.query.brandId : undefined;
    const runId = typeof req.query.runId === "string" ? req.query.runId : undefined;
    const limit = typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 200;
    const offset = typeof req.query.offset === "string" ? Number.parseInt(req.query.offset, 10) : 0;

    const [candidates, summary] = await Promise.all([
      monitoringService.getCandidates(brandId, runId, {
        limit: Number.isFinite(limit) ? limit : 200,
        offset: Number.isFinite(offset) ? offset : 0,
      }),
      monitoringService.getCandidatesSummary(brandId),
    ]);

    res.json({
      success: true,
      count: candidates.length,
      data: candidates,
      summary,
      pagination: {
        limit: Number.isFinite(limit) ? limit : 200,
        offset: Number.isFinite(offset) ? offset : 0,
      },
    });
  } catch (error) {
    logger.error("[monitoring.routes] Failed to load monitoring candidates", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to load monitoring candidates.",
    });
  }
});

monitoringRouter.get("/summary", async (req: Request, res: Response): Promise<void> => {
  try {
    const brandId = typeof req.query.brandId === "string" ? req.query.brandId : undefined;
    const summary = await monitoringService.getCandidatesSummary(brandId);
    res.json({ success: true, data: summary });
  } catch (error) {
    logger.error("[monitoring.routes] Failed to summarise candidates", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({ success: false, error: "Failed to summarise candidates." });
  }
});

monitoringRouter.get("/results/:brandId", async (req: Request, res: Response): Promise<void> => {
  const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
  if (!brandId) {
    res.status(400).json({ success: false, error: "A brandId is required." });
    return;
  }
  try {
    const limit = typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 200;
    const offset = typeof req.query.offset === "string" ? Number.parseInt(req.query.offset, 10) : 0;

    const run = await monitoringService.getLatestRun(brandId);
    const runId = typeof run?.id === "string" ? run.id : null;
    const [candidates, counters] = await Promise.all([
      runId
        ? monitoringService.getCandidates(brandId, runId, {
            limit: Number.isFinite(limit) ? limit : 200,
            offset: Number.isFinite(offset) ? offset : 0,
          })
        : Promise.resolve([]),
      monitoringService.getCandidatesSummary(brandId),
    ]);
    res.json({
      success: true,
      data: {
        brandId,
        run,
        candidates,
        summary: {
          total: counters.total,
          suspicious: candidates.filter((candidate) => !candidate.is_official_excluded).length,
          excluded: counters.excluded,
          highRisk: counters.highRisk,
          returned: candidates.length,
        },
      },
    });
  } catch (error) {
    logger.error("[monitoring.routes] Failed to load monitoring results", {
      brandId,
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to load monitoring results.",
    });
  }
});

export default monitoringRouter;
