import { Router, type Request, type Response } from "express";
import { externalBrandWatchService } from "../external-watch.service";
import { logger } from "../utils/logger";

/**
 * Automatic Internet-Wide Brand Impersonation Detection ("External Brand Watch") API.
 *
 *   GET   /api/external-watch/overview            — monitoring status, sources checked,
 *                                                   last/next scan, newly discovered
 *                                                   external candidates, alerts & emails
 *   POST  /api/external-watch/scan/:brandId       — run immediate external internet watch
 *                                                   for a registered brand
 *   POST  /api/external-watch/run-due             — run due scheduled watches now
 *   PATCH /api/external-watch/schedules/:brandId  — configure schedule interval, enabled
 *                                                   state, or alert risk threshold
 */
export const externalWatchRouter = Router();

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

externalWatchRouter.get("/overview", async (req: Request, res: Response) => {
  try {
    const rawBrandId = typeof req.query.brandId === "string" ? req.query.brandId.trim() : "";
    if (rawBrandId && !UUID_REGEX.test(rawBrandId)) {
      res.status(400).json({
        success: false,
        error: "Invalid 'brandId' UUID parameter.",
        code: "INVALID_BRAND_ID",
      });
      return;
    }

    const overview = await externalBrandWatchService.getOverview(rawBrandId || undefined);
    res.json({ success: true, data: overview });
  } catch (error) {
    logger.error("[external-watch.routes] Failed to load overview", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to load External Brand Watch overview",
    });
  }
});

externalWatchRouter.post("/scan/:brandId", async (req: Request, res: Response) => {
  try {
    const brandId = String(req.params.brandId ?? "").trim();
    if (!UUID_REGEX.test(brandId)) {
      res.status(400).json({
        success: false,
        error: "Provide a valid 'brandId' UUID.",
        code: "INVALID_BRAND_ID",
      });
      return;
    }

    const run = await externalBrandWatchService.runBrandWatch(brandId, "manual");
    res.json({ success: true, data: run });
  } catch (error) {
    const message = error instanceof Error ? error.message : "External Brand Watch scan failed";
    const status = message.includes("not found")
      ? 404
      : message.includes("already running")
        ? 409
        : 500;
    logger.error("[external-watch.routes] Scan execution error", { error: message });
    res.status(status).json({
      success: false,
      error: message,
    });
  }
});

externalWatchRouter.post("/run-due", async (_req: Request, res: Response) => {
  try {
    const outcome = await externalBrandWatchService.runDueWatches();
    res.json({ success: true, data: outcome });
  } catch (error) {
    logger.error("[external-watch.routes] Failed to run due watches", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to execute due scheduled watches",
    });
  }
});

externalWatchRouter.patch("/schedules/:brandId", async (req: Request, res: Response) => {
  try {
    const brandId = String(req.params.brandId ?? "").trim();
    if (!UUID_REGEX.test(brandId)) {
      res.status(400).json({
        success: false,
        error: "Provide a valid 'brandId' UUID.",
        code: "INVALID_BRAND_ID",
      });
      return;
    }

    const { isEnabled, intervalMinutes, alertRiskThreshold } = req.body ?? {};
    const schedule = await externalBrandWatchService.enrollBrand(brandId, {
      ...(typeof isEnabled === "boolean" ? { isEnabled } : {}),
      ...(typeof intervalMinutes === "number" && Number.isFinite(intervalMinutes)
        ? { intervalMinutes: Math.trunc(intervalMinutes) }
        : {}),
      ...(typeof alertRiskThreshold === "number" && Number.isFinite(alertRiskThreshold)
        ? { alertRiskThreshold }
        : {}),
    });

    res.json({ success: true, data: schedule });
  } catch (error) {
    logger.error("[external-watch.routes] Failed to update schedule", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to update External Brand Watch schedule",
    });
  }
});

export default externalWatchRouter;
