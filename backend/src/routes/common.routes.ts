import { Router, type Request, type Response } from "express";
import { recoveryService } from "../recovery";
import { alertsService, type AlertStatus, type AlertSeverity } from "../alerts";
import { complaintService, type ComplaintStatus, type ComplaintType } from "../complaints";
import { reportsService } from "../reports";
import { logger } from "../utils/logger";
import { ComplaintsRepository } from "../repositories";
import { complaintDispatchService } from "../complaints-dispatch.service";
import { threatFeedService } from "../integrations/threat-feed.client";
import { query } from "../db";

export const commonRouter = Router();

// ==========================================
// 1. Health & Recovery Endpoints
// ==========================================

commonRouter.get("/health", async (_req: Request, res: Response) => {
  try {
    const health = await recoveryService.checkHealth();
    res.status(health.status === "unhealthy" ? 503 : 200).json({
      success: health.status !== "unhealthy",
      data: health,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Health check failed",
    });
  }
});

commonRouter.post("/recovery/recover-stalled", async (req: Request, res: Response) => {
  try {
    const timeout = typeof req.body?.timeoutMinutes === "number" ? req.body.timeoutMinutes : 15;
    const result = await recoveryService.recoverStalledJobs(timeout);
    res.json({
      success: true,
      message: "Stalled jobs recovered successfully",
      data: result,
    });
  } catch (error) {
    logger.error("[common.routes] Failed stalled job recovery", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to run stalled job recovery",
    });
  }
});

commonRouter.post("/recovery/assess", async (req: Request, res: Response) => {
  const target = typeof req.body?.identifier === "string" ? req.body.identifier.trim() : "";
  const incidentType = typeof req.body?.incident_type === "string" ? req.body.incident_type : "";
  if (!target || target.length > 2048 || !incidentType) {
    res.status(400).json({
      success: false,
      error: "A target identifier (up to 2048 characters) and incident_type are required.",
    });
    return;
  }
  res.json({
    success: true,
    data: recoveryService.assessIncident(target, incidentType),
  });
});

commonRouter.get("/recovery/audit-summary", async (_req: Request, res: Response) => {
  try {
    const auditSummary = await recoveryService.exportSystemAuditSummary();
    res.json({
      success: true,
      data: auditSummary,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve audit summary",
    });
  }
});

// ==========================================
// 2. Global Security Alerts Endpoints
// ==========================================

commonRouter.get("/alerts", async (req: Request, res: Response) => {
  try {
    const brandId = typeof req.query.brandId === "string" ? req.query.brandId : undefined;
    const status = typeof req.query.status === "string" ? (req.query.status as AlertStatus) : undefined;

    const alerts = await alertsService.listAlerts(brandId, status);
    res.json({
      success: true,
      count: alerts.length,
      data: alerts,
    });
  } catch (error) {
    logger.error("[common.routes] Failed to list alerts", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to list alerts",
    });
  }
});

commonRouter.patch("/alerts/:id/status", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status } = req.body;

    if (!id) {
      res.status(400).json({ success: false, error: "Alert ID is required" });
      return;
    }

    if (!["open", "acknowledged", "resolved", "dismissed"].includes(status)) {
      res.status(400).json({ success: false, error: "Invalid alert status provided" });
      return;
    }

    const updated = await alertsService.updateAlertStatus(String(id), status as AlertStatus);
    res.json({
      success: true,
      data: updated,
    });
  } catch (error) {
    logger.error("[common.routes] Failed to update alert status", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to update alert status",
    });
  }
});

// ==========================================
// 3. Legal & Abuse Complaints Endpoints
// ==========================================

commonRouter.get("/complaints", async (_req: Request, res: Response) => {
  try {
    const complaints = await ComplaintsRepository.list(100);
    res.json({
      success: true,
      count: complaints.length,
      data: complaints,
    });
  } catch (error) {
    logger.error("[common.routes] Failed to list complaints", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve complaints",
    });
  }
});

commonRouter.post("/complaints", async (req: Request, res: Response) => {
  try {
    const {
      investigationId,
      brandId,
      brandName,
      brandContactEmail,
      complaintType,
      recipientEmail,
      targetUrl,
      infringingEvidenceSummary,
      trademarkNumber,
    } = req.body;

    if (typeof req.body?.target_url === "string") {
      const targetUrl = req.body.target_url.trim();
      const description = typeof req.body.description === "string" ? req.body.description.trim() : "";
      const platform = typeof req.body.platform === "string" ? req.body.platform.trim() : "";
      let parsedTarget: URL;
      try {
        parsedTarget = new URL(targetUrl);
      } catch {
        res.status(400).json({ success: false, error: "target_url must be a valid absolute URL." });
        return;
      }
      if (!["http:", "https:"].includes(parsedTarget.protocol)) {
        res.status(400).json({ success: false, error: "Only HTTP and HTTPS report targets are supported." });
        return;
      }
      if (!platform || !description) {
        res.status(400).json({
          success: false,
          error: "platform and a non-empty description are required.",
        });
        return;
      }
      const duplicate = await query(
        `SELECT id, reference_number, status FROM complaints
         WHERE lower(target_url) = lower($1)
           AND status IN ('received', 'generated', 'draft', 'sent')
         ORDER BY created_at DESC LIMIT 1;`,
        [parsedTarget.toString()],
      );
      if (duplicate.rows[0]) {
        res.status(409).json({
          success: false,
          error: "A report for this target is already recorded.",
          data: duplicate.rows[0],
        });
        return;
      }
      const complaint = await ComplaintsRepository.create({
        brand_id: typeof req.body.brandId === "string" ? req.body.brandId : null,
        platform,
        target_identifier: targetUrl,
        target_url: parsedTarget.toString(),
        complaint_category: "brand_impersonation",
        description,
        claim_description: description,
      });
      res.status(201).json({
        success: true,
        data: {
          ...complaint,
          reference_id: complaint.reference_number ?? complaint.id,
          description: complaint.description ?? complaint.claim_description,
        },
      });
      return;
    }

    if (!investigationId || !brandId || !recipientEmail || !targetUrl) {
      res.status(400).json({
        success: false,
        error: "Missing required complaint parameters (investigationId, brandId, recipientEmail, targetUrl)",
      });
      return;
    }

    const complaint = await complaintService.createComplaint({
      investigationId: String(investigationId),
      brandId: String(brandId),
      brandName: brandName ?? "Protected Brand",
      brandContactEmail: brandContactEmail ?? "abuse@brandprotection.ai",
      complaintType: (complaintType as ComplaintType) ?? "registrar_abuse",
      recipientEmail: String(recipientEmail),
      targetUrl: String(targetUrl),
      infringingEvidenceSummary,
      trademarkNumber,
    });

    res.status(201).json({
      success: true,
      data: complaint,
    });
  } catch (error) {
    logger.error("[common.routes] Failed to create complaint", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to create takedown complaint",
    });
  }
});

commonRouter.get("/complaints/investigation/:investigationId", async (req: Request, res: Response) => {
  try {
    const invId = Array.isArray(req.params.investigationId) ? req.params.investigationId[0] : req.params.investigationId;
    if (!invId) {
      res.status(400).json({ success: false, error: "Investigation ID required" });
      return;
    }

    const complaints = await complaintService.getComplaintsByInvestigation(String(invId));
    res.json({
      success: true,
      count: complaints.length,
      data: complaints,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve complaints",
    });
  }
});

commonRouter.patch("/complaints/:id/status", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status } = req.body;

    if (!id) {
      res.status(400).json({ success: false, error: "Complaint ID is required" });
      return;
    }

    if (!["draft", "generated", "sent", "accepted", "rejected"].includes(status)) {
      res.status(400).json({ success: false, error: "Invalid complaint status provided" });
      return;
    }

    // "sent" must never be recorded by accident: either the platform delivered
    // the notice (POST /complaints/:id/send) or an operator confirms that it was
    // sent from an external mailbox.
    if (status === "sent" && req.body?.confirmManual !== true) {
      res.status(409).json({
        success: false,
        error:
          "Use POST /api/complaints/:id/send to submit the notice. If it was sent outside Find_out, repeat this call with confirmManual=true.",
      });
      return;
    }

    const updated = await complaintService.updateStatus(String(id), status as ComplaintStatus);
    res.json({
      success: true,
      data: updated,
    });
  } catch (error) {
    logger.error("[common.routes] Failed to update complaint status", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to update complaint status",
    });
  }
});

// Delivery status + real outbound submission for takedown notices.
commonRouter.get("/complaints/delivery/status", (_req: Request, res: Response) => {
  const status = complaintDispatchService.status();
  res.json({ success: true, data: status });
});

commonRouter.post("/complaints/:id/send", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id || !/^[0-9a-fA-F-]{36}$/.test(id)) {
      res.status(400).json({ success: false, error: "A valid complaint UUID is required." });
      return;
    }

    const { complaint, result } = await complaintDispatchService.deliver(id);

    if (!complaint) {
      res.status(404).json({ success: false, error: "Complaint not found." });
      return;
    }

    const httpStatus = result.status === "sent" ? 200 : result.status === "not_configured" ? 503 : 502;

    res.status(httpStatus).json({
      success: result.status === "sent",
      data: {
        complaint,
        delivery: result,
      },
      ...(result.status === "not_configured"
        ? {
            error:
              "No outbound transport is configured, so the notice was NOT submitted. Configure SMTP or COMPLAINT_WEBHOOK_URL first.",
          }
        : {}),
      ...(result.status === "failed" ? { error: result.detail } : {}),
    });
  } catch (error) {
    logger.error("[common.routes] Complaint delivery failed", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Complaint delivery failed",
    });
  }
});

// Live cyber-security threat feed (CISA KEV by default).
commonRouter.get("/alerts/feed", async (req: Request, res: Response) => {
  try {
    const limitRaw = typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 20;
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 20;
    const search = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const refresh = req.query.refresh === "1";

    const feed = await threatFeedService.getFeed({ limit, search, refresh });
    res.status(feed.status === "available" ? 200 : 503).json({
      success: feed.status === "available",
      data: feed,
      ...(feed.status === "available" ? {} : { error: feed.detail }),
    });
  } catch (error) {
    logger.error("[common.routes] Threat feed failed", { error });
    res.status(502).json({
      success: false,
      error: error instanceof Error ? error.message : "Threat feed unavailable",
    });
  }
});

// ==========================================
// 4. Forensic Reports Endpoints
// ==========================================

commonRouter.get("/reports/dossier/:investigationId", async (req: Request, res: Response) => {
  try {
    const invId = Array.isArray(req.params.investigationId) ? req.params.investigationId[0] : req.params.investigationId;
    if (!invId) {
      res.status(400).json({ success: false, error: "Investigation ID required" });
      return;
    }

    const dossier = await reportsService.buildDossier(String(invId));
    res.json({
      success: true,
      data: dossier,
    });
  } catch (error) {
    res.status(404).json({
      success: false,
      error: error instanceof Error ? error.message : "Dossier compilation failed",
    });
  }
});

commonRouter.get("/reports/markdown/:investigationId", async (req: Request, res: Response) => {
  try {
    const invId = Array.isArray(req.params.investigationId) ? req.params.investigationId[0] : req.params.investigationId;
    if (!invId) {
      res.status(400).json({ success: false, error: "Investigation ID required" });
      return;
    }

    const markdown = await reportsService.generateMarkdownReport(String(invId));
    res.setHeader("Content-Type", "text/markdown; charset=utf-8");
    res.send(markdown);
  } catch (error) {
    res.status(404).json({
      success: false,
      error: error instanceof Error ? error.message : "Markdown report generation failed",
    });
  }
});

commonRouter.post("/reports/:investigationId", async (req: Request, res: Response) => {
  try {
    const invId = Array.isArray(req.params.investigationId) ? req.params.investigationId[0] : req.params.investigationId;
    const format = req.body?.format === "json" ? "json" : "markdown";

    if (!invId) {
      res.status(400).json({ success: false, error: "Investigation ID required" });
      return;
    }

    const saved = await reportsService.saveReport(String(invId), format);
    res.status(201).json({
      success: true,
      data: saved,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to persist report",
    });
  }
});

export default commonRouter;
