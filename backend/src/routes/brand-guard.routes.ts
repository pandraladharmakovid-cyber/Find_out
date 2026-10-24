import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type Request, type Response } from "express";
import {
  BrandGuardError,
  brandGuardService,
  type BrandGuardMatchType,
  type BrandGuardVerdict,
} from "../brand-guard.service";
import { config } from "../config";
import {
  isResendConfigured,
  resendFromAddress,
} from "../integrations/resend.client";
import { logger } from "../utils/logger";

/**
 * Brand Guard API.
 *
 *   GET  /api/brand-guard/status      — is the alert e-mail transport ready?
 *   POST /api/brand-guard/check       — does {name, domain} collide with a
 *                                       registered official brand?
 *   POST /api/brand-guard/alert       — "Notify official brand" button: e-mail
 *                                       the official brand through Resend.
 *   GET  /api/brand-guard/alerts      — alert history (optionally per brand).
 */
export const brandGuardRouter = Router();

function handleGuardError(res: Response, error: unknown, fallback: string): void {
  if (error instanceof BrandGuardError) {
    res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
    });
    return;
  }
  logger.error("[brand-guard.routes] Unexpected failure", { error });
  res.status(500).json({
    success: false,
    error: error instanceof Error ? error.message : fallback,
  });
}

brandGuardRouter.get("/status", (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      emailConfigured: isResendConfigured(),
      provider: "resend",
      from: resendFromAddress(),
    },
  });
});

brandGuardRouter.post("/check", async (req: Request, res: Response) => {
  try {
    const { name, domain, primaryDomain, website, excludeBrandId } = req.body ?? {};

    if (typeof name !== "string" || !name.trim()) {
      res.status(400).json({
        success: false,
        error: "Provide the brand 'name' to check.",
        code: "MISSING_NAME",
      });
      return;
    }

    const suppliedDomain = [domain, primaryDomain, website].find(
      (value): value is string => typeof value === "string" && Boolean(value.trim()),
    );

    const result = await brandGuardService.findConflicts({
      name: name.trim().slice(0, 200),
      domain: suppliedDomain ?? null,
      excludeBrandId: typeof excludeBrandId === "string" ? excludeBrandId : null,
    });

    res.json({ success: true, data: result });
  } catch (error) {
    handleGuardError(res, error, "Failed to run the brand impersonation check");
  }
});

brandGuardRouter.post("/alert", async (req: Request, res: Response) => {
  try {
    const {
      brandId,
      suspectName,
      suspectDomain,
      suspectWebsite,
      matchType,
      similarity,
      verdict,
      note,
      reporterNote,
    } = req.body ?? {};

    if (typeof brandId !== "string" || !brandId.trim()) {
      res.status(400).json({
        success: false,
        error: "Provide 'brandId' — the official brand to notify.",
        code: "MISSING_BRAND_ID",
      });
      return;
    }
    if (typeof suspectName !== "string" || !suspectName.trim()) {
      res.status(400).json({
        success: false,
        error: "Provide 'suspectName' — the suspicious brand name that was submitted.",
        code: "MISSING_SUSPECT_NAME",
      });
      return;
    }

    const allowedMatchTypes: BrandGuardMatchType[] = ["name", "alternate_name", "domain"];
    const allowedVerdicts: BrandGuardVerdict[] = ["exact", "impersonation", "lookalike"];

    const record = await brandGuardService.sendImpersonationAlert({
      brandId: brandId.trim(),
      suspectName: suspectName.trim(),
      suspectDomain: typeof suspectDomain === "string" ? suspectDomain : null,
      suspectWebsite: typeof suspectWebsite === "string" ? suspectWebsite : null,
      matchType: allowedMatchTypes.includes(matchType) ? matchType : undefined,
      similarity: typeof similarity === "number" ? similarity : null,
      verdict: allowedVerdicts.includes(verdict) ? verdict : undefined,
      reporterNote:
        typeof reporterNote === "string"
          ? reporterNote
          : typeof note === "string"
            ? note
            : null,
    });

    res.status(201).json({
      success: true,
      data: record,
      meta: {
        delivered: record.status === "sent",
        recipient: record.recipient_email,
        provider: "resend",
        providerMessageId: record.provider_message_id,
      },
    });
  } catch (error) {
    handleGuardError(res, error, "Failed to send the impersonation alert");
  }
});

brandGuardRouter.get("/alerts", async (req: Request, res: Response) => {
  try {
    const brandId =
      typeof req.query.brandId === "string" && req.query.brandId.trim()
        ? req.query.brandId.trim()
        : null;
    const limit =
      typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) || 50 : 50;

    const alerts = await brandGuardService.listAlerts(brandId, limit);
    res.json({ success: true, data: alerts, meta: { count: alerts.length } });
  } catch (error) {
    handleGuardError(res, error, "Failed to list impersonation alerts");
  }
});

brandGuardRouter.post("/brands/:brandId/contact", async (req: Request, res: Response) => {
  try {
    const brandId = Array.isArray(req.params.brandId)
      ? req.params.brandId[0]
      : req.params.brandId;
    const rawEmail = req.body?.contactEmail ?? req.body?.contact_email;

    if (!brandId || !brandId.trim()) {
      res.status(400).json({
        success: false,
        error: "Provide 'brandId'.",
        code: "MISSING_BRAND_ID",
      });
      return;
    }
    if (typeof rawEmail !== "string" || !rawEmail.trim()) {
      res.status(400).json({
        success: false,
        error: "Provide 'contactEmail' for impersonation alerts.",
        code: "MISSING_CONTACT_EMAIL",
      });
      return;
    }

    const configuredAdminKey = config.ASSET_REGISTRY_ADMIN_KEY;
    const suppliedAdminKey = req.get("x-registry-admin-key") ?? "";
    const isOperator =
      configuredAdminKey.length >= 32 &&
      Boolean(suppliedAdminKey) &&
      timingSafeEqual(
        createHash("sha256").update(configuredAdminKey, "utf8").digest(),
        createHash("sha256").update(suppliedAdminKey, "utf8").digest(),
      );

    const updated = await brandGuardService.configureContactEmail(
      brandId.trim(),
      rawEmail,
      isOperator,
    );
    res.json({ success: true, data: updated });
  } catch (error) {
    handleGuardError(res, error, "Failed to configure brand contact e-mail");
  }
});

export default brandGuardRouter;
