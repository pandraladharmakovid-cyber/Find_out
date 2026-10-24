import { Router, type Request, type Response } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  BrandProfileError,
  brandService,
  normalizeBrandPrimaryDomain,
  normalizeBrandWebsite,
} from "../brands";
import { BrandAssetsRepository } from "../repositories";
import { brandGuardService } from "../brand-guard.service";
import { logger } from "../utils/logger";
import { logoSimilarityService } from "../logo-similarity.service";
import { assetService, AssetVerificationError, type AssetType } from "../assets";
import type { DomainChallengeMethod } from "../asset-proof";
import { config } from "../config";

export const brandsRouter = Router();

// ==========================================
// 1. Brand Profile Management
// ==========================================

brandsRouter.post("/", async (req: Request, res: Response) => {
  try {
    const {
      name,
      primaryDomain,
      primary_domain,
      website,
      domains,
      industry,
      lookalikeThreshold,
      alternateNames,
      alternate_names,
      keywords,
      logoUrl,
      logo_url,
      description,
      contactEmail,
      contact_email,
    } = req.body;

    const domainList = Array.isArray(domains)
      ? domains.filter((value: unknown): value is string => typeof value === "string")
      : [];
    const suppliedDomain = primaryDomain ?? primary_domain ?? domainList[0] ?? website;

    if (typeof name !== "string" || !name.trim() || typeof suppliedDomain !== "string") {
      res.status(400).json({
        success: false,
        error: "Missing required brand parameters: 'name' and 'primaryDomain' are mandatory",
      });
      return;
    }

    let normalizedPrimaryDomain: string;
    let associatedDomains: string[];
    let normalizedWebsite: string | null;
    try {
      normalizedPrimaryDomain = normalizeBrandPrimaryDomain(suppliedDomain);
      associatedDomains = domainList.map(normalizeBrandPrimaryDomain);
      normalizedWebsite = typeof website === "string" && website.trim()
        ? normalizeBrandWebsite(website)
        : null;
    } catch (error) {
      if (error instanceof BrandProfileError) {
        res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
        return;
      }
      throw error;
    }

    const normalizeStringList = (value: unknown): string[] =>
      Array.isArray(value)
        ? value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean)
        : [];

    // Brand Guard: compare the submission against every registered official
    // brand before saving, so impersonation attempts are flagged server-side
    // even when the client-side pop-up check is bypassed.
    let brandGuard = null;
    try {
      brandGuard = await brandGuardService.findConflicts({
        name: String(name).trim(),
        domain: normalizedPrimaryDomain,
      });
    } catch (guardError) {
      logger.warn("[brands.routes] Brand Guard pre-registration check failed", {
        error: guardError instanceof Error ? guardError.message : guardError,
      });
    }

    const brand = await brandService.createBrand({
      name: String(name).trim(),
      primaryDomain: normalizedPrimaryDomain,
      industry: industry ? String(industry) : undefined,
      lookalikeThreshold: typeof lookalikeThreshold === "number" ? lookalikeThreshold : 0.75,
      alternateNames: normalizeStringList(alternateNames ?? alternate_names),
      associatedDomains,
      keywords: normalizeStringList(keywords),
      website: normalizedWebsite,
      logoUrl: logoUrl ?? logo_url ?? null,
      description: description ?? null,
      contactEmail:
        typeof (contactEmail ?? contact_email) === "string"
          ? (contactEmail ?? contact_email)
          : null,
    });

    res.status(201).json({
      success: true,
      data: brand,
      meta: {
        official: false,
        verificationStatus: "UNVERIFIED",
        message: "Profile saved for review. Verify its primary domain before treating it as official.",
        brandGuard,
      },
    });
  } catch (error) {
    if (error instanceof BrandProfileError) {
      res.status(error.statusCode).json({
        success: false,
        error: error.message,
        code: error.code,
      });
      return;
    }
    logger.error("[brands.routes] Failed to create brand", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to register brand",
    });
  }
});

brandsRouter.get("/", async (req: Request, res: Response) => {
  try {
    const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 50;
    const offset = typeof req.query.offset === "string" ? parseInt(req.query.offset, 10) : 0;

    const brands = await brandService.listBrands(limit, offset);
    const brandsWithAssets = await Promise.all(
      brands.map(async (brand) => {
        const assets = await BrandAssetsRepository.findByBrandId(brand.id);

        // Logo resolution order, exposed to the frontend so it renders a real
        // logo instead of an icon: uploaded logo asset → verified asset URL →
        // stored logo_url → the primary domain (resolved on demand).
        const logoAsset = assets.find(
          (asset) =>
            asset.asset_type === "logo" &&
            Boolean(asset.canonical_url || asset.image_data),
        );

        return {
          ...brand,
          assets,
          logo_url: brand.logo_url ?? null,
          logo_asset_url: logoAsset?.canonical_url ?? null,
          logo_domain: brand.primary_domain ?? null,
          logo_image_url: `/api/intelligence/logo/brand/${brand.id}/image`,
        };
      })
    );
    res.json({
      success: true,
      count: brandsWithAssets.length,
      data: brandsWithAssets,
    });
  } catch (error) {
    logger.error("[brands.routes] Failed to list brands", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve brands",
    });
  }
});

brandsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Brand ID is required" });
      return;
    }

    const brand = await brandService.getBrandById(String(id));
    if (!brand) {
      res.status(404).json({ success: false, error: "Brand not found" });
      return;
    }

    res.json({
      success: true,
      data: brand,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve brand",
    });
  }
});

brandsRouter.patch("/:id", async (req: Request, res: Response) => {
  try {
    requireRegistryOperator(req);
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!id) {
      res.status(400).json({ success: false, error: "Brand ID is required" });
      return;
    }

    const updated = await brandService.updateBrand(String(id), req.body);
    res.json({
      success: true,
      data: updated,
    });
  } catch (error) {
    assetError(res, error, "Failed to update brand");
  }
});

// ==========================================
// 2. Official Brand Assets Management
// ==========================================

function requireRegistryOperator(req: Request): void {
  const configured = config.ASSET_REGISTRY_ADMIN_KEY;
  if (configured.length < 32) {
    throw new AssetVerificationError(
      503,
      "REGISTRY_OPERATOR_NOT_CONFIGURED",
      "Registry administration is disabled until a server-only operator key of at least 32 characters is configured.",
    );
  }
  const supplied = req.get("x-registry-admin-key") ?? "";
  const expectedHash = createHash("sha256").update(configured, "utf8").digest();
  const suppliedHash = createHash("sha256").update(supplied, "utf8").digest();
  if (!supplied || !timingSafeEqual(expectedHash, suppliedHash)) {
    throw new AssetVerificationError(
      403,
      "REGISTRY_OPERATOR_REQUIRED",
      "A valid registry operator credential is required for this administrative operation.",
    );
  }
}

function assetError(
  res: Response,
  error: unknown,
  fallback: string,
): void {
  if (error instanceof AssetVerificationError) {
    res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
      details: error.details ?? null,
    });
    return;
  }
  logger.error("[brands.routes] Asset workflow failed", {
    error: error instanceof Error ? error.message : "Unknown error",
  });
  res.status(500).json({
    success: false,
    error: error instanceof Error ? error.message : fallback,
  });
}

brandsRouter.post("/:brandId/assets", async (req: Request, res: Response) => {
  try {
    // Verification is a server-owned state. Reject self-approval attempts rather
    // than silently accepting a forged trust flag with the submission.
    if (
      Object.prototype.hasOwnProperty.call(req.body ?? {}, "is_verified") ||
      Object.prototype.hasOwnProperty.call(req.body ?? {}, "verified") ||
      Object.prototype.hasOwnProperty.call(req.body ?? {}, "verification_status")
    ) {
      res.status(403).json({
        success: false,
        error: "Verification status cannot be set by an asset submission.",
        code: "SELF_APPROVAL_FORBIDDEN",
      });
      return;
    }

    const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
    const {
      assetType,
      asset_type,
      value,
      identifier,
      platform,
      url,
      canonicalUrl,
      canonical_url,
      meta,
      metadata,
      imageBase64,
      imageMime,
    } = req.body;
    const resolvedType = assetType ?? asset_type;
    const resolvedIdentifier = identifier ?? value;

    if (
      !brandId ||
      typeof resolvedType !== "string" ||
      typeof resolvedIdentifier !== "string" ||
      !resolvedIdentifier.trim()
    ) {
      res.status(400).json({
        success: false,
        error: "Missing required parameters: 'brandId', 'asset_type', and 'identifier' are required",
      });
      return;
    }

    const allowedAssetTypes = new Set([
      "domain",
      "subdomain",
      "logo",
      "trademark",
      "social_handle",
      "social_account",
      "social_profile",
      "mobile_app",
      "app_store_id",
      "website",
    ]);
    if (!allowedAssetTypes.has(resolvedType.toLowerCase())) {
      res.status(400).json({ success: false, error: "Unsupported official asset type." });
      return;
    }

    const suppliedAssetUrl = canonicalUrl ?? canonical_url ?? url;
    let logoImage: Buffer | null = null;
    let logoHash: string | null = null;
    if (imageBase64 !== undefined) {
      if (resolvedType.toLowerCase() !== "logo" || typeof imageBase64 !== "string") {
        res.status(400).json({ success: false, error: "Image uploads are supported for logo assets only." });
        return;
      }
      if (
        imageBase64.length > 2_800_000 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(imageBase64)
      ) {
        res.status(400).json({ success: false, error: "Logo image must be valid base64 and no larger than 2 MB." });
        return;
      }
      logoImage = Buffer.from(imageBase64, "base64");
      if (logoImage.length === 0 || logoImage.length > 2 * 1024 * 1024) {
        res.status(400).json({ success: false, error: "Logo image must be non-empty and no larger than 2 MB." });
        return;
      }
      const mime = typeof imageMime === "string" ? imageMime.toLowerCase() : "";
      const validSignature =
        (mime === "image/png" && logoImage.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) ||
        (mime === "image/jpeg" && logoImage[0] === 0xff && logoImage[1] === 0xd8 && logoImage[2] === 0xff) ||
        (mime === "image/webp" &&
          logoImage.subarray(0, 4).toString("ascii") === "RIFF" &&
          logoImage.subarray(8, 12).toString("ascii") === "WEBP");
      if (!validSignature) {
        res.status(400).json({ success: false, error: "Upload a valid PNG, JPEG, or WebP logo image." });
        return;
      }
      try {
        logoHash = await logoSimilarityService.computeImageHash(logoImage);
      } catch (error) {
        res.status(400).json({
          success: false,
          error: error instanceof Error ? `Invalid logo image: ${error.message}` : "Invalid logo image.",
        });
        return;
      }
    }

    let canonicalAssetUrl: string | null = null;
    if (typeof suppliedAssetUrl === "string" && suppliedAssetUrl.trim()) {
      try {
        const parsedAssetUrl = new URL(suppliedAssetUrl.trim());
        if (!["http:", "https:"].includes(parsedAssetUrl.protocol)) throw new Error("Unsupported protocol");
        if (resolvedType.toLowerCase() === "logo" && parsedAssetUrl.protocol !== "https:") {
          throw new Error("Logo URLs must use HTTPS.");
        }
        canonicalAssetUrl = parsedAssetUrl.toString();
      } catch {
        res.status(400).json({
          success: false,
          error: resolvedType.toLowerCase() === "logo"
            ? "Logo URL must be a valid HTTPS URL."
            : "Asset URL must be a valid HTTP or HTTPS URL.",
        });
        return;
      }
    }
    if (resolvedType.toLowerCase() === "logo" && !logoImage && !canonicalAssetUrl) {
      res.status(400).json({ success: false, error: "Provide an HTTPS logo URL or upload a logo image." });
      return;
    }

    const result = await assetService.registerAsset({
      brandId: String(brandId),
      assetType: resolvedType.toLowerCase() as AssetType,
      platform: typeof platform === "string" && platform.trim() ? platform.trim().toLowerCase() : "unknown",
      value: resolvedIdentifier.trim(),
      canonicalUrl: canonicalAssetUrl,
      hashSignature: logoHash,
      imageData: logoImage,
      metadata: {
        ...(meta ?? {}),
        ...(metadata ?? {}),
        ...(typeof imageMime === "string" ? { imageMime } : {}),
      },
    });

    res.status(result.created ? 201 : 200).json({
      success: true,
      data: result.asset,
      meta: {
        created: result.created,
        trusted: result.asset.is_verified,
        message: result.asset.is_verified
          ? "Existing verified asset returned unchanged."
          : "Asset stored as pending verification. No exclusion was created.",
      },
    });
  } catch (error) {
    assetError(res, error, "Failed to associate asset with brand");
  }
});

brandsRouter.get("/:brandId/assets", async (req: Request, res: Response) => {
  try {
    const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
    if (!brandId) {
      res.status(400).json({ success: false, error: "Brand ID is required" });
      return;
    }
    const result = await assetService.listAssetsByBrand(String(brandId));
    res.json({ success: true, count: result.length, data: result });
  } catch (error) {
    assetError(res, error, "Failed to retrieve brand assets");
  }
});

brandsRouter.post(
  "/:brandId/assets/:assetId/verification-challenges",
  async (req: Request, res: Response) => {
    try {
      const brandId = String(req.params.brandId);
      const assetId = String(req.params.assetId);
      const method = String(req.body?.method ?? "DNS_TXT").toUpperCase() as DomainChallengeMethod;
      const challenge = await assetService.createDomainChallenge(brandId, assetId, method);
      res.status(201).json({ success: true, data: challenge });
    } catch (error) {
      assetError(res, error, "Failed to create verification challenge");
    }
  },
);

brandsRouter.post(
  "/:brandId/assets/:assetId/verification-challenges/:challengeId/verify",
  async (req: Request, res: Response) => {
    try {
      const token = typeof req.body?.token === "string" ? req.body.token.trim() : "";
      if (!token || token.length > 512) {
        res.status(400).json({ success: false, error: "A valid challenge token is required." });
        return;
      }
      const asset = await assetService.verifyDomainChallenge({
        brandId: String(req.params.brandId),
        assetId: String(req.params.assetId),
        challengeId: String(req.params.challengeId),
        token,
      });
      res.json({ success: true, data: asset });
    } catch (error) {
      assetError(res, error, "Domain verification failed");
    }
  },
);

brandsRouter.post(
  "/:brandId/assets/:assetId/verify-association",
  async (req: Request, res: Response) => {
    try {
      const asset = await assetService.verifyAssociation(
        String(req.params.brandId),
        String(req.params.assetId),
      );
      res.json({ success: true, data: asset });
    } catch (error) {
      assetError(res, error, "Asset association verification failed");
    }
  },
);

brandsRouter.post(
  "/:brandId/assets/:assetId/revoke",
  async (req: Request, res: Response) => {
    try {
      requireRegistryOperator(req);
      const reason = typeof req.body?.reason === "string"
        ? req.body.reason
        : "Ownership or authorization revoked by registry user.";
      const asset = await assetService.revokeAsset(
        String(req.params.brandId),
        String(req.params.assetId),
        reason,
      );
      res.json({ success: true, data: asset });
    } catch (error) {
      assetError(res, error, "Failed to revoke asset");
    }
  },
);

brandsRouter.get(
  "/:brandId/assets/:assetId/verification-events",
  async (req: Request, res: Response) => {
    try {
      const events = await assetService.listVerificationEvents(
        String(req.params.brandId),
        String(req.params.assetId),
      );
      res.json({ success: true, count: events.length, data: events });
    } catch (error) {
      assetError(res, error, "Failed to retrieve verification history");
    }
  },
);

brandsRouter.delete("/:brandId/assets/:assetId", async (req: Request, res: Response) => {
  try {
    requireRegistryOperator(req);
    const brandId = String(req.params.brandId);
    const assetId = String(req.params.assetId);
    const asset = await assetService.revokeAsset(
      brandId,
      assetId,
      "Asset removal requested; retained as a revocation audit record.",
    );
    res.json({
      success: true,
      message: "Asset trust revoked; audit history retained.",
      data: asset,
    });
  } catch (error) {
    assetError(res, error, "Failed to revoke brand asset");
  }
});

export default brandsRouter;
