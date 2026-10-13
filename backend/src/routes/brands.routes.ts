import { Router, type Request, type Response } from "express";
import { brandService } from "../brands";
import { BrandAssetsRepository, ExclusionRulesRepository } from "../repositories";
import { logger } from "../utils/logger";
import { query } from "../db";
import { logoSimilarityService } from "../logo-similarity.service";

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

    let parsedDomain: URL;
    try {
      parsedDomain = new URL(
        /^https?:\/\//i.test(suppliedDomain.trim())
          ? suppliedDomain.trim()
          : `https://${suppliedDomain.trim()}`
      );
      if (!["http:", "https:"].includes(parsedDomain.protocol)) throw new Error("Unsupported protocol");
    } catch {
      res.status(400).json({
        success: false,
        error: "The brand primary domain must be a valid HTTP or HTTPS hostname.",
      });
      return;
    }

    const normalizeStringList = (value: unknown): string[] =>
      Array.isArray(value)
        ? value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean)
        : [];

    const brand = await brandService.createBrand({
      name: String(name).trim(),
      primaryDomain: parsedDomain.hostname.toLowerCase(),
      industry: industry ? String(industry) : undefined,
      lookalikeThreshold: typeof lookalikeThreshold === "number" ? lookalikeThreshold : 0.75,
      alternateNames: normalizeStringList(alternateNames ?? alternate_names),
      associatedDomains: domainList.map((value) => value.trim()).filter(Boolean),
      keywords: normalizeStringList(keywords),
      website: website ? String(website).trim() : parsedDomain.origin,
      logoUrl: logoUrl ?? logo_url ?? null,
      description: description ?? null,
    });

    res.status(201).json({
      success: true,
      data: brand,
    });
  } catch (error) {
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
      brands.map(async (brand) => ({
        ...brand,
        assets: await BrandAssetsRepository.findByBrandId(brand.id),
      }))
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
    logger.error("[brands.routes] Failed to update brand", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to update brand",
    });
  }
});

// ==========================================
// 2. Official Brand Assets Management
// ==========================================

brandsRouter.post("/:brandId/assets", async (req: Request, res: Response) => {
  try {
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
      is_verified,
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

    const result = await BrandAssetsRepository.create({
      brand_id: String(brandId),
      asset_type: resolvedType.toLowerCase(),
      platform: typeof platform === "string" && platform.trim() ? platform.trim().toLowerCase() : "unknown",
      identifier: resolvedIdentifier.trim(),
      value: resolvedIdentifier.trim(),
      canonical_url: canonicalAssetUrl,
      hash_signature: logoHash,
      image_data: logoImage,
      is_verified: typeof is_verified === "boolean" ? is_verified : false,
      metadata: {
        ...(meta ?? {}),
        ...(metadata ?? {}),
        ...(typeof imageMime === "string" ? { imageMime } : {}),
      },
    });
    if (["domain", "subdomain", "website"].includes(resolvedType.toLowerCase())) {
      await ExclusionRulesRepository.addRule(
        resolvedIdentifier.trim(),
        `Registered official ${resolvedType.toLowerCase()} for brand ${brandId}`
      );
    }

    res.status(201).json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.error("[brands.routes] Failed to create brand asset", { error });
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to associate asset with brand",
    });
  }
});

brandsRouter.get("/:brandId/assets", async (req: Request, res: Response) => {
  try {
    const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
    if (!brandId) {
      res.status(400).json({ success: false, error: "Brand ID is required" });
      return;
    }

    const result = await query(
      `SELECT id, brand_id, asset_type, platform, identifier, value, canonical_url,
              hash_signature, is_verified, metadata, created_at, updated_at
       FROM official_assets WHERE brand_id = $1 ORDER BY created_at DESC;`,
      [String(brandId)]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to retrieve brand assets",
    });
  }
});

brandsRouter.delete("/:brandId/assets/:assetId", async (req: Request, res: Response) => {
  try {
    const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
    const assetId = Array.isArray(req.params.assetId) ? req.params.assetId[0] : req.params.assetId;
    if (!assetId || !brandId) {
      res.status(400).json({ success: false, error: "Brand ID and asset ID are required" });
      return;
    }

    const deleted = await query(
      `DELETE FROM official_assets WHERE id = $1 AND brand_id = $2 RETURNING id;`,
      [String(assetId), String(brandId)]
    );
    if (deleted.rowCount === 0) {
      res.status(404).json({ success: false, error: "Official asset not found for this brand" });
      return;
    }

    res.json({
      success: true,
      message: "Asset removed successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Failed to delete brand asset",
    });
  }
});

export default brandsRouter;