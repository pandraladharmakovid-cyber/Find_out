import { Router, type Request, type Response } from "express";

import { lookalikeDetectionService } from "../lookalike.service";
import { logoSimilarityService } from "../logo-similarity.service";
import { logoResolverService } from "../logo-resolver.service";
import { brandService } from "../brands";
import { BrandAssetsRepository } from "../repositories";
import { logger } from "../utils/logger";

export const intelligenceRouter = Router();

const MAX_IMAGE_BYTES = 2 * 1024 * 1024;

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function decodeBase64Image(value: string): Buffer {
  const payload = value.includes(",") ? value.slice(value.indexOf(",") + 1) : value;
  const buffer = Buffer.from(payload, "base64");
  if (buffer.length === 0) {
    throw new Error("The supplied image data is empty.");
  }
  if (buffer.length > MAX_IMAGE_BYTES) {
    throw new Error("Images must be 2 MB or smaller.");
  }
  return buffer;
}

intelligenceRouter.post("/lookalike/generate", (req: Request, res: Response) => {
  const brandName = asString(req.body?.brandName);
  const tld = (asString(req.body?.tld) || "com").replace(/^\./, "").toLowerCase();

  if (!brandName || brandName.length > 120) {
    res.status(400).json({
      success: false,
      error: "A brand name of 1-120 characters is required.",
    });
    return;
  }

  if (!/^[a-z0-9-]{2,24}$/.test(tld)) {
    res.status(400).json({ success: false, error: "Enter a valid TLD such as com, in, or net." });
    return;
  }

  const permutations = lookalikeDetectionService.generatePermutations(brandName, tld);

  res.json({
    success: true,
    data: {
      brandName,
      tld,
      count: permutations.length,
      permutations,
      // The generator only proposes candidates; it never asserts that a domain
      // exists or is malicious.
      note: "Generated candidates are hypotheses for review. Confirm registration and ownership before acting.",
    },
  });
});

intelligenceRouter.post("/lookalike/evaluate", (req: Request, res: Response) => {
  const domain = asString(req.body?.domain);
  const brandName = asString(req.body?.brandName);

  if (!domain || !brandName) {
    res.status(400).json({ success: false, error: "domain and brandName are required." });
    return;
  }

  const evaluation = lookalikeDetectionService.evaluateLookalike(domain, brandName);
  res.json({ success: true, data: evaluation });
});

intelligenceRouter.post("/lookalike/batch", (req: Request, res: Response) => {
  const brandName = asString(req.body?.brandName);
  const domains = Array.isArray(req.body?.domains)
    ? (req.body.domains as unknown[]).filter((entry): entry is string => typeof entry === "string")
    : [];

  if (!brandName || domains.length === 0) {
    res.status(400).json({ success: false, error: "brandName and a domains array are required." });
    return;
  }
  if (domains.length > 200) {
    res.status(400).json({ success: false, error: "Evaluate at most 200 domains per request." });
    return;
  }

  const results = domains.map((domain) => lookalikeDetectionService.evaluateLookalike(domain, brandName));
  res.json({
    success: true,
    data: {
      brandName,
      total: results.length,
      lookalikes: results.filter((result) => result.isLookalike).length,
      results,
    },
  });
});

intelligenceRouter.post("/logo/compare", async (req: Request, res: Response) => {
  const referenceUrl = asString(req.body?.referenceUrl);
  const targetUrl = asString(req.body?.targetUrl);
  const referenceBase64 = asString(req.body?.referenceBase64);
  const targetBase64 = asString(req.body?.targetBase64);
  const thresholdRaw = req.body?.threshold;
  const threshold =
    typeof thresholdRaw === "number" && thresholdRaw > 0 && thresholdRaw <= 1 ? thresholdRaw : undefined;

  try {
    let reference: Buffer | null = null;
    let target: Buffer | null = null;

    if (referenceBase64) reference = decodeBase64Image(referenceBase64);
    if (targetBase64) target = decodeBase64Image(targetBase64);

    if (!reference && !referenceUrl) {
      res.status(400).json({
        success: false,
        error: "Provide referenceUrl (HTTPS) or referenceBase64 for the registered logo.",
      });
      return;
    }
    if (!target && !targetUrl) {
      res.status(400).json({
        success: false,
        error: "Provide targetUrl (HTTPS) or targetBase64 for the suspect icon.",
      });
      return;
    }

    let result;
    if (reference && target) {
      result = await logoSimilarityService.compareImageBuffers({
        targetImage: target,
        referenceImage: reference,
        targetImageUri: "uploaded-suspect",
        referenceAssetUri: "uploaded-reference",
        threshold,
      });
    } else if (reference && targetUrl) {
      result = await logoSimilarityService.compareImageUrlToBuffer({
        targetImageUri: targetUrl,
        referenceImage: reference,
        referenceAssetUri: "uploaded-reference",
        threshold,
      });
    } else if (referenceUrl && target) {
      // Suspect icon uploaded, registered logo fetched from its HTTPS URL.
      result = await logoSimilarityService.compareImageBufferToUrl({
        targetImage: target,
        referenceAssetUri: referenceUrl,
        threshold,
      });
    } else {
      result = await logoSimilarityService.compareImageUrls({
        targetImageUri: targetUrl,
        referenceAssetUri: referenceUrl,
        threshold,
      });
    }

    res.json({
      success: true,
      data: {
        ...result,
        method: "8x8 greyscale average hash (64-bit perceptual hash)",
        note: "Perceptual similarity is supporting evidence, not proof of impersonation.",
      },
    });
  } catch (error) {
    logger.warn("[intelligence.routes] Logo comparison failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : "Logo comparison failed.",
    });
  }
});

intelligenceRouter.post("/logo/hash", async (req: Request, res: Response) => {
  const imageBase64 = asString(req.body?.imageBase64);
  if (!imageBase64) {
    res.status(400).json({ success: false, error: "imageBase64 is required." });
    return;
  }

  try {
    const buffer = decodeBase64Image(imageBase64);
    const hash = await logoSimilarityService.computeImageHash(buffer);
    res.json({
      success: true,
      data: { hash, bits: hash.length, bytes: buffer.length, algorithm: "average-hash-8x8" },
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not hash the image.",
    });
  }
});

/**
 * Streams the real logo of a public domain. The frontend uses this as an
 * <img> source, so the browser never has to reach a third-party host and the
 * image keeps working even when the site blocks hot-linking.
 */
intelligenceRouter.get("/logo/domain/:domain/image", async (req: Request, res: Response) => {
  const raw = Array.isArray(req.params.domain) ? req.params.domain[0] : req.params.domain;
  const refresh = req.query.refresh === "1";

  if (!raw || raw.length > 253) {
    res.status(400).json({ success: false, error: "A domain is required." });
    return;
  }

  try {
    const { logo, buffer } = await logoResolverService.resolveWithBytes(raw, { refresh });

    if (!buffer || logo.status !== "resolved") {
      res.status(404).json({
        success: false,
        error: logo.detail,
        data: { ...logo },
      });
      return;
    }

    res.setHeader("Content-Type", logo.contentType || "image/png");
    res.setHeader("Cache-Control", "public, max-age=21600, stale-while-revalidate=86400");
    res.setHeader("X-Logo-Source", logo.sourceUrl ?? "");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(buffer);
  } catch (error) {
    logger.warn("[intelligence.routes] Logo resolution failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(502).json({
      success: false,
      error: error instanceof Error ? error.message : "The logo could not be resolved.",
    });
  }
});

/** Metadata for the same resolution: dimensions, hash, declaration source. */
intelligenceRouter.get("/logo/domain/:domain/meta", async (req: Request, res: Response) => {
  const raw = Array.isArray(req.params.domain) ? req.params.domain[0] : req.params.domain;
  if (!raw || raw.length > 253) {
    res.status(400).json({ success: false, error: "A domain is required." });
    return;
  }

  try {
    const logo = await logoResolverService.resolve(raw, { refresh: req.query.refresh === "1" });
    res.status(logo.status === "resolved" ? 200 : 404).json({
      success: logo.status === "resolved",
      data: {
        ...logo,
        imageUrl: `/api/intelligence/logo/domain/${encodeURIComponent(logo.domain)}/image`,
      },
    });
  } catch (error) {
    res.status(502).json({
      success: false,
      error: error instanceof Error ? error.message : "The logo could not be resolved.",
    });
  }
});

/**
 * Streams a brand's registered logo. Priority: stored upload → verified logo
 * asset URL → logo declared on the brand's own primary domain.
 */
intelligenceRouter.get("/logo/brand/:brandId/image", async (req: Request, res: Response) => {
  const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
  if (!brandId) {
    res.status(400).json({ success: false, error: "A brand id is required." });
    return;
  }

  try {
    const brand = await brandService.getBrandById(brandId);
    if (!brand) {
      res.status(404).json({ success: false, error: "Brand not found." });
      return;
    }

    const assets = await BrandAssetsRepository.findByBrandId(brandId);
    const logoAssets = assets.filter(
      (asset) => asset.asset_type.toLowerCase() === "logo" && asset.is_verified,
    );

    for (const asset of logoAssets) {
      if (Buffer.isBuffer(asset.image_data) && asset.image_data.length > 0) {
        const contentType =
          asset.image_data.subarray(0, 4).toString("ascii") === "RIFF"
            ? "image/webp"
            : asset.image_data[0] === 0xff && asset.image_data[1] === 0xd8
              ? "image/jpeg"
              : "image/png";
        res.setHeader("Content-Type", contentType);
        res.setHeader("Cache-Control", "public, max-age=86400");
        res.setHeader("X-Logo-Source", "registered-upload");
        res.send(asset.image_data);
        return;
      }

      const candidateUrl = asset.canonical_url ?? brand.logo_url;
      if (candidateUrl) {
        const remote = await logoResolverService.resolveWithBytes(candidateUrl, {});
        if (remote.buffer) {
          res.setHeader("Content-Type", remote.logo.contentType || "image/png");
          res.setHeader("Cache-Control", "public, max-age=21600");
          res.setHeader("X-Logo-Source", candidateUrl);
          res.send(remote.buffer);
          return;
        }
      }
    }

    if (brand.logo_url) {
      const remote = await logoResolverService.resolveWithBytes(brand.logo_url, {});
      if (remote.buffer) {
        res.setHeader("Content-Type", remote.logo.contentType || "image/png");
        res.setHeader("Cache-Control", "public, max-age=21600");
        res.setHeader("X-Logo-Source", brand.logo_url);
        res.send(remote.buffer);
        return;
      }
    }

    const resolved = await logoResolverService.resolveWithBytes(brand.primary_domain, {});
    if (resolved.buffer) {
      res.setHeader("Content-Type", resolved.logo.contentType || "image/png");
      res.setHeader("Cache-Control", "public, max-age=21600");
      res.setHeader("X-Logo-Source", resolved.logo.sourceUrl ?? brand.primary_domain);
      res.send(resolved.buffer);
      return;
    }

    res.status(404).json({
      success: false,
      error: "No logo is registered for this brand and none could be resolved from its primary domain.",
      data: { brandId, domain: brand.primary_domain, attempts: resolved.logo.attempts },
    });
  } catch (error) {
    logger.warn("[intelligence.routes] Brand logo streaming failed", {
      error: error instanceof Error ? error.message : "unknown",
    });
    res.status(502).json({
      success: false,
      error: error instanceof Error ? error.message : "The brand logo could not be loaded.",
    });
  }
});

intelligenceRouter.get("/brands/:brandId/logo", async (req: Request, res: Response) => {
  const brandId = Array.isArray(req.params.brandId) ? req.params.brandId[0] : req.params.brandId;
  if (!brandId) {
    res.status(400).json({ success: false, error: "A brand id is required." });
    return;
  }

  try {
    const brand = await brandService.getBrandById(brandId);
    if (!brand) {
      res.status(404).json({ success: false, error: "Brand not found." });
      return;
    }

    const assets = await BrandAssetsRepository.findByBrandId(brandId);
    const logos = assets.filter((asset) => asset.asset_type.toLowerCase() === "logo");

    res.json({
      success: true,
      data: {
        brandId,
        brandName: brand.name,
        brandLogoUrl: brand.logo_url,
        logos: logos.map((asset) => ({
          id: asset.id,
          identifier: asset.identifier,
          canonicalUrl: asset.canonical_url,
          verificationStatus: asset.verification_status,
          isVerified: asset.is_verified,
          hasStoredImage: Buffer.isBuffer(asset.image_data) && asset.image_data.length > 0,
        })),
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Could not load brand logos.",
    });
  }
});

export default intelligenceRouter;
