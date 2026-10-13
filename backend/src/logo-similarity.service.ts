import { lookup } from "node:dns/promises";
import sharp from "sharp";
import { config } from "./config";
import { urlSafetyEngine } from "./url-safety";
import { logger } from "./utils/logger";

export interface LogoComparisonResult {
  targetImageUri: string;
  referenceAssetUri: string;
  hammingDistance: number;
  similarityScore: number;
  isImpersonating: boolean;
  confidence: number;
}

const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_IMAGE_PIXELS = 16_000_000;

export class LogoSimilarityService {
  hammingDistance(hashA: string, hashB: string): number {
    if (hashA.length !== hashB.length) {
      const maxLen = Math.max(hashA.length, hashB.length);
      hashA = hashA.padEnd(maxLen, "0");
      hashB = hashB.padEnd(maxLen, "0");
    }
    let distance = 0;
    for (let index = 0; index < hashA.length; index++) {
      if (hashA[index] !== hashB[index]) distance++;
    }
    return distance;
  }

  async computeImageHash(image: Buffer): Promise<string> {
    if (!image.length) throw new Error("Cannot compare an empty image.");
    const pixels = await sharp(image, { limitInputPixels: MAX_IMAGE_PIXELS })
      .resize(8, 8, { fit: "fill" })
      .greyscale()
      .raw()
      .toBuffer();
    const average = pixels.reduce((sum, pixel) => sum + pixel, 0) / pixels.length;
    return Array.from(pixels, (pixel) => (pixel >= average ? "1" : "0")).join("");
  }

  async compareImageBuffers(params: {
    targetImage: Buffer;
    referenceImage: Buffer;
    targetImageUri?: string;
    referenceAssetUri?: string;
    threshold?: number;
  }): Promise<LogoComparisonResult> {
    const [targetHash, referenceHash] = await Promise.all([
      this.computeImageHash(params.targetImage),
      this.computeImageHash(params.referenceImage),
    ]);
    return this.buildResult({
      targetHash,
      referenceHash,
      targetImageUri: params.targetImageUri ?? "uploaded-image",
      referenceAssetUri: params.referenceAssetUri ?? "registered-logo",
      threshold: params.threshold,
    });
  }

  async compareImageUrls(params: {
    targetImageUri: string;
    referenceAssetUri: string;
    threshold?: number;
  }): Promise<LogoComparisonResult> {
    const [targetImage, referenceImage] = await Promise.all([
      this.fetchImage(params.targetImageUri),
      this.fetchImage(params.referenceAssetUri),
    ]);
    return this.compareImageBuffers({
      targetImage,
      referenceImage,
      targetImageUri: params.targetImageUri,
      referenceAssetUri: params.referenceAssetUri,
      threshold: params.threshold,
    });
  }

  async compareImageUrlToBuffer(params: {
    targetImageUri: string;
    referenceImage: Buffer;
    referenceAssetUri?: string;
    threshold?: number;
  }): Promise<LogoComparisonResult> {
    const targetImage = await this.fetchImage(params.targetImageUri);
    return this.compareImageBuffers({
      targetImage,
      referenceImage: params.referenceImage,
      targetImageUri: params.targetImageUri,
      referenceAssetUri: params.referenceAssetUri,
      threshold: params.threshold,
    });
  }

  private async fetchImage(uri: string): Promise<Buffer> {
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw new Error("Image address must be a valid absolute URL.");
    }
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new Error("Logo comparison accepts public HTTPS image URLs only.");
    }
    if (!urlSafetyEngine.validateTargetUrl(url.toString()).isAllowed) {
      throw new Error("Private or internal image hosts are not allowed.");
    }

    const addresses = await lookup(url.hostname, { all: true, verbatim: true });
    if (
      addresses.length === 0 ||
      addresses.some(({ address }) => {
        const host = address.includes(":") ? `[${address}]` : address;
        return !urlSafetyEngine.validateTargetUrl(`https://${host}/`).isAllowed;
      })
    ) {
      throw new Error("Image host resolves to a private or reserved network address.");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(url, {
        headers: { Accept: "image/*" },
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Image source returned HTTP ${response.status}.`);
      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      if (!contentType.startsWith("image/")) throw new Error("Image source did not return an image.");
      const declaredLength = Number(response.headers.get("content-length") ?? 0);
      if (declaredLength > MAX_IMAGE_BYTES) throw new Error("Image exceeds the 2 MB limit.");
      if (!response.body) throw new Error("Image source returned no response body.");
      const reader = response.body.getReader();
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        const bytes = Buffer.from(chunk.value);
        totalBytes += bytes.length;
        if (totalBytes > MAX_IMAGE_BYTES) {
          await reader.cancel();
          throw new Error("Image exceeds the 2 MB limit.");
        }
        chunks.push(bytes);
      }
      if (totalBytes === 0) throw new Error("Image source returned an empty body.");
      return Buffer.concat(chunks, totalBytes);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown image download error";
      logger.warn("[logo-similarity] Image download failed", {
        hostname: url.hostname,
        error: message,
      });
      throw new Error(`Unable to retrieve logo image: ${message}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildResult(params: {
    targetHash: string;
    referenceHash: string;
    targetImageUri: string;
    referenceAssetUri: string;
    threshold?: number;
  }): LogoComparisonResult {
    const threshold = params.threshold ?? 0.82;
    const distance = this.hammingDistance(params.targetHash, params.referenceHash);
    const similarityScore = Number((1 - distance / 64).toFixed(3));
    const isImpersonating = similarityScore >= threshold;
    logger.debug("[logo-similarity] Perceptual image comparison completed", {
      targetUri: params.targetImageUri,
      referenceUri: params.referenceAssetUri,
      distance,
      similarityScore,
      isImpersonating,
    });
    return {
      targetImageUri: params.targetImageUri,
      referenceAssetUri: params.referenceAssetUri,
      hammingDistance: distance,
      similarityScore,
      isImpersonating,
      confidence: similarityScore >= 0.94 ? 0.95 : similarityScore >= threshold ? 0.8 : 0.6,
    };
  }
}

export const logoSimilarityService = new LogoSimilarityService();
export default logoSimilarityService;
