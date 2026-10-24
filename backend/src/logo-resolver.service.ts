import sharp from "sharp";

import { pinnedHttpsClient } from "./safe-https";
import { logoSimilarityService } from "./logo-similarity.service";
import { logger } from "./utils/logger";

/**
 * Resolves the real, publicly served logo of a domain.
 *
 * The dashboard used to render whatever `logo_url` happened to be stored, and a
 * brand registered without one showed nothing. This service fetches the site's
 * own icon/image declaration (apple-touch-icon → icon → og:image → favicon.ico)
 * through the SSRF-pinned HTTPS client, validates that the bytes really are an
 * image, and caches the result.
 *
 * Nothing is invented: when no usable image can be fetched the result is
 * `not_found` with the reasons collected along the way.
 */

export type LogoResolveStatus = "resolved" | "not_found" | "unavailable";

export interface ResolvedLogo {
  domain: string;
  status: LogoResolveStatus;
  sourceUrl: string | null;
  contentType: string;
  width: number;
  height: number;
  bytes: number;
  hash: string | null;
  declaredIn: string | null;
  cached: boolean;
  attempts: Array<{ url: string; outcome: string }>;
  detail: string;
}

interface CacheEntry {
  logo: ResolvedLogo;
  buffer: Buffer | null;
  expiresAt: number;
}

const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_HTML_BYTES = 512 * 1024;
const ICON_ACCEPT = "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.9,*/*;q=0.5";

const cache = new Map<string, CacheEntry>();

function normaliseDomain(input: string): string {
  const trimmed = input.trim().toLowerCase();
  const withScheme = /^https?:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const url = new URL(withScheme);
    return url.hostname.replace(/^www\./, "").replace(/\.$/, "");
  } catch {
    return trimmed.replace(/^www\./, "").replace(/\/.*$/, "");
  }
}

/** Extracts icon/image candidates from a homepage, largest declared size first. */
export function extractLogoCandidates(
  html: string,
  baseUrl: string,
): Array<{ url: string; declaredIn: string; weight: number }> {
  const candidates: Array<{ url: string; declaredIn: string; weight: number }> = [];
  const seen = new Set<string>();

  const push = (rawHref: string, declaredIn: string, weight: number): void => {
    const href = rawHref.trim();
    if (!href || href.startsWith("data:") || href.startsWith("javascript:")) return;

    let absolute: string;
    try {
      absolute = new URL(href, baseUrl).toString();
    } catch {
      return;
    }

    if (!absolute.startsWith("https://")) return;
    if (seen.has(absolute)) return;
    seen.add(absolute);
    candidates.push({ url: absolute, declaredIn, weight });
  };

  const linkTags = [...html.matchAll(/<link\b[^>]*>/gi)].map((match) => match[0]);

  for (const tag of linkTags) {
    const rel = /rel\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]?.toLowerCase() ?? "";
    const href = /href\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1] ?? "";
    const sizes = /sizes\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1] ?? "";

    if (!href) continue;

    if (rel.includes("apple-touch-icon")) {
      const largest = Math.max(
        0,
        ...sizes
          .split(/\s+/)
          .map((size) => Number.parseInt(size.split("x")[0] ?? "0", 10))
          .filter((value) => Number.isFinite(value)),
      );
      push(href, "apple-touch-icon", 100 + Math.min(largest, 512) / 10);
    } else if (rel.includes("icon")) {
      const largest = Math.max(
        0,
        ...sizes
          .split(/\s+/)
          .map((size) => Number.parseInt(size.split("x")[0] ?? "0", 10))
          .filter((value) => Number.isFinite(value)),
      );
      push(href, rel.includes("shortcut") ? "shortcut icon" : "icon", 80 + Math.min(largest, 512) / 10);
    } else if (rel.includes("mask-icon")) {
      push(href, "mask-icon", 20); // Monochrome; last resort only.
    }
  }

  const ogImage =
    /<meta[^>]+property\s*=\s*["']og:image["'][^>]*content\s*=\s*["']([^"']+)["']/i.exec(html)?.[1] ??
    /<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*property\s*=\s*["']og:image["']/i.exec(html)?.[1];
  if (ogImage) push(ogImage, "og:image", 60);

  const twitterImage =
    /<meta[^>]+name\s*=\s*["']twitter:image["'][^>]*content\s*=\s*["']([^"']+)["']/i.exec(html)?.[1];
  if (twitterImage) push(twitterImage, "twitter:image", 50);

  // Manifest icons are commonly the highest-resolution asset available.
  const manifestHref = /<link[^>]+rel\s*=\s*["']manifest["'][^>]*href\s*=\s*["']([^"']+)["']/i.exec(html)?.[1];
  if (manifestHref) {
    push(manifestHref, "manifest", 40);
  }

  return candidates.sort((a, b) => b.weight - a.weight);
}

/**
 * Follows same-purpose redirects (http→https, apex→www) a bounded number of
 * times. Every hop is re-validated by the pinned client, so an open redirect
 * cannot be used to reach a private address.
 */
async function fetchHtmlFollowingRedirects(
  url: string,
  attempts: Array<{ url: string; outcome: string }>,
): Promise<{ status: number; body: string; finalUrl: string } | null> {
  let current = url;

  for (let hop = 0; hop < 4; hop += 1) {
    const response = await pinnedHttpsClient.get(current, {
      accept: "text/html,application/xhtml+xml",
      maxBytes: MAX_HTML_BYTES,
    });
    attempts.push({ url: current, outcome: `HTTP ${response.status}` });

    if (response.status >= 300 && response.status < 400 && response.location) {
      const next = new URL(response.location, current).toString();
      if (!next.startsWith("https://")) return null;
      current = next;
      continue;
    }

    if (response.status >= 200 && response.status < 300) {
      return { status: response.status, body: response.body, finalUrl: current };
    }

    return null;
  }

  return null;
}

async function fetchImageFollowingRedirects(
  url: string,
  attempts: Array<{ url: string; outcome: string }>,
): Promise<
  | { ok: true; buffer: Buffer; contentType: string; finalUrl: string }
  | { ok: false; outcome: string }
> {
  let current = url;

  for (let hop = 0; hop < 4; hop += 1) {
    const response = await pinnedHttpsClient.getBinary(current, {
      accept: ICON_ACCEPT,
      maxBytes: MAX_IMAGE_BYTES,
    });

    if (response.status >= 300 && response.status < 400 && response.location) {
      const next = new URL(response.location, current).toString();
      if (!next.startsWith("https://")) return { ok: false, outcome: "redirected to a non-HTTPS URL" };
      current = next;
      continue;
    }

    if (response.status < 200 || response.status >= 300) {
      return { ok: false, outcome: `HTTP ${response.status}` };
    }
    if (!response.contentType.toLowerCase().startsWith("image/")) {
      return { ok: false, outcome: `not an image (${response.contentType || "unknown"})` };
    }
    if (response.body.length < 256) {
      return { ok: false, outcome: `too small (${response.body.length} bytes)` };
    }

    return { ok: true, buffer: response.body, contentType: response.contentType, finalUrl: current };
  }

  return { ok: false, outcome: "too many redirects" };
}

export class LogoResolverService {
  private readonly inflight = new Map<string, Promise<CacheEntry>>();

  /** Metadata-only resolve; never returns the image bytes. */
  async resolve(domainInput: string, options: { refresh?: boolean } = {}): Promise<ResolvedLogo> {
    const entry = await this.load(domainInput, options.refresh === true);
    return { ...entry.logo };
  }

  /** Resolve and return the image bytes (used by the proxying route). */
  async resolveWithBytes(
    domainInput: string,
    options: { refresh?: boolean } = {},
  ): Promise<{ logo: ResolvedLogo; buffer: Buffer | null }> {
    const entry = await this.load(domainInput, options.refresh === true);
    return { logo: entry.logo, buffer: entry.buffer };
  }

  private async load(domainInput: string, refresh: boolean): Promise<CacheEntry> {
    const domain = normaliseDomain(domainInput);
    const cached = cache.get(domain);
    if (!refresh && cached && cached.expiresAt > Date.now()) {
      return { ...cached, logo: { ...cached.logo, cached: true } };
    }

    const pending = this.inflight.get(domain);
    if (pending) return pending;

    const task = this.fetchLogo(domain).finally(() => {
      this.inflight.delete(domain);
    });
    this.inflight.set(domain, task);

    const entry = await task;
    cache.set(domain, entry);
    return entry;
  }

  private async fetchLogo(domain: string): Promise<CacheEntry> {
    const attempts: Array<{ url: string; outcome: string }> = [];
    const bases = [`https://${domain}`, `https://www.${domain}`];

    let candidates: Array<{ url: string; declaredIn: string; weight: number }> = [];

    for (const base of bases) {
      try {
        const page = await fetchHtmlFollowingRedirects(base, attempts);
        if (page && page.body) {
          candidates = extractLogoCandidates(page.body, `${page.finalUrl}/`);
          if (candidates.length > 0) break;
        }
      } catch (error) {
        attempts.push({
          url: base,
          outcome: error instanceof Error ? error.message : "request failed",
        });
      }
    }

    // Well-known locations are always worth trying, even without a declaration.
    for (const base of bases) {
      for (const path of ["/favicon.ico", "/apple-touch-icon.png"]) {
        const url = `${base}${path}`;
        if (!candidates.some((candidate) => candidate.url === url)) {
          candidates.push({ url, declaredIn: "well-known", weight: 10 });
        }
      }
    }

    for (const candidate of candidates.slice(0, 10)) {
      try {
        const image = await fetchImageFollowingRedirects(candidate.url, attempts);
        if (!image.ok) {
          attempts.push({ url: candidate.url, outcome: image.outcome });
          continue;
        }

        const response = { body: image.buffer, contentType: image.contentType };

        let metadata: { width?: number; height?: number };
        try {
          metadata = await sharp(response.body, { failOn: "none" }).metadata();
        } catch {
          attempts.push({ url: candidate.url, outcome: "unreadable image bytes" });
          continue;
        }

        if (!metadata.width || !metadata.height) {
          attempts.push({ url: candidate.url, outcome: "image has no dimensions" });
          continue;
        }

        const hash = await logoSimilarityService.computeImageHash(response.body);

        attempts.push({ url: candidate.url, outcome: `image ${metadata.width}x${metadata.height}` });

        return {
          buffer: response.body,
          expiresAt: Date.now() + CACHE_TTL_MS,
          logo: {
            domain,
            status: "resolved",
            sourceUrl: image.finalUrl,
            contentType: response.contentType.split(";")[0] ?? "image/png",
            width: metadata.width,
            height: metadata.height,
            bytes: response.body.length,
            hash,
            declaredIn: candidate.declaredIn,
            cached: false,
            attempts,
            detail: `Found a ${metadata.width}x${metadata.height} logo declared as ${candidate.declaredIn}.`,
          },
        };
      } catch (error) {
        attempts.push({
          url: candidate.url,
          outcome: error instanceof Error ? error.message : "fetch failed",
        });
      }
    }

    logger.warn("[logo-resolver] No usable logo found", { domain, attempts: attempts.length });

    return {
      buffer: null,
      expiresAt: Date.now() + 10 * 60 * 1000, // Retry sooner when nothing was found.
      logo: {
        domain,
        status: candidates.length === 0 ? "unavailable" : "not_found",
        sourceUrl: null,
        contentType: "",
        width: 0,
        height: 0,
        bytes: 0,
        hash: null,
        declaredIn: null,
        cached: false,
        attempts,
        detail:
          candidates.length === 0
            ? "The site did not declare an icon and the well-known icon paths could not be read."
            : "Candidates were found but none returned a usable image.",
      },
    };
  }

  /** Test helper. */
  clearCache(): void {
    cache.clear();
    this.inflight.clear();
  }
}

export const logoResolverService = new LogoResolverService();
export default logoResolverService;
