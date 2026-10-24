import { config } from "../config";
import { logger } from "../utils/logger";
import { runWithDeadline, mapWithConcurrency } from "../utils/timeout";

/**
 * Google Play Store client.
 *
 * Google publishes no public "search apps" API for third parties, so this
 * client reads the public store search page and extracts the structured card
 * data that the page already renders server-side. Parsing is defensive: any
 * markup change produces an explicit "unavailable" status instead of inventing
 * results, and every failure is surfaced in the monitoring source report.
 */

export interface PlayStoreListing {
  packageId: string;
  title: string;
  developer: string;
  description: string;
  iconUrl: string;
  storeUrl: string;
  rating?: number;
  reviewCount?: number;
}

export interface PlayStoreSearchResult {
  source: "google_play";
  status: "available" | "unavailable";
  query: string;
  listings: PlayStoreListing[];
  error?: string;
  latencyMs: number;
}

const PLAY_BASE = "https://play.google.com";
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const CACHE_TTL_MS = 10 * 60 * 1000;

function decodeEntities(value: string): string {
  return value
    .replace(/&#(\d+);/g, (_match, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, code: string) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ");
}

function firstMatch(segment: string, patterns: RegExp[]): string {
  for (const pattern of patterns) {
    const match = pattern.exec(segment);
    if (match?.[1]) {
      return decodeEntities(match[1]).trim();
    }
  }
  return "";
}

interface ParsedCard {
  packageId: string;
  title: string;
  developer: string;
  iconUrl: string;
  rating?: number;
}

/**
 * Extracts app cards from a Play Store search page. Exported for tests so the
 * parser can be verified against a stored fixture without network access.
 */
export function parsePlayStoreSearchHtml(
  html: string,
  limit: number,
): Array<{ packageId: string; title: string; developer: string; iconUrl: string; rating?: number }> {
  const matches = [...html.matchAll(/\/store\/apps\/details\?id=([A-Za-z0-9._]+)/g)];
  const cards: ParsedCard[] = [];
  const seen = new Set<string>();

  for (let index = 0; index < matches.length; index += 1) {
    const match = matches[index];
    const packageId = match?.[1];
    const start = match?.index ?? 0;
    if (!packageId || seen.has(packageId)) continue;

    const nextStart = matches[index + 1]?.index ?? Math.min(html.length, start + 6000);
    const segment = html.slice(start, Math.min(nextStart, start + 6000));

    const title = firstMatch(segment, [
      /class="vWM94c">([^<]+)</,
      /class="DdYX5">([^<]+)</,
      /aria-label="([^"]+)"\s+class="Qfxief"/,
    ]);
    const developer = firstMatch(segment, [
      /class="LbQbAe">([^<]+)</,
      /class="wMUdtb">([^<]+)</,
    ]);

    if (!title || !developer) continue;

    const iconUrl = firstMatch(segment, [
      /<img src="(https:\/\/play-lh\.googleusercontent\.com\/[^"]+)"[^>]*class="T75of bzqKMd"/,
      /<img src="(https:\/\/play-lh\.googleusercontent\.com\/[^"]+)"/,
    ]);
    const ratingText = firstMatch(segment, [
      /aria-label="Rated ([\d.]+) stars?/,
      /<span aria-hidden="true">(\d\.\d)<\/span>/,
    ]);
    const rating = Number.parseFloat(ratingText);

    seen.add(packageId);
    cards.push({
      packageId,
      title,
      developer,
      iconUrl,
      ...(Number.isFinite(rating) ? { rating } : {}),
    });

    if (cards.length >= limit) break;
  }

  return cards;
}

/** Parses the metadata of a Play Store app detail page. Exported for tests. */
export function parsePlayStoreDetailHtml(html: string): {
  title: string;
  developer: string;
  description: string;
  iconUrl: string;
} {
  const title = firstMatch(html, [
    /<h1[^>]*>[\s\S]{0,400}?<span[^>]*>([^<]{1,200})<\/span>/,
    /<title[^>]*>([^<]{1,200})[\s\S]{0,80}?<\/title>/,
  ]);
  const developer = firstMatch(html, [
    /class="Vbfug auoIOc">[\s\S]{0,300}?<span>([^<]{1,120})<\/span>/,
    /<div class="Vbfug[^"]*">[\s\S]{0,300}?<span>([^<]{1,120})<\/span>/,
  ]);
  const description = firstMatch(html, [
    /property="og:description" content="([^"]{0,2000})"/,
    /name="description" content="([^"]{0,2000})"/,
  ]);
  const iconUrl = firstMatch(html, [
    /property="og:image" content="([^"]+play-lh\.googleusercontent\.com[^"]*)"/,
    /property="og:image" content="([^"]+)"/,
  ]);

  return {
    title: title.replace(/\s*[-–]\s*Apps on Google Play\s*$/i, "").trim(),
    developer,
    description: decodeEntities(description),
    iconUrl: iconUrl.split("=")[0] ?? iconUrl,
  };
}

export class GooglePlayClient {
  private cache = new Map<string, { expiresAt: number; result: PlayStoreSearchResult }>();

  private async fetchHtml(url: string, timeoutMs: number): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          "Accept-Language": `${config.GOOGLE_PLAY_LANGUAGE},en;q=0.8`,
          Accept: "text/html,application/xhtml+xml",
        },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`Google Play returned HTTP ${response.status}.`);
      }
      return await response.text();
    } finally {
      clearTimeout(timer);
    }
  }

  async search(
    searchQuery: string,
    options: { limit?: number; timeoutMs?: number } = {},
  ): Promise<PlayStoreSearchResult> {
    const startedAt = Date.now();
    const limit = Math.max(1, Math.min(options.limit ?? config.APP_STORE_RESULT_LIMIT, 50));
    const cacheKey = `${searchQuery.toLowerCase()}::${limit}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }

    const timeoutMs = options.timeoutMs ?? config.MONITORING_SOURCE_TIMEOUT_MS;

    const outcome = await runWithDeadline(
      async () => {
        const url = new URL(`${PLAY_BASE}/store/search`);
        url.searchParams.set("q", searchQuery);
        url.searchParams.set("c", "apps");
        url.searchParams.set("hl", config.GOOGLE_PLAY_LANGUAGE);
        url.searchParams.set("gl", config.GOOGLE_PLAY_COUNTRY);

        const html = await this.fetchHtml(url.toString(), timeoutMs);
        const cards = parsePlayStoreSearchHtml(html, limit);

        if (cards.length === 0) {
          throw new Error(
            "Google Play returned a page without parseable app cards. The store markup may have changed.",
          );
        }

        return cards;
      },
      timeoutMs,
      "Google Play search",
    );

    let result: PlayStoreSearchResult;

    if (outcome.value) {
      result = {
        source: "google_play",
        status: "available",
        query: searchQuery,
        listings: outcome.value.map((card) => ({
          packageId: card.packageId,
          title: card.title,
          developer: card.developer,
          description: "",
          iconUrl: card.iconUrl,
          storeUrl: `${PLAY_BASE}/store/apps/details?id=${encodeURIComponent(card.packageId)}`,
          ...(card.rating !== undefined ? { rating: card.rating } : {}),
        })),
        latencyMs: outcome.durationMs,
      };
    } else {
      result = {
        source: "google_play",
        status: "unavailable",
        query: searchQuery,
        listings: [],
        error: outcome.error ?? "Google Play search failed.",
        latencyMs: outcome.durationMs,
      };
      logger.warn("[google-play] Search unavailable", {
        query: searchQuery,
        error: result.error,
      });
    }

    if (result.status === "available") {
      this.cache.set(cacheKey, { expiresAt: Date.now() + CACHE_TTL_MS, result });
    }

    logger.debug("[google-play] Search completed", {
      query: searchQuery,
      status: result.status,
      listings: result.listings.length,
      latencyMs: Date.now() - startedAt,
    });

    return result;
  }

  /**
   * Enriches the most relevant listings with description + icon. Only a small
   * number of apps are enriched to keep a monitoring scan fast.
   */
  async enrichListings(
    listings: PlayStoreListing[],
    options: { limit?: number; timeoutMs?: number } = {},
  ): Promise<PlayStoreListing[]> {
    const limit = Math.max(0, options.limit ?? 5);
    const timeoutMs = options.timeoutMs ?? Math.min(20_000, config.MONITORING_SOURCE_TIMEOUT_MS);
    const targets = listings.slice(0, limit);

    const enriched = await mapWithConcurrency(targets, 3, async (listing) => {
      const outcome = await runWithDeadline(
        async () => {
          const html = await this.fetchHtml(listing.storeUrl, timeoutMs);
          return parsePlayStoreDetailHtml(html);
        },
        timeoutMs,
        `Google Play details (${listing.packageId})`,
      );

      if (!outcome.value) return listing;

      const detail = outcome.value;
      return {
        ...listing,
        title: detail.title || listing.title,
        developer: detail.developer || listing.developer,
        description: detail.description || listing.description,
        iconUrl: detail.iconUrl || listing.iconUrl,
      };
    });

    const byId = new Map(enriched.map((listing) => [listing.packageId, listing]));
    return listings.map((listing) => byId.get(listing.packageId) ?? listing);
  }
}

export const googlePlayClient = new GooglePlayClient();
export default googlePlayClient;
