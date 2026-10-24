import { config } from "../config";
import { logger } from "../utils/logger";

/**
 * Live cyber-security threat feed.
 *
 * The platform previously had no verified live feed: "alerts" were only rows
 * created by internal scans. This client pulls CISA's Known Exploited
 * Vulnerabilities catalogue, which is public, key-free and updated continuously.
 * The response is cached in-process so a burst of dashboard requests cannot
 * hammer the upstream feed.
 */

export type ThreatFeedStatus = "available" | "unavailable" | "not_configured";

export interface ThreatFeedItem {
  id: string;
  title: string;
  vendor: string;
  product: string;
  description: string;
  dateAdded: string;
  dueDate: string | null;
  knownRansomware: boolean;
  severity: "critical" | "high" | "medium" | "low";
  url: string;
  source: "cisa-kev";
}

export interface ThreatFeedResult {
  status: ThreatFeedStatus;
  source: string;
  detail: string;
  fetchedAt: string | null;
  cached: boolean;
  totalAvailable: number;
  count: number;
  items: ThreatFeedItem[];
  catalogVersion: string | null;
}

interface CacheEntry {
  payload: ThreatFeedResult;
  expiresAt: number;
}

const CISA_KEV_BASE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

let cache: CacheEntry | null = null;

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** CISA marks ransomware use with "Known" / "Unknown". */
function mapRansomware(value: unknown): boolean {
  return asString(value).trim().toLowerCase() === "known";
}

/**
 * CISA does not publish CVSS in KEV. Severity is derived conservatively from
 * the catalogue metadata: everything in KEV is actively exploited, so anything
 * with ransomware use or a due date inside 21 days is treated as critical.
 */
function deriveSeverity(item: Record<string, unknown>): ThreatFeedItem["severity"] {
  const ransomware = mapRansomware(item.knownRansomwareCampaignUse);
  const due = asString(item.dueDate);

  if (ransomware) return "critical";
  if (due) {
    const dueAt = Date.parse(due);
    if (Number.isFinite(dueAt)) {
      const days = (dueAt - Date.now()) / 86_400_000;
      if (days <= 21) return "critical";
      if (days <= 60) return "high";
    }
  }
  return "high";
}

export function parseKevCatalog(payload: unknown): { items: ThreatFeedItem[]; version: string | null } {
  if (typeof payload !== "object" || payload === null) {
    throw new Error("The threat feed returned an unexpected payload.");
  }

  const record = payload as Record<string, unknown>;
  const vulnerabilities = Array.isArray(record.vulnerabilities) ? record.vulnerabilities : [];

  const items: ThreatFeedItem[] = [];

  for (const entry of vulnerabilities) {
    if (typeof entry !== "object" || entry === null) continue;
    const item = entry as Record<string, unknown>;
    const cveId = asString(item.cveID).trim();
    if (!cveId) continue;

    const vendor = asString(item.vendorProject).trim();
    const product = asString(item.product).trim();

    items.push({
      id: cveId,
      title: asString(item.vulnerabilityName).trim() || `${vendor} ${product}`.trim() || cveId,
      vendor,
      product,
      description: asString(item.shortDescription).trim(),
      dateAdded: asString(item.dateAdded),
      dueDate: asString(item.dueDate) || null,
      knownRansomware: mapRansomware(item.knownRansomwareCampaignUse),
      severity: deriveSeverity(item),
      url: `${CISA_KEV_BASE}?search=${encodeURIComponent(cveId)}`,
      source: "cisa-kev",
    });
  }

  // Newest first.
  items.sort((a, b) => Date.parse(b.dateAdded || "1970-01-01") - Date.parse(a.dateAdded || "1970-01-01"));

  return { items, version: asString(record.catalogVersion) || null };
}

export class ThreatFeedService {
  private inflight: Promise<ThreatFeedResult> | null = null;

  async getFeed(options: { limit?: number; search?: string; refresh?: boolean } = {}): Promise<ThreatFeedResult> {
    const limit = Math.min(Math.max(options.limit ?? 20, 1), 100);
    const search = (options.search ?? "").trim().toLowerCase();

    const base = await this.load(options.refresh === true);
    const filtered = search
      ? base.items.filter((item) =>
          [item.id, item.title, item.vendor, item.product, item.description]
            .join(" ")
            .toLowerCase()
            .includes(search),
        )
      : base.items;

    return {
      ...base,
      count: Math.min(filtered.length, limit),
      items: filtered.slice(0, limit),
    };
  }

  async status(): Promise<{ status: ThreatFeedStatus; detail: string; items: number; fetchedAt: string | null }> {
    if (!config.THREAT_FEED_ENABLED) {
      return {
        status: "not_configured",
        detail: "THREAT_FEED_ENABLED=false.",
        items: 0,
        fetchedAt: null,
      };
    }

    const result = await this.getFeed({ limit: 1 });
    return {
      status: result.status,
      detail: result.detail,
      items: result.totalAvailable,
      fetchedAt: result.fetchedAt,
    };
  }

  private async load(refresh: boolean): Promise<ThreatFeedResult> {
    if (!config.THREAT_FEED_ENABLED) {
      return {
        status: "not_configured",
        source: "cisa-kev",
        detail: "The live threat feed is disabled (THREAT_FEED_ENABLED=false).",
        fetchedAt: null,
        cached: false,
        totalAvailable: 0,
        count: 0,
        items: [],
        catalogVersion: null,
      };
    }

    if (!refresh && cache && cache.expiresAt > Date.now()) {
      return { ...cache.payload, cached: true };
    }

    if (this.inflight) return this.inflight;

    this.inflight = this.fetchCatalog().finally(() => {
      this.inflight = null;
    });

    return this.inflight;
  }

  private async fetchCatalog(): Promise<ThreatFeedResult> {
    const fetchedAt = new Date().toISOString();

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20_000);

      let response: Response;
      try {
        response = await fetch(config.THREAT_FEED_URL, {
          method: "GET",
          headers: { Accept: "application/json", "User-Agent": "Find_out/1.0 (+brand-protection)" },
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      if (!response.ok) {
        throw new Error(`The threat feed answered HTTP ${response.status}.`);
      }

      const payload = await response.json();
      const { items, version } = parseKevCatalog(payload);

      const result: ThreatFeedResult = {
        status: "available",
        source: "cisa-kev",
        detail: `CISA KEV catalogue (${items.length} known-exploited vulnerabilities).`,
        fetchedAt,
        cached: false,
        totalAvailable: items.length,
        count: items.length,
        items,
        catalogVersion: version,
      };

      cache = { payload: result, expiresAt: Date.now() + config.THREAT_FEED_CACHE_MS };
      return result;
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Unknown threat-feed error";
      logger.warn("[threat-feed] Live feed unavailable", { error: detail });

      return {
        status: "unavailable",
        source: "cisa-kev",
        detail: `The live feed could not be read: ${detail}`,
        fetchedAt: null,
        cached: false,
        totalAvailable: 0,
        count: 0,
        items: [],
        catalogVersion: null,
      };
    }
  }

  /** Test helper. */
  clearCache(): void {
    cache = null;
  }
}

export const threatFeedService = new ThreatFeedService();
export default threatFeedService;
