import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const KEV_PAYLOAD = {
  catalogVersion: "2026.10.23",
  dateReleased: "2026-10-23T00:00:00Z",
  count: 2,
  vulnerabilities: [
    {
      cveID: "CVE-2026-1111",
      vendorProject: "Nexus",
      product: "Pay Gateway",
      vulnerabilityName: "Nexus Pay Gateway Authentication Bypass",
      shortDescription: "Authentication bypass allows account takeover.",
      dateAdded: "2026-10-22",
      dueDate: "2026-10-30",
      knownRansomwareCampaignUse: "Known",
    },
    {
      cveID: "CVE-2026-2222",
      vendorProject: "Plex",
      product: "Media Server",
      vulnerabilityName: "Plex Media Server RCE",
      shortDescription: "Remote code execution in the media server.",
      dateAdded: "2026-09-01",
      dueDate: "2027-06-01",
      knownRansomwareCampaignUse: "Unknown",
    },
  ],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("Live CISA KEV threat feed", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("normalises catalogue entries and derives severity", async () => {
    const { parseKevCatalog } = await import("../src/integrations/threat-feed.client");
    const parsed = parseKevCatalog(KEV_PAYLOAD);

    expect(parsed.version).toBe("2026.10.23");
    expect(parsed.items).toHaveLength(2);

    const [first, second] = parsed.items;
    expect(first?.id).toBe("CVE-2026-1111");
    expect(first?.severity).toBe("critical"); // ransomware use
    expect(first?.knownRansomware).toBe(true);
    expect(first?.url).toContain("CVE-2026-1111");
    expect(second?.severity).toBe("high");
    // Newest first
    expect(first?.dateAdded).toBe("2026-10-22");
  });

  it("rejects a malformed payload instead of inventing entries", async () => {
    const { parseKevCatalog } = await import("../src/integrations/threat-feed.client");
    expect(() => parseKevCatalog(null)).toThrow(/unexpected payload/i);
  });

  it("serves the live feed, filters it, and caches the catalogue", async () => {
    vi.stubEnv("THREAT_FEED_ENABLED", "true");
    const fetchMock = vi.fn(async () => jsonResponse(KEV_PAYLOAD));
    vi.stubGlobal("fetch", fetchMock);

    const { ThreatFeedService } = await import("../src/integrations/threat-feed.client");
    const service = new ThreatFeedService();

    const all = await service.getFeed({ limit: 10 });
    expect(all.status).toBe("available");
    expect(all.totalAvailable).toBe(2);
    expect(all.count).toBe(2);

    const filtered = await service.getFeed({ limit: 10, search: "nexus" });
    expect(filtered.count).toBe(1);
    expect(filtered.items[0]?.id).toBe("CVE-2026-1111");

    // Second call must be answered from cache, not the network.
    await service.getFeed({ limit: 10 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports unavailable (never empty success) when the feed cannot be read", async () => {
    vi.stubEnv("THREAT_FEED_ENABLED", "true");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "down" }, 503)),
    );

    const { ThreatFeedService } = await import("../src/integrations/threat-feed.client");
    const service = new ThreatFeedService();

    const result = await service.getFeed({ limit: 5 });
    expect(result.status).toBe("unavailable");
    expect(result.items).toHaveLength(0);
    expect(result.detail).toContain("503");
  });

  it("honours THREAT_FEED_ENABLED=false without calling the network", async () => {
    vi.stubEnv("THREAT_FEED_ENABLED", "false");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const { ThreatFeedService } = await import("../src/integrations/threat-feed.client");
    const status = await new ThreatFeedService().status();

    expect(status.status).toBe("not_configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
