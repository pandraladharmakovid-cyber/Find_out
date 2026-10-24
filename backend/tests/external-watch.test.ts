import { PGlite } from "@electric-sql/pglite";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  pglite: null as PGlite | null,
  configOverrides: {
    RESEND_API_KEY: "re_watch_test_key",
    RESEND_API_URL: "https://api.resend.com/emails",
    RESEND_FROM_EMAIL: "watch@findout.example",
    RESEND_FROM_NAME: "Find_out Brand Watch",
    EXTERNAL_WATCH_ALERT_THRESHOLD: 65,
    EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES: 60,
    EXTERNAL_WATCH_DNS_PROBE_LIMIT: 12,
    EXTERNAL_WATCH_MAX_INVESTIGATIONS_PER_RUN: 5,
  } as Record<string, unknown>,
}));

vi.mock("../src/db", () => {
  const run = async (text: string, params: unknown[] = []) => {
    if (!state.pglite) throw new Error("PGlite not initialized");
    const result = await state.pglite.query(text, params);
    return {
      rows: result.rows,
      rowCount: result.affectedRows ?? result.rows.length,
    };
  };

  return {
    pool: {
      query: run,
      connect: async () => ({ query: run, release() {} }),
      on() {},
      end: async () => {},
    },
    query: run,
    checkDatabaseConnection: async () => ({ connected: true, latencyMs: 1 }),
    withTransaction: async <T>(cb: (client: { query: typeof run }) => Promise<T>) => {
      await state.pglite!.query("BEGIN");
      try {
        const out = await cb({ query: run });
        await state.pglite!.query("COMMIT");
        return out;
      } catch (err) {
        await state.pglite!.query("ROLLBACK");
        throw err;
      }
    },
    closeDatabase: async () => {},
  };
});

vi.mock("../src/config", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/config")>();
  return {
    ...original,
    config: new Proxy(original.config, {
      get(target, prop: string) {
        if (prop in state.configOverrides) {
          return state.configOverrides[prop];
        }
        return (target as Record<string, unknown>)[prop];
      },
    }),
  };
});

import {
  CtLogDiscoveryClient,
  isPublicIpAddress,
} from "../src/integrations/ct-log.client";
import {
  ExternalBrandWatchService,
  extractCorroboratingSignals,
} from "../src/external-watch.service";
import { INIT_SCHEMA_SQL } from "../src/schema";
import { brandService } from "../src/brands";
import { monitoringService } from "../src/monitoring";
import { investigationService } from "../src/investigations";
import { detectionRecordService } from "../src/detection-records.service";
import { app } from "../src/app";

describe("CtLogDiscoveryClient & Public IP Guardrails", () => {
  it("accepts public IPv4/IPv6 addresses and rejects loopback, private, and link-local space", () => {
    expect(isPublicIpAddress("93.184.216.34")).toBe(true);
    expect(isPublicIpAddress("2606:2800:220:1:248:1893:25c8:1946")).toBe(true);

    expect(isPublicIpAddress("127.0.0.1")).toBe(false);
    expect(isPublicIpAddress("10.0.0.8")).toBe(false);
    expect(isPublicIpAddress("172.16.5.4")).toBe(false);
    expect(isPublicIpAddress("192.168.1.20")).toBe(false);
    expect(isPublicIpAddress("169.254.169.254")).toBe(false);
    expect(isPublicIpAddress("::1")).toBe(false);
    expect(isPublicIpAddress("fe80::1")).toBe(false);
  });

  it("discovers live external look-alikes from CT logs and DNS while excluding official domains and NXDOMAINs", async () => {
    const fakeCtFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify([
          // Official brand domains must be excluded:
          {
            common_name: "nexuspay.io",
            name_value: "*.nexuspay.io\nlogin.nexuspay.io",
            issuer_name: "Let's Encrypt",
            entry_timestamp: "2026-10-20T10:00:00Z",
          },
          // External phishing domain logged in CT:
          {
            common_name: "nexusp4y-login.top",
            name_value: "nexusp4y-login.top",
            issuer_name: "Let's Encrypt E5",
            entry_timestamp: "2026-10-23T08:00:00Z",
          },
          // Dead historical CT domain that no longer resolves:
          {
            common_name: "nexuspay-old-dead.top",
            name_value: "nexuspay-old-dead.top",
            issuer_name: "Let's Encrypt",
            entry_timestamp: "2024-01-01T00:00:00Z",
          },
        ]),
    }) as unknown as typeof fetch;

    const fakeDns = vi.fn(async (hostname: string): Promise<string[]> => {
      if (hostname === "nexusp4y-login.top") return ["198.51.100.42"];
      if (hostname === "nexuspay-verify.com") return ["203.0.113.77"];
      return [];
    });

    const client = new CtLogDiscoveryClient({
      fetchFn: fakeCtFetch,
      dnsResolver: fakeDns,
    });

    const result = await client.discoverExternalDomains({
      brandName: "NexusPay",
      primaryDomain: "nexuspay.io",
      associatedDomains: ["nexuspay.com"],
    });

    const hostnames = result.domains.map((d) => d.domain);
    expect(hostnames).toContain("nexusp4y-login.top");
    expect(hostnames).not.toContain("nexuspay.io");
    expect(hostnames).not.toContain("login.nexuspay.io");
    expect(hostnames).not.toContain("nexuspay-old-dead.top");
    expect(result.sources.find((s) => s.source === "crt_sh_ct_logs")?.status).toBe("available");
    expect(result.sources.find((s) => s.source === "dns_lookalike_probe")?.status).toBe("available");
  });

  it("reports crt_sh_ct_logs as unavailable on HTTP failure without crashing DNS discovery", async () => {
    const failingCtFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => "Service Unavailable",
    }) as unknown as typeof fetch;

    const fakeDns = vi.fn(async (hostname: string) =>
      hostname === "nexuspay-login.com" ? ["203.0.113.88"] : [],
    );

    const client = new CtLogDiscoveryClient({
      fetchFn: failingCtFetch,
      dnsResolver: fakeDns,
    });

    const result = await client.discoverExternalDomains({
      brandName: "NexusPay",
      primaryDomain: "nexuspay.io",
    });

    const ctSource = result.sources.find((s) => s.source === "crt_sh_ct_logs");
    expect(ctSource?.status).toBe("unavailable");
    expect(ctSource?.error).toContain("503");
    expect(result.domains.some((d) => d.domain === "nexuspay-login.com")).toBe(true);
  });
});

describe("Evidence-Based Corroboration Gate", () => {
  it("treats bare name or logo similarity alone as uncorroborated (never auto-alerts)", () => {
    const signals = extractCorroboratingSignals({
      platform: "domain",
      evidenceTypes: ["NAME_LOOKALIKE", "LOGO_SIMILARITY"],
      primaryReasons: ["Look-alike technique: homoglyph (similarity 91%)."],
    });
    expect(signals).toHaveLength(0);
  });

  it("recognizes deceptive affixes, suspicious TLDs, publisher mismatches, and threat-intel hits as corroborating", () => {
    const signals = extractCorroboratingSignals({
      platform: "domain",
      evidenceTypes: ["NAME_LOOKALIKE", "DECEPTIVE_AFFIX", "SUSPICIOUS_TLD"],
      primaryReasons: ["Deceptive credential/brand affix in external domain"],
    });
    expect(signals).toContain("DECEPTIVE_AFFIX");
    expect(signals).toContain("SUSPICIOUS_TLD");
  });
});

describe("ExternalBrandWatchService End-to-End Pipeline & Deduplicated Alerting", () => {
  const sentEmails: Array<{ url: string; body: Record<string, unknown> }> = [];

  beforeAll(async () => {
    state.pglite = new PGlite();
    await state.pglite.waitReady;
    await state.pglite.exec(
      INIT_SCHEMA_SQL.replace(/CREATE EXTENSION IF NOT EXISTS "pgcrypto";/g, ""),
    );
  });

  afterAll(async () => {
    if (state.pglite) {
      await state.pglite.close();
      state.pglite = null;
    }
  });

  beforeEach(() => {
    sentEmails.length = 0;
    vi.restoreAllMocks();

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("resend.com")) {
          const parsedBody = init?.body ? JSON.parse(String(init.body)) : {};
          sentEmails.push({ url, body: parsedBody });
          return new Response(JSON.stringify({ id: `re_watch_${sentEmails.length}` }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
  });

  it("discovers external domains, suppresses similarity-only alerts, dispatches corroborated alerts once, and links into analyst workflows", async () => {
    // Stub social/app scan so test is offline-deterministic
    vi.spyOn(monitoringService, "runBrandScan").mockImplementation(async (brandId: string) => {
      const runRow = await state.pglite!.query<{ id: string }>(
        `INSERT INTO monitoring_runs (brand_id, target_type, status, completed_at)
         VALUES ($1, 'BRAND_THREAT_SCAN', 'COMPLETED', NOW())
         RETURNING id;`,
        [brandId],
      );
      return {
        runId: runRow.rows[0]!.id,
        brandId,
        candidatesFound: 0,
        excludedOfficialAssets: 0,
        alertsGenerated: 0,
        sourceStatuses: [
          { source: "bluesky", status: "available", candidatesFound: 0 },
          { source: "apple_app_store", status: "available", candidatesFound: 0 },
        ],
      };
    });

    vi.spyOn(investigationService, "runInvestigation").mockImplementation(async (dto) => {
      const isPhish = dto.targetUrl.includes("login.top");
      const res = await state.pglite!.query(
        `INSERT INTO investigations (title, target_url, brand_id, status, verdict, risk_score, confidence_score, summary)
         VALUES ($1, $2, $3, 'completed', $4, $5, 0.85, $6)
         RETURNING *;`,
        [
          dto.title ?? "External Watch",
          dto.targetUrl,
          dto.brandId ?? null,
          isPhish ? "malicious" : "unverified",
          isPhish ? 88 : 42,
          isPhish
            ? "External look-alike domain combines brand name with deceptive login keyword on .top TLD."
            : "Lexical similarity only; no malicious indicators observed.",
        ],
      );
      return res.rows[0] as Awaited<ReturnType<typeof investigationService.runInvestigation>>;
    });

    const stubDiscovery = new CtLogDiscoveryClient({
      fetchFn: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify([
            {
              common_name: "acmevault-login.top",
              name_value: "acmevault-login.top",
              issuer_name: "Let's Encrypt",
              entry_timestamp: "2026-10-24T01:00:00Z",
            },
            {
              common_name: "acmevau1t.org",
              name_value: "acmevau1t.org",
              issuer_name: "DigiCert",
              entry_timestamp: "2026-10-24T01:05:00Z",
            },
          ]),
      }) as unknown as typeof fetch,
      dnsResolver: async (host: string) => {
        if (host === "acmevault-login.top") return ["198.51.100.11"];
        if (host === "acmevau1t.org") return ["198.51.100.12"];
        return [];
      },
    });

    const watchService = new ExternalBrandWatchService({ domainDiscovery: stubDiscovery });

    const brand = await brandService.createBrand({
      name: "AcmeVault",
      primaryDomain: "acmevault.com",
      associatedDomains: ["portal.acmevault.com"],
      contactEmail: "soc@acmevault.com",
      keywords: ["acmevault"],
    });

    // Run 1: Initial scan on registration
    const registrationOutcome = await watchService.handleBrandRegistration(brand.id, {
      runImmediateScan: true,
    });
    expect(registrationOutcome.schedule.is_enabled).toBe(true);
    expect(registrationOutcome.run).not.toBeNull();
    expect(registrationOutcome.run?.status).toBe("COMPLETED");
    expect(registrationOutcome.run?.candidates_discovered).toBe(2);
    expect(registrationOutcome.run?.new_candidates_count).toBe(2);
    // Only acmevault-login.top has corroborating signals; acmevau1t.org is similarity-only!
    expect(registrationOutcome.run?.high_risk_count).toBe(1);
    expect(registrationOutcome.run?.alerts_created).toBe(1);
    expect(registrationOutcome.run?.emails_sent).toBe(1);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.body.to).toEqual(["soc@acmevault.com"]);

    // Run 2: Re-running scan with unchanged findings must NOT create duplicate alerts or emails
    const secondRun = await watchService.runBrandWatch(brand.id, "scheduled");
    expect(secondRun.new_candidates_count).toBe(0);
    expect(secondRun.alerts_created).toBe(0);
    expect(secondRun.emails_sent).toBe(0);
    expect(secondRun.deduplicated_alerts_skipped).toBe(1);
    expect(sentEmails).toHaveLength(1);

    // Overview reflects both candidates, accurate risk capping, and analyst workflow link
    const overview = await watchService.getOverview(brand.id);
    expect(overview.summary.monitoredBrands).toBe(1);
    expect(overview.summary.highRiskCount).toBe(1);
    expect(overview.externalCandidates).toHaveLength(2);

    const similarityOnly = overview.externalCandidates.find(
      (c) => c.canonical_id === "acmevau1t.org",
    );
    expect(similarityOnly).toBeDefined();
    expect(similarityOnly!.last_risk_score).toBeLessThanOrEqual(55);
    expect(similarityOnly!.corroborating_signals).toHaveLength(0);

    const corroboratedPhish = overview.externalCandidates.find(
      (c) => c.canonical_id === "acmevault-login.top",
    );
    expect(corroboratedPhish).toBeDefined();
    expect(corroboratedPhish!.last_risk_score).toBeGreaterThanOrEqual(65);
    expect(corroboratedPhish!.detection_record_id).toBeTruthy();

    // Analyst confirms threat via existing DetectionRecordService workflow
    await detectionRecordService.decide({
      id: corroboratedPhish!.detection_record_id!,
      status: "CONFIRMED",
      actor: "soc-analyst",
      note: "Confirmed active phishing infrastructure.",
    });

    const afterConfirm = await watchService.getOverview(brand.id);
    expect(afterConfirm.summary.confirmedThreatsCount).toBeGreaterThanOrEqual(1);
  });

  it("exposes /api/external-watch REST endpoints and validates UUID parameters", async () => {
    const badIdRes = await request(app).get("/api/external-watch/overview?brandId=not-a-uuid");
    expect(badIdRes.status).toBe(400);
    expect(badIdRes.body.code).toBe("INVALID_BRAND_ID");

    const okRes = await request(app).get("/api/external-watch/overview");
    expect(okRes.status).toBe(200);
    expect(okRes.body.success).toBe(true);
    expect(okRes.body.data.scheduler).toBeDefined();
    expect(Array.isArray(okRes.body.data.schedules)).toBe(true);
  });
});
