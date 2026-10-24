#!/usr/bin/env node
/**
 * External Brand Watch end-to-end HTTP smoke test.
 *
 * Boots the compiled Express application against a real PostgreSQL engine
 * (PGlite), spins up local HTTP stubs for Certificate Transparency (`crt.sh`)
 * and Resend e-mail delivery, and verifies every requirement end-to-end:
 *
 *   1. Official brand registration (`POST /api/brands`) + automatic watch enrollment.
 *   2. Schedule management (`PATCH /api/external-watch/schedules/:brandId`).
 *   3. External scan (`POST /api/external-watch/scan/:brandId`):
 *        - Excludes official brand domains (`cloudshield.io`, `auth.cloudshield.io`)
 *        - Discovers corroborated phishing domain (`cloudshie1d-login.top`)
 *        - Discovers similarity-only domain (`cloudshie1d.org`)
 *        - Enforces corroboration gate: similarity-only score <= 55, no alert!
 *        - Emits 1 in-app alert + 1 Resend email to `soc@cloudshield.io`
 *   4. Deduplication: second scan with unchanged findings creates 0 duplicate alerts
 *      and sends 0 duplicate e-mails (`deduplicated_alerts_skipped >= 1`).
 *   5. Analyst confirmation workflow (`POST /api/detection-records/:id/decision`)
 *      updates `confirmedThreatsCount` in `GET /api/external-watch/overview`.
 *   6. Graceful degradation when Certificate Transparency returns HTTP 503.
 *
 * Usage:  npm run build && npm run smoke:external-watch
 */
const path = require("node:path");
const http = require("node:http");

const BACKEND_ROOT = path.resolve(__dirname, "..");
const DIST = path.join(BACKEND_ROOT, "dist");

const capturedEmails = [];
let ctShouldFail = false;

async function startStubs() {
  const resendServer = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      capturedEmails.push(JSON.parse(raw || "{}"));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: `re_watch_smoke_${capturedEmails.length}` }));
    });
  });
  await new Promise((resolve) => resendServer.listen(0, "127.0.0.1", resolve));

  const ctServer = http.createServer((_req, res) => {
    if (ctShouldFail) {
      res.writeHead(503, { "Content-Type": "text/plain" });
      res.end("CT Upstream Temporarily Unavailable");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify([
        {
          common_name: "cloudshield.io",
          name_value: "*.cloudshield.io\nauth.cloudshield.io",
          issuer_name: "Let's Encrypt",
          entry_timestamp: "2026-10-20T00:00:00Z",
        },
        {
          common_name: "cloudshie1d-login.top",
          name_value: "cloudshie1d-login.top",
          issuer_name: "Let's Encrypt E6",
          entry_timestamp: "2026-10-24T04:00:00Z",
        },
        {
          common_name: "cloudshie1d.org",
          name_value: "cloudshie1d.org",
          issuer_name: "Sectigo",
          entry_timestamp: "2026-10-24T04:10:00Z",
        },
      ]),
    );
  });
  await new Promise((resolve) => ctServer.listen(0, "127.0.0.1", resolve));

  return { resendServer, ctServer };
}

async function main() {
  const { resendServer, ctServer } = await startStubs();
  const resendUrl = `http://127.0.0.1:${resendServer.address().port}/emails`;
  const ctUrl = `http://127.0.0.1:${ctServer.address().port}`;

  process.env.NODE_ENV = "test";
  process.env.LOG_LEVEL = "error";
  process.env.DATABASE_URL = "postgres://pglite";
  process.env.FRONTEND_URL = "http://localhost:5173";
  process.env.RESEND_API_KEY = "re_smoke_watch_key";
  process.env.RESEND_API_URL = resendUrl;
  process.env.RESEND_FROM_EMAIL = "onboarding@resend.dev";
  process.env.EXTERNAL_WATCH_CT_URL = ctUrl;
  process.env.EXTERNAL_WATCH_DNS_PROBE_LIMIT = "5";
  process.env.EXTERNAL_WATCH_ALERT_THRESHOLD = "65";

  // Deterministic public DNS shim for offline sandbox execution
  const dnsPromises = require("node:dns/promises");
  dnsPromises.resolve4 = async (host) => {
    if (host === "cloudshie1d-login.top") return ["198.51.100.55"];
    if (host === "cloudshie1d.org") return ["198.51.100.56"];
    const err = new Error(`queryA ENOTFOUND ${host}`);
    err.code = "ENOTFOUND";
    throw err;
  };
  dnsPromises.resolve6 = async (host) => {
    const err = new Error(`queryAAAA ENODATA ${host}`);
    err.code = "ENODATA";
    throw err;
  };

  const { PGlite } = require(path.join(BACKEND_ROOT, "node_modules", "@electric-sql/pglite"));
  const pglite = new PGlite();
  await pglite.waitReady;

  const run = async (text, params = []) => {
    const result = await pglite.query(text, params);
    return { rows: result.rows, rowCount: result.affectedRows ?? result.rows.length };
  };

  const dbShim = {
    pool: {
      query: run,
      connect: async () => ({ query: run, release() {} }),
      on() {},
      end: async () => pglite.close(),
    },
    query: run,
    checkDatabaseConnection: async () => ({ connected: true, latencyMs: 1 }),
    withTransaction: async (callback) => {
      await pglite.query("BEGIN");
      try {
        const out = await callback({ query: run });
        await pglite.query("COMMIT");
        return out;
      } catch (err) {
        await pglite.query("ROLLBACK");
        throw err;
      }
    },
    closeDatabase: async () => pglite.close(),
  };
  dbShim.default = dbShim.pool;

  const dbPath = require.resolve(path.join(DIST, "db.js"));
  require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    exports: dbShim,
    children: [],
    paths: [],
  };

  const { INIT_SCHEMA_SQL } = require(path.join(DIST, "schema.js"));
  await pglite.exec(INIT_SCHEMA_SQL.replace(/CREATE EXTENSION IF NOT EXISTS "pgcrypto";/g, ""));

  // Stub social/app network calls so smoke script stays deterministic & offline-safe
  const { monitoringService } = require(path.join(DIST, "monitoring.js"));
  monitoringService.runBrandScan = async (brandId) => {
    const ins = await run(
      `INSERT INTO monitoring_runs (brand_id, target_type, status, completed_at)
       VALUES ($1, 'BRAND_THREAT_SCAN', 'COMPLETED', NOW())
       RETURNING id;`,
      [brandId],
    );
    return {
      runId: ins.rows[0].id,
      brandId,
      candidatesFound: 0,
      excludedOfficialAssets: 0,
      alertsGenerated: 0,
      sourceStatuses: [
        { source: "bluesky", status: "available", candidatesFound: 0 },
        { source: "apple_app_store", status: "available", candidatesFound: 0 },
      ],
    };
  };

  const { investigationService } = require(path.join(DIST, "investigations.js"));
  investigationService.runInvestigation = async (dto) => {
    const phish = dto.targetUrl.includes("-login.top");
    const ins = await run(
      `INSERT INTO investigations (title, target_url, brand_id, status, verdict, risk_score, confidence_score, summary)
       VALUES ($1, $2, $3, 'completed', $4, $5, 0.86, $6)
       RETURNING *;`,
      [
        dto.title || "Watch Scan",
        dto.targetUrl,
        dto.brandId || null,
        phish ? "malicious" : "unverified",
        phish ? 89 : 40,
        phish
          ? "Suspected external credential-harvesting domain targeting CloudShield."
          : "Lexical resemblance only; no corroborating abuse indicators.",
      ],
    );
    return ins.rows[0];
  };

  const { app } = require(path.join(DIST, "app.js"));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  let passed = 0;
  let failed = 0;
  const assert = (label, ok, detail = "") => {
    if (ok) {
      passed += 1;
      console.log(`  PASS  ${label}${detail ? ` (${detail})` : ""}`);
    } else {
      failed += 1;
      console.error(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
    }
  };

  const reqJson = async (method, urlPath, body) => {
    const res = await fetch(`${base}${urlPath}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  };

  console.log("\n=== External Brand Watch E2E Smoke Verification ===");

  // 1. Register Official Brand
  const created = await reqJson("POST", "/api/brands", {
    name: "CloudShield",
    primaryDomain: "cloudshield.io",
    domains: ["cloudshield.io", "portal.cloudshield.io"],
    contactEmail: "soc@cloudshield.io",
    keywords: ["cloudshield"],
  });
  assert("POST /api/brands creates official brand", created.status === 201, created.json?.data?.id);
  const brandId = created.json.data.id;

  // 2. Overview automatically enrolls active brand
  const initialOverview = await reqJson("GET", `/api/external-watch/overview?brandId=${brandId}`);
  assert("GET /api/external-watch/overview returns 200", initialOverview.status === 200);
  assert(
    "Active brand automatically enrolled in external_watch_schedules",
    initialOverview.json?.data?.schedules?.length === 1,
    `interval=${initialOverview.json?.data?.schedules?.[0]?.interval_minutes}m`,
  );

  // 3. Configure schedule interval & threshold
  const patched = await reqJson("PATCH", `/api/external-watch/schedules/${brandId}`, {
    intervalMinutes: 30,
    alertRiskThreshold: 65,
    isEnabled: true,
  });
  assert(
    "PATCH /api/external-watch/schedules/:brandId updates cadence",
    patched.status === 200 && patched.json?.data?.interval_minutes === 30,
  );

  // 4. Trigger External Brand Watch scan
  const firstScan = await reqJson("POST", `/api/external-watch/scan/${brandId}`);
  const run1 = firstScan.json?.data;
  assert("POST /api/external-watch/scan/:brandId completes", firstScan.status === 200 && run1?.status === "COMPLETED");
  assert(
    "Discovers 2 external domains while excluding official cloudshield.io & auth.cloudshield.io",
    run1?.candidates_discovered === 2 && run1?.new_candidates_count === 2,
    `discovered=${run1?.candidates_discovered}`,
  );
  assert(
    "Enforces corroboration gate: only corroborated phishing domain triggers alert & email",
    run1?.high_risk_count === 1 && run1?.alerts_created === 1 && run1?.emails_sent === 1,
    `highRisk=${run1?.high_risk_count}, alerts=${run1?.alerts_created}, emails=${run1?.emails_sent}`,
  );
  assert(
    "Resend email delivered to official brand contact_email",
    capturedEmails.length === 1 && capturedEmails[0]?.to?.[0] === "soc@cloudshield.io",
    capturedEmails[0]?.subject,
  );

  // 5. Re-run scan: verify deduplication prevents duplicate alerts & duplicate emails
  const secondScan = await reqJson("POST", `/api/external-watch/scan/${brandId}`);
  const run2 = secondScan.json?.data;
  assert(
    "Second scan suppresses duplicate alerts for unchanged findings",
    secondScan.status === 200 &&
      run2?.alerts_created === 0 &&
      run2?.emails_sent === 0 &&
      run2?.deduplicated_alerts_skipped === 1 &&
      capturedEmails.length === 1,
    `dedupSkipped=${run2?.deduplicated_alerts_skipped}`,
  );

  // 6. Verify candidate details & analyst confirm workflow
  const midOverview = await reqJson("GET", `/api/external-watch/overview?brandId=${brandId}`);
  const extCandidates = midOverview.json?.data?.externalCandidates ?? [];
  const simOnly = extCandidates.find((c) => c.canonical_id === "cloudshie1d.org");
  const phishCand = extCandidates.find((c) => c.canonical_id === "cloudshie1d-login.top");
  assert(
    "Similarity-only candidate capped <= 55 without corroborating signals",
    Boolean(simOnly && simOnly.last_risk_score <= 55 && simOnly.corroborating_signals.length === 0),
    `score=${simOnly?.last_risk_score}`,
  );
  assert(
    "Corroborated candidate linked to DetectionRecord analyst workflow",
    Boolean(phishCand && phishCand.detection_record_id && phishCand.last_risk_score >= 65),
    `detectionRecordId=${phishCand?.detection_record_id}`,
  );

  const decision = await reqJson(
    "POST",
    `/api/detection-records/${phishCand.detection_record_id}/decision`,
    {
      status: "CONFIRMED",
      actor: "smoke-analyst",
      note: "Confirmed external credential phishing domain.",
    },
  );
  assert("Analyst confirms external finding via /api/detection-records/:id/decision", decision.status === 200);

  const afterConfirm = await reqJson("GET", `/api/external-watch/overview?brandId=${brandId}`);
  assert(
    "Overview reflects confirmedThreatsCount === 1",
    afterConfirm.json?.data?.summary?.confirmedThreatsCount === 1,
  );

  // 7. Provider failure containment: simulate CT outage (HTTP 503)
  ctShouldFail = true;
  const degradedScan = await reqJson("POST", `/api/external-watch/scan/${brandId}`);
  const run3 = degradedScan.json?.data;
  const ctStatus = (run3?.sources_checked || []).find((s) => s.source === "crt_sh_ct_logs");
  assert(
    "CT outage degrades gracefully to PARTIAL and reports crt_sh_ct_logs unavailable",
    degradedScan.status === 200 &&
      run3?.status === "PARTIAL" &&
      ctStatus?.status === "unavailable",
    ctStatus?.error,
  );

  console.log("=".repeat(64));
  console.log(`${passed}/${passed + failed} External Brand Watch smoke checks passed`);

  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => resendServer.close(resolve));
  await new Promise((resolve) => ctServer.close(resolve));
  await pglite.close();

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("External Brand Watch smoke script crashed:", err);
  process.exit(1);
});
