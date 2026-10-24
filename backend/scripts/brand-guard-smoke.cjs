#!/usr/bin/env node
/**
 * Brand Guard end-to-end smoke test.
 *
 * Boots the real Express app against a real PostgreSQL engine (PGlite),
 * applies the real schema, and drives the new Brand Guard module over HTTP
 * exactly as the frontend does:
 *
 *   1. Register the OFFICIAL brand (with its alert contact e-mail).
 *   2. An impersonator submits a confusingly similar brand
 *      -> POST /api/brand-guard/check reports the conflict (the web pop-up).
 *   3. The pop-up button "Notify official brand"
 *      -> POST /api/brand-guard/alert e-mails the official company via Resend.
 *   4. GET /api/brand-guard/alerts shows the auditable alert history.
 *   5. Negative paths: unknown brand, missing contact e-mail, bad input.
 *
 * The Resend API itself is answered by a local HTTP stub (unless
 * SMOKE_LIVE_RESEND=1 and a real RESEND_API_KEY are provided), so the run is
 * offline-safe while still exercising the full HTTP transport.
 *
 * Usage:  npm run build && node scripts/brand-guard-smoke.cjs
 */
const path = require("node:path");
const http = require("node:http");

const BACKEND_ROOT = path.resolve(__dirname, "..");
const DIST = path.join(BACKEND_ROOT, "dist");

// ---------------------------------------------------------------------------
// 0. Local Resend stub (unless a live run is requested)
// ---------------------------------------------------------------------------
const LIVE = process.env.SMOKE_LIVE_RESEND === "1" && process.env.RESEND_API_KEY;
const captured = [];

async function startResendStub() {
  if (LIVE) return null;
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      captured.push({
        url: req.url,
        authorization: req.headers.authorization,
        payload: JSON.parse(body || "{}"),
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: `re_mock_${captured.length}` }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}

async function main() {
  const resendStub = await startResendStub();
  const resendUrl = LIVE
    ? "https://api.resend.com/emails"
    : `http://127.0.0.1:${resendStub.address().port}/emails`;

  // -------------------------------------------------------------------------
  // Environment must be set before the compiled config module is loaded.
  // -------------------------------------------------------------------------
  process.env.NODE_ENV = "test";
  process.env.LOG_LEVEL = "error";
  process.env.DATABASE_URL = "postgres://pglite";
  process.env.FRONTEND_URL = "http://localhost:5173";
  if (!LIVE) {
    process.env.RESEND_API_KEY = "re_smoke_test_key";
    process.env.RESEND_API_URL = resendUrl;
  }
  process.env.RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "onboarding@resend.dev";

  // -------------------------------------------------------------------------
  // Real Postgres (PGlite) behind the real db module interface.
  // -------------------------------------------------------------------------
  const { PGlite } = require(path.join(BACKEND_ROOT, "node_modules", "@electric-sql/pglite"));
  const pglite = new PGlite();
  await pglite.waitReady;

  const run = async (text, params = []) => {
    const result = await pglite.query(text, params);
    return { rows: result.rows, rowCount: result.affectedRows ?? result.rows.length };
  };

  const dbShim = {
    pool: { query: run, connect: async () => ({ query: run, release() {} }), on() {}, end: async () => pglite.close() },
    query: run,
    checkDatabaseConnection: async () => ({ connected: true, latencyMs: 1 }),
    withTransaction: async (callback) => {
      await pglite.query("BEGIN");
      try {
        const result = await callback({ query: run });
        await pglite.query("COMMIT");
        return result;
      } catch (error) {
        await pglite.query("ROLLBACK");
        throw error;
      }
    },
    closeDatabase: async () => pglite.close(),
  };
  dbShim.default = dbShim.pool;

  const dbPath = require.resolve(path.join(DIST, "db.js"));
  require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: dbShim, children: [], paths: [] };

  const { INIT_SCHEMA_SQL } = require(path.join(DIST, "schema.js"));
  await pglite.exec(INIT_SCHEMA_SQL.replace(/CREATE EXTENSION IF NOT EXISTS "pgcrypto";/g, ""));

  const { app } = require(path.join(DIST, "app.js"));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  // -------------------------------------------------------------------------
  // Assertion helpers
  // -------------------------------------------------------------------------
  let passed = 0;
  let failed = 0;
  const ok = (condition, label) => {
    if (condition) {
      passed += 1;
      console.log(`  PASS  ${label}`);
    } else {
      failed += 1;
      console.error(`  FAIL  ${label}`);
    }
  };
  const api = async (method, endpoint, body) => {
    const response = await fetch(`${base}/api${endpoint}`, {
      method,
      headers: { "Content-Type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, json: await response.json().catch(() => ({})) };
  };

  console.log(`\nBrand Guard smoke test  (Resend transport: ${LIVE ? "LIVE api.resend.com" : "local stub " + resendUrl})\n`);

  // --- 1. Official brand registers (with alert contact e-mail) --------------
  console.log("1. Official brand registration");
  const official = await api("POST", "/brands", {
    name: "NexusPay",
    primaryDomain: "nexuspay.io",
    website: "https://nexuspay.io",
    keywords: ["nexuspay", "payments"],
    alternateNames: ["Nexus Wallet"],
    contactEmail: "security@nexuspay.io",
  });
  ok(official.status === 201, `official brand created (HTTP ${official.status})`);
  const officialId = official.json?.data?.id;
  ok(Boolean(officialId), `official brand id assigned (${officialId})`);
  ok(official.json?.data?.contact_email === "security@nexuspay.io", "contact e-mail stored on the profile");
  ok(official.json?.meta?.brandGuard?.conflict === false, "no false conflict for the first registration");

  // --- 2. Impersonator checked by the pop-up endpoint ------------------------
  console.log("\n2. Impersonation attempt -> /brand-guard/check (drives the web pop-up)");
  const check = await api("POST", "/brand-guard/check", {
    name: "NexusP4y Secure",
    domain: "nexusp4y-login.top",
  });
  ok(check.status === 200, `check endpoint answered (HTTP ${check.status})`);
  ok(check.json?.data?.conflict === true, "conflict detected for 'NexusP4y Secure' / nexusp4y-login.top");
  const conflict = check.json?.data?.conflicts?.[0];
  ok(conflict?.brandName === "NexusPay", `conflicting official brand identified (${conflict?.brandName})`);
  ok(typeof conflict?.similarity === "number" && conflict.similarity >= 0.72, `similarity ${conflict?.similarity} >= threshold`);
  ok(conflict?.canNotify === true, "pop-up knows the official brand can be notified");

  const clean = await api("POST", "/brand-guard/check", {
    name: "Sunrise Bakery",
    domain: "sunrise-bakery.in",
  });
  ok(clean.json?.data?.conflict === false, "unrelated brand produces no pop-up");

  // --- 3. Server-side guard on actual registration ---------------------------
  console.log("\n3. Registration itself carries the server-side warning");
  const fake = await api("POST", "/brands", {
    name: "NexusP4y Secure",
    primaryDomain: "nexusp4y-login.top",
  });
  ok(fake.status === 201, `fake profile stored for review (HTTP ${fake.status})`);
  ok(fake.json?.meta?.brandGuard?.conflict === true, "response meta flags the impersonation conflict server-side");

  // --- 4. The pop-up button -> alert e-mail through Resend -------------------
  console.log("\n4. 'Notify official brand' button -> /brand-guard/alert");
  const status = await api("GET", "/brand-guard/status");
  ok(status.json?.data?.emailConfigured === true, "alert transport reports configured");

  const alert = await api("POST", "/brand-guard/alert", {
    brandId: officialId,
    suspectName: "NexusP4y Secure",
    suspectDomain: "nexusp4y-login.top",
    matchType: conflict?.matchType,
    similarity: conflict?.similarity,
    verdict: conflict?.verdict,
    note: "Smoke-test alert fired from scripts/brand-guard-smoke.cjs",
  });
  ok(alert.status === 201, `alert accepted (HTTP ${alert.status})`);
  ok(alert.json?.data?.status === "sent", `alert status is 'sent' (${alert.json?.data?.status})`);
  ok(alert.json?.meta?.recipient === "security@nexuspay.io", `delivered to the official contact (${alert.json?.meta?.recipient})`);
  ok(Boolean(alert.json?.meta?.providerMessageId), `Resend message id recorded (${alert.json?.meta?.providerMessageId})`);

  if (!LIVE) {
    const mail = captured[0];
    ok(captured.length === 1, "exactly one e-mail hit the Resend API");
    ok(mail?.authorization === "Bearer re_smoke_test_key", "Resend called with Bearer RESEND_API_KEY");
    ok(Array.isArray(mail?.payload?.to) && mail.payload.to[0] === "security@nexuspay.io", "e-mail 'to' is the official brand contact");
    ok(String(mail?.payload?.subject).includes("NexusPay"), `subject names the brand: "${mail?.payload?.subject}"`);
    ok(String(mail?.payload?.html).includes("nexusp4y-login.top"), "e-mail body contains the suspect domain");
    ok(String(mail?.payload?.text).includes("NexusP4y Secure"), "plain-text body contains the suspect name");
  }

  // --- 5. Alert history -------------------------------------------------------
  console.log("\n5. Alert history");
  const history = await api("GET", `/brand-guard/alerts?brandId=${officialId}`);
  ok(history.status === 200 && history.json?.data?.length === 1, `one auditable alert row recorded (${history.json?.data?.length})`);
  ok(history.json?.data?.[0]?.provider === "resend", "alert row records the provider");

  // --- 6. Negative paths -------------------------------------------------------
  console.log("\n6. Negative paths");
  const noName = await api("POST", "/brand-guard/check", {});
  ok(noName.status === 400, `check without a name rejected (HTTP ${noName.status})`);

  const noBrand = await api("POST", "/brand-guard/alert", {
    brandId: "99999999-9999-4999-8999-999999999999",
    suspectName: "Ghost",
  });
  ok(noBrand.status === 404, `alert for unknown brand rejected (HTTP ${noBrand.status})`);

  const noEmailBrand = await api("POST", "/brands", {
    name: "Quiet Labs",
    primaryDomain: "quietlabs.dev",
  });
  const noEmailAlert = await api("POST", "/brand-guard/alert", {
    brandId: noEmailBrand.json?.data?.id,
    suspectName: "Qu1et Labs",
  });
  ok(noEmailAlert.status === 409 && noEmailAlert.json?.code === "NO_CONTACT_EMAIL", `brand without contact e-mail answered 409 NO_CONTACT_EMAIL (HTTP ${noEmailAlert.status})`);

  const badEmail = await api("POST", "/brands", {
    name: "Broken Mail Co",
    primaryDomain: "brokenmail.example.com",
    contactEmail: "not-an-email",
  });
  ok(badEmail.status === 400 && badEmail.json?.code === "INVALID_CONTACT_EMAIL", `invalid contact e-mail rejected (HTTP ${badEmail.status})`);

  // -------------------------------------------------------------------------
  console.log(`\nRESULT: ${passed} passed, ${failed} failed\n`);
  server.close();
  if (resendStub) resendStub.close();
  await pglite.close();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error("brand-guard-smoke failed:", error);
  process.exit(1);
});
