#!/usr/bin/env node
/**
 * Find_out end-to-end verification.
 *
 * Boots the real Express app against a real PostgreSQL engine (PGlite — the
 * actual Postgres compiled to WASM), applies the real schema, and drives the
 * HTTP API exactly as the frontend does:
 *
 *   brand -> official asset -> monitoring scan -> findings -> investigation
 *         -> look-alike / logo -> AI agent -> complaint -> delivery attempt
 *         -> report -> live threat feed
 *
 * External providers (iTunes, Play Store, Bluesky, CISA) are answered by a
 * deterministic fetch stub so the run is offline-safe and reproducible. Every
 * other layer (routing, validation, SQL, risk engine, sharp, the agent loop) is
 * the production implementation.
 *
 * Usage:
 *   npm run build && npm run e2e          # deterministic
 *   E2E_LIVE=1 npm run e2e               # hit the real external APIs as well
 */
const path = require("node:path");
const { randomUUID } = require("node:crypto");

// ---------------------------------------------------------------------------
// Environment must be set before the compiled config module is loaded.
// ---------------------------------------------------------------------------
process.env.NODE_ENV = "test";
process.env.LOG_LEVEL = "error";
process.env.DATABASE_URL = "postgres://pglite";
process.env.FRONTEND_URL = "http://localhost:5173";
process.env.OPENAI_BASE_URL = "";
process.env.OPENAI_API_KEY = "";
process.env.AI_AGENT_ENABLED = "true";
process.env.SMTP_HOST = "";
process.env.COMPLAINT_FROM_EMAIL = "";
process.env.COMPLAINT_WEBHOOK_URL = "";
process.env.BLUESKY_HANDLE = "brandwatch.bsky.social";
process.env.BLUESKY_APP_PASSWORD = "app-password";
process.env.GEMINI_API_KEY = "";
process.env.URLHAUS_AUTH_KEY = "";
process.env.GOOGLE_SAFE_BROWSING_API_KEY = "";
process.env.YOUTUBE_API_KEY = "";
process.env.APP_STORE_RESULT_LIMIT = "25";

const BACKEND_ROOT = path.resolve(__dirname, "..");
const DIST = path.join(BACKEND_ROOT, "dist");

let PGlite;
try {
  ({ PGlite } = require("@electric-sql/pglite"));
} catch {
  console.error("Missing dev dependency @electric-sql/pglite. Run: npm install");
  process.exit(2);
}

function loadDist(name) {
  try {
    return require(path.join(DIST, name));
  } catch (error) {
    console.error(`Cannot load dist/${name}. Run "npm run build" first.\n${error.message}`);
    process.exit(2);
  }
}

// ---------------------------------------------------------------------------
// External fetch fixtures
// ---------------------------------------------------------------------------
const PLAY_SEARCH_HTML = `
<html><body>
<div class="ZmHEEd">
  <div class="vWM94c">NexusPay Wallet</div><div class="LbQbAe">Unknown Dev Studio</div>
  <a href="/store/apps/details?id=com.fake.nexuspay">Link</a>
  <img src="https://play-lh.googleusercontent.com/play-icon-one=s64" class="T75of bzqKMd" />
  <span aria-label="Rated 4.1 stars"></span>
</div>
<div class="ZmHEEd">
  <div class="DdYX5">Nexusp4y</div><div class="wMUdtb">Nexuspay Ltd</div>
  <a href="/store/apps/details?id=io.nexusp4y.app">Link</a>
  <img src="https://play-lh.googleusercontent.com/play-icon-two=s64" class="T75of bzqKMd" />
  <span aria-label="Rated 4.7 stars"></span>
</div>
<div class="ZmHEEd">
  <div class="DdYX5">Nexus Bank</div><div class="wMUdtb">Nexus Bank Ltd</div>
  <a href="/store/apps/details?id=com.nexusbank.mobile">Link</a>
  <img src="https://play-lh.googleusercontent.com/play-icon-three=s64" class="T75of bzqKMd" />
  <span aria-label="Rated 3.9 stars"></span>
</div>
</body></html>`;

const PLAY_DETAIL_HTML = `
<html><head>
<meta property="og:image" content="https://play-lh.googleusercontent.com/play-icon-one=w240-h480" />
<meta property="og:description" content="NexusPay Wallet — sign in to your account." />
<title>NexusPay Wallet - Apps on Google Play</title>
</head><body>
<h1><span>NexusPay Wallet</span></h1>
<div class="Vbfug auoIOc"><a href="#"><span>Unknown Dev Studio</span></a></div>
</body></html>`;

const ITUNES_FIXTURE = {
  resultCount: 1,
  results: [
    {
      trackId: 900001,
      trackName: "NexusPay Secure",
      sellerName: "Unverified Apps LLC",
      bundleId: "com.unverified.nexuspay",
      artworkUrl100: "https://is1-ssl.mzstatic.com/image/thumb/apple-icon.png/100x100bb.png",
      trackViewUrl: "https://apps.apple.com/us/app/nexuspay-secure/id900001",
      description: "NexusPay login and wallet verification.",
      averageUserRating: 4.2,
    },
  ],
};

const BLUESKY_SESSION = { accessJwt: "test-jwt", refreshJwt: "refresh", did: "did:plc:brandwatch" };
const BLUESKY_POSTS = {
  posts: [
    {
      uri: "at://did:plc:scammer/app.bsky.feed.post/3kabc",
      cid: "bafy",
      author: { did: "did:plc:scammer", handle: "nexuspay-support.bsky.social", displayName: "NexusPay Support" },
      record: { text: "NexusPay account locked? Verify now at https://nexusp4y-login.top", createdAt: "2026-10-23T10:00:00Z" },
      likeCount: 3,
    },
  ],
};

const CISA_FIXTURE = {
  catalogVersion: "2026.10.23",
  dateReleased: "2026-10-23T00:00:00Z",
  count: 3,
  vulnerabilities: [
    {
      cveID: "CVE-2026-4242",
      vendorProject: "Nexus",
      product: "Pay Gateway",
      vulnerabilityName: "Nexus Pay Gateway Authentication Bypass",
      shortDescription: "Authentication bypass in Nexus Pay Gateway allows account takeover.",
      dateAdded: "2026-10-22",
      dueDate: "2026-11-05",
      knownRansomwareCampaignUse: "Known",
    },
    {
      cveID: "CVE-2026-1111",
      vendorProject: "Plex",
      product: "Media Server",
      vulnerabilityName: "Plex Media Server RCE",
      shortDescription: "Remote code execution.",
      dateAdded: "2026-10-21",
      dueDate: "2026-12-01",
      knownRansomwareCampaignUse: "Unknown",
    },
    {
      cveID: "CVE-2026-3333",
      vendorProject: "Cisco",
      product: "IOS XE",
      vulnerabilityName: "Cisco IOS XE Command Injection",
      shortDescription: "Command injection in the web UI.",
      dateAdded: "2026-10-20",
      dueDate: "2026-11-10",
      knownRansomwareCampaignUse: "Unknown",
    },
  ],
};

const LIVE = process.env.E2E_LIVE === "1";
const realFetch = global.fetch.bind(global);

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function urlOf(input) {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  if (input && typeof input.url === "string") return input.url;
  return String(input);
}

global.fetch = async (input, init) => {
  const url = urlOf(input);

  if (url.startsWith("http://127.0.0.1") || url.startsWith("http://localhost")) {
    return realFetch(input, init);
  }

  if (LIVE && !url.includes("cisa.gov")) {
    // Opt-in: exercise the real providers (iTunes, Play, Bluesky, gateway).
  } else {
    if (url.includes("itunes.apple.com/search")) return jsonResponse(ITUNES_FIXTURE);
    if (url.includes("play.google.com/store/search")) {
      return new Response(PLAY_SEARCH_HTML, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (url.includes("play.google.com/store/apps/details")) {
      return new Response(PLAY_DETAIL_HTML, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (url.includes("com.atproto.server.createSession")) return jsonResponse(BLUESKY_SESSION);
    if (url.includes("app.bsky.feed.searchPosts")) return jsonResponse(BLUESKY_POSTS);
    if (url.includes("known_exploited_vulnerabilities.json")) return jsonResponse(CISA_FIXTURE);
  }

  return jsonResponse({ error: "network disabled in e2e" }, 599);
};

// ---------------------------------------------------------------------------
// Database shim (real Postgres via PGlite), installed before dist/app loads.
// ---------------------------------------------------------------------------
const pglite = new PGlite();

const dbShim = {
  pool: {
    query: async (text, values = []) => {
      const result = await pglite.query(text, values);
      return { rows: result.rows, rowCount: result.rows.length, fields: result.fields };
    },
    connect: async () => ({
      query: async (text, values = []) => {
        const result = await pglite.query(text, values);
        return { rows: result.rows, rowCount: result.rows.length };
      },
      release: () => {},
    }),
    on: () => {},
    end: async () => {},
  },
  query: async (text, values = []) => {
    const result = await pglite.query(text, values);
    return { rows: result.rows, rowCount: result.rows.length, fields: result.fields };
  },
  checkDatabaseConnection: async () => ({ connected: true, latencyMs: 1 }),
  withTransaction: async (callback) => {
    await pglite.query("BEGIN");
    try {
      const result = await callback(dbShim.pool);
      await pglite.query("COMMIT");
      return result;
    } catch (error) {
      await pglite.query("ROLLBACK");
      throw error;
    }
  },
  closeDatabase: async () => pglite.close(),
  default: null,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const results = [];
let server;
let baseUrl;

function record(name, ok, detail, extra = {}) {
  results.push({ name, ok, detail, ...extra });
  const icon = ok ? "PASS" : "FAIL";
  console.log(`  [${formatIcon(ok)}] ${icon}  ${name.padEnd(42)} ${detail}`);
}

function formatIcon(ok) {
  return ok ? "✓" : "✗";
}

async function api(method, endpoint, body) {
  const started = Date.now();
  const response = await realFetch(`${baseUrl}${endpoint}`, {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = { raw: text.slice(0, 400) };
  }
  return { status: response.status, body: payload, ms: Date.now() - started, text };
}

function assert(name, condition, detail, extra) {
  record(name, Boolean(condition), detail, extra);
  return Boolean(condition);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
(async () => {
  const { INIT_SCHEMA_SQL } = loadDist("schema.js");
  const { app } = loadDist("app.js");

  console.log("\nFind_out end-to-end verification");
  console.log("=".repeat(78));

  await pglite.waitReady;
  const schemaSql = INIT_SCHEMA_SQL.replace(/CREATE EXTENSION IF NOT EXISTS "pgcrypto";/, "");
  await pglite.exec(schemaSql);
  console.log(`Postgres engine ready (${(await pglite.query("SELECT version() AS v")).rows[0].v.split(",")[0]})`);

  server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  console.log(`API listening on ${baseUrl}\n`);

  // 1. Health -------------------------------------------------------------
  const health = await api("GET", "/health");
  assert("health endpoint", health.status === 200, `HTTP ${health.status} in ${health.ms}ms`);

  // 2. Brand --------------------------------------------------------------
  const brand = await api("POST", "/api/brands", {
    name: "NexusPay",
    primaryDomain: "nexuspay.io",
    domains: ["nexuspay.io", "nexuspay.in"],
    keywords: ["nexuspay", "nexus pay"],
    industry: "fintech",
    description: "Payments platform used for end-to-end verification.",
  });
  const brandId = brand.body?.data?.id;
  assert("create brand", brand.status === 201 && Boolean(brandId), `HTTP ${brand.status} brandId=${brandId ?? "none"}`);

  if (!brandId) {
    console.error("Cannot continue without a brand:", JSON.stringify(brand.body).slice(0, 600));
    return finish(1);
  }

  // 3. Official asset -----------------------------------------------------
  const asset = await api("POST", `/api/brands/${brandId}/assets`, {
    assetType: "DOMAIN",
    identifier: "nexuspay.io",
    platform: "web",
    value: "nexuspay.io",
    notes: "Primary domain for e2e verification",
  });
  assert(
    "register official asset",
    [200, 201].includes(asset.status),
    `HTTP ${asset.status} ${asset.body?.error ?? ""}`.trim(),
  );

  // 4. Monitoring scan ----------------------------------------------------
  const scan = await api("POST", "/api/monitoring/scan", { brandId });
  const scanData = scan.body?.data ?? {};
  const sources = Array.isArray(scanData.sourceStatuses)
    ? scanData.sourceStatuses
    : Array.isArray(scanData.sources)
      ? scanData.sources
      : [];
  assert(
    "monitoring scan completes",
    scan.status === 200 && scan.ms < 60_000,
    `HTTP ${scan.status} in ${scan.ms}ms`,
    { ms: scan.ms },
  );
  record(
    "monitoring sources reported",
    sources.length > 0,
    sources.map((source) => `${source.source ?? source.id}:${source.status}`).join(", ") || "no source statuses",
  );

  // 5. Findings (the page that used to time out at 20 s) ------------------
  const candidates = await api("GET", `/api/monitoring/candidates?brandId=${brandId}&limit=500`);
  assert(
    "findings page under 3 s",
    candidates.status === 200 && candidates.ms < 3000,
    `HTTP ${candidates.status} in ${candidates.ms}ms, ${candidates.body?.data?.length ?? 0} rows`,
    { ms: candidates.ms },
  );

  const summary = await api("GET", `/api/monitoring/summary?brandId=${brandId}`);
  assert(
    "findings summary",
    summary.status === 200 && typeof summary.body?.data?.total === "number",
    `HTTP ${summary.status} total=${summary.body?.data?.total ?? "?"}`,
  );

  // 6. Investigation ------------------------------------------------------
  const investigation = await api("POST", "/api/investigations", {
    brandId,
    targetUrl: "https://nexusp4y-login.top/verify",
    title: "End-to-end verification target",
  });
  const investigationId = investigation.body?.data?.id;
  assert(
    "investigation runs",
    investigation.status === 201 && Boolean(investigationId) && investigation.ms < 45_000,
    `HTTP ${investigation.status} in ${investigation.ms}ms verdict=${investigation.body?.data?.verdict ?? "?"}`,
    { ms: investigation.ms },
  );

  if (investigationId) {
    const detail = await api("GET", `/api/investigations/${investigationId}`);
    const evidence = await api("GET", `/api/investigations/${investigationId}/evidence`);
    const rows = evidence.body?.data?.evidence ?? evidence.body?.data ?? [];
    assert(
      "investigation detail + evidence",
      detail.status === 200 &&
        evidence.status === 200 &&
        Array.isArray(rows) &&
        rows.length > 0,
      `HTTP ${detail.status}/${evidence.status}, ${Array.isArray(rows) ? rows.length : 0} evidence rows`,
    );
  }

  // 7. Look-alike + logo --------------------------------------------------
  const generate = await api("POST", "/api/intelligence/lookalike/generate", {
    brandName: "NexusPay",
    tld: "com",
  });
  const permutations = generate.body?.data?.permutations ?? [];
  assert(
    "look-alike generation",
    generate.status === 200 && permutations.length >= 5,
    `HTTP ${generate.status}, ${permutations.length} permutations`,
  );

  const evaluate = await api("POST", "/api/intelligence/lookalike/evaluate", {
    domain: "nexusp4y-login.com",
    brandName: "NexusPay",
  });
  assert(
    "look-alike evaluation flags a typosquat",
    evaluate.status === 200 && evaluate.body?.data?.isLookalike === true,
    `similarity=${evaluate.body?.data?.similarity ?? "?"} distance=${evaluate.body?.data?.editDistance ?? "?"}`,
  );

  const sharp = require(path.join(BACKEND_ROOT, "node_modules", "sharp"));
  const pngA = await sharp({ create: { width: 64, height: 64, channels: 3, background: "#1d4ed8" } }).png().toBuffer();
  const pngB = await sharp(pngA).png().toBuffer();
  const logo = await api("POST", "/api/intelligence/logo/compare", {
    referenceBase64: pngA.toString("base64"),
    targetBase64: pngB.toString("base64"),
  });
  assert(
    "logo comparison (sharp aHash)",
    logo.status === 200 && Number(logo.body?.data?.similarityScore) > 0.99,
    `HTTP ${logo.status}, similarity=${logo.body?.data?.similarityScore ?? "?"}`,
  );

  // 8. AI agent (deterministic engine: no gateway key configured) ---------
  const agent = await api("POST", "/api/agent/run", {
    goal: "Audit every module, list what is broken, and say what to do next.",
    mode: "audit",
    brandId,
  });
  const report = agent.body?.data?.report;
  assert(
    "AI agent audit run",
    agent.status === 200 && Boolean(report?.answer) && Array.isArray(report?.moduleStatus),
    `HTTP ${agent.status} in ${agent.ms}ms engine=${report?.engine ?? "?"} modules=${report?.moduleStatus?.length ?? 0}`,
    { ms: agent.ms },
  );
  if (report) {
    const failing = (report.moduleStatus ?? []).filter((module) => module.status !== "ok");
    record(
      "agent reports non-working modules",
      failing.length > 0,
      failing.map((module) => `${module.id}:${module.status}`).slice(0, 6).join(", ") || "none reported",
    );
  }

  const agentStatus = await api("GET", "/api/agent/status");
  assert("agent status endpoint", agentStatus.status === 200, `HTTP ${agentStatus.status}`);

  const diagnostics = await api("GET", "/api/agent/diagnostics?deep=0");
  assert(
    "diagnostics endpoint",
    diagnostics.status === 200 && Array.isArray(diagnostics.body?.data?.modules),
    `HTTP ${diagnostics.status}, ${diagnostics.body?.data?.modules?.length ?? 0} modules`,
  );

  // 9. Complaints: draft, guard, honest delivery --------------------------
  const complaint = await api("POST", "/api/complaints", {
    investigationId,
    brandId,
    brandName: "NexusPay",
    brandContactEmail: "security@nexuspay.io",
    complaintType: "registrar_abuse",
    recipientEmail: "abuse@registrar.example",
    targetUrl: "https://nexusp4y-login.top/verify",
    infringingEvidenceSummary: "Look-alike domain hosting a credential phishing page.",
  });
  const complaintId = complaint.body?.data?.id;
  assert("complaint drafted", complaint.status === 201 && Boolean(complaintId), `HTTP ${complaint.status}`);

  if (complaintId) {
    const forced = await api("PATCH", `/api/complaints/${complaintId}/status`, { status: "sent" });
    assert(
      "complaint cannot be marked sent without delivery",
      forced.status === 409,
      `HTTP ${forced.status} (expected 409)`,
    );

    const delivery = await api("POST", `/api/complaints/${complaintId}/send`);
    assert(
      "delivery reports not_configured instead of lying",
      delivery.status === 503 && delivery.body?.data?.delivery?.status === "not_configured",
      `HTTP ${delivery.status} status=${delivery.body?.data?.delivery?.status ?? "?"}`,
    );
  }

  // 10. Report ------------------------------------------------------------
  if (investigationId) {
    const markdown = await api("GET", `/api/reports/markdown/${investigationId}`);
    assert(
      "forensic report renders",
      markdown.status === 200 && markdown.text.length > 100,
      `HTTP ${markdown.status}, ${markdown.text.length} chars`,
    );
  }

  // 10b. Rulebook v2 detection records ------------------------------------
  const records = await api("GET", "/api/detection-records");
  const firstRecord = records.body?.data?.records?.[0];
  assert(
    "detection records carry the five required fields",
    records.status === 200 &&
      Boolean(firstRecord) &&
      typeof firstRecord.source_label === "string" &&
      typeof firstRecord.suspected_asset === "string" &&
      Array.isArray(firstRecord.evidence_summary) &&
      firstRecord.evidence_summary.length > 0 &&
      typeof firstRecord.similarity_risk_score === "number" &&
      typeof firstRecord.status === "string",
    `HTTP ${records.status}, ${records.body?.data?.records?.length ?? 0} records, status=${firstRecord?.status ?? "?"}`,
  );

  if (firstRecord) {
    const openRecord =
      [...records.body.data.records]
        .filter((record) => record.status === "NEW")
        .sort((a, b) => b.similarity_risk_score - a.similarity_risk_score)[0] ?? firstRecord;

    const review = await api("POST", `/api/detection-records/${openRecord.id}/decision`, {
      status: "UNDER_REVIEW",
      actor: "e2e.analyst@findout",
      note: "Reviewing the evidence before deciding.",
    });
    const confirm = await api("POST", `/api/detection-records/${openRecord.id}/decision`, {
      status: "CONFIRMED",
      actor: "e2e.analyst@findout",
      note: "Evidence confirms impersonation.",
    });
    const detail = await api("GET", `/api/detection-records/${openRecord.id}`);
    const history = detail.body?.data?.history ?? [];
    const lastEvent = history[history.length - 1];

    assert(
      "analyst decision records who and when",
      review.status === 200 &&
        confirm.status === 200 &&
        confirm.body?.data?.record?.decided_by === "e2e.analyst@findout" &&
        Boolean(lastEvent) &&
        lastEvent.actor === "e2e.analyst@findout" &&
        lastEvent.from_status === "UNDER_REVIEW" &&
        lastEvent.to_status === "CONFIRMED",
      `HTTP ${review.status}/${confirm.status}, ${history.length} history events`,
    );

    const draft = await api("GET", `/api/detection-records/${openRecord.id}/takedown-draft`);
    assert(
      "takedown draft is evidence based",
      draft.status === 200 &&
        String(draft.body?.data?.body ?? "").includes("Evidence gathered by our monitoring platform") &&
        !String(draft.body?.data?.body ?? "").includes("{"),
      `HTTP ${draft.status}, ${String(draft.body?.data?.body ?? "").length} chars`,
    );

    const alertsAfter = await api("GET", "/api/detection-records/alerts");
    const forRecord = (alertsAfter.body?.data ?? []).filter(
      (alert) => String(alert.record_id) === String(openRecord.id),
    );
    const repeat = await api("POST", `/api/detection-records/${openRecord.id}/decision`, {
      status: "CLOSED",
      actor: "e2e.analyst@findout",
      note: "Takedown filed.",
    });
    const alertsAgain = await api("GET", "/api/detection-records/alerts");
    const forRecordAgain = (alertsAgain.body?.data ?? []).filter(
      (alert) => String(alert.record_id) === String(openRecord.id),
    );

    // Alerts are reserved for high-risk records (score >= 70), and the dedupe
    // key means a second review action can never produce a second alert.
    const expectedAlerts = openRecord.similarity_risk_score >= 70 ? 1 : 0;
    assert(
      "high-risk alert fires once for high-risk records only",
      forRecord.length === expectedAlerts &&
        forRecordAgain.length === forRecord.length &&
        repeat.status === 200,
      `score=${openRecord.similarity_risk_score} expected=${expectedAlerts} got ${forRecord.length} → ${forRecordAgain.length}`,
    );
  }

  // 10b2. Official assets are never flagged ------------------------------
  const allRecords = records.body?.data?.records ?? [];
  const officialRecords = allRecords.filter((record) => record.is_official_excluded);
  const queue = records.body?.data?.priorityQueue ?? [];
  assert(
    "official assets never enter the priority queue",
    officialRecords.every((record) => record.status === "CLOSED") &&
      officialRecords.every((record) => !queue.some((row) => row.id === record.id)),
    `${officialRecords.length} official record(s), ${queue.length} queued`,
  );

  // 10c. Dashboard copilot chat -------------------------------------------
  const chat = await api("POST", "/api/agent/chat", {
    message: "Which modules are not working right now?",
    history: [],
  });
  assert(
    "copilot chat answers and names its engine",
    chat.status === 200 &&
      typeof chat.body?.data?.answer === "string" &&
      chat.body.data.answer.length > 20 &&
      ["llm", "deterministic"].includes(chat.body?.data?.engine),
    `HTTP ${chat.status} engine=${chat.body?.data?.engine ?? "?"} in ${chat.ms}ms`,
  );

  // 10d. Overall risk score on an investigation ----------------------------
  if (investigationId) {
    const detail = await api("GET", `/api/investigations/${investigationId}`);
    const data = detail.body?.data;
    assert(
      "investigation exposes an overall score and readable evidence",
      detail.status === 200 &&
        typeof data?.overall_risk_score === "number" &&
        Array.isArray(data?.risk_factors) &&
        Array.isArray(data?.evidence_narrative) &&
        data.evidence_narrative.length > 0 &&
        data.evidence_narrative.every((entry) => typeof entry.statement === "string"),
      `HTTP ${detail.status} score=${data?.overall_risk_score ?? "?"} statements=${data?.evidence_narrative?.length ?? 0}`,
    );
  }

  // 11. Live threat feed ---------------------------------------------------
  const feed = await api("GET", "/api/alerts/feed?limit=3");
  const feedStatus = feed.body?.data?.status;
  assert(
    "live threat feed parsed",
    feed.status === 200 && feedStatus === "available" && (feed.body?.data?.items?.length ?? 0) > 0,
    `HTTP ${feed.status} status=${feedStatus ?? "?"} items=${feed.body?.data?.items?.length ?? 0}`,
  );

  return finish(0);
})()
  .catch((error) => {
    console.error("\nE2E run crashed:", error);
    return finish(1);
  })
  .finally(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    await pglite.close().catch(() => {});
  });

function finish(exitCode) {
  const failed = results.filter((entry) => !entry.ok);
  console.log("=".repeat(78));
  console.log(`${results.length - failed.length}/${results.length} checks passed`);

  if (failed.length > 0) {
    console.log("\nFailures:");
    for (const entry of failed) console.log(`  - ${entry.name}: ${entry.detail}`);
  }

  process.exitCode = failed.length > 0 ? 1 : exitCode;
  return exitCode;
}
