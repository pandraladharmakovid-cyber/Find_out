#!/usr/bin/env node
/**
 * Find_out demo server.
 *
 * Runs the real Express application against a real PostgreSQL engine (PGlite,
 * the WASM build of Postgres — no external database needed), serves the built
 * frontend from `frontend/dist`, seeds a small but realistic workspace, and
 * listens on 0.0.0.0 so it can be viewed as a live preview.
 *
 * Real API keys are read from backend/.env, so the dashboard chat box talks to
 * the configured model gateway. Everything the seeded data cannot prove is
 * reported as unavailable rather than faked.
 *
 *   node scripts/demo-server.cjs           # port 5000
 *   PORT=8080 node scripts/demo-server.cjs
 */
const path = require("node:path");
const fs = require("node:fs");

// ---------------------------------------------------------------------------
// Environment — must be set before the compiled config module is loaded.
// ---------------------------------------------------------------------------
const backendRoot = path.resolve(__dirname, "..");

// Load the real .env so OPENAI_* credentials are available, then override the
// values that must point at the in-process database.
try {
  require(path.join(backendRoot, "node_modules", "dotenv")).config({
    path: path.join(backendRoot, ".env"),
  });
} catch {
  /* dotenv is optional — the server still boots without it. */
}

const PORT = Number.parseInt(process.env.PORT ?? "5000", 10);
process.env.NODE_ENV = process.env.NODE_ENV || "production";
process.env.LOG_LEVEL = process.env.LOG_LEVEL || "warn";
process.env.DATABASE_URL = "postgres://pglite";
process.env.DATABASE_SSL = "false";
process.env.AI_AGENT_ENABLED = "true";
process.env.FRONTEND_URL = `http://localhost:${PORT}`;
process.env.SERVE_FRONTEND_DIR =
  process.env.FRONTEND_DIST || path.resolve(backendRoot, "..", "frontend", "dist");

const { PGlite } = require(path.join(backendRoot, "node_modules", "@electric-sql/pglite"));

const DIST = path.join(backendRoot, "dist");

async function main() {
  const pglite = new PGlite();
  await pglite.waitReady;

  const run = async (text, params = []) => {
    const result = await pglite.query(text, params);
    const affected = result.affectedRows;
    return { rows: result.rows, rowCount: affected ?? result.rows.length };
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

  await seed(run);

  if (!fs.existsSync(path.join(process.env.SERVE_FRONTEND_DIR, "index.html"))) {
    console.warn(
      "[demo] frontend/dist is missing — build it first: cd frontend && VITE_API_URL=/api npx vite build",
    );
  }

  // app.ts serves the built frontend from SERVE_FRONTEND_DIR, so the browser
  // uses relative /api URLs and no CORS or proxy configuration is needed.
  const { app } = require(path.join(DIST, "app.js"));

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Find_out demo listening on http://0.0.0.0:${PORT}`);
  });
}

async function seed(run) {
  const existing = await run("SELECT COUNT(*)::int AS count FROM brands");
  if ((existing.rows[0]?.count ?? 0) > 0) {
    console.log("[demo] workspace already seeded");
    return;
  }

  const brands = [
    {
      name: "PayPal",
      slug: "paypal",
      domain: "paypal.com",
      industry: "payments",
      keywords: ["paypal", "paypal secure"],
      candidates: [
        {
          platform: "google_play",
          identifier: "com.paypa1.secure",
          name: "PayPal Secure Verify",
          publisher: "Unverified Apps LLC",
          evidence: [
            { type: "APP_NAME_SIMILARITY", severity: "HIGH", similarity: 0.93, details: { reason: "digit 1 replaces the letter l" } },
            { type: "LOGO_SIMILARITY", severity: "HIGH", similarity: 0.88, details: {} },
            { type: "PUBLISHER_MISMATCH", severity: "HIGH", similarity: null, details: { expectedPublisher: "PayPal Inc" } },
          ],
          risk: { level: "HIGH", score: 91, confidence: 0.82 },
        },
        {
          platform: "bluesky",
          identifier: "paypal-support.bsky.social",
          name: "PayPal Support",
          publisher: "unknown",
          evidence: [
            { type: "NAME_LOOKALIKE", severity: "MEDIUM", similarity: 0.61, details: { reason: "brand keyword with support suffix" } },
          ],
          risk: { level: "MEDIUM", score: 48, confidence: 0.55 },
        },
        {
          platform: "apple_app_store",
          identifier: "com.paypal.app",
          name: "PayPal",
          publisher: "PayPal Inc",
          official: true,
          evidence: [],
          risk: { level: "BENIGN", score: 0, confidence: 0.9 },
        },
      ],
    },
    {
      name: "GitHub",
      slug: "github",
      domain: "github.com",
      industry: "developer tools",
      keywords: ["github"],
      candidates: [
        {
          platform: "google_play",
          identifier: "com.githuh.mobile",
          name: "GitHub Mobile",
          publisher: "Soft Apps Studio",
          evidence: [
            { type: "APP_NAME_SIMILARITY", severity: "HIGH", similarity: 0.9, details: { reason: "one character transposed" } },
            { type: "PUBLISHER_MISMATCH", severity: "MEDIUM", similarity: null, details: { expectedPublisher: "GitHub Inc" } },
          ],
          risk: { level: "HIGH", score: 78, confidence: 0.7 },
        },
      ],
    },
    {
      name: "Wikipedia",
      slug: "wikipedia",
      domain: "wikipedia.org",
      industry: "media",
      keywords: ["wikipedia"],
      candidates: [],
    },
  ];

  for (const brand of brands) {
    const brandRow = await run(
      `INSERT INTO brands (name, slug, primary_domain, industry, lookalike_threshold, status, keywords, website)
       VALUES ($1, $2, $3, $4, 0.75, 'active', $5::text[], $6)
       RETURNING id`,
      [brand.name, brand.slug, brand.domain, brand.industry, brand.keywords, `https://${brand.domain}`],
    );
    const brandId = brandRow.rows[0].id;

    if (brand.candidates.length === 0) continue;

    const runRow = await run(
      `INSERT INTO monitoring_runs (brand_id, target_type, status, started_at, completed_at)
       VALUES ($1::uuid, 'brand', 'completed', NOW(), NOW())
       RETURNING id`,
      [brandId],
    );
    const runId = runRow.rows[0].id;

    for (const candidate of brand.candidates) {
      const candidateRow = await run(
        `INSERT INTO discovered_candidates
           (run_id, brand_id, platform, candidate_identifier, candidate_url, display_name,
            developer_publisher, is_excluded_official)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
        [
          runId,
          brandId,
          candidate.platform,
          candidate.identifier,
          `https://example.invalid/${candidate.identifier}`,
          candidate.name,
          candidate.publisher,
          candidate.official === true,
        ],
      );
      const candidateId = candidateRow.rows[0].id;

      for (const item of candidate.evidence) {
        await run(
          `INSERT INTO candidate_evidence (candidate_id, evidence_type, severity, details, similarity_score)
           VALUES ($1::uuid, $2, $3, $4::jsonb, $5)`,
          [candidateId, item.type, item.severity, JSON.stringify(item.details ?? {}), item.similarity],
        );
      }

      await run(
        `INSERT INTO risk_assessments
           (candidate_id, risk_level, risk_score, confidence_score, primary_reasons, status)
         VALUES ($1::uuid, $2, $3, $4, $5::text[], $6)`,
        [
          candidateId,
          candidate.risk.level,
          candidate.risk.score,
          candidate.risk.confidence,
          candidate.evidence.map((item) => item.type).slice(0, 3),
          candidate.official ? "RESOLVED" : "UNRESOLVED",
        ],
      );
    }
  }

  // Materialise the Rulebook-v2 detection records for the seeded candidates.
  const { detectionRecordService } = require(path.join(DIST, "detection-records.service.js"));
  const synced = await detectionRecordService.sync();
  console.log(`[demo] seeded ${brands.length} brands and ${synced.created} detection records`);
}

main().catch((error) => {
  console.error("[demo] failed to start:", error);
  process.exit(1);
});
