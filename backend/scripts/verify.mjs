#!/usr/bin/env node
/**
 * Find_out self-check.
 *
 * Verifies the deployment without starting the HTTP server:
 *   1. backend/.env is loaded and required variables are present
 *   2. PostgreSQL answers and the expected tables exist
 *   3. the AI gateway key is valid and reports which model/transport works
 *   4. optional integrations are listed as configured / not configured
 *
 * Usage:  node backend/scripts/verify.mjs        (from the repository root)
 *         node scripts/verify.mjs                (from backend/)
 *
 * Exit code 0 = no blockers, 1 = at least one blocking failure.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import dotenv from "dotenv";
import pg from "pg";

const here = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(here, "..");
dotenv.config({ path: path.join(backendDir, ".env") });

const results = [];
const add = (area, status, detail) => results.push({ area, status, detail });

function env(name, fallback = "") {
  return (process.env[name] ?? fallback).trim();
}

function hasAny(value) {
  return value.length > 0;
}

// ---------------------------------------------------------------------------
// 1. Environment
// ---------------------------------------------------------------------------
const required = ["DATABASE_URL"];
for (const name of required) {
  if (hasAny(env(name))) add(`env:${name}`, "ok", "set");
  else add(`env:${name}`, "error", "missing — copy backend/.env.example to backend/.env");
}

const baseUrl = env("OPENAI_BASE_URL").replace(/\/+$/, "");
const apiKey = env("OPENAI_API_KEY");
const model = env("OPENAI_MODEL", "anthropic/claude-3.5-sonnet");
const fallbacks = env("OPENAI_FALLBACK_MODELS", "openai/gpt-4o-mini")
  .split(",")
  .map((entry) => entry.trim())
  .filter(Boolean);

if (baseUrl && apiKey) add("env:AI gateway", "ok", `${baseUrl} (model ${model})`);
else add("env:AI gateway", "error", "OPENAI_BASE_URL / OPENAI_API_KEY missing — the agent will run deterministic-only");

// ---------------------------------------------------------------------------
// 2. Database
// ---------------------------------------------------------------------------
let pool = null;
try {
  pool = new pg.Pool({
    connectionString: env("DATABASE_URL"),
    ssl: env("DATABASE_SSL").toLowerCase() === "true" ? { rejectUnauthorized: true } : false,
    connectionTimeoutMillis: 8000,
  });
  const version = await pool.query("SELECT version() AS version");
  add("database", "ok", String(version.rows[0]?.version ?? "").split(",")[0]);

  const tables = [
    "brands",
    "official_assets",
    "monitoring_runs",
    "discovered_candidates",
    "candidate_evidence",
    "risk_assessments",
    "investigations",
    "evidence_items",
    "alerts",
    "complaints",
    "reports",
    "agent_runs",
    "agent_messages",
  ];
  const present = await pool.query(
    `SELECT ${tables.map((table) => `to_regclass('public.${table}') IS NOT NULL AS ${table}`).join(", ")};`,
  );
  const missing = tables.filter((table) => present.rows[0]?.[table] !== true);
  add(
    "schema",
    missing.length === 0 ? "ok" : "error",
    missing.length === 0 ? `all ${tables.length} tables present` : `missing: ${missing.join(", ")}`,
  );
} catch (error) {
  add("database", "error", error instanceof Error ? error.message : "connection failed");
}

// ---------------------------------------------------------------------------
// 3. AI gateway (model discovery + real completion)
// ---------------------------------------------------------------------------
if (baseUrl && apiKey) {
  try {
    const response = await fetch(`${baseUrl}/models`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(20000),
    });
    const payload = await response.json().catch(() => ({}));
    const count = Array.isArray(payload?.data) ? payload.data.length : 0;
    add(
      "ai:models",
      response.ok ? "ok" : "error",
      response.ok ? `${count} models exposed by the gateway` : `HTTP ${response.status}`,
    );
  } catch (error) {
    add("ai:models", "error", error instanceof Error ? error.message : "request failed");
  }

  const attempts = [];
  let success = null;

  for (const candidateModel of [...new Set([model, ...fallbacks])]) {
    for (const transport of ["chat", "responses"]) {
      const startedAt = Date.now();
      try {
        const body =
          transport === "chat"
            ? {
                model: candidateModel,
                messages: [{ role: "user", content: "Reply with the single word READY." }],
                max_tokens: 24,
              }
            : {
                model: candidateModel,
                input: "Reply with the single word READY.",
                max_output_tokens: 64,
              };

        const response = await fetch(
          `${baseUrl}/${transport === "chat" ? "chat/completions" : "responses"}`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000),
          },
        );

        if (!response.ok) {
          const text = (await response.text()).slice(0, 180);
          attempts.push(`${candidateModel}/${transport}: HTTP ${response.status} ${text}`);
          continue;
        }

        attempts.push(`${candidateModel}/${transport}: OK (${Date.now() - startedAt} ms)`);
        success = { model: candidateModel, transport };
        break;
      } catch (error) {
        attempts.push(`${candidateModel}/${transport}: ${error instanceof Error ? error.message : "failed"}`);
      }
    }
    if (success) break;
  }

  add(
    "ai:completion",
    success ? "ok" : "error",
    success
      ? `${success.model} via /${success.transport === "chat" ? "chat/completions" : "responses"}`
      : attempts.at(-1) ?? "no model answered",
  );

  if (!success) {
    console.log("\nAll gateway attempts:");
    for (const attempt of attempts) console.log(`  - ${attempt}`);
  }
}

// ---------------------------------------------------------------------------
// 4. Optional integrations (configuration only)
// ---------------------------------------------------------------------------
const optional = [
  ["gemini", "GEMINI_API_KEY"],
  ["urlhaus", "URLHAUS_AUTH_KEY"],
  ["safe browsing", "GOOGLE_SAFE_BROWSING_API_KEY"],
  ["youtube", "YOUTUBE_API_KEY"],
  ["bluesky", "BLUESKY_APP_PASSWORD"],
];
for (const [label, variable] of optional) {
  add(`source:${label}`, hasAny(env(variable)) ? "ok" : "not_configured", hasAny(env(variable)) ? "configured" : `${variable} unset — reported as not_configured`);
}

if (pool) await pool.end().catch(() => {});

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const symbol = { ok: "✓", error: "✗", not_configured: "○" };
const width = Math.max(...results.map((entry) => entry.area.length));

console.log("\nFind_out self-check\n" + "=".repeat(width + 60));
for (const entry of results) {
  console.log(`${symbol[entry.status] ?? "?"} ${entry.area.padEnd(width)}  ${entry.detail}`);
}
const blockers = results.filter((entry) => entry.status === "error");
console.log("=".repeat(width + 60));
console.log(
  blockers.length === 0
    ? "No blocking problems detected. Optional sources that show ○ can be enabled later."
    : `${blockers.length} blocking problem(s) detected.`,
);

process.exit(blockers.length === 0 ? 0 : 1);
