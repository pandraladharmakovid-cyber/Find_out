
import dotenv from "dotenv";
import { Pool } from "pg";
import { resolve } from "node:path";

const envPath = resolve(process.cwd(), "backend/.env");
const loaded = dotenv.config({ path: envPath });

if (loaded.error) {
  console.error("Could not load backend/.env. Run this script from your project root.");
  process.exit(1);
}

const env = loaded.parsed ?? {};
const results = [];

function report(name, status, details = "") {
  results.push({ name, status, details });
  console.log(`${status.padEnd(13)} ${name}${details ? " — " + details : ""}`);
}

async function request(url, options = {}) {
  return fetch(url, {
    ...options,
    signal: AbortSignal.timeout(12000),
  });
}

async function check(name, fn) {
  try {
    await fn();
  } catch (error) {
    report(
      name,
      "FAILED",
      error?.name === "TimeoutError"
        ? "Request timed out"
        : `${error?.name ?? "Error"}: ${String(error?.message ?? "Network/request failed").slice(0, 200)}`
    );
  }
}

async function reportHttpError(name, response) {
  const detail = (await response.text()).replace(/\s+/g, " ").slice(0, 400);
  report(name, "REJECTED", `HTTP ${response.status}${detail ? `: ${detail}` : ""}`);
}

console.log("\nFind_out — full credential and integration check");
console.log("Secret values will not be printed.\n");

console.log("=== Environment variables found ===");
for (const name of Object.keys(env).filter(k => !k.startsWith("#")).sort()) {
  const value = env[name]?.trim();
  const looksSecret = /KEY|SECRET|TOKEN|PASSWORD|CLIENT_ID|DATABASE_URL|CREDENTIAL/i.test(name);
  console.log(
    `${name}: ${value ? "PRESENT" : "EMPTY"}${looksSecret ? " [credential/config]" : ""}`
  );
}

// Gemini
await check("Gemini API", async () => {
  const key = env.GEMINI_API_KEY?.trim();
  if (!key) return report("Gemini API", "MISSING", "GEMINI_API_KEY");

  const response = await request(
    `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`
  );

  if (!response.ok) return reportHttpError("Gemini API", response);

  const data = await response.json();
  const models = (data.models ?? []).filter(m =>
    (m.supportedGenerationMethods ?? []).includes("generateContent")
  );

  report(
    "Gemini API",
    models.length ? "WORKING" : "WARNING",
    `${models.length} generation model(s) available`
  );
  console.log("  Model examples:", models.slice(0, 8).map(m => m.name).join(", ") || "none");
});

// Bluesky session and authenticated public-post search
await check("Bluesky API", async () => {
  const handle = env.BLUESKY_HANDLE?.trim().replace(/^@/, "");
  const appPassword = env.BLUESKY_APP_PASSWORD?.trim();

  if (
    !handle ||
    !appPassword ||
    handle === "your-handle.bsky.social" ||
    /paste-.*app-password/i.test(appPassword)
  ) {
    return report(
      "Bluesky API",
      "MISSING",
      "Set a real BLUESKY_HANDLE and generated BLUESKY_APP_PASSWORD"
    );
  }

  const sessionResponse = await request(
    "https://bsky.social/xrpc/com.atproto.server.createSession",
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ identifier: handle, password: appPassword }),
    }
  );
  if (!sessionResponse.ok) return reportHttpError("Bluesky API", sessionResponse);

  const session = await sessionResponse.json();
  if (!session.accessJwt) {
    return report("Bluesky API", "WARNING", "Session response contained no accessJwt");
  }

  const url = new URL("https://bsky.social/xrpc/app.bsky.feed.searchPosts");
  url.search = new URLSearchParams({ q: "Find_out", limit: "1", sort: "latest" }).toString();
  const response = await request(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${session.accessJwt}`,
      "atproto-proxy": "did:web:api.bsky.app#bsky_appview",
    },
  });
  if (!response.ok) return reportHttpError("Bluesky API", response);

  const data = await response.json();
  report(
    "Bluesky API",
    "WORKING",
    `Session and authenticated search succeeded; ${data.posts?.length ?? 0} test result(s)`
  );
});

// YouTube Data API
await check("YouTube Data API", async () => {
  const key = env.YOUTUBE_API_KEY?.trim();
  if (!key) return report("YouTube Data API", "MISSING", "YOUTUBE_API_KEY");

  const url = new URL("https://www.googleapis.com/youtube/v3/search");
  url.search = new URLSearchParams({
    key,
    part: "snippet",
    q: "Find_out",
    maxResults: "1",
    type: "channel",
  });

  const response = await request(url);
  if (!response.ok) return reportHttpError("YouTube Data API", response);

  const data = await response.json();
  report("YouTube Data API", "WORKING", `Search succeeded; ${data.items?.length ?? 0} result(s)`);
});

// Google Safe Browsing
await check("Google Safe Browsing", async () => {
  const key = env.GOOGLE_SAFE_BROWSING_API_KEY?.trim()
    || env.SAFE_BROWSING_API_KEY?.trim();

  if (!key) {
    return report("Google Safe Browsing", "MISSING", "GOOGLE_SAFE_BROWSING_API_KEY");
  }

  if (!env.GOOGLE_SAFE_BROWSING_API_KEY?.trim()) {
    console.log("  WARNING: using legacy SAFE_BROWSING_API_KEY; app expects GOOGLE_SAFE_BROWSING_API_KEY.");
  }

  const response = await request(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "find-out-check",
          clientVersion: "1.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [
            { url: "http://testsafebrowsing.appspot.com/s/malware.html" },
          ],
        },
      }),
    }
  );

  if (!response.ok) return reportHttpError("Google Safe Browsing", response);

  const data = await response.json();
  report(
    "Google Safe Browsing",
    "WORKING",
    data.matches?.length
      ? `API accepted request; ${data.matches.length} threat match(es) returned`
      : "API accepted request; no threat matches returned"
  );
});

// URLhaus
await check("URLhaus", async () => {
  const key = env.URLHAUS_AUTH_KEY?.trim();
  if (!key) return report("URLhaus", "MISSING", "URLHAUS_AUTH_KEY");

  const response = await request("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: {
      "Auth-Key": key,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ url: "https://example.com/" }),
  });

  if (!response.ok) return reportHttpError("URLhaus", response);

  const data = await response.json();
  report("URLhaus", "WORKING", `API replied with query_status=${data.query_status ?? "unknown"}`);
});

// PostgreSQL
await check("PostgreSQL database", async () => {
  const connectionString = env.DATABASE_URL?.trim();
  if (!connectionString) return report("PostgreSQL database", "MISSING", "DATABASE_URL");

  const pool = new Pool({
    connectionString,
    ssl: env.DATABASE_SSL?.trim().toLowerCase() === "true"
      ? { rejectUnauthorized: false }
      : undefined,
    connectionTimeoutMillis: 10000,
    max: 1,
  });

  try {
    await pool.query("SELECT 1");
    report("PostgreSQL database", "WORKING", "Connection and SELECT 1 succeeded");
  } finally {
    await pool.end();
  }
});

// Apple App Store Search
await check("Apple App Store Search", async () => {
  const url = new URL("https://itunes.apple.com/search");
  url.search = new URLSearchParams({
    term: "WhatsApp",
    entity: "software",
    limit: "1",
    country: "in",
  });

  const response = await request(url);
  if (!response.ok) return reportHttpError("Apple App Store Search", response);

  const data = await response.json();
  report("Apple App Store Search", "WORKING", `Search succeeded; ${data.resultCount ?? 0} result(s)`);
});

console.log("\n=== Summary ===");
for (const status of ["WORKING", "WARNING", "MISSING", "REJECTED", "FAILED"]) {
  const count = results.filter(r => r.status === status).length;
  if (count) console.log(`${status}: ${count}`);
}

console.log("\nNote: connectivity/authentication checks do not prove detection accuracy.");
