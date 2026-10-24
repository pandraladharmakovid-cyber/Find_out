import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "production", "test"])
    .default("development"),

  PORT: z.coerce.number().int().min(1).max(65535).default(5000),

  FRONTEND_URL: z.string().default("http://localhost:5173"),

  // Optional: serve the built frontend from the same origin as the API.
  // Empty means API-only (the normal dev setup with Vite on :5173).
  SERVE_FRONTEND_DIR: z.string().trim().default(""),

  DATABASE_URL: z.string().default(""),

  DATABASE_SSL: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() === "true"),

  // ---------------------------------------------------------------------
  // Threat-intelligence sources
  // ---------------------------------------------------------------------
  GEMINI_API_KEY: z.string().trim().default(""),
  // Gemini model names are retired regularly; the old hard-coded
  // "gemini-1.5-pro" produced HTTP 404. The model is configurable and a
  // fallback chain is attempted before the client reports failure.
  GEMINI_MODEL: z.string().trim().default("gemini-2.5-flash"),
  GEMINI_FALLBACK_MODELS: z
    .string()
    .trim()
    .default("gemini-2.0-flash,gemini-1.5-flash-latest"),

  BLUESKY_HANDLE: z.string().trim().default(""),
  BLUESKY_APP_PASSWORD: z.string().trim().default(""),
  YOUTUBE_API_KEY: z.string().trim().default(""),
  GOOGLE_SAFE_BROWSING_API_KEY: z.string().trim().default(""),
  URLHAUS_AUTH_KEY: z.string().trim().default(""),
  URLHAUS_API_URL: z.string().trim().default("https://urlhaus-api.abuse.ch/v1"),

  // App-store monitoring
  APPLE_STORE_COUNTRY: z.string().trim().length(2).default("us"),
  GOOGLE_PLAY_LANGUAGE: z.string().trim().default("en"),
  GOOGLE_PLAY_COUNTRY: z.string().trim().length(2).default("US"),
  APP_STORE_RESULT_LIMIT: z.coerce.number().int().min(1).max(50).default(25),

  // ---------------------------------------------------------------------
  // AI agent (OpenAI-compatible gateway: api.aicredits.in)
  // ---------------------------------------------------------------------
  OPENAI_BASE_URL: z.string().trim().default(""),
  OPENAI_API_KEY: z.string().trim().default(""),
  // Model requested by the deployment owner. When the gateway key is not
  // permitted to use it, the agent falls back through OPENAI_FALLBACK_MODELS.
  OPENAI_MODEL: z.string().trim().default("anthropic/claude-sonnet-4.5"),
  OPENAI_FALLBACK_MODELS: z
    .string()
    .trim()
    .default("anthropic/claude-sonnet-4.6,openai/gpt-4o-mini,openai/gpt-4.1-mini"),
  // "auto" tries Chat Completions first and falls back to the Responses API,
  // which is required by some keys that only permit OpenAI models.
  OPENAI_TRANSPORT: z
    .enum(["auto", "chat", "responses"])
    .default("auto"),
  AI_AGENT_ENABLED: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() !== "false"),
  AI_AGENT_MAX_STEPS: z.coerce.number().int().min(1).max(12).default(6),
  AI_AGENT_TIMEOUT_MS: z.coerce.number().int().min(5000).max(180000).default(90000),
  AI_AGENT_MAX_OUTPUT_TOKENS: z.coerce
    .number()
    .int()
    .min(128)
    .max(16000)
    .default(2400),

  // ---------------------------------------------------------------------
  // Runtime limits
  // ---------------------------------------------------------------------
  // Complaint delivery (outbound notices)
  // ---------------------------------------------------------------------
  // A complaint is only ever marked "sent" after one of these transports
  // actually accepted it.
  SMTP_HOST: z.string().trim().default(""),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_SECURE: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() === "true"),
  SMTP_USER: z.string().trim().default(""),
  SMTP_PASS: z.string().trim().default(""),
  COMPLAINT_FROM_EMAIL: z.string().trim().default(""),
  COMPLAINT_FROM_NAME: z.string().trim().default("Find_out Brand Protection"),
  // Optional HTTP relay (e.g. an internal mail micro-service). Receives a JSON
  // payload and must answer 2xx for the complaint to be marked as sent.
  COMPLAINT_WEBHOOK_URL: z.string().trim().default(""),
  COMPLAINT_WEBHOOK_TOKEN: z.string().trim().default(""),

  // ---------------------------------------------------------------------
  // Brand Guard — impersonation alerts delivered through Resend
  // ---------------------------------------------------------------------
  // With no key configured the alert endpoint reports "not_configured"
  // (HTTP 503) instead of pretending an e-mail was sent.
  RESEND_API_KEY: z.string().trim().default(""),
  RESEND_API_URL: z.string().trim().default("https://api.resend.com/emails"),
  // The sender must belong to a domain verified in your Resend account.
  // "onboarding@resend.dev" works out of the box for testing.
  RESEND_FROM_EMAIL: z.string().trim().default("onboarding@resend.dev"),
  RESEND_FROM_NAME: z.string().trim().default("Find_out Brand Guard"),
  // Similarity (0..1) at which a new registration is flagged as a conflict
  // with an already-registered official brand.
  BRAND_GUARD_SIMILARITY_THRESHOLD: z.coerce
    .number()
    .min(0.3)
    .max(1)
    .default(0.72),

  // ---------------------------------------------------------------------
  // External Brand Watch — continuous external internet impersonation watch
  // ---------------------------------------------------------------------
  EXTERNAL_WATCH_SCHEDULER_ENABLED: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() !== "false"),
  EXTERNAL_WATCH_AUTO_SCAN_ON_REGISTER: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() !== "false"),
  EXTERNAL_WATCH_DEFAULT_INTERVAL_MINUTES: z.coerce
    .number()
    .int()
    .min(5)
    .max(1440)
    .default(60),
  EXTERNAL_WATCH_TICK_MS: z.coerce
    .number()
    .int()
    .min(5000)
    .max(3_600_000)
    .default(60_000),
  EXTERNAL_WATCH_ALERT_THRESHOLD: z.coerce
    .number()
    .int()
    .min(40)
    .max(100)
    .default(70),
  EXTERNAL_WATCH_CT_URL: z
    .string()
    .trim()
    .default("https://crt.sh"),
  EXTERNAL_WATCH_CT_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(2000)
    .max(60_000)
    .default(12_000),
  EXTERNAL_WATCH_DNS_PROBE_LIMIT: z.coerce
    .number()
    .int()
    .min(1)
    .max(60)
    .default(18),
  EXTERNAL_WATCH_MAX_INVESTIGATIONS_PER_RUN: z.coerce
    .number()
    .int()
    .min(1)
    .max(25)
    .default(6),

  // ---------------------------------------------------------------------
  // Live cyber threat feed
  // ---------------------------------------------------------------------
  THREAT_FEED_ENABLED: z
    .string()
    .optional()
    .transform((value) => value?.trim().toLowerCase() !== "false"),
  THREAT_FEED_URL: z
    .string()
    .trim()
    .default("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
  THREAT_FEED_CACHE_MS: z.coerce
    .number()
    .int()
    .min(60_000)
    .max(86_400_000)
    .default(15 * 60_000),

  // ---------------------------------------------------------------------
  ASSET_REGISTRY_ADMIN_KEY: z.string().trim().default(""),

  LOG_LEVEL: z
    .enum(["debug", "info", "warn", "error"])
    .default("info"),

  REQUEST_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(120000)
    .default(15000),

  // Upper bound for a single monitoring source (Bluesky, YouTube, Apple, Play).
  MONITORING_SOURCE_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(2000)
    .max(120000)
    .default(45000),

  // Upper bound for an entire brand scan before partial results are returned.
  MONITORING_RUN_DEADLINE_MS: z.coerce
    .number()
    .int()
    .min(5000)
    .max(300000)
    .default(110000),

  // PostgreSQL statement timeout used to keep evidence queries responsive.
  DB_STATEMENT_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(120000)
    .default(15000),

  MAX_REQUEST_BODY_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .max(10485760)
    .default(1048576),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const invalidVariables = parsed.error.issues
    .map((issue) => String(issue.path[0] ?? "unknown"))
    .filter((name, index, names) => names.indexOf(name) === index);

  console.error(
    `Invalid environment configuration: ${invalidVariables.join(", ")}`,
  );

  throw new Error(
    "Invalid environment variables. Check backend/.env.",
  );
}

export const config = parsed.data;

export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export default config;
