import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(5000),
  FRONTEND_URL: z.string().default("http://localhost:5173"),

  DATABASE_URL: z.string().optional().default(""),
  DATABASE_SSL: z
    .string()
    .optional()
    .transform((val) => val === "true"),

  GEMINI_API_KEY: z.string().optional().default(""),
  REDDIT_CLIENT_ID: z.string().optional().default(""),
  REDDIT_CLIENT_SECRET: z.string().optional().default(""),
  REDDIT_USER_AGENT: z.string().default("FindOut/1.0"),
  YOUTUBE_API_KEY: z.string().optional().default(""),
  GOOGLE_SAFE_BROWSING_API_KEY: z.string().optional().default(""),
  URLHAUS_AUTH_KEY: z.string().optional().default(""),

  LOG_LEVEL: z.string().default("info"),
  REQUEST_TIMEOUT_MS: z.coerce.number().default(15000),
  MAX_REQUEST_BODY_BYTES: z.coerce.number().default(1048576),
});

const parsed = envSchema.safeParse({ ...process.env });

if (!parsed.success) {
  console.error("Invalid environment configuration:", parsed.error.format());
  throw new Error("Invalid environment variables");
}

export const config = parsed.data;
export default config;
