import { z } from "zod";

/**
 * Common schema primitives
 */
export const uuidSchema = z.string().uuid("Invalid UUID format");

export const urlSchema = z
  .string()
  .trim()
  .url("Invalid URL format")
  .refine((val) => val.startsWith("http://") || val.startsWith("https://"), {
    message: "URL must use HTTP or HTTPS protocol",
  });

/**
 * Investigation Creation Schema
 */
export const createInvestigationSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(3, "Title must be at least 3 characters")
      .max(255, "Title cannot exceed 255 characters"),
    target_url: urlSchema.optional().nullable(),
    query_text: z.string().trim().max(1000).optional().nullable(),
    metadata: z.record(z.string(), z.unknown()).optional().default({}),
  })
  .refine((data) => Boolean(data.target_url || data.query_text), {
    message: "Either target_url or query_text must be provided",
    path: ["target_url"],
  });

export type CreateInvestigationInput = z.infer<typeof createInvestigationSchema>;

/**
 * Evidence Submission Schema
 */
export const createEvidenceSchema = z.object({
  source: z.enum([
    "gemini",
    // Accept legacy evidence values so historical clients/records remain compatible.
    "reddit",
    "bluesky",
    "youtube",
    "safebrowsing",
    "urlhaus",
    "app_store",
    "manual",
  ]),
  source_url: urlSchema.optional().nullable(),
  raw_payload: z.record(z.string(), z.unknown()).default({}),
  is_verified: z.boolean().default(false),
  reliability_score: z.number().min(0).max(100).default(0),
  extracted_claim: z.string().trim().max(2000).optional().nullable(),
});

export const batchEvidenceSchema = z.object({
  items: z.array(createEvidenceSchema).min(1, "At least one evidence item is required"),
});

export type CreateEvidenceInput = z.infer<typeof createEvidenceSchema>;
export type BatchEvidenceInput = z.infer<typeof batchEvidenceSchema>;

/**
 * Investigation Verdict Update Schema
 */
export const updateVerdictSchema = z.object({
  status: z.enum(["completed", "failed", "in_progress", "flagged"]),
  summary: z.string().trim().max(5000).optional().nullable(),
  risk_score: z.number().min(0).max(100),
  confidence_score: z.number().min(0).max(100),
  verdict: z.enum(["clean", "suspicious", "malicious", "phishing", "unverified"]),
  metadata: z.record(z.string(), z.unknown()).optional().default({}),
});

export type UpdateVerdictInput = z.infer<typeof updateVerdictSchema>;

/**
 * User Complaint Submission Schema
 */
export const createComplaintSchema = z.object({
  investigation_id: uuidSchema.optional().nullable(),
  reporter_email: z.string().trim().email("Invalid email address").optional().nullable(),
  claim_description: z
    .string()
    .trim()
    .min(10, "Complaint description must be at least 10 characters")
    .max(5000, "Complaint description cannot exceed 5000 characters"),
});

export type CreateComplaintInput = z.infer<typeof createComplaintSchema>;

/**
 * Exclusion Rule Schema
 */
export const createExclusionRuleSchema = z.object({
  pattern: z
    .string()
    .trim()
    .min(2, "Pattern must be at least 2 characters")
    .max(255),
  reason: z.string().trim().max(500).optional().nullable(),
});

export type CreateExclusionRuleInput = z.infer<typeof createExclusionRuleSchema>;

/**
 * Generic query pagination schema
 */
export const paginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export type PaginationQueryInput = z.infer<typeof paginationQuerySchema>;
