import { query, withTransaction } from "./db";
import type { PoolClient, QueryResultRow } from "pg";

export interface InvestigationRecord extends QueryResultRow {
  id: string;
  title: string;
  target_url: string | null;
  query_text: string | null;
  status: string;
  summary: string | null;
  risk_score: number;
  confidence_score: number;
  verdict: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface EvidenceRecord extends QueryResultRow {
  id: string;
  investigation_id: string;
  source: string;
  source_url: string | null;
  raw_payload: Record<string, unknown>;
  is_verified: boolean;
  reliability_score: number;
  extracted_claim: string | null;
  created_at: string;
}

export interface AuditLogRecord extends QueryResultRow {
  id: string;
  investigation_id: string | null;
  source: string;
  status: string;
  latency_ms: number;
  error_message: string | null;
  attempted_at: string;
}

export interface ComplaintRecord extends QueryResultRow {
  id: string;
  investigation_id: string | null;
  brand_id?: string | null;
  platform?: string;
  target_url?: string;
  reference_number?: string | null;
  description?: string;
  reporter_email: string | null;
  claim_description: string;
  status: string;
  created_at: string;
}

export interface ExclusionRuleRecord extends QueryResultRow {
  id: string;
  pattern: string;
  reason: string | null;
  is_active: boolean;
  created_at: string;
  asset_id?: string | null;
  brand_id?: string | null;
  asset_type?: string | null;
  asset_value?: string | null;
}

export interface BrandAssetRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  asset_type: string;
  platform: string;
  identifier: string;
  value: string;
  canonical_url: string | null;
  is_verified: boolean;
  verification_status?:
    | "PENDING_VERIFICATION"
    | "VERIFIED"
    | "VERIFIED_LEGACY"
    | "REJECTED"
    | "REVOKED";
  verification_method?: string | null;
  verification_evidence?: Record<string, unknown>;
  verified_at?: string | null;
  verified_by?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  safety_status?: "NOT_ASSESSED" | "NO_THREAT_MATCH" | "THREAT_DETECTED";
  safety_evidence?: Record<string, unknown>;
  metadata: Record<string, unknown>;
  image_data?: Buffer | null;
  created_at: string;
}

/* ==========================================================================
   Investigations Repository
   ========================================================================== */
export const InvestigationsRepository = {
  async create(data: {
    title: string;
    target_url?: string | null;
    query_text?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<InvestigationRecord> {
    const text = `
      INSERT INTO investigations (title, target_url, query_text, metadata, status)
      VALUES ($1, $2, $3, $4, 'in_progress')
      RETURNING *;
    `;
    const res = await query<InvestigationRecord>(text, [
      data.title,
      data.target_url ?? null,
      data.query_text ?? null,
      JSON.stringify(data.metadata ?? {}),
    ]);
    const row = res.rows[0];
    if (!row) {
      throw new Error("Failed to create investigation record");
    }
    return row;
  },

  async findById(id: string): Promise<InvestigationRecord | null> {
    const res = await query<InvestigationRecord>(
      `SELECT * FROM investigations WHERE id = $1;`,
      [id]
    );
    return res.rows[0] ?? null;
  },

  async list(limit: number = 50, offset: number = 0): Promise<InvestigationRecord[]> {
    const res = await query<InvestigationRecord>(
      `SELECT * FROM investigations ORDER BY created_at DESC LIMIT $1 OFFSET $2;`,
      [limit, offset]
    );
    return res.rows;
  },

  async updateVerdict(
    id: string,
    update: {
      status: string;
      summary?: string | null;
      risk_score: number;
      confidence_score: number;
      verdict: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<InvestigationRecord> {
    const text = `
      UPDATE investigations
      SET status = $2,
          summary = COALESCE($3, summary),
          risk_score = $4,
          confidence_score = $5,
          verdict = $6,
          metadata = metadata || $7::jsonb,
          updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;
    const res = await query<InvestigationRecord>(text, [
      id,
      update.status,
      update.summary ?? null,
      update.risk_score,
      update.confidence_score,
      update.verdict,
      JSON.stringify(update.metadata ?? {}),
    ]);
    const row = res.rows[0];
    if (!row) {
      throw new Error(`Investigation with ID ${id} not found to update`);
    }
    return row;
  },
};

/* ==========================================================================
   Evidence Repository
   ========================================================================== */
export const EvidenceRepository = {
  async addBatch(
    investigationId: string,
    items: Array<{
      source: string;
      source_url?: string | null;
      raw_payload?: Record<string, unknown>;
      is_verified?: boolean;
      reliability_score?: number;
      extracted_claim?: string | null;
    }>
  ): Promise<void> {
    if (items.length === 0) return;

    await withTransaction(async (client) => {
      for (const item of items) {
        await client.query(
          `
          INSERT INTO evidence_items (
            investigation_id, source, source_url, raw_payload, 
            is_verified, reliability_score, extracted_claim
          ) VALUES ($1, $2, $3, $4, $5, $6, $7);
          `,
          [
            investigationId,
            item.source,
            item.source_url ?? null,
            JSON.stringify(item.raw_payload ?? {}),
            item.is_verified ?? false,
            item.reliability_score ?? 0,
            item.extracted_claim ?? null,
          ]
        );
      }
    });
  },

  async findByInvestigationId(investigationId: string): Promise<EvidenceRecord[]> {
    const res = await query<EvidenceRecord>(
      `SELECT * FROM evidence_items WHERE investigation_id = $1 ORDER BY created_at ASC;`,
      [investigationId]
    );
    return res.rows;
  },
};

/* ==========================================================================
   Source Audit Log Repository
   ========================================================================== */
export const AuditLogsRepository = {
  async recordLog(data: {
    investigation_id?: string | null;
    source: string;
    status: string;
    latency_ms: number;
    error_message?: string | null;
  }): Promise<void> {
    const text = `
      INSERT INTO source_audit_logs (investigation_id, source, status, latency_ms, error_message)
      VALUES ($1, $2, $3, $4, $5);
    `;
    await query(text, [
      data.investigation_id ?? null,
      data.source,
      data.status,
      data.latency_ms,
      data.error_message ?? null,
    ]);
  },

  async listRecent(limit: number = 100): Promise<AuditLogRecord[]> {
    const res = await query<AuditLogRecord>(
      `SELECT * FROM source_audit_logs ORDER BY attempted_at DESC LIMIT $1;`,
      [limit]
    );
    return res.rows;
  },
};

/* ==========================================================================
   Exclusion Rules Repository
   ========================================================================== */
export const ExclusionRulesRepository = {
  async listActive(brandId?: string): Promise<ExclusionRuleRecord[]> {
    if (!brandId) return [];
    const res = await query<ExclusionRuleRecord>(
      `SELECT r.id, r.pattern, r.reason, r.is_active, r.created_at,
              r.asset_id, r.brand_id, a.asset_type, a.value AS asset_value
       FROM exclusion_rules r
       INNER JOIN official_assets a ON a.id = r.asset_id
       WHERE r.is_active = TRUE
         AND r.brand_id = $1 AND a.brand_id = $1
         AND a.is_verified = TRUE
         AND a.verification_status IN ('VERIFIED', 'VERIFIED_LEGACY');`,
      [brandId],
    );
    return res.rows;
  },

  async addRule(
    pattern: string,
    reason: string | undefined,
    assetId: string,
    brandId: string,
    client?: PoolClient,
  ): Promise<ExclusionRuleRecord> {
    const text = `
      INSERT INTO exclusion_rules (pattern, reason, is_active, asset_id, brand_id)
      SELECT $1, $2, TRUE, a.id, a.brand_id
      FROM official_assets a
      WHERE a.id = $3 AND a.brand_id = $4
        AND a.is_verified = TRUE
        AND a.verification_status IN ('VERIFIED', 'VERIFIED_LEGACY')
      ON CONFLICT (pattern) DO UPDATE SET
        reason = EXCLUDED.reason,
        is_active = TRUE,
        asset_id = EXCLUDED.asset_id,
        brand_id = EXCLUDED.brand_id
      RETURNING id, pattern, reason, is_active, created_at, asset_id, brand_id;
    `;
    const values = [pattern, reason ?? null, assetId, brandId];
    const res = client
      ? await client.query<ExclusionRuleRecord>(text, values)
      : await query<ExclusionRuleRecord>(text, values);
    const row = res.rows[0];
    if (!row) {
      throw new Error("Exclusion denied: the linked asset is not verified for this brand.");
    }
    return row;
  },
};

/* ==========================================================================
   Official Brand Asset Repository
   ========================================================================== */
export const BrandAssetsRepository = {
  async findByBrandId(brandId: string, includeImageData = false): Promise<BrandAssetRecord[]> {
    const res = await query<BrandAssetRecord>(
      `SELECT id, brand_id, asset_type, platform, identifier, value, canonical_url,
              hash_signature, is_verified, verification_status, verification_method,
              verification_evidence, verified_at, verified_by, revoked_at,
              revocation_reason, safety_status, safety_evidence, metadata, created_at
       ${includeImageData ? ", image_data" : ""}
       FROM official_assets WHERE brand_id = $1 ORDER BY created_at ASC;`,
      [brandId]
    );
    return res.rows;
  },

  async create(data: {
    brand_id: string;
    asset_type: string;
    platform: string;
    identifier: string;
    value: string;
    canonical_url?: string | null;
    hash_signature?: string | null;
    image_data?: Buffer | null;
    is_verified?: boolean;
    metadata?: Record<string, unknown>;
  }): Promise<BrandAssetRecord> {
    const columns = `id, brand_id, asset_type, platform, identifier, value,
      canonical_url, hash_signature, is_verified, verification_status,
      verification_method, verification_evidence, verified_at, verified_by,
      revoked_at, revocation_reason, safety_status, safety_evidence, metadata, created_at`;
    const res = await query<BrandAssetRecord>(
      `INSERT INTO official_assets (
         brand_id, asset_type, platform, identifier, value, canonical_url,
         hash_signature, image_data, is_verified, verification_status,
         verification_evidence, safety_status, safety_evidence, metadata
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE,
                 'PENDING_VERIFICATION', '{}'::jsonb, 'NOT_ASSESSED', '{}'::jsonb, $9)
       ON CONFLICT (brand_id, asset_type, platform, identifier)
       DO UPDATE SET value = EXCLUDED.value,
                     canonical_url = EXCLUDED.canonical_url,
                     hash_signature = EXCLUDED.hash_signature,
                     image_data = EXCLUDED.image_data,
                     metadata = EXCLUDED.metadata,
                     is_verified = FALSE,
                     verification_status = 'PENDING_VERIFICATION',
                     verification_method = NULL,
                     verification_evidence = '{}'::jsonb,
                     verified_at = NULL,
                     verified_by = NULL,
                     safety_status = 'NOT_ASSESSED',
                     safety_evidence = '{}'::jsonb,
                     updated_at = NOW()
       WHERE official_assets.verification_status IN ('PENDING_VERIFICATION', 'REJECTED')
       RETURNING ${columns};`,
      [
        data.brand_id,
        data.asset_type,
        data.platform,
        data.identifier,
        data.value,
        data.canonical_url ?? null,
        data.hash_signature ?? null,
        data.image_data ?? null,
        JSON.stringify(data.metadata ?? {}),
      ]
    );
    if (res.rows[0]) return res.rows[0];

    const existing = await query<BrandAssetRecord>(
      `SELECT ${columns} FROM official_assets
       WHERE brand_id = $1 AND asset_type = $2 AND platform = $3 AND identifier = $4;`,
      [data.brand_id, data.asset_type, data.platform, data.identifier],
    );
    const row = existing.rows[0];
    if (!row) throw new Error("Failed to save official brand asset");
    return row;
  },
};

/* ==========================================================================
   Complaints Repository
   ========================================================================== */
export const ComplaintsRepository = {
  async create(data: {
    investigation_id?: string | null;
    brand_id?: string | null;
    platform?: string;
    target_identifier?: string;
    target_url?: string;
    complaint_category?: string;
    description?: string;
    reporter_email?: string | null;
    claim_description: string;
  }): Promise<ComplaintRecord> {
    const text = `
      INSERT INTO complaints (
        investigation_id, brand_id, platform, target_identifier, target_url,
        complaint_category, description, reporter_email, claim_description,
        status, submission_status
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'received', 'DRAFT')
      RETURNING *;
    `;
    const res = await query<ComplaintRecord>(text, [
      data.investigation_id ?? null,
      data.brand_id ?? null,
      data.platform ?? "unknown",
      data.target_identifier ?? "",
      data.target_url ?? "",
      data.complaint_category ?? "impersonation",
      data.description ?? data.claim_description,
      data.reporter_email ?? null,
      data.claim_description,
    ]);
    const row = res.rows[0];
    if (!row) {
      throw new Error("Failed to create complaint record");
    }
    return row;
  },

  async list(limit: number = 50): Promise<ComplaintRecord[]> {
    const res = await query<ComplaintRecord>(
      `SELECT * FROM complaints ORDER BY created_at DESC LIMIT $1;`,
      [limit]
    );
    return res.rows;
  },
};
