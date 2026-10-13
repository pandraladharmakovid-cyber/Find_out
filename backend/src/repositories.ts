import { query, withTransaction } from "./db";
import type { QueryResultRow } from "pg";

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
  async listActive(): Promise<ExclusionRuleRecord[]> {
    const res = await query<ExclusionRuleRecord>(
      `SELECT * FROM exclusion_rules WHERE is_active = true;`
    );
    return res.rows;
  },

  async addRule(pattern: string, reason?: string): Promise<ExclusionRuleRecord> {
    const text = `
      INSERT INTO exclusion_rules (pattern, reason, is_active)
      VALUES ($1, $2, true)
      ON CONFLICT (pattern) DO UPDATE SET reason = EXCLUDED.reason, is_active = true
      RETURNING *;
    `;
    const res = await query<ExclusionRuleRecord>(text, [pattern, reason ?? null]);
    const row = res.rows[0];
    if (!row) {
      throw new Error("Failed to insert exclusion rule");
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
              hash_signature, is_verified, metadata, created_at
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
    const res = await query<BrandAssetRecord>(
      `INSERT INTO official_assets (
         brand_id, asset_type, platform, identifier, value, canonical_url,
         hash_signature, image_data, is_verified, metadata
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (brand_id, asset_type, platform, identifier)
       DO UPDATE SET value = EXCLUDED.value,
                     canonical_url = EXCLUDED.canonical_url,
                     hash_signature = EXCLUDED.hash_signature,
                     image_data = EXCLUDED.image_data,
                     is_verified = EXCLUDED.is_verified,
                     metadata = EXCLUDED.metadata,
                     updated_at = NOW()
       RETURNING id, brand_id, asset_type, platform, identifier, value,
                 canonical_url, hash_signature, is_verified, metadata, created_at;`,
      [
        data.brand_id,
        data.asset_type,
        data.platform,
        data.identifier,
        data.value,
        data.canonical_url ?? null,
        data.hash_signature ?? null,
        data.image_data ?? null,
        data.is_verified ?? false,
        JSON.stringify(data.metadata ?? {}),
      ]
    );
    const row = res.rows[0];
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