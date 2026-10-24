import { query } from "./db";
import { logger } from "./utils/logger";

/**
 * Detection records (Rulebook v2).
 *
 * Every detection is stored as a record that carries the five required fields —
 * Source, Suspected asset, Evidence, Similarity/Risk score and Status — plus a
 * complete change history. Two rules are enforced here rather than in the UI:
 *
 * - **Official assets are never flagged.** A candidate that matched a verified
 *   official asset is excluded by the exclusion engine and forced to
 *   CLOSED/FALSE_POSITIVE with the reason recorded, so it can never appear in a
 *   priority queue.
 * - **Every status change records who made it and when.** There is no update
 *   path that skips the event log.
 */

export type DetectionStatus =
  | "NEW"
  | "UNDER_REVIEW"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "CLOSED";

export type DetectionPriority = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export const DETECTION_STATUSES: DetectionStatus[] = [
  "NEW",
  "UNDER_REVIEW",
  "CONFIRMED",
  "FALSE_POSITIVE",
  "CLOSED",
];

/** Statuses an analyst may move to from a given status. */
const ALLOWED_TRANSITIONS: Record<DetectionStatus, DetectionStatus[]> = {
  NEW: ["UNDER_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"],
  UNDER_REVIEW: ["CONFIRMED", "FALSE_POSITIVE", "CLOSED", "NEW"],
  CONFIRMED: ["CLOSED", "FALSE_POSITIVE", "UNDER_REVIEW"],
  FALSE_POSITIVE: ["CLOSED", "UNDER_REVIEW"],
  CLOSED: ["UNDER_REVIEW"],
};

export interface DetectionRecord {
  id: string;
  candidate_id: string | null;
  investigation_id: string | null;
  brand_id: string | null;
  brand_name: string | null;
  source: string;
  source_label: string;
  suspected_asset: string;
  suspected_url: string;
  suspected_asset_type: string;
  evidence_summary: string[];
  evidence_count: number;
  similarity_risk_score: number;
  confidence_score: number;
  risk_level: string;
  risk_explanation: string;
  status: DetectionStatus;
  priority: DetectionPriority;
  assigned_to: string | null;
  is_official_excluded: boolean;
  created_at: string;
  updated_at: string;
  decided_at: string | null;
  decided_by: string | null;
}

export interface DetectionRecordEvent {
  id: string;
  record_id: string;
  action: string;
  from_status: DetectionStatus | null;
  to_status: DetectionStatus | null;
  actor: string;
  note: string;
  created_at: string;
}

const SOURCE_PRESENTATION: Record<string, { label: string; type: string }> = {
  google_play: { label: "Google Play Store", type: "mobile app" },
  play_store: { label: "Google Play Store", type: "mobile app" },
  apple_app_store: { label: "Apple App Store", type: "mobile app" },
  bluesky: { label: "Bluesky", type: "social profile" },
  reddit: { label: "Reddit", type: "social post" },
  youtube: { label: "YouTube", type: "video channel" },
  domain: { label: "Domain inspection", type: "website" },
  website: { label: "Domain inspection", type: "website" },
  unknown: { label: "Unknown source", type: "unknown" },
};

function priorityFor(score: number, status: DetectionStatus): DetectionPriority {
  if (status === "FALSE_POSITIVE" || status === "CLOSED") return "LOW";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

function clampScore(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Number(Math.max(0, Math.min(100, numeric)).toFixed(2));
}

/**
 * `risk_assessments.confidence_score` is stored as a 0-1 fraction while the
 * detection record stores 0-100, so a raw 0.8 must become 80% — never "0.8%".
 */
function normaliseConfidence(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return 0;
  if (numeric > 0 && numeric <= 1) return Number((numeric * 100).toFixed(2));
  return clampScore(numeric);
}

function asSentence(value: unknown): string {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

/**
 * Turns stored candidate evidence into plain-English sentences, so the record
 * never shows a JSON blob to an analyst.
 */
export function buildEvidenceSentences(
  evidenceRows: Array<{ evidence_type?: string; severity?: string; details?: unknown; similarity_score?: unknown }>,
  params: { suspectedName: string; brandName: string | null; score: number },
): string[] {
  const sentences: string[] = [];
  const brand = params.brandName ?? "the protected brand";

  for (const row of evidenceRows) {
    const type = String(row.evidence_type ?? "").toUpperCase();
    const details = (row.details ?? {}) as Record<string, unknown>;
    const similarity = Number(row.similarity_score ?? 0);

    switch (type) {
      case "NAME_LOOKALIKE":
        sentences.push(
          asSentence(
            details.technique || details.reason
              ? `${params.suspectedName} imitates the name ${brand}: ${String(details.reason ?? details.technique)}`
              : `${params.suspectedName} imitates the name ${brand} (${Math.round(similarity * 100)}% name similarity)`,
          ),
        );
        break;
      case "APP_NAME_SIMILARITY":
        sentences.push(
          asSentence(
            `The app name "${params.suspectedName}" is ${Math.round(similarity * 100)}% similar to the official ${brand} app name`,
          ),
        );
        break;
      case "LOGO_SIMILARITY":
        sentences.push(
          asSentence(
            `The logo is ${Math.round(similarity * 100)}% visually similar to the official ${brand} logo`,
          ),
        );
        break;
      case "PUBLISHER_MISMATCH":
        sentences.push(
          asSentence(
            `The publisher is not the official ${brand} developer${details.expectedPublisher ? ` (expected ${String(details.expectedPublisher)})` : ""}`,
          ),
        );
        break;
      case "SUSPICIOUS_PERMISSIONS":
        sentences.push(asSentence("The app requests permissions that the official app does not need"));
        break;
      case "OFFICIAL_ASSET_MATCH":
        sentences.push(
          asSentence(`This candidate matches an official, verified ${brand} asset and must not be flagged`),
        );
        break;
      default: {
        const claim = typeof details.claim === "string" ? details.claim : typeof details.summary === "string" ? details.summary : "";
        if (claim) sentences.push(asSentence(claim));
      }
    }
  }

  if (sentences.length === 0) {
    sentences.push(
      asSentence(
        params.score > 0
          ? `${params.suspectedName} scored ${params.score}/100 on similarity and risk checks`
          : `${params.suspectedName} was collected by monitoring but no specific similarity evidence was recorded yet`,
      ),
    );
  }

  return [...new Set(sentences)].slice(0, 8);
}

/**
 * Reads unrecorded candidates (and candidates whose risk was re-assessed) and
 * materialises them as detection records. Idempotent: one record per candidate.
 */
async function syncFromCandidates(limit = 200): Promise<number> {
  const result = await query<{
    id: string;
    brand_id: string;
    brand_name: string | null;
    platform: string;
    candidate_identifier: string;
    candidate_url: string | null;
    display_name: string | null;
    developer_publisher: string | null;
    is_excluded_official: boolean | null;
    risk_score: string | null;
    risk_level: string | null;
    confidence_score: string | null;
    primary_reasons: string[] | null;
    ai_summary: string | null;
  }>(
    `SELECT c.id, c.brand_id, b.name AS brand_name, c.platform,
            c.candidate_identifier, c.candidate_url, c.display_name,
            c.developer_publisher, c.is_excluded_official,
            lr.risk_score, lr.risk_level, lr.confidence_score, lr.primary_reasons, lr.ai_summary
       FROM discovered_candidates c
       JOIN brands b ON b.id = c.brand_id
       LEFT JOIN LATERAL (
         SELECT ra.risk_score, ra.risk_level, ra.confidence_score, ra.primary_reasons, ra.ai_summary
           FROM risk_assessments ra
          WHERE ra.candidate_id = c.id
          ORDER BY ra.assessed_at DESC
          LIMIT 1
       ) lr ON TRUE
      WHERE NOT EXISTS (SELECT 1 FROM detection_records dr WHERE dr.candidate_id = c.id)
      ORDER BY c.discovered_at DESC
      LIMIT $1`,
    [limit],
  );

  let created = 0;

  for (const row of result.rows) {
    const presentation = SOURCE_PRESENTATION[row.platform] ?? {
      label: row.platform.replace(/_/g, " "),
      type: "asset",
    };
    const score = clampScore(row.risk_score ?? 0);
    const official = row.is_excluded_official === true;

    const evidenceRows = await query<{
      evidence_type: string;
      severity: string;
      details: unknown;
      similarity_score: string | null;
    }>(
      `SELECT evidence_type, severity, details, similarity_score
         FROM candidate_evidence WHERE candidate_id = $1::uuid
        ORDER BY recorded_at ASC`,
      [row.id],
    );

    const suspectedName = row.display_name?.trim() || row.candidate_identifier;
    const evidenceSummary = official
      ? [
          `${suspectedName} matches a verified official ${row.brand_name ?? "brand"} asset, so it is excluded from detection.`,
        ]
      : buildEvidenceSentences(evidenceRows.rows, {
          suspectedName,
          brandName: row.brand_name,
          score,
        });

    const riskExplanation = official
      ? "Official assets are never flagged: the exclusion engine matched this candidate to a registered, verified brand asset."
      : row.ai_summary?.trim() ||
        (row.primary_reasons && row.primary_reasons.length > 0
          ? row.primary_reasons.slice(0, 4).join(" ")
          : score >= 60
            ? `The candidate scored ${score}/100 because it imitates ${row.brand_name ?? "the brand"} on name, logo or publisher checks.`
            : `The candidate scored ${score}/100; there is not enough evidence to call it impersonation yet.`);

    const status: DetectionStatus = official ? "CLOSED" : "NEW";
    const priority = priorityFor(official ? 0 : score, status);

    const inserted = await query<{ id: string }>(
      `INSERT INTO detection_records
         (candidate_id, brand_id, source, source_label, suspected_asset, suspected_url,
          suspected_asset_type, evidence_summary, evidence_count, similarity_risk_score,
          confidence_score, risk_level, risk_explanation, status, priority,
          is_official_excluded, decided_at, decided_by)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::text[], $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
       ON CONFLICT (candidate_id) WHERE candidate_id IS NOT NULL DO NOTHING
       RETURNING id`,
      [
        row.id,
        row.brand_id,
        row.platform,
        presentation.label,
        suspectedName.slice(0, 500),
        row.candidate_url ?? "",
        presentation.type,
        evidenceSummary,
        evidenceRows.rows.length,
        official ? 0 : score,
        normaliseConfidence(row.confidence_score),
        String(row.risk_level ?? "UNASSESSED"),
        riskExplanation,
        status,
        priority,
        official,
        official ? new Date().toISOString() : null,
        official ? "exclusion-engine" : null,
      ],
    );

    if (inserted.rows[0]) {
      created += 1;
      await query(
        `INSERT INTO detection_record_events (record_id, action, from_status, to_status, actor, note)
         VALUES ($1::uuid, 'CREATED', NULL, $2, $3, $4)`,
        [
          inserted.rows[0].id,
          status,
          official ? "exclusion-engine" : "monitoring",
          official
            ? "Created and immediately closed: matched a verified official asset."
            : "Created automatically from monitoring results.",
        ],
      );
    }
  }

  return created;
}

export class DetectionRecordService {
  /** Ensures monitoring results are mirrored into detection records. */
  async sync(limit = 200): Promise<{ created: number }> {
    try {
      const created = await syncFromCandidates(limit);
      return { created };
    } catch (error) {
      logger.warn("[detection-records] Sync failed", {
        error: error instanceof Error ? error.message : "unknown",
      });
      return { created: 0 };
    }
  }

  async list(filters: {
    status?: DetectionStatus;
    priority?: DetectionPriority;
    brandId?: string;
    search?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ records: DetectionRecord[]; total: number; counts: Record<string, number> }> {
    const values: Array<string | number> = [];
    const where: string[] = [];

    if (filters.status) {
      values.push(filters.status);
      where.push(`d.status = $${values.length}`);
    }
    if (filters.priority) {
      values.push(filters.priority);
      where.push(`d.priority = $${values.length}`);
    }
    if (filters.brandId) {
      values.push(filters.brandId);
      where.push(`d.brand_id = $${values.length}::uuid`);
    }
    if (filters.search) {
      values.push(`%${filters.search.slice(0, 120)}%`);
      where.push(`(d.suspected_asset ILIKE $${values.length} OR d.suspected_url ILIKE $${values.length})`);
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const limit = Math.max(1, Math.min(filters.limit ?? 100, 300));
    const offset = Math.max(0, filters.offset ?? 0);

    values.push(limit);
    const limitParam = `$${values.length}`;
    values.push(offset);
    const offsetParam = `$${values.length}`;

    const rows = await query<Record<string, unknown>>(
      `SELECT d.*, b.name AS brand_name
         FROM detection_records d
         LEFT JOIN brands b ON b.id = d.brand_id
         ${whereClause}
        ORDER BY
          CASE d.priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
          d.similarity_risk_score DESC,
          d.created_at DESC
        LIMIT ${limitParam} OFFSET ${offsetParam}`,
      values,
    );

    const countsResult = await query<{ status: string; count: string }>(
      `SELECT status, COUNT(*)::text AS count FROM detection_records GROUP BY status`,
    );

    const counts: Record<string, number> = {};
    for (const status of DETECTION_STATUSES) counts[status] = 0;
    for (const row of countsResult.rows) {
      counts[row.status] = Number(row.count);
    }

    return {
      records: rows.rows.map((row) => this.mapRecord(row)),
      total: Object.values(counts).reduce((total, value) => total + value, 0),
      counts,
    };
  }

  /** Highest-risk records that still need an analyst decision. */
  async priorityQueue(limit = 10): Promise<DetectionRecord[]> {
    const { records } = await this.list({ limit });
    return records
      .filter((record) => record.status === "NEW" || record.status === "UNDER_REVIEW")
      .sort((a, b) => b.similarity_risk_score - a.similarity_risk_score)
      .slice(0, limit);
  }

  async get(id: string): Promise<{ record: DetectionRecord; history: DetectionRecordEvent[] } | null> {
    const row = await query<Record<string, unknown>>(
      `SELECT d.*, b.name AS brand_name
         FROM detection_records d
         LEFT JOIN brands b ON b.id = d.brand_id
        WHERE d.id = $1::uuid`,
      [id],
    );

    if (!row.rows[0]) return null;

    const history = await query<Record<string, unknown>>(
      `SELECT * FROM detection_record_events
        WHERE record_id = $1::uuid
        ORDER BY created_at ASC`,
      [id],
    );

    return {
      record: this.mapRecord(row.rows[0]),
      history: history.rows.map((entry) => ({
        id: String(entry.id),
        record_id: String(entry.record_id),
        action: String(entry.action),
        from_status: (entry.from_status as DetectionStatus | null) ?? null,
        to_status: (entry.to_status as DetectionStatus | null) ?? null,
        actor: String(entry.actor),
        note: String(entry.note ?? ""),
        created_at: new Date(String(entry.created_at)).toISOString(),
      })),
    };
  }

  /**
   * Analyst decision. Records the actor, the previous status and the note, so
   * the history answers "who changed this, when, and why".
   */
  async decide(params: {
    id: string;
    status: DetectionStatus;
    actor: string;
    note?: string;
  }): Promise<{ record: DetectionRecord; history: DetectionRecordEvent[] }> {
    const current = await this.get(params.id);
    if (!current) throw new Error("Detection record not found.");

    if (current.record.is_official_excluded && params.status === "CONFIRMED") {
      throw new Error(
        "This candidate is a verified official asset and can never be confirmed as impersonation.",
      );
    }

    const allowed = ALLOWED_TRANSITIONS[current.record.status] ?? [];
    if (!allowed.includes(params.status)) {
      throw new Error(
        `Cannot move a record from ${current.record.status} to ${params.status}. Allowed: ${allowed.join(", ")}.`,
      );
    }

    const actor = params.actor.trim().slice(0, 120) || "unknown-analyst";
    const now = new Date().toISOString();
    const decided = params.status === "CONFIRMED" || params.status === "FALSE_POSITIVE" || params.status === "CLOSED";

    await query(
      `UPDATE detection_records
          SET status = $2,
              priority = $3,
              updated_at = $4,
              assigned_to = COALESCE(assigned_to, $5),
              decided_at = CASE WHEN $6 THEN $4 ELSE decided_at END,
              decided_by = CASE WHEN $6 THEN $5 ELSE decided_by END
        WHERE id = $1::uuid`,
      [
        params.id,
        params.status,
        priorityFor(current.record.similarity_risk_score, params.status),
        now,
        actor,
        decided,
      ],
    );

    await query(
      `INSERT INTO detection_record_events (record_id, action, from_status, to_status, actor, note)
       VALUES ($1::uuid, 'STATUS_CHANGE', $2, $3, $4, $5)`,
      [params.id, current.record.status, params.status, actor, (params.note ?? "").slice(0, 2000)],
    );

    const updated = await this.get(params.id);
    if (!updated) throw new Error("Detection record disappeared during the update.");

    // A confirmed high-risk record alerts once, never on every refresh.
    if (params.status === "CONFIRMED" && updated.record.similarity_risk_score >= 70) {
      await this.raiseHighRiskAlert(updated.record);
    }

    return updated;
  }

  /**
   * One-time high-risk alert. The unique dedupe key means repeat scans and page
   * refreshes cannot produce a second alert for the same record.
   */
  async raiseHighRiskAlert(record: DetectionRecord): Promise<{ created: boolean; id?: string }> {
    const dedupeKey = `high-risk:${record.id}`;
    const title = `High-risk impersonation confirmed: ${record.suspected_asset}`;
    const message =
      `${record.suspected_asset} (${record.source_label}) was confirmed as impersonation with a risk score of ` +
      `${record.similarity_risk_score}/100. Evidence: ${record.evidence_summary.slice(0, 2).join(" ")}`;

    const inserted = await query<{ id: string }>(
      `INSERT INTO high_risk_alerts (record_id, dedupe_key, severity, title, message)
       VALUES ($1::uuid, $2, $3, $4, $5)
       ON CONFLICT (dedupe_key) DO NOTHING
       RETURNING id`,
      [record.id, dedupeKey, record.similarity_risk_score >= 85 ? "CRITICAL" : "HIGH", title, message],
    );

    if (inserted.rows[0]) {
      // Mirror into the existing alerts table so the Alerts screen shows it too.
      try {
        await query(
          `INSERT INTO alerts (severity, title, description, summary, category, source_url)
           VALUES ($1, $2, $3, $3, 'IMPERSONATION', $4)`,
          [
            record.similarity_risk_score >= 85 ? "CRITICAL" : "HIGH",
            title,
            message,
            record.suspected_url,
          ],
        );
      } catch {
        // The alerts table is optional for this feature; the dedicated table is
        // the source of truth.
      }

      return { created: true, id: inserted.rows[0].id };
    }

    return { created: false };
  }

  async listAlerts(includeAcknowledged = false): Promise<Array<Record<string, unknown>>> {
    const result = await query<Record<string, unknown>>(
      `SELECT a.*, d.suspected_asset, d.source_label, d.status
         FROM high_risk_alerts a
         JOIN detection_records d ON d.id = a.record_id
        ${includeAcknowledged ? "" : "WHERE a.acknowledged_at IS NULL"}
        ORDER BY a.created_at DESC
        LIMIT 50`,
    );
    return result.rows;
  }

  async acknowledgeAlert(id: string, actor: string): Promise<boolean> {
    const result = await query(
      `UPDATE high_risk_alerts
          SET acknowledged_at = COALESCE(acknowledged_at, NOW()), acknowledged_by = COALESCE(acknowledged_by, $2)
        WHERE id = $1::uuid`,
      [id, actor.slice(0, 120) || "unknown-analyst"],
    );
    return (result.rowCount ?? 0) > 0;
  }

  /**
   * Evidence-based takedown draft. Every claim is traceable to a stored
   * evidence sentence; nothing is embellished.
   */
  async takedownDraft(id: string): Promise<{
    record: DetectionRecord;
    subject: string;
    body: string;
    evidenceLines: string[];
    generatedAt: string;
  } | null> {
    const found = await this.get(id);
    if (!found) return null;

    const record = found.record;
    const brand = record.brand_name ?? "the brand owner";
    const evidenceLines = record.evidence_summary.map((sentence, index) => `${index + 1}. ${sentence}`);

    const subject = `Takedown request — impersonation of ${brand}: ${record.suspected_asset}`;

    const body = [
      `To the ${record.source_label} trust and safety team,`,
      "",
      `We are writing on behalf of ${brand} to report an asset on your platform that impersonates the brand.`,
      "",
      `Suspected asset: ${record.suspected_asset}`,
      record.suspected_url ? `Location: ${record.suspected_url}` : "",
      record.suspected_asset_type ? `Asset type: ${record.suspected_asset_type}` : "",
      `Detection reference: ${record.id}`,
      "",
      "Evidence gathered by our monitoring platform:",
      ...evidenceLines,
      "",
      `Assessed risk: ${record.similarity_risk_score}/100 (${record.risk_level}), confidence ${record.confidence_score}%.`,
      record.risk_explanation ? `Assessment: ${record.risk_explanation}` : "",
      "",
      `This asset was reviewed and marked ${record.status.replace(/_/g, " ").toLowerCase()}${
        record.decided_by ? ` by ${record.decided_by}` : ""
      }${record.decided_at ? ` on ${new Date(record.decided_at).toISOString().slice(0, 10)}` : ""}.`,
      "",
      "We request that the asset be reviewed under your impersonation and trademark policy and removed or suspended while the review takes place.",
      "",
      "We are happy to provide additional verification of our trademark rights on request.",
      "",
      `Regards,`,
      `${brand} brand protection`,
    ]
      .filter((line) => line !== "")
      .join("\n");

    return {
      record,
      subject,
      body,
      evidenceLines,
      generatedAt: new Date().toISOString(),
    };
  }

  private mapRecord(row: Record<string, unknown>): DetectionRecord {
    return {
      id: String(row.id),
      candidate_id: (row.candidate_id as string | null) ?? null,
      investigation_id: (row.investigation_id as string | null) ?? null,
      brand_id: (row.brand_id as string | null) ?? null,
      brand_name: (row.brand_name as string | null) ?? null,
      source: String(row.source ?? "unknown"),
      source_label: String(row.source_label ?? "Unknown source"),
      suspected_asset: String(row.suspected_asset ?? ""),
      suspected_url: String(row.suspected_url ?? ""),
      suspected_asset_type: String(row.suspected_asset_type ?? "unknown"),
      evidence_summary: (row.evidence_summary as string[] | null) ?? [],
      evidence_count: Number(row.evidence_count ?? 0),
      similarity_risk_score: Number(row.similarity_risk_score ?? 0),
      confidence_score: normaliseConfidence(row.confidence_score),
      risk_level: String(row.risk_level ?? "UNASSESSED"),
      risk_explanation: String(row.risk_explanation ?? ""),
      status: (row.status as DetectionStatus) ?? "NEW",
      priority: (row.priority as DetectionPriority) ?? "MEDIUM",
      assigned_to: (row.assigned_to as string | null) ?? null,
      is_official_excluded: row.is_official_excluded === true,
      created_at: new Date(String(row.created_at)).toISOString(),
      updated_at: new Date(String(row.updated_at)).toISOString(),
      decided_at: row.decided_at ? new Date(String(row.decided_at)).toISOString() : null,
      decided_by: (row.decided_by as string | null) ?? null,
    };
  }
}

export const detectionRecordService = new DetectionRecordService();
export default detectionRecordService;
