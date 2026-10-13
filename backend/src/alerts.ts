import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import type { QueryResultRow } from "pg";

export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved" | "dismissed";

export interface AlertRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  investigation_id: string | null;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string;
  evidence_snapshot: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface CreateAlertDTO {
  brandId: string;
  investigationId?: string | null;
  severity: AlertSeverity;
  title: string;
  description: string;
  evidenceSnapshot?: Record<string, unknown>;
}

export class AlertsService {
  async createAlert(dto: CreateAlertDTO): Promise<AlertRecord> {
    logger.info("[alerts] Creating brand security alert", {
      brandId: dto.brandId,
      severity: dto.severity,
      title: dto.title,
    });

    const text = `
      INSERT INTO alerts (
        brand_id, investigation_id, severity, status, title, description, evidence_snapshot
      ) VALUES ($1, $2, $3, 'open', $4, $5, $6)
      RETURNING *;
    `;

    const res = await query<AlertRecord>(text, [
      dto.brandId,
      dto.investigationId ?? null,
      dto.severity,
      dto.title,
      dto.description,
      JSON.stringify(dto.evidenceSnapshot ?? {}),
    ]);

    const alert = res.rows[0];
    if (!alert) {
      throw new Error("Failed to insert security alert");
    }

    return alert;
  }

  async listAlerts(brandId?: string, status?: AlertStatus): Promise<AlertRecord[]> {
    let sql = `SELECT * FROM alerts`;
    const params: (string | undefined)[] = [];

    if (brandId && status) {
      sql += ` WHERE brand_id = $1 AND status = $2`;
      params.push(brandId, status);
    } else if (brandId) {
      sql += ` WHERE brand_id = $1`;
      params.push(brandId);
    } else if (status) {
      sql += ` WHERE status = $1`;
      params.push(status);
    }

    sql += ` ORDER BY created_at DESC LIMIT 100;`;

    const res = await query<AlertRecord>(sql, params);
    return res.rows;
  }

  async updateAlertStatus(alertId: string, status: AlertStatus): Promise<AlertRecord> {
    logger.info("[alerts] Updating alert status", { alertId, status });

    const text = `
      UPDATE alerts
      SET status = $2, updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await query<AlertRecord>(text, [alertId, status]);
    const updated = res.rows[0];
    if (!updated) {
      throw new Error(`Alert with id ${alertId} not found`);
    }

    return updated;
  }
}

export const alertsService = new AlertsService();
export default alertsService;