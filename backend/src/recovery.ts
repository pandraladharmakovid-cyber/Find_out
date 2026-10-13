import { query, pool } from "./db";
import { logger } from "./utils/logger";
import type { QueryResultRow } from "pg";

export interface SystemHealthReport {
  status: "healthy" | "degraded" | "unhealthy";
  databaseConnected: boolean;
  tableCounts: Record<string, number>;
  activeInvestigations: number;
  openAlerts: number;
  timestamp: string;
}

export interface StalledJobRepairResult {
  repairedInvestigationsCount: number;
  repairedMonitoringJobsCount: number;
}

export interface IncidentAssessment {
  target: string;
  safety_verdict: "unverified";
  compromised_count: null;
  click_consequences: string;
  victim_details: string;
  immediate_safety: string;
  existing_access_check: string;
  complete_solution: string;
  delivery_channel: string;
  device_risk: string;
  recovery_steps: string[];
  evidence_note: string;
}

export class RecoveryService {
  assessIncident(target: string, incidentType: string): IncidentAssessment {
    const normalizedType = incidentType.toLowerCase().replace(/[\s-]+/g, "_");
    const stepsByIncident: Record<string, string[]> = {
      entered_password: [
        "From a separate trusted device, change the exposed password on the real service and any account that reused it.",
        "Sign out other sessions and review recent sign-ins and recovery details.",
        "Enable multi-factor authentication and contact the service provider if you see unknown activity.",
      ],
      password_entered: [
        "From a separate trusted device, change the exposed password on the real service and any account that reused it.",
        "Sign out other sessions and review recent sign-ins and recovery details.",
        "Enable multi-factor authentication and contact the service provider if you see unknown activity.",
      ],
      installed_app: [
        "Disconnect the device from sensitive accounts and remove the untrusted app using the operating system's app settings.",
        "Run the device's trusted security scan and install operating-system updates.",
        "From a separate trusted device, change passwords for accounts used on the affected device and review active sessions.",
      ],
      granted_permissions: [
        "Revoke the unfamiliar app or website in the account's connected-apps and permissions settings.",
        "Review recent sign-ins, active sessions, forwarding rules, and recovery methods.",
        "Change the account password from a trusted device and enable multi-factor authentication.",
      ],
      clicked_link: [
        "Close the page and do not enter credentials, payment details, or one-time codes.",
        "Check whether a file was downloaded or an app was installed; do not open unexpected downloads.",
        "If credentials or permissions were submitted, follow the corresponding recovery steps immediately.",
      ],
      opened_link: [
        "Close the page and do not enter credentials, payment details, or one-time codes.",
        "Check whether a file was downloaded or an app was installed; do not open unexpected downloads.",
        "If credentials or permissions were submitted, follow the corresponding recovery steps immediately.",
      ],
    };
    const steps = stepsByIncident[normalizedType] ?? stepsByIncident.opened_link ?? [];
    const consequenceByIncident: Record<string, string> = {
      entered_password: "A deceptive page could capture the submitted password and enable account access, especially if it is reused.",
      password_entered: "A deceptive page could capture the submitted password and enable account access, especially if it is reused.",
      installed_app: "An untrusted installation may request excessive permissions or expose data on the device; this has not been verified for the supplied target.",
      granted_permissions: "Granted permissions may allow the connected app to read or change account data within the scope shown by the service.",
      clicked_link: "Opening a link alone does not prove compromise; risk depends on what the page loaded and whether data or files were submitted.",
      opened_link: "Opening a link alone does not prove compromise; risk depends on what the page loaded and whether data or files were submitted.",
    };

    let deliveryChannel = "Not determined from the submitted identifier.";
    try {
      const parsed = new URL(target);
      deliveryChannel = `Web link on ${parsed.hostname}; how it was delivered is not known.`;
    } catch {
      if (/whatsapp/i.test(target)) deliveryChannel = "WhatsApp was mentioned in the submitted identifier; delivery is not independently verified.";
      else if (/sms|text message/i.test(target)) deliveryChannel = "SMS/text message was mentioned; delivery is not independently verified.";
    }

    const deviceRisk = normalizedType === "installed_app"
      ? "Elevated review recommended because software was installed; no device scan was performed."
      : normalizedType === "granted_permissions"
        ? "Account permission exposure is possible; device compromise is not established."
        : "No device compromise is established by the information supplied.";

    return {
      target,
      safety_verdict: "unverified",
      compromised_count: null,
      click_consequences: consequenceByIncident[normalizedType] ?? consequenceByIncident.opened_link ?? "",
      victim_details: "No victim or breach dataset was queried. No affected account or victim is confirmed.",
      immediate_safety: steps[0] ?? "Use the official service directly and do not share passwords or one-time codes.",
      existing_access_check: "No account access check is available without authorized provider data. Review active sessions, recent sign-ins, connected apps, and recovery details directly in the official account settings.",
      complete_solution: steps.join(" "),
      delivery_channel: deliveryChannel,
      device_risk: deviceRisk,
      recovery_steps: steps,
      evidence_note: "This is scenario-based guidance only. No external reputation, account, breach, or device source was queried for this assessment.",
    };
  }

  /**
   * Performs an end-to-end database connectivity and system integrity audit.
   */
  async checkHealth(): Promise<SystemHealthReport> {
    try {
      const dbCheck = await query<{ now: string }>(`SELECT NOW() as now;`);
      const isDbUp = Boolean(dbCheck.rows[0]?.now);

      const tables = [
        "brands",
        "official_assets",
        "investigations",
        "evidence_items",
        "alerts",
        "complaints",
        "reports",
        "audit_logs",
      ];

      const counts: Record<string, number> = {};

      for (const table of tables) {
        try {
          const res = await query<{ count: string }>(`SELECT COUNT(*) as count FROM ${table};`);
          counts[table] = parseInt(res.rows[0]?.count ?? "0", 10);
        } catch {
          counts[table] = 0;
        }
      }

      const activeInvRes = await query<{ count: string }>(
        `SELECT COUNT(*) as count FROM investigations WHERE status = 'analyzing';`
      );
      const openAlertsRes = await query<{ count: string }>(
        `SELECT COUNT(*) as count FROM alerts WHERE status = 'open';`
      );

      return {
        status: isDbUp ? "healthy" : "unhealthy",
        databaseConnected: isDbUp,
        tableCounts: counts,
        activeInvestigations: parseInt(activeInvRes.rows[0]?.count ?? "0", 10),
        openAlerts: parseInt(openAlertsRes.rows[0]?.count ?? "0", 10),
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error("[recovery] Health check evaluation failed", {
        error: error instanceof Error ? error.message : "Unknown",
      });

      return {
        status: "unhealthy",
        databaseConnected: false,
        tableCounts: {},
        activeInvestigations: 0,
        openAlerts: 0,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Resets investigations and background monitoring jobs stalled due to unhandled restarts.
   */
  async recoverStalledJobs(timeoutMinutes = 15): Promise<StalledJobRepairResult> {
    logger.info("[recovery] Scanning for orphan or stalled jobs", { timeoutMinutes });

    // Mark stalled analyzing investigations as failed
    const invRes = await query<QueryResultRow>(
      `UPDATE investigations
       SET status = 'failed',
           summary = 'Investigation terminated: Execution timed out or container restarted unexpectedly',
           updated_at = NOW()
       WHERE status = 'analyzing'
         AND updated_at < NOW() - ($1 || ' minutes')::interval
       RETURNING id;`,
      [timeoutMinutes.toString()]
    );

    // Reset stalled monitoring jobs
    const monRes = await query<QueryResultRow>(
      `UPDATE monitoring_jobs
       SET status = 'failed',
           completed_at = NOW()
       WHERE status = 'running'
         AND started_at < NOW() - ($1 || ' minutes')::interval
       RETURNING id;`,
      [timeoutMinutes.toString()]
    );

    const repairedInvestigationsCount = invRes.rowCount ?? 0;
    const repairedMonitoringJobsCount = monRes.rowCount ?? 0;

    logger.info("[recovery] Stalled job repair routine completed", {
      repairedInvestigationsCount,
      repairedMonitoringJobsCount,
    });

    return {
      repairedInvestigationsCount,
      repairedMonitoringJobsCount,
    };
  }

  /**
   * Exports an audit summary for backup and compliance verification.
   */
  async exportSystemAuditSummary(): Promise<Record<string, unknown>> {
    const health = await this.checkHealth();
    const recentAudits = await query(
      `SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50;`
    );

    return {
      exportedAt: new Date().toISOString(),
      health,
      recentAuditLogs: recentAudits.rows,
    };
  }
}

export const recoveryService = new RecoveryService();
export default recoveryService;