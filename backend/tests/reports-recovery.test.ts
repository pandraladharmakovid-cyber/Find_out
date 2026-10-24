import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  getInvestigation: vi.fn(),
}));

vi.mock("../src/db", () => ({ query: mocks.query, pool: {} }));
vi.mock("../src/investigations", () => ({
  investigationService: { getInvestigationById: mocks.getInvestigation },
}));

import { ReportsService } from "../src/reports";
import { RecoveryService } from "../src/recovery";

function investigation(verdict: string) {
  return {
    id: "inv-1",
    title: "Test investigation",
    target_url: "https://target.example",
    brand_id: null,
    status: "completed",
    verdict,
    risk_score: 0,
    confidence_score: 0,
    summary: "Test summary",
    metadata: {},
    created_at: "2026-10-23T10:00:00.000Z",
    updated_at: "2026-10-23T10:00:00.000Z",
  };
}

describe("Reports and recovery audit reliability", () => {
  beforeEach(() => {
    mocks.query.mockReset();
    mocks.getInvestigation.mockReset();
  });

  it("reads active source audit logs and keeps unverified recommendations cautious", async () => {
    mocks.getInvestigation.mockResolvedValue(investigation("unverified"));
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("FROM source_audit_logs")) {
        return { rows: [{ id: "audit-1", source: "bluesky", status: "success", created_at: "2026-10-23T10:00:00.000Z" }] };
      }
      return { rows: [], rowCount: 0 };
    });

    const dossier = await new ReportsService().buildDossier("inv-1");

    expect(mocks.query).toHaveBeenCalledWith(
      expect.stringContaining("FROM source_audit_logs"),
      ["inv-1"],
    );
    expect(dossier.auditTimeline).toHaveLength(1);
    expect(dossier.recommendations.join(" ")).toContain("insufficient");
    expect(dossier.recommendations.join(" ")).not.toContain("low risk");
  });

  it("treats phishing as a high-risk report verdict", async () => {
    mocks.getInvestigation.mockResolvedValue(investigation("phishing"));
    mocks.query.mockResolvedValue({ rows: [], rowCount: 0 });

    const dossier = await new ReportsService().buildDossier("inv-1");
    expect(dossier.recommendations.join(" ")).toContain("immediate abuse takedown");
  });

  it("uses source_audit_logs for the recovery audit summary", async () => {
    mocks.query.mockImplementation(async (sql: string) => {
      if (sql.includes("SELECT NOW()")) return { rows: [{ now: "2026-10-23T10:00:00.000Z" }] };
      if (sql.includes("COUNT(*)")) return { rows: [{ count: "0" }] };
      return { rows: [], rowCount: 0 };
    });

    await new RecoveryService().exportSystemAuditSummary();
    expect(mocks.query).toHaveBeenCalledWith(
      expect.stringContaining("FROM source_audit_logs ORDER BY attempted_at DESC"),
    );
  });

  it("repairs stalled monitoring_runs as well as monitoring_jobs", async () => {
    mocks.query.mockResolvedValue({ rows: [{ id: "run-1" }], rowCount: 1 });
    const result = await new RecoveryService().recoverStalledJobs(15);

    expect(result.repairedMonitoringRunsCount).toBe(1);
    expect(mocks.query).toHaveBeenCalledWith(
      expect.stringContaining("UPDATE monitoring_runs"),
      ["15", expect.any(String)],
    );
  });
});
