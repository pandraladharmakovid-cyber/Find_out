import { describe, expect, it } from "vitest";
import { agentTools, executeTool, getTool, toolCatalogForPrompt } from "../src/ai-agent/tools";

describe("Agent tool registry", () => {
  it("exposes the full module surface as tools", () => {
    const names = agentTools.map((tool) => tool.name);

    expect(names).toEqual(
      expect.arrayContaining([
        "system_diagnostics",
        "list_brands",
        "get_brand_overview",
        "run_monitoring_scan",
        "list_findings",
        "findings_summary",
        "investigate_target",
        "get_investigation",
        "generate_lookalikes",
        "evaluate_lookalike",
        "compare_logos",
        "list_alerts",
        "draft_takedown_notice",
      ]),
    );

    for (const tool of agentTools) {
      expect(tool.description.length).toBeGreaterThan(20);
      expect(tool.parameters).toMatchObject({ type: "object" });
    }
  });

  it("describes every tool in the model prompt", () => {
    const catalog = toolCatalogForPrompt();
    expect(catalog).toContain("system_diagnostics");
    expect(catalog).toContain("investigate_target");
    expect(catalog.split("\n").length).toBeGreaterThan(agentTools.length);
  });

  it("fails politely for an unknown tool", async () => {
    const result = await executeTool("delete_everything", {});
    expect(result.ok).toBe(false);
    expect(result.summary).toContain("Unknown tool");
  });

  it("generates look-alike domains through the real engine", async () => {
    const result = await executeTool("generate_lookalikes", {
      brandName: "nexuspay",
      tld: "com",
    });

    expect(result.ok).toBe(true);
    expect(result.summary).toContain("look-alike domains");
    expect(Array.isArray(result.data)).toBe(true);
    expect((result.data as unknown[]).length).toBeGreaterThan(0);
  });

  it("evaluates a suspect domain and explains the technique", async () => {
    const result = await executeTool("evaluate_lookalike", {
      domain: "nexus-pay-login.com",
      brandName: "nexuspay",
    });

    expect(result.ok).toBe(true);
    const data = result.data as { isLookalike: boolean; detectedTechnique: string | null };
    expect(data.isLookalike).toBe(true);
    expect(data.detectedTechnique).toBeTruthy();
  });

  it("drafts a takedown notice without sending it anywhere", async () => {
    const result = await executeTool("draft_takedown_notice", {
      brandName: "NexusPay",
      targetUrl: "https://nexus-pay-login.example",
      platform: "Example Host",
      evidenceSummary: "Logo similarity 96%\nRegistered publisher mismatch",
    });

    expect(result.ok).toBe(true);
    const data = result.data as { notice: string };
    expect(data.notice).toContain("NexusPay");
    expect(data.notice).toContain("nexus-pay-login.example");
    expect(data.notice).toContain("Logo similarity 96%");
    expect(data.notice).toContain("not a legal opinion");
  });

  it("returns a tool lookup by name", () => {
    expect(getTool("list_brands")?.readOnly).toBe(true);
    expect(getTool("run_monitoring_scan")?.readOnly).toBe(false);
    expect(getTool("nope")).toBeUndefined();
  });
});
