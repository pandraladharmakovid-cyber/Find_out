import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The deterministic engine is what the agent falls back to when the gateway is
 * down. These tests pin the guarantees the UI relies on:
 *   - it never throws,
 *   - it never invents a "clean" verdict,
 *   - it reports the modules that do not work.
 */

const queryMock = vi.fn();

vi.mock("../src/db", () => ({
  query: (...args: unknown[]) => queryMock(...args),
  pool: { query: vi.fn() },
  withTransaction: vi.fn(),
}));

vi.mock("../src/ai-agent/provider", async () => {
  const actual = await vi.importActual<typeof import("../src/ai-agent/provider")>(
    "../src/ai-agent/provider",
  );
  return {
    ...actual,
    aiProvider: {
      configured: false,
      modelChain: ["anthropic/claude-3.5-sonnet"],
      status: {
        configured: false,
        baseUrl: "",
        primaryModel: "anthropic/claude-3.5-sonnet",
        modelChain: ["anthropic/claude-3.5-sonnet"],
        transportPreference: "auto",
        lastSuccessfulRoute: null,
        lastError: null,
      },
      generate: vi.fn(async () => {
        throw new Error("generate must not be called without a configured provider");
      }),
    },
  };
});

describe("Agent deterministic fallback", () => {
  beforeEach(() => {
    queryMock.mockReset();
    // Brand lookup + findings summary + run persistence are the only queries
    // the deterministic path needs.
    queryMock.mockImplementation(async (sql: string) => {
      const text = String(sql);
      if (text.includes("FROM brands")) {
        return {
          rows: [
            {
              id: "brand-1",
              name: "NexusPay",
              slug: "nexuspay",
              primary_domain: "nexuspay.io",
              status: "active",
            },
          ],
        };
      }
      if (text.includes("FROM discovered_candidates")) {
        return { rows: [{ total: "12", excluded: "2", high_risk: "3", medium_risk: "4", unassessed: "5", by_platform: {} }] };
      }
      return { rows: [] };
    });
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("produces a usable report from stored evidence when the gateway is unconfigured", async () => {
    const { AIAgentService } = await import("../src/ai-agent/agent");
    const service = new AIAgentService();

    const result = await service.run({
      goal: "Audit the platform and tell me what is broken.",
      mode: "audit",
      brandId: "11111111-1111-4111-8111-111111111111",
    });

    expect(result.status).toBe("completed");
    expect(result.report.engine).toBe("deterministic");
    expect(result.report.answer.length).toBeGreaterThan(20);
    expect(result.report.keyFindings.length).toBeGreaterThan(0);
    expect(result.report.limitations.join(" ")).toMatch(/gateway|evidence|unverified/i);
    // An unavailable model must never be reported as a clean target.
    expect(result.report.verdict).not.toBe("clean");
    // The modules that do not work are exposed to the UI.
    expect(result.report.moduleStatus.length).toBeGreaterThan(0);
  });

  it("reports the run even when the database lookups fail", async () => {
    queryMock.mockRejectedValue(new Error("database offline"));

    const { AIAgentService } = await import("../src/ai-agent/agent");
    const result = await new AIAgentService().run({
      goal: "What is the status of the platform?",
      mode: "ask",
    });

    expect(result.report.answer.length).toBeGreaterThan(0);
    expect(result.report.limitations.join(" ")).toMatch(/database offline|not configured|evidence/i);
  });
});
