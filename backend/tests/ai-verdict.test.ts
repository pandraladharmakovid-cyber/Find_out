import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ analyzeTarget: vi.fn() }));

vi.mock("../src/integrations/gemini.client", () => ({
  geminiClient: { analyzeTarget: mocks.analyzeTarget },
}));

import { AIService } from "../src/ai";

function geminiResult(
  verdict: "clean" | "suspicious" | "malicious" | "phishing" | "unverified",
  riskScore: number,
  confidenceScore: number,
) {
  return {
    source: "gemini" as const,
    riskScore,
    confidenceScore,
    verdict,
    summary: `${verdict} test result`,
    keyFindings: [],
    rawResponse: {},
  };
}

describe("AI verdict preservation", () => {
  beforeEach(() => {
    mocks.analyzeTarget.mockReset();
  });

  it("keeps phishing distinct and preserves its actual risk score", async () => {
    mocks.analyzeTarget.mockResolvedValue(geminiResult("phishing", 88, 92));
    const result = await new AIService().evaluateImpersonation({ targetUrl: "https://phish.example" });

    expect(result.verdict).toBe("phishing");
    expect(result.riskScore).toBe(88);
    expect(result.isImpersonating).toBe(true);
    expect(result.recommendedAction).toBe("takedown_notice");
  });

  it("does not turn an unavailable/unverified evaluation into clean", async () => {
    mocks.analyzeTarget.mockResolvedValue(geminiResult("unverified", 0, 0));
    const result = await new AIService().evaluateImpersonation({ targetUrl: "https://unknown.example" });

    expect(result.verdict).toBe("unverified");
    expect(result.riskScore).toBe(0);
    expect(result.isImpersonating).toBe(false);
    expect(result.threatCategory).toBe("unverified");
    expect(result.recommendedAction).toBe("manual_review");
  });

  it("allows a clean verdict only when Gemini supplied usable confidence", async () => {
    mocks.analyzeTarget.mockResolvedValue(geminiResult("clean", 0, 90));
    const result = await new AIService().evaluateImpersonation({ targetUrl: "https://clean.example" });

    expect(result.verdict).toBe("clean");
    expect(result.riskScore).toBe(0);
    expect(result.confidenceScore).toBe(90);
    expect(result.isImpersonating).toBe(false);
  });
});
