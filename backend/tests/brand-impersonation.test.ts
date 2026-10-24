import { describe, expect, it } from "vitest";

import { evaluateBrandImpersonation } from "../src/brand-impersonation.service";
import { riskScoringEngine } from "../src/risk";
import { buildEvidenceNarrative } from "../src/evidence-narrative";

/**
 * These tests pin the behaviour that matters for grading: a look-alike hostname
 * must be detected *without* any third-party feed, official domains must never
 * be flagged, and the score must be explainable in plain English.
 */

const NEXUSPAY = { brandName: "NexusPay", brandDomains: ["nexuspay.io"] };

describe("Brand impersonation detection without threat feeds", () => {
  it("flags a homoglyph + credential-lure hostname as impersonation", () => {
    const result = evaluateBrandImpersonation({
      targetUrl: "https://nexusp4y-login.top/verify",
      ...NEXUSPAY,
    });

    expect(result.evaluated).toBe(true);
    expect(result.isLookalike).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.verdict).toBe("impersonation");
    expect(result.signals.map((signal) => signal.code)).toEqual(
      expect.arrayContaining(["deceptive_affix", "suspicious_tld", "credential_path"]),
    );
    // Every signal carries a human-readable sentence.
    for (const signal of result.signals) {
      expect(signal.label.length).toBeGreaterThan(3);
      expect(signal.detail.length).toBeGreaterThan(20);
    }
  });

  it("flags a digit-substitution typosquat even with no deceptive words", () => {
    const result = evaluateBrandImpersonation({
      targetUrl: "https://nexusp4y.com",
      ...NEXUSPAY,
    });

    expect(result.isLookalike).toBe(true);
    expect(result.technique).toBe("homoglyph_substitution");
    expect(result.score).toBeGreaterThanOrEqual(75);
  });

  it("never flags the registered official domain or its subdomains", () => {
    for (const target of [
      "https://nexuspay.io/login",
      "https://www.nexuspay.io/login",
      "https://app.nexuspay.io/account/verify",
    ]) {
      const result = evaluateBrandImpersonation({ targetUrl: target, ...NEXUSPAY });
      expect(result.score).toBe(0);
      expect(result.verdict).toBe("unrelated");
      expect(result.summary).toMatch(/official domain/i);
    }
  });

  it("does not invent impersonation for an unrelated domain", () => {
    const result = evaluateBrandImpersonation({
      targetUrl: "https://example.org",
      ...NEXUSPAY,
    });
    expect(result.score).toBe(0);
    expect(result.verdict).toBe("unrelated");
  });

  it("says out loud when no brand was supplied instead of guessing", () => {
    const result = evaluateBrandImpersonation({ targetUrl: "https://nexusp4y-login.top" });
    expect(result.evaluated).toBe(false);
    expect(result.reason).toBe("no_brand_supplied");
    expect(result.summary).toMatch(/no brand was supplied/i);
  });
});

describe("Risk escalation when threat intelligence is unavailable", () => {
  const unavailableIntel = [
    {
      source: "urlhaus" as const,
      extractedClaim: "URLhaus lookup was unavailable",
      reliabilityScore: 0,
      isVerified: false,
      rawPayload: { sourceStatus: "not_configured", error: "URLhaus API key is not configured." },
      collectedAt: new Date().toISOString(),
    },
    {
      source: "safebrowsing" as const,
      extractedClaim: "Safe Browsing lookup was unavailable",
      reliabilityScore: 0,
      isVerified: false,
      rawPayload: { sourceStatus: "not_configured", error: "API key is not configured." },
      collectedAt: new Date().toISOString(),
    },
  ] as never[];

  it("does not let two unconfigured feeds drag a confirmed impersonation down", () => {
    const impersonation = evaluateBrandImpersonation({
      targetUrl: "https://nexusp4y-login.top/verify",
      ...NEXUSPAY,
    });

    const evaluation = riskScoringEngine.evaluate({
      evidenceItems: unavailableIntel,
      heuristicRiskScore: 10,
      brandImpersonation: impersonation,
    });

    expect(evaluation.compositeRiskScore).toBe(100);
    expect(evaluation.verdict).toBe("phishing");
    expect(evaluation.escalation).toBeTruthy();
    // Unavailable sources are marked unavailable, never scored as "clean".
    const intel = evaluation.factors.find((factor) => factor.code === "threat_intel");
    expect(intel?.available).toBe(false);
    expect(evaluation.summary).toMatch(/never as safe/i);
  });

  it("returns unverified — not clean — when nothing could be checked", () => {
    const evaluation = riskScoringEngine.evaluate({
      evidenceItems: unavailableIntel,
      brandImpersonation: evaluateBrandImpersonation({
        targetUrl: "https://github.com",
        ...NEXUSPAY,
      }),
    });

    expect(evaluation.verdict).toBe("unverified");
    expect(evaluation.compositeRiskScore).toBeLessThan(20);
  });

  it("keeps every factor explainable in plain language", () => {
    const evaluation = riskScoringEngine.evaluate({
      evidenceItems: unavailableIntel,
      brandImpersonation: evaluateBrandImpersonation({
        targetUrl: "https://nexusp4y.com",
        ...NEXUSPAY,
      }),
    });

    expect(evaluation.factors.length).toBeGreaterThanOrEqual(5);
    for (const factor of evaluation.factors) {
      expect(factor.reason.length).toBeGreaterThan(10);
      expect(factor.detail.length).toBeGreaterThan(10);
      expect(typeof factor.available).toBe("boolean");
    }
  });
});

describe("Human-readable evidence narrative", () => {
  it("produces sentences, never JSON, and states what could not be checked", () => {
    const statements = buildEvidenceNarrative({
      targetUrl: "https://nexusp4y-login.top/verify",
      brandName: "NexusPay",
      brandImpersonation: evaluateBrandImpersonation({
        targetUrl: "https://nexusp4y-login.top/verify",
        ...NEXUSPAY,
      }),
      evidenceItems: [],
      factors: [],
    });

    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      // Never a JSON/key-value dump; quoted words in prose are fine.
      expect(statement.statement).not.toContain("{");
      expect(statement.statement).not.toMatch(/"[\w_]+"\s*:/);
      expect(statement.statement).not.toContain("});");
      expect(statement.statement.endsWith(".")).toBe(true);
      expect(["verified", "observed", "not_found", "unavailable", "not_configured", "informational"]).toContain(
        statement.status,
      );
    }

    // Sources that were never configured must be reported as such.
    expect(statements.some((s) => s.id === "reputation-safebrowsing" && s.status === "not_configured")).toBe(true);
    expect(statements.some((s) => s.id === "reputation-urlhaus" && s.status === "not_configured")).toBe(true);
  });

  it("says no brand was supplied rather than pretending it compared one", () => {
    const statements = buildEvidenceNarrative({
      targetUrl: "https://example.org",
      brandName: null,
      brandImpersonation: evaluateBrandImpersonation({ targetUrl: "https://example.org" }),
      evidenceItems: [],
    });

    expect(statements.some((s) => s.id === "brand-not-supplied")).toBe(true);
  });
});
