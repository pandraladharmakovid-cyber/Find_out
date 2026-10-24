import { describe, expect, it } from "vitest";

import {
  lookalikeDetectionService,
  normalizeComparableName,
  stripDeceptiveAffixes,
} from "../src/lookalike.service";

describe("Look-alike evaluation", () => {
  it("folds leetspeak before comparing, so nexusp4y is a homoglyph of NexusPay", () => {
    expect(normalizeComparableName("nexusp4y")).toBe("nexuspay");

    const result = lookalikeDetectionService.evaluateLookalike("nexusp4y.com", "NexusPay");
    expect(result.isLookalike).toBe(true);
    expect(result.detectedTechnique).toBe("homoglyph_substitution");
  });

  it("flags a deceptive suffix attached to the brand", () => {
    const result = lookalikeDetectionService.evaluateLookalike("nexuspay-login.top", "NexusPay");
    expect(result.isLookalike).toBe(true);
    expect(result.detectedTechnique).toBe("deceptive_affix_typosquat");
    expect(result.coreLabel).toBe("nexuspay");
    expect(result.coreEditDistance).toBe(0);
  });

  it("does not mangle brands that contain an affix word (PayPal contains 'pay')", () => {
    expect(stripDeceptiveAffixes("paypal", "paypal")).toBe("paypal");
    expect(stripDeceptiveAffixes("paypalsecure", "paypal")).toBe("paypal");

    const official = lookalikeDetectionService.evaluateLookalike("paypal.com", "PayPal");
    expect(official.isLookalike).toBe(false);
  });

  it("flags an unrelated brand keyword embedded in a longer domain", () => {
    const result = lookalikeDetectionService.evaluateLookalike("flipkart-offer.com", "Flipkart");
    expect(result.isLookalike).toBe(true);
    expect(["deceptive_affix_typosquat", "brand_keyword_embedding"]).toContain(
      result.detectedTechnique,
    );
  });

  it("leaves unrelated domains and the official domain alone", () => {
    expect(lookalikeDetectionService.evaluateLookalike("example.org", "NexusPay").isLookalike).toBe(false);
    expect(lookalikeDetectionService.evaluateLookalike("nexuspay.io", "NexusPay").isLookalike).toBe(false);
    expect(lookalikeDetectionService.evaluateLookalike("google.com", "Google").isLookalike).toBe(false);
  });

  it("still detects edit-distance typosquats", () => {
    const result = lookalikeDetectionService.evaluateLookalike("nexuspayy.com", "NexusPay");
    expect(result.isLookalike).toBe(true);
    expect(result.levenshteinDistance).toBeGreaterThan(0);
  });

  it("reports the core comparison inputs so the UI can explain a decision", () => {
    const result = lookalikeDetectionService.evaluateLookalike("nexusp4y-support.net", "NexusPay");
    expect(result.normalizedLabel).toBe("nexuspaysupport");
    expect(result.coreLabel).toBe("nexuspay");
    expect(typeof result.similarityRatio).toBe("number");
    expect(result.similarityRatio).toBeGreaterThanOrEqual(0);
    expect(result.similarityRatio).toBeLessThanOrEqual(1);
  });
});
