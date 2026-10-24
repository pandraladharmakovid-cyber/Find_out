import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ listActive: vi.fn() }));
vi.mock("../src/repositories", () => ({
  ExclusionRulesRepository: { listActive: mocks.listActive },
}));

import { exclusionEngineService, exactDomainExclusionMatch } from "../src/exclusion-engine.service";

describe("Verified-domain exclusion boundaries", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.listActive.mockResolvedValue([{
      id: "rule-1",
      pattern: "example.com",
      reason: "Verified domain",
      is_active: true,
      created_at: new Date().toISOString(),
      asset_id: "asset-1",
      brand_id: "brand-1",
      asset_type: "domain",
      asset_value: "example.com",
    }]);
  });

  it("matches the exact verified hostname with any HTTP(S) path", async () => {
    expect(exactDomainExclusionMatch("https://example.com/login", "example.com")).toBe(true);
    const result = await exclusionEngineService.checkExclusion("https://example.com/login", "brand-1");
    expect(result.isExcluded).toBe(true);
  });

  it("does not suppress regex lookalikes, suffix domains, or unverified subdomains", async () => {
    for (const target of [
      "https://exampleXcom/",
      "https://example.com.evil.test/",
      "https://sub.example.com/",
    ]) {
      const result = await exclusionEngineService.checkExclusion(target, "brand-1");
      expect(result.isExcluded).toBe(false);
    }
  });
  it("does not apply a verified asset exclusion globally without its brand context", async () => {
    const result = await exclusionEngineService.checkExclusion("https://example.com/login");
    expect(result.isExcluded).toBe(false);
    expect(mocks.listActive).not.toHaveBeenCalled();
  });

});
