import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  clientQuery: vi.fn(),
  withTransaction: vi.fn(),
}));

vi.mock("../src/db", () => ({
  query: mocks.query,
  withTransaction: mocks.withTransaction,
}));

import {
  BrandProfileError,
  BrandService,
  normalizeBrandPrimaryDomain,
} from "../src/brands";

describe("Brand profile registration eligibility", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.withTransaction.mockImplementation(async (callback) =>
      callback({ query: mocks.clientQuery }),
    );
  });

  it.each([
    "nexorapay-test.invalid",
    "fake.test",
    "localhost",
    "127.0.0.1",
    "8.8.8.8",
    "singlelabel",
    "bad_label.example.com",
    "https://user:password@example.com/",
  ])("rejects %s before opening a database transaction", async (primaryDomain) => {
    await expect(new BrandService().createBrand({
      name: "Fake or ineligible profile",
      primaryDomain,
    })).rejects.toBeInstanceOf(BrandProfileError);
    expect(mocks.withTransaction).not.toHaveBeenCalled();
  });

  it("normalizes an eligible public domain and saves only an unverified profile", async () => {
    const row = {
      id: "brand-1",
      name: "NexusPay",
      slug: "nexuspay",
      primary_domain: "nexuspay.io",
      status: "active",
    };
    mocks.clientQuery.mockResolvedValue({ rows: [row] });

    const result = await new BrandService().createBrand({
      name: "NexusPay",
      primaryDomain: "https://NexusPay.io/welcome",
      associatedDomains: ["https://WWW.NexusPay.io/path"],
      website: "https://nexuspay.io/welcome",
    });

    expect(result.primary_domain).toBe("nexuspay.io");
    expect(mocks.clientQuery).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO brands"),
      expect.arrayContaining([
        "nexuspay.io",
        ["www.nexuspay.io"],
        "https://nexuspay.io",
      ]),
    );
    expect(mocks.clientQuery).toHaveBeenCalledTimes(1);
  });

  it("applies the same domain guard to authorized profile updates", async () => {
    mocks.query.mockResolvedValue({ rows: [{
      id: "brand-1",
      name: "NexusPay",
      primary_domain: "nexuspay.io",
      status: "active",
    }] });

    await expect(new BrandService().updateBrand("brand-1", {
      primaryDomain: "attacker.invalid",
    })).rejects.toBeInstanceOf(BrandProfileError);
    expect(mocks.query).toHaveBeenCalledTimes(1);
    expect(mocks.query).not.toHaveBeenCalledWith(
      expect.stringContaining("UPDATE brands"),
      expect.anything(),
    );
  });

  it("keeps public IDN and normal HTTPS hostname forms eligible for later proof", () => {
    expect(normalizeBrandPrimaryDomain("https://www.example.com/path")).toBe("www.example.com");
    expect(normalizeBrandPrimaryDomain("https://xn--bcher-kva.com/")).toBe("xn--bcher-kva.com");
  });
});
