import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  configOverrides: {
    RESEND_API_KEY: "re_test_key_123",
    RESEND_API_URL: "https://api.resend.com/emails",
    RESEND_FROM_EMAIL: "alerts@findout.example",
    RESEND_FROM_NAME: "Find_out Brand Guard",
    BRAND_GUARD_SIMILARITY_THRESHOLD: 0.72,
  } as Record<string, unknown>,
}));

vi.mock("../src/db", () => ({
  query: mocks.query,
}));

vi.mock("../src/config", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/config")>();
  return {
    ...original,
    config: new Proxy(original.config, {
      get(target, property: string) {
        if (property in mocks.configOverrides) {
          return mocks.configOverrides[property];
        }
        return (target as Record<string, unknown>)[property];
      },
    }),
  };
});

import { BrandGuardError, brandGuardService } from "../src/brand-guard.service";

const officialBrand = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "NexusPay",
  primary_domain: "nexuspay.io",
  website: "https://nexuspay.io",
  logo_url: null,
  contact_email: "security@nexuspay.io",
  alternate_names: ["Nexus Wallet"],
  associated_domains: ["www.nexuspay.io"],
  status: "active",
};

const fetchMock = vi.fn();

describe("BrandGuardService.findConflicts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.configOverrides.RESEND_API_KEY = "re_test_key_123";
    mocks.query.mockResolvedValue({ rows: [officialBrand] });
  });

  it("flags an exact name reuse as an exact conflict", async () => {
    const result = await brandGuardService.findConflicts({
      name: "NexusPay",
      domain: "totally-different.example",
    });

    expect(result.conflict).toBe(true);
    expect(result.conflicts[0]?.verdict).toBe("exact");
    expect(result.conflicts[0]?.brandName).toBe("NexusPay");
    expect(result.conflicts[0]?.canNotify).toBe(true);
  });

  it("flags a homoglyph typosquat name (NexusP4y) as impersonation", async () => {
    const result = await brandGuardService.findConflicts({ name: "NexusP4y" });

    expect(result.conflict).toBe(true);
    expect(result.conflicts[0]?.similarity).toBeGreaterThanOrEqual(0.9);
    expect(["exact", "impersonation"]).toContain(result.conflicts[0]?.verdict);
  });

  it("flags a deceptive-affix domain (nexusp4y-login.top)", async () => {
    const result = await brandGuardService.findConflicts({
      name: "Totally Unrelated Studio",
      domain: "nexusp4y-login.top",
    });

    expect(result.conflict).toBe(true);
    expect(result.conflicts[0]?.matchType).toBe("domain");
  });

  it("flags a match against an alternate brand name", async () => {
    const result = await brandGuardService.findConflicts({ name: "Nexus Wall3t" });

    expect(result.conflict).toBe(true);
    expect(result.conflicts[0]?.matchType).toBe("alternate_name");
  });

  it("does not flag an unrelated brand", async () => {
    const result = await brandGuardService.findConflicts({
      name: "Sunrise Bakery",
      domain: "sunrise-bakery.in",
    });

    expect(result.conflict).toBe(false);
    expect(result.conflicts).toHaveLength(0);
  });

  it("skips the excluded brand id so profile edits do not self-conflict", async () => {
    const result = await brandGuardService.findConflicts({
      name: "NexusPay",
      excludeBrandId: officialBrand.id,
    });

    expect(result.conflict).toBe(false);
  });
});

describe("BrandGuardService.sendImpersonationAlert", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.configOverrides.RESEND_API_KEY = "re_test_key_123";
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockBrandAndInsert(brandRow: Record<string, unknown> | null) {
    mocks.query.mockImplementation(async (text: string, values: unknown[]) => {
      if (/SELECT[\s\S]*FROM brands/i.test(text)) {
        return { rows: brandRow ? [brandRow] : [] };
      }
      if (/INSERT INTO impersonation_alerts/i.test(text)) {
        return {
          rows: [
            {
              id: "22222222-2222-4222-8222-222222222222",
              brand_id: values[0],
              suspect_name: values[1],
              suspect_domain: values[2],
              recipient_email: values[7],
              subject: values[8],
              status: values[9],
              provider: "resend",
              provider_message_id: values[10],
              error_detail: values[11],
            },
          ],
        };
      }
      throw new Error(`Unexpected query: ${text}`);
    });
  }

  it("delivers the alert through Resend and records a 'sent' row", async () => {
    mockBrandAndInsert(officialBrand);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: "re_msg_abc123" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const record = await brandGuardService.sendImpersonationAlert({
      brandId: officialBrand.id,
      suspectName: "NexusP4y Secure",
      suspectDomain: "nexusp4y-login.top",
      similarity: 0.94,
      matchType: "domain",
      verdict: "impersonation",
    });

    expect(record.status).toBe("sent");
    expect(record.recipient_email).toBe("security@nexuspay.io");
    expect(record.provider_message_id).toBe("re_msg_abc123");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.resend.com/emails");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer re_test_key_123",
    );
    const body = JSON.parse(String(init.body));
    expect(body.to).toEqual(["security@nexuspay.io"]);
    expect(body.subject).toContain("NexusPay");
    expect(body.html).toContain("nexusp4y-login.top");
    expect(body.text).toContain("NexusP4y Secure");
  });

  it("records a 'failed' row and raises 502 when Resend rejects the e-mail", async () => {
    mockBrandAndInsert(officialBrand);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ message: "API key is invalid" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(
      brandGuardService.sendImpersonationAlert({
        brandId: officialBrand.id,
        suspectName: "NexusP4y",
      }),
    ).rejects.toMatchObject({ statusCode: 502, code: "EMAIL_DELIVERY_FAILED" });

    const insertCall = mocks.query.mock.calls.find(([text]) =>
      /INSERT INTO impersonation_alerts/i.test(String(text)),
    );
    expect(insertCall?.[1]?.[9]).toBe("failed");
  });

  it("reports not_configured (503) when RESEND_API_KEY is empty, never pretending delivery", async () => {
    mocks.configOverrides.RESEND_API_KEY = "";
    mockBrandAndInsert(officialBrand);

    await expect(
      brandGuardService.sendImpersonationAlert({
        brandId: officialBrand.id,
        suspectName: "NexusP4y",
      }),
    ).rejects.toMatchObject({ statusCode: 503, code: "EMAIL_NOT_CONFIGURED" });

    expect(fetchMock).not.toHaveBeenCalled();
    const insertCall = mocks.query.mock.calls.find(([text]) =>
      /INSERT INTO impersonation_alerts/i.test(String(text)),
    );
    expect(insertCall?.[1]?.[9]).toBe("not_configured");
  });

  it("rejects with 409 when the official brand has no contact e-mail", async () => {
    mockBrandAndInsert({ ...officialBrand, contact_email: null });

    await expect(
      brandGuardService.sendImpersonationAlert({
        brandId: officialBrand.id,
        suspectName: "NexusP4y",
      }),
    ).rejects.toMatchObject({ statusCode: 409, code: "NO_CONTACT_EMAIL" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects with 404 when the brand does not exist", async () => {
    mockBrandAndInsert(null);

    await expect(
      brandGuardService.sendImpersonationAlert({
        brandId: "33333333-3333-4333-8333-333333333333",
        suspectName: "NexusP4y",
      }),
    ).rejects.toBeInstanceOf(BrandGuardError);
  });
});

describe("BrandGuardService.configureContactEmail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("sets initial contact e-mail when the brand had none", async () => {
    mocks.query
      .mockResolvedValueOnce({
        rows: [{ id: officialBrand.id, name: "NexusPay", contact_email: null }],
      })
      .mockResolvedValueOnce({
        rows: [
          {
            id: officialBrand.id,
            name: "NexusPay",
            contact_email: "security@nexuspay.io",
          },
        ],
      });

    const result = await brandGuardService.configureContactEmail(
      officialBrand.id,
      "Security@NexusPay.io",
    );

    expect(result.contact_email).toBe("security@nexuspay.io");
  });

  it("blocks unauthenticated replacement of an already-set contact e-mail", async () => {
    mocks.query.mockResolvedValueOnce({
      rows: [
        {
          id: officialBrand.id,
          name: "NexusPay",
          contact_email: "security@nexuspay.io",
        },
      ],
    });

    await expect(
      brandGuardService.configureContactEmail(
        officialBrand.id,
        "attacker@evil.example",
        false,
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "CONTACT_EMAIL_ALREADY_SET",
    });
  });

  it("allows replacing an existing contact e-mail with operator authorization", async () => {
    mocks.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: officialBrand.id,
            name: "NexusPay",
            contact_email: "security@nexuspay.io",
          },
        ],
      })
      .mockResolvedValueOnce({
        rows: [
          {
            id: officialBrand.id,
            name: "NexusPay",
            contact_email: "soc@nexuspay.io",
          },
        ],
      });

    const result = await brandGuardService.configureContactEmail(
      officialBrand.id,
      "soc@nexuspay.io",
      true,
    );
    expect(result.contact_email).toBe("soc@nexuspay.io");
  });
});
