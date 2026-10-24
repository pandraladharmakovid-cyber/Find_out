import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/repositories", () => ({
  AuditLogsRepository: { recordLog: vi.fn().mockResolvedValue(undefined) },
}));

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("URLhaus source status", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("skips the call and reports not_configured when no Auth-Key is set", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const { UrlhausClient } = await import("../src/integrations/urlhaus.client");
    const result = await new UrlhausClient().checkUrl("https://example.com/");

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.status).toBe("not_configured");
    expect(result.isMalicious).toBe(false);
    expect(result.error).toContain("Auth-Key");
  });

  it("surfaces a rejected Auth-Key as unavailable instead of a clean result", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "bad-key");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: "Unauthorized" }, 401)),
    );

    const { UrlhausClient } = await import("../src/integrations/urlhaus.client");
    const result = await new UrlhausClient().checkUrl("https://example.com/");

    expect(result.status).toBe("unavailable");
    expect(result.isMalicious).toBe(false);
    expect(result.confidence).toBe(0);
    expect(result.error).toContain("401");
  });

  it("returns a verified threat when URLhaus reports query_status=ok", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "good-key");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          query_status: "ok",
          url_status: "online",
          threat: "malware_download",
        }),
      ),
    );

    const { UrlhausClient } = await import("../src/integrations/urlhaus.client");
    const result = await new UrlhausClient().checkUrl("https://malware.example/x");

    expect(result.status).toBe("available");
    expect(result.isMalicious).toBe(true);
    expect(result.threatType).toBe("malware_download");
    expect(result.confidence).toBe(95);
  });

  it("returns available/no-match for query_status=no_results", async () => {
    vi.stubEnv("URLHAUS_AUTH_KEY", "good-key");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ query_status: "no_results" })),
    );

    const { UrlhausClient } = await import("../src/integrations/urlhaus.client");
    const result = await new UrlhausClient().checkUrl("https://clean.example/");

    expect(result.status).toBe("available");
    expect(result.isMalicious).toBe(false);
    expect(result.confidence).toBeGreaterThan(0);
  });
});

describe("Gemini model fallback", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("retries a retired model (HTTP 404) with the configured fallback", async () => {
    vi.stubEnv("GEMINI_API_KEY", "gemini-test-key");
    vi.stubEnv("GEMINI_MODEL", "gemini-1.5-pro");
    vi.stubEnv("GEMINI_FALLBACK_MODELS", "gemini-2.5-flash");

    const requested: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        requested.push(url);

        if (url.includes("gemini-1.5-pro")) {
          return jsonResponse(
            { error: { code: 404, message: "models/gemini-1.5-pro is not found for API version v1beta" } },
            404,
          );
        }

        return jsonResponse({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: JSON.stringify({
                      riskScore: 71,
                      confidenceScore: 80,
                      verdict: "suspicious",
                      summary: "Look-alike login page detected.",
                      keyFindings: ["Credential form posts to a third-party host."],
                    }),
                  },
                ],
              },
            },
          ],
        });
      }),
    );

    const { GeminiClient } = await import("../src/integrations/gemini.client");
    const result = await new GeminiClient().analyzeTarget(
      "https://evil.example/login",
      "NexusPay",
      "context",
    );

    expect(requested[0]).toContain("gemini-1.5-pro");
    expect(requested.at(-1)).toContain("gemini-2.5-flash");
    expect(result.status).toBe("available");
    expect(result.model).toBe("gemini-2.5-flash");
    expect(result.verdict).toBe("suspicious");
    expect(result.riskScore).toBe(71);
  });

  it("reports unverified (never clean) when every Gemini model fails", async () => {
    vi.stubEnv("GEMINI_API_KEY", "gemini-test-key");
    vi.stubEnv("GEMINI_MODEL", "gemini-1.5-pro");
    vi.stubEnv("GEMINI_FALLBACK_MODELS", "gemini-2.0-flash");

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: { message: "model not found" } }, 404)),
    );

    const { GeminiClient } = await import("../src/integrations/gemini.client");
    const result = await new GeminiClient().analyzeTarget("https://x.example", null, "");

    expect(result.status).toBe("unavailable");
    expect(result.verdict).toBe("unverified");
    expect(result.confidenceScore).toBe(0);
    expect(result.summary).toContain("unavailable");
  });

  it("does not call Gemini when the key is absent", async () => {
    vi.stubEnv("GEMINI_API_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const { GeminiClient } = await import("../src/integrations/gemini.client");
    const result = await new GeminiClient().analyzeTarget("https://x.example", null, "");

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.status).toBe("not_configured");
    expect(result.verdict).toBe("unverified");
  });
});
