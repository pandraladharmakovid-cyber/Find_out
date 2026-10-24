import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("Gateway request formatting", () => {
  beforeEach(() => {
    vi.stubEnv("OPENAI_BASE_URL", "https://gateway.test/v1");
    vi.stubEnv("OPENAI_API_KEY", "sk-test-key");
    vi.stubEnv("OPENAI_MODEL", "openai/gpt-4o-mini");
    vi.stubEnv("OPENAI_FALLBACK_MODELS", "");
    vi.stubEnv("OPENAI_TRANSPORT", "chat");
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("rewrites union type arrays that the gateway rejects with HTTP 400", async () => {
    const { sanitizeJsonSchema } = await import("../src/ai-agent/provider");

    const sanitized = sanitizeJsonSchema({
      type: "object",
      properties: {
        tool: { type: ["string", "null"] },
        final: { type: ["object", "null"] },
        mixed: { type: ["string", "number"] },
        kept: { type: "boolean" },
      },
      required: ["tool"],
      additionalProperties: true,
      $schema: "http://json-schema.org/draft-07/schema#",
    });

    expect(sanitized).not.toBeNull();
    const properties = sanitized?.properties as Record<string, Record<string, unknown>>;

    expect(Array.isArray(properties.tool?.type)).toBe(false);
    expect(properties.tool).toEqual({ anyOf: [{ type: "string" }, { type: "null" }] });
    expect(properties.final).toEqual({ anyOf: [{ type: "object" }, { type: "null" }] });
    expect(properties.mixed).toEqual({ anyOf: [{ type: "string" }, { type: "number" }] });
    expect(properties.kept).toEqual({ type: "boolean" });
    expect(sanitized?.$schema).toBeUndefined();

    // Nothing in the tree may contain an array-valued `type`.
    const serialized = JSON.stringify(sanitized);
    expect(serialized).not.toContain('"type":["');
  });

  it("never sends union types or temperature to a reasoning model", async () => {
    vi.stubEnv("OPENAI_MODEL", "openai/gpt-5.4-mini");
    vi.resetModules();

    let capturedBody: Record<string, unknown> | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        capturedBody = JSON.parse(String(init?.body));
        return jsonResponse({
          choices: [{ message: { content: '{"ok":true}' } }],
          usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
        });
      }),
    );

    const { AIProvider } = await import("../src/ai-agent/provider");
    const provider = new AIProvider();

    await provider.generate({
      messages: [{ role: "user", content: "Reply with JSON" }],
      jsonSchema: {
        name: "probe",
        schema: { type: "object", properties: { value: { type: ["string", "null"] } } },
      },
    });

    expect(capturedBody).not.toBeNull();
    expect(capturedBody).not.toHaveProperty("temperature");
    const format = (capturedBody as any)?.response_format?.json_schema?.schema;
    expect(JSON.stringify(format)).not.toContain('"type":["');
  });
});
