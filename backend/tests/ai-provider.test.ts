import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("AI provider transport fallback", () => {
  beforeEach(() => {
    vi.stubEnv("OPENAI_BASE_URL", "https://gateway.test/v1");
    vi.stubEnv("OPENAI_API_KEY", "sk-test-key");
    vi.stubEnv("OPENAI_MODEL", "anthropic/claude-3.5-sonnet");
    vi.stubEnv("OPENAI_FALLBACK_MODELS", "openai/gpt-4o-mini");
    vi.stubEnv("OPENAI_TRANSPORT", "auto");
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("falls back to /responses when chat completions rejects the model for this key", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = init?.body ? (JSON.parse(String(init.body)) as { model?: string }) : {};
      const model = body.model ?? "";

      // The real gateway rejects Claude for this key on every transport and
      // only serves OpenAI models through /responses.
      if (url.endsWith("/chat/completions") || model.startsWith("anthropic/")) {
        return jsonResponse(
          {
            error: {
              message: `This API key is not permitted to use model '${model}'.`,
              code: "model_not_allowed",
            },
          },
          403,
        );
      }

      if (url.endsWith("/responses")) {
        return jsonResponse({
          id: "resp_1",
          object: "response",
          status: "completed",
          model: "gpt-4o-mini-2024-07-18",
          output: [
            {
              type: "message",
              content: [{ type: "output_text", text: '{"ok":true}' }],
            },
          ],
          usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
        });
      }

      return jsonResponse({ error: "unexpected" }, 500);
    });

    vi.stubGlobal("fetch", fetchMock);

    const { AIProvider } = await import("../src/ai-agent/provider");
    const provider = new AIProvider();
    const result = await provider.generate({
      messages: [{ role: "user", content: "Return JSON" }],
      jsonSchema: {
        name: "probe",
        schema: { type: "object", properties: { ok: { type: "boolean" } } },
      },
    });

    expect(result.transport).toBe("responses");
    expect(result.model).toBe("openai/gpt-4o-mini");
    expect(result.parsed).toEqual({ ok: true });
    expect(result.fallbackUsed).toBe(true);
    // claude on chat → claude on responses → gpt-4o-mini on chat → gpt on responses (success)
    expect(result.attempts.map((attempt) => attempt.model)).toEqual([
      "anthropic/claude-3.5-sonnet",
      "anthropic/claude-3.5-sonnet",
      "openai/gpt-4o-mini",
      "openai/gpt-4o-mini",
    ]);
    expect(result.attempts.slice(0, 3).every((attempt) => attempt.ok === false)).toBe(true);
    expect(result.attempts.at(-1)?.ok).toBe(true);
  });

  it("reports a structured error when every model and transport fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          { error: { message: "This API key is not permitted to use model 'x'.", code: "model_not_allowed" } },
          403,
        ),
      ),
    );

    const { AIProvider, AIProviderError } = await import("../src/ai-agent/provider");
    const provider = new AIProvider();

    await expect(
      provider.generate({ messages: [{ role: "user", content: "hi" }] }),
    ).rejects.toMatchObject({
      name: "AIProviderError",
      code: "model_not_allowed",
    });

    const error = await provider
      .generate({ messages: [{ role: "user", content: "hi" }] })
      .catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(AIProviderError);
    expect((error as InstanceType<typeof AIProviderError>).message).toContain("All AI models failed");
  });

  it("does not call the network when the gateway is not configured", async () => {
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.resetModules();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const { AIProvider } = await import("../src/ai-agent/provider");
    const provider = new AIProvider();

    await expect(
      provider.generate({ messages: [{ role: "user", content: "hi" }] }),
    ).rejects.toMatchObject({ code: "not_configured" });

    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("extractJson", () => {
  it("recovers JSON wrapped in prose and code fences", async () => {
    const { extractJson } = await import("../src/ai-agent/provider");

    expect(extractJson('```json\n{"verdict":"suspicious","riskScore":60}\n```')).toEqual({
      verdict: "suspicious",
      riskScore: 60,
    });

    expect(
      extractJson('Here is my analysis: {"thought":"check", "done": true} — thanks.'),
    ).toEqual({ thought: "check", done: true });

    expect(extractJson("no json here")).toBeNull();
  });
});
