import { config, splitList } from "../config";
import { logger } from "../utils/logger";

/**
 * OpenAI-compatible gateway client used by the Find_out AI agent.
 *
 * The deployment owner points OPENAI_BASE_URL at https://api.aicredits.in/v1
 * and supplies OPENAI_API_KEY. Two transports exist on that gateway:
 *
 *   POST /chat/completions  - standard OpenAI SDK shape (preferred)
 *   POST /responses         - OpenAI Responses API
 *
 * Gateway keys can be restricted per model, and some keys only serve OpenAI
 * models through /responses. The provider therefore walks a model chain and,
 * when a model is not permitted on Chat Completions, retries it through the
 * Responses API before moving to the next model. This is what keeps the agent
 * working when the account cannot use the requested Anthropic model yet.
 */

export type AITransport = "chat" | "responses";

export type AIErrorCode =
  | "not_configured"
  | "auth_failed"
  | "model_not_allowed"
  | "model_unavailable"
  | "rate_limited"
  | "timeout"
  | "network_error"
  | "server_error"
  | "invalid_response";

export class AIProviderError extends Error {
  readonly code: AIErrorCode;
  readonly status: number;
  readonly model: string;
  readonly transport: AITransport;
  readonly detail: string;

  constructor(params: {
    code: AIErrorCode;
    message: string;
    status?: number;
    model?: string;
    transport?: AITransport;
    detail?: string;
  }) {
    super(params.message);
    this.name = "AIProviderError";
    this.code = params.code;
    this.status = params.status ?? 0;
    this.model = params.model ?? "";
    this.transport = params.transport ?? "chat";
    this.detail = params.detail ?? "";
  }
}

export interface AIMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AIJsonSchema {
  name: string;
  schema: Record<string, unknown>;
  strict?: boolean;
}

export interface AIGenerateOptions {
  messages: AIMessage[];
  jsonSchema?: AIJsonSchema;
  temperature?: number;
  maxOutputTokens?: number;
  timeoutMs?: number;
  purpose?: string;
}

export interface AIUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface AIAttempt {
  model: string;
  transport: AITransport;
  ok: boolean;
  status: number;
  code?: AIErrorCode;
  message?: string;
  latencyMs: number;
}

export interface AIGenerateResult {
  text: string;
  parsed: unknown;
  model: string;
  transport: AITransport;
  usage: AIUsage;
  latencyMs: number;
  attempts: AIAttempt[];
  fallbackUsed: boolean;
}

export interface AIClientStatus {
  configured: boolean;
  baseUrl: string;
  primaryModel: string;
  modelChain: string[];
  transportPreference: "auto" | "chat" | "responses";
  lastSuccessfulRoute: { model: string; transport: AITransport } | null;
  lastError: { code: AIErrorCode; message: string } | null;
}

const ROUTE_CACHE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 90_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Some OpenAI-compatible gateways validate JSON Schema with a strict Go
 * decoder that rejects union `type` arrays such as `["string", "null"]`
 * (HTTP 400: "cannot unmarshal array into ... DataType"). OpenAI's own
 * structured outputs do not need them either, so every schema is normalised
 * to a representation every gateway accepts before it is sent.
 */
export function sanitizeJsonSchema(schema: unknown): Record<string, unknown> | null {
  const convert = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(convert);
    if (!isRecord(node)) return node;

    const clone: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(node)) {
      if (key === "$schema" || key === "$id" || key === "definitions") continue;
      clone[key] = convert(value);
    }

    if (Array.isArray(node.type)) {
      const types = node.type.filter((entry): entry is string => typeof entry === "string");
      const nonNull = types.filter((entry) => entry !== "null");
      const nullable = types.includes("null");

      // A single concrete type plus null becomes anyOf: [type, null], which is
      // the portable way to express nullability without a type array.
      if (nonNull.length === 1) {
        const base: Record<string, unknown> = { ...clone, type: nonNull[0] };
        if (nullable) return { anyOf: [base, { type: "null" }] };
        return base;
      }
      if (nonNull.length > 1) {
        const variants = nonNull.map((entry) => ({ type: entry }));
        return nullable ? { anyOf: [...variants, { type: "null" }] } : { anyOf: variants };
      }
    }

    return clone;
  };

  const sanitized = convert(schema);
  return isRecord(sanitized) ? sanitized : null;
}

const REASONING_MODEL_PATTERN = /(^|\/)(o[134](-|$)|gpt-5|gpt-6)/i;

function isReasoningModel(model: string): boolean {
  return REASONING_MODEL_PATTERN.test(model);
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/**
 * Extracts the first JSON object/array from a model response, tolerating code
 * fences and surrounding prose. Returns null when no JSON can be recovered.
 */
export function extractJson(text: string): unknown {
  if (!text) return null;

  const cleaned = text
    .replace(/```(?:json)?/gi, "")
    .replace(/```/g, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    // Fall through to brace scanning.
  }

  const firstObject = cleaned.indexOf("{");
  const firstArray = cleaned.indexOf("[");

  const startCandidates = [firstObject, firstArray].filter((index) => index >= 0);
  if (startCandidates.length === 0) return null;

  const start = Math.min(...startCandidates);
  const opening = cleaned[start];
  const closing = opening === "{" ? "}" : "]";

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let index = start; index < cleaned.length; index += 1) {
    const char = cleaned[index];

    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;

    if (char === opening) depth += 1;
    if (char === closing) {
      depth -= 1;
      if (depth === 0) {
        const slice = cleaned.slice(start, index + 1);
        try {
          return JSON.parse(slice);
        } catch {
          return null;
        }
      }
    }
  }

  return null;
}

function classifyStatus(status: number, message: string): AIErrorCode {
  const lower = message.toLowerCase();

  if (
    lower.includes("model_not_allowed") ||
    lower.includes("not permitted to use model") ||
    lower.includes("model not allowed")
  ) {
    return "model_not_allowed";
  }
  if (
    lower.includes("no longer available") ||
    lower.includes("does not exist") ||
    lower.includes("has been deprecated") ||
    lower.includes("model_not_found")
  ) {
    return "model_unavailable";
  }
  if (status === 401) return "auth_failed";
  if (status === 403) return "model_not_allowed";
  if (status === 404) return "model_unavailable";
  if (status === 408) return "timeout";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "server_error";
  return "invalid_response";
}

export class AIProvider {
  private routeCache: {
    model: string;
    transport: AITransport;
    expiresAt: number;
  } | null = null;

  private lastError: { code: AIErrorCode; message: string } | null = null;
  private lastAttempts: AIAttempt[] = [];

  get baseUrl(): string {
    return config.OPENAI_BASE_URL.replace(/\/+$/, "");
  }

  get modelChain(): string[] {
    const chain = [config.OPENAI_MODEL, ...splitList(config.OPENAI_FALLBACK_MODELS)];
    return [...new Set(chain.filter(Boolean))];
  }

  get configured(): boolean {
    return Boolean(this.baseUrl && config.OPENAI_API_KEY);
  }

  get status(): AIClientStatus {
    return {
      configured: this.configured,
      baseUrl: this.baseUrl,
      primaryModel: config.OPENAI_MODEL,
      modelChain: this.modelChain,
      transportPreference: config.OPENAI_TRANSPORT,
      lastSuccessfulRoute: this.routeCache
        ? { model: this.routeCache.model, transport: this.routeCache.transport }
        : null,
      lastError: this.lastError,
    };
  }

  get recentAttempts(): AIAttempt[] {
    return [...this.lastAttempts];
  }

  /**
   * Generates a completion using the first model/transport pair that works.
   * Throws AIProviderError when every candidate fails.
   */
  async generate(options: AIGenerateOptions): Promise<AIGenerateResult> {
    if (!this.configured) {
      throw new AIProviderError({
        code: "not_configured",
        message:
          "The AI agent is not configured. Set OPENAI_BASE_URL and OPENAI_API_KEY in backend/.env.",
      });
    }

    const startedAt = Date.now();
    const attempts: AIAttempt[] = [];
    const timeoutMs = options.timeoutMs ?? config.AI_AGENT_TIMEOUT_MS;
    const deadline = startedAt + timeoutMs;

    const candidates = this.resolveCandidates();

    for (const candidate of candidates) {
      const remaining = deadline - Date.now();
      if (remaining <= 1000) {
        attempts.push({
          model: candidate.model,
          transport: candidate.transport,
          ok: false,
          status: 0,
          code: "timeout",
          message: "The agent time budget was exhausted before this model was tried.",
          latencyMs: 0,
        });
        break;
      }

      const transport = candidate.transport;
      const attemptStart = Date.now();

      try {
        const result = await this.callTransport(transport, candidate.model, options, remaining);

        attempts.push({
          model: candidate.model,
          transport,
          ok: true,
          status: 200,
          latencyMs: Date.now() - attemptStart,
        });

        this.routeCache = {
          model: candidate.model,
          transport,
          expiresAt: Date.now() + ROUTE_CACHE_TTL_MS,
        };
        this.lastError = null;
        this.lastAttempts = attempts;

        logger.info("[ai-provider] Completion succeeded", {
          model: candidate.model,
          transport,
          purpose: options.purpose,
          latencyMs: result.latencyMs,
          totalLatencyMs: Date.now() - startedAt,
        });

        return {
          text: result.text,
          parsed: result.parsed,
          model: candidate.model,
          transport,
          usage: result.usage,
          latencyMs: Date.now() - startedAt,
          attempts,
          fallbackUsed: candidate.model !== config.OPENAI_MODEL,
        };
      } catch (error) {
        const providerError =
          error instanceof AIProviderError
            ? error
            : new AIProviderError({
                code: "network_error",
                message: error instanceof Error ? error.message : "Unknown AI error",
                model: candidate.model,
                transport,
              });

        attempts.push({
          model: candidate.model,
          transport,
          ok: false,
          status: providerError.status,
          code: providerError.code,
          message: providerError.message,
          latencyMs: Date.now() - attemptStart,
        });

        this.lastError = {
          code: providerError.code,
          message: providerError.message,
        };

        logger.warn("[ai-provider] Attempt failed", {
          model: candidate.model,
          transport,
          code: providerError.code,
          status: providerError.status,
          message: providerError.message,
        });

        // A bad key will fail identically on every model; stop early.
        if (providerError.code === "auth_failed" && providerError.status === 401) {
          break;
        }
      }
    }

    this.lastAttempts = attempts;

    const summary = attempts
      .map((attempt) => `${attempt.model} [${attempt.transport}] → ${attempt.code ?? "error"}`)
      .join("; ");

    throw new AIProviderError({
      code: attempts.at(-1)?.code ?? "invalid_response",
      message:
        attempts.length === 0
          ? "No AI model candidates were available."
          : `All AI models failed for this key: ${summary}`,
      status: attempts.at(-1)?.status ?? 0,
      detail: summary,
    });
  }

  /**
   * Cheap connectivity probe used by the diagnostics endpoint.
   */
  async probe(timeoutMs = 45_000): Promise<{
    ok: boolean;
    model?: string;
    transport?: AITransport;
    latencyMs: number;
    message: string;
    code?: AIErrorCode;
  }> {
    const startedAt = Date.now();

    if (!this.configured) {
      return {
        ok: false,
        latencyMs: 0,
        code: "not_configured",
        message:
          "OPENAI_BASE_URL or OPENAI_API_KEY is missing. The agent will run in deterministic mode.",
      };
    }

    try {
      const result = await this.generate({
        messages: [
          {
            role: "user",
            content: "Reply with the single word READY. Do not add punctuation.",
          },
        ],
        maxOutputTokens: 32,
        timeoutMs,
        purpose: "diagnostics-probe",
      });

      return {
        ok: true,
        model: result.model,
        transport: result.transport,
        latencyMs: Date.now() - startedAt,
        message: `${result.model} responded via ${result.transport} in ${Date.now() - startedAt} ms.`,
      };
    } catch (error) {
      const providerError =
        error instanceof AIProviderError
          ? error
          : new AIProviderError({
              code: "network_error",
              message: error instanceof Error ? error.message : "Unknown AI error",
            });

      return {
        ok: false,
        latencyMs: Date.now() - startedAt,
        code: providerError.code,
        message: providerError.message,
      };
    }
  }

  /**
   * Lists models exposed by the gateway. Used by diagnostics to explain which
   * models the key can actually consume.
   */
  async listModels(timeoutMs = 20_000): Promise<{
    ok: boolean;
    count: number;
    ids: string[];
    message: string;
  }> {
    if (!this.configured) {
      return { ok: false, count: 0, ids: [], message: "AI gateway is not configured." };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/models`, {
        headers: { Authorization: `Bearer ${config.OPENAI_API_KEY}` },
        signal: controller.signal,
      });

      const payload = (await response.json().catch(() => ({}))) as unknown;

      if (!response.ok) {
        return {
          ok: false,
          count: 0,
          ids: [],
          message: `Model listing returned HTTP ${response.status}.`,
        };
      }

      const data = isRecord(payload) && Array.isArray(payload.data) ? payload.data : [];
      const ids = data
        .map((entry) => (isRecord(entry) && typeof entry.id === "string" ? entry.id : ""))
        .filter(Boolean);

      return {
        ok: true,
        count: ids.length,
        ids,
        message: `${ids.length} models are exposed by the gateway.`,
      };
    } catch (error) {
      return {
        ok: false,
        count: 0,
        ids: [],
        message: error instanceof Error ? error.message : "Model listing failed.",
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private resolveCandidates(): Array<{ model: string; transport: AITransport }> {
    const candidates: Array<{ model: string; transport: AITransport }> = [];
    const preference = config.OPENAI_TRANSPORT;
    const cached = this.routeCache;

    // A recent success is tried first to avoid paying the discovery cost twice.
    if (cached && cached.expiresAt > Date.now()) {
      candidates.push({ model: cached.model, transport: cached.transport });
    }

    const transportsFor = (model: string): AITransport[] => {
      if (preference === "chat") return ["chat"];
      if (preference === "responses") return ["responses"];
      return ["chat", "responses"];
    };

    for (const model of this.modelChain) {
      for (const transport of transportsFor(model)) {
        if (
          candidates.some(
            (candidate) => candidate.model === model && candidate.transport === transport,
          )
        ) {
          continue;
        }
        candidates.push({ model, transport });
      }
    }

    return candidates;
  }

  private async callTransport(
    transport: AITransport,
    model: string,
    options: AIGenerateOptions,
    timeoutMs: number,
  ): Promise<{ text: string; parsed: unknown; usage: AIUsage; latencyMs: number }> {
    return transport === "chat"
      ? this.callChatCompletions(model, options, timeoutMs)
      : this.callResponses(model, options, timeoutMs);
  }

  private buildUserPayload(messages: AIMessage[]): {
    system: string;
    conversation: Array<{ role: "user" | "assistant"; content: string }>;
  } {
    const system = messages
      .filter((message) => message.role === "system")
      .map((message) => message.content)
      .join("\n\n");

    const conversation = messages
      .filter((message): message is AIMessage & { role: "user" | "assistant" } =>
        message.role === "user" || message.role === "assistant",
      )
      .map((message) => ({ role: message.role, content: message.content }));

    if (conversation.length === 0) {
      conversation.push({ role: "user", content: "Continue." });
    }

    return { system, conversation };
  }

  private async callChatCompletions(
    model: string,
    options: AIGenerateOptions,
    timeoutMs: number,
  ): Promise<{ text: string; parsed: unknown; usage: AIUsage; latencyMs: number }> {
    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, timeoutMs));

    const body: Record<string, unknown> = {
      model,
      messages: options.messages.map((message) => ({
        role: message.role,
        content: message.content,
      })),
      max_tokens: options.maxOutputTokens ?? config.AI_AGENT_MAX_OUTPUT_TOKENS,
    };

    // Reasoning models reject `temperature` on some gateways.
    if (!isReasoningModel(model)) {
      body.temperature = options.temperature ?? 0.1;
    }

    if (options.jsonSchema) {
      const schema = sanitizeJsonSchema(options.jsonSchema.schema);
      if (schema) {
        body.response_format = {
          type: "json_schema",
          json_schema: {
            name: options.jsonSchema.name,
            schema,
            strict: options.jsonSchema.strict ?? false,
          },
        };
      }
    }

    try {
      const response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const raw = await response.text();
      const payload = safeJson(raw);

      if (!response.ok) {
        const message = errorMessageOf(payload, raw, response.status);
        throw new AIProviderError({
          code: classifyStatus(response.status, message),
          message,
          status: response.status,
          model,
          transport: "chat",
        });
      }

      const choice = isRecord(payload) && Array.isArray(payload.choices) ? payload.choices[0] : null;
      const message = isRecord(choice) && isRecord(choice.message) ? choice.message : null;
      const content = message ? message.content : null;

      let text = "";
      if (typeof content === "string") {
        text = content;
      } else if (Array.isArray(content)) {
        text = content
          .map((part) =>
            isRecord(part) && typeof part.text === "string" ? part.text : "",
          )
          .join("");
      }

      if (!text.trim()) {
        throw new AIProviderError({
          code: "invalid_response",
          message: "The gateway returned an empty completion.",
          status: response.status,
          model,
          transport: "chat",
        });
      }

      const usage = usageFrom(payload);

      return {
        text,
        parsed: options.jsonSchema ? extractJson(text) : null,
        usage,
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      throw this.normalizeTransportError(error, model, "chat", timeoutMs);
    } finally {
      clearTimeout(timer);
    }
  }

  private async callResponses(
    model: string,
    options: AIGenerateOptions,
    timeoutMs: number,
  ): Promise<{ text: string; parsed: unknown; usage: AIUsage; latencyMs: number }> {
    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, timeoutMs));
    const { system, conversation } = this.buildUserPayload(options.messages);

    const body: Record<string, unknown> = {
      model,
      input: conversation.map((message) => ({
        role: message.role,
        content: message.content,
      })),
      max_output_tokens: options.maxOutputTokens ?? config.AI_AGENT_MAX_OUTPUT_TOKENS,
    };

    if (system) body.instructions = system;
    if (typeof options.temperature === "number" && !isReasoningModel(model)) {
      body.temperature = options.temperature;
    }

    if (options.jsonSchema) {
      const schema = sanitizeJsonSchema(options.jsonSchema.schema);
      if (schema) {
        body.text = {
          format: {
            type: "json_schema",
            name: options.jsonSchema.name,
            schema,
            strict: options.jsonSchema.strict ?? false,
          },
        };
      }
    }

    try {
      const response = await fetch(`${this.baseUrl}/responses`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const raw = await response.text();
      const payload = safeJson(raw);

      if (!response.ok) {
        const message = errorMessageOf(payload, raw, response.status);
        throw new AIProviderError({
          code: classifyStatus(response.status, message),
          message,
          status: response.status,
          model,
          transport: "responses",
        });
      }

      const text = extractResponsesText(payload);

      if (!text.trim()) {
        const status = isRecord(payload) && typeof payload.status === "string" ? payload.status : "unknown";
        throw new AIProviderError({
          code: "invalid_response",
          message:
            status === "incomplete"
              ? "The model returned an incomplete response (increase AI_AGENT_MAX_OUTPUT_TOKENS)."
              : "The gateway returned an empty response.",
          status: response.status,
          model,
          transport: "responses",
        });
      }

      return {
        text,
        parsed: options.jsonSchema ? extractJson(text) : null,
        usage: usageFrom(payload),
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      throw this.normalizeTransportError(error, model, "responses", timeoutMs);
    } finally {
      clearTimeout(timer);
    }
  }

  private normalizeTransportError(
    error: unknown,
    model: string,
    transport: AITransport,
    timeoutMs: number,
  ): AIProviderError {
    if (error instanceof AIProviderError) return error;

    if (error instanceof Error && error.name === "AbortError") {
      return new AIProviderError({
        code: "timeout",
        message: `${model} did not respond within ${Math.round(timeoutMs / 1000)}s.`,
        status: 408,
        model,
        transport,
      });
    }

    return new AIProviderError({
      code: "network_error",
      message: error instanceof Error ? error.message : "Unknown network error",
      model,
      transport,
    });
  }
}

function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function errorMessageOf(payload: unknown, raw: string, status: number): string {
  if (isRecord(payload)) {
    const error = payload.error;
    if (isRecord(error) && typeof error.message === "string") return error.message;
    if (typeof error === "string") return error;
    if (typeof payload.message === "string") return payload.message;
  }
  const trimmed = raw.trim();
  return trimmed ? trimmed.slice(0, 300) : `Gateway returned HTTP ${status}.`;
}

function extractResponsesText(payload: unknown): string {
  if (!isRecord(payload)) return "";

  if (typeof payload.output_text === "string") return payload.output_text;

  const output = Array.isArray(payload.output) ? payload.output : [];
  const chunks: string[] = [];

  for (const item of output) {
    if (!isRecord(item)) continue;
    const content = Array.isArray(item.content) ? item.content : [];
    for (const part of content) {
      if (isRecord(part) && typeof part.text === "string") {
        chunks.push(part.text);
      }
    }
  }

  return chunks.join("");
}

function usageFrom(payload: unknown): AIUsage {
  if (!isRecord(payload) || !isRecord(payload.usage)) {
    return { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
  }

  const usage = payload.usage;

  return {
    inputTokens: asNumber(usage.input_tokens ?? usage.prompt_tokens),
    outputTokens: asNumber(usage.output_tokens ?? usage.completion_tokens),
    totalTokens: asNumber(
      usage.total_tokens ?? asNumber(usage.input_tokens) + asNumber(usage.output_tokens),
    ),
  };
}

export const aiProvider = new AIProvider();
export default aiProvider;
