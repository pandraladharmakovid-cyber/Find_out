import { config } from "../config";
import { AuditLogsRepository } from "../repositories";
import { logger } from "../utils/logger";

export interface BlueskyPostFinding {
  id: string;
  text: string;
  author: string;
  authorDid: string;
  displayName: string;
  permalink: string;
  likeCount: number;
  createdAt: string;
}

export interface BlueskySearchResult {
  source: "bluesky";
  query: string;
  totalFound: number;
  posts: BlueskyPostFinding[];
  hasScamSignals: boolean;
  confidence: number;
  rawPayload: Record<string, unknown>;
}

const PDS_URL = "https://bsky.social";
const APP_VIEW_PROXY = "did:web:api.bsky.app#bsky_appview";
const MAX_RESULTS = 15;
const MAX_QUERY_LENGTH = 200;
const SESSION_CACHE_MS = 4 * 60 * 1000;

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function normalizeSearchTerm(value: string): string {
  let term = value.trim();
  if (term.startsWith('"') && term.endsWith('"') && term.length >= 2) {
    term = term.slice(1, -1).trim();
  }
  if (!term) {
    return "";
  }

  const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(term);
  const looksLikeDomain = !term.includes(" ") && /^[\w.-]+\.[a-z]{2,}(?:[/:?#].*)?$/i.test(term);
  if (hasScheme || looksLikeDomain) {
    try {
      const parsed = new URL(hasScheme ? term : `https://${term}`);
      if (parsed.hostname.includes(".")) {
        return parsed.hostname.replace(/^www\./i, "").toLowerCase().slice(0, MAX_QUERY_LENGTH);
      }
    } catch {
      // Treat an invalid URL-like value as an ordinary text query.
    }
  }

  return term.slice(0, MAX_QUERY_LENGTH);
}

function buildSearchQueries(searchQuery: string): string[] {
  const terms = searchQuery.trim().split(/\s+OR\s+/);
  return [...new Set(terms.map(normalizeSearchTerm).filter(Boolean))].slice(0, 2);
}

export class BlueskyClient {
  private accessToken = "";
  private sessionExpiresAt = 0;
  private sessionPromise: Promise<string> | null = null;

  private async request(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Bluesky request timed out after ${config.REQUEST_TIMEOUT_MS}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async createSession(): Promise<string> {
    const identifier = config.BLUESKY_HANDLE.trim().replace(/^@/, "");
    const response = await this.request(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password: config.BLUESKY_APP_PASSWORD }),
    });
    const payload = asRecord(await response.json().catch(() => ({})));
    if (!response.ok) {
      throw new Error(
        `Bluesky authentication failed (HTTP ${response.status}). Check BLUESKY_HANDLE and BLUESKY_APP_PASSWORD.`,
      );
    }

    const token = stringValue(payload.accessJwt);
    if (!token) {
      throw new Error("Bluesky authentication succeeded but returned no access token.");
    }
    this.accessToken = token;
    this.sessionExpiresAt = Date.now() + SESSION_CACHE_MS;
    return token;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.sessionExpiresAt) {
      return this.accessToken;
    }
    if (this.sessionPromise) {
      return this.sessionPromise;
    }

    const pending = this.createSession();
    this.sessionPromise = pending;
    try {
      return await pending;
    } finally {
      if (this.sessionPromise === pending) {
        this.sessionPromise = null;
      }
    }
  }

  private normalizePost(value: unknown): BlueskyPostFinding | null {
    const post = asRecord(value);
    const author = asRecord(post.author);
    const record = asRecord(post.record);
    const id = stringValue(post.uri) || stringValue(post.cid);
    if (!id) {
      return null;
    }

    const authorDid = stringValue(author.did);
    const handle = stringValue(author.handle);
    const actor = handle || authorDid;
    const postKey = id.startsWith("at://") ? id.split("/").at(-1) ?? "" : "";
    const permalink = actor && postKey
      ? `https://bsky.app/profile/${encodeURIComponent(actor)}/post/${encodeURIComponent(postKey)}`
      : actor
        ? `https://bsky.app/profile/${encodeURIComponent(actor)}`
        : "";

    return {
      id,
      text: stringValue(record.text).slice(0, 4000),
      author: handle,
      authorDid,
      displayName: stringValue(author.displayName) || handle || authorDid,
      permalink,
      likeCount: numberValue(post.likeCount),
      createdAt: stringValue(record.createdAt) || stringValue(post.indexedAt),
    };
  }

  private async searchPosts(searchQuery: string, token: string): Promise<BlueskyPostFinding[]> {
    const url = new URL(`${PDS_URL}/xrpc/app.bsky.feed.searchPosts`);
    url.search = new URLSearchParams({
      q: searchQuery,
      limit: String(MAX_RESULTS),
      sort: "latest",
    }).toString();

    const response = await this.request(url.toString(), {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        "atproto-proxy": APP_VIEW_PROXY,
      },
    });
    if (response.status === 401) {
      this.accessToken = "";
      this.sessionExpiresAt = 0;
    }
    if (!response.ok) {
      throw new Error(`Bluesky post search failed (HTTP ${response.status}).`);
    }

    const payload = asRecord(await response.json().catch(() => ({})));
    const posts = Array.isArray(payload.posts) ? payload.posts : [];
    return posts
      .map((post) => this.normalizePost(post))
      .filter((post): post is BlueskyPostFinding => post !== null);
  }

  private unavailable(searchQuery: string, reason: string, error?: string): BlueskySearchResult {
    return {
      source: "bluesky",
      query: searchQuery,
      totalFound: 0,
      posts: [],
      hasScamSignals: false,
      confidence: 0,
      rawPayload: {
        sourceStatus: "unavailable",
        skipped: !error,
        reason,
        ...(error ? { error } : {}),
        relevanceVerified: false,
        note: "Bluesky returned no usable findings for this scan; no safety conclusion is inferred.",
      },
    };
  }

  private async writeAudit(
    entry: Parameters<typeof AuditLogsRepository.recordLog>[0],
  ): Promise<void> {
    try {
      await AuditLogsRepository.recordLog(entry);
    } catch (error) {
      logger.warn("[bluesky] Audit logging failed", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  /**
   * Verifies credentials without running a search. Used by the diagnostics
   * endpoint so the agent can report Bluesky health separately from results.
   */
  async probe(): Promise<{ ok: boolean; handle: string; latencyMs: number; message: string }> {
    const startedAt = Date.now();
    if (!config.BLUESKY_HANDLE || !config.BLUESKY_APP_PASSWORD) {
      return {
        ok: false,
        handle: "",
        latencyMs: 0,
        message: "BLUESKY_HANDLE or BLUESKY_APP_PASSWORD is missing.",
      };
    }

    try {
      this.accessToken = "";
      this.sessionExpiresAt = 0;
      await this.getAccessToken();
      return {
        ok: true,
        handle: config.BLUESKY_HANDLE,
        latencyMs: Date.now() - startedAt,
        message: `Bluesky session created for @${config.BLUESKY_HANDLE}.`,
      };
    } catch (error) {
      return {
        ok: false,
        handle: config.BLUESKY_HANDLE,
        latencyMs: Date.now() - startedAt,
        message: error instanceof Error ? error.message : "Bluesky authentication failed.",
      };
    }
  }

  async searchDiscussions(searchQuery: string, investigationId?: string): Promise<BlueskySearchResult> {
    const startTime = Date.now();
    if (!config.BLUESKY_HANDLE || !config.BLUESKY_APP_PASSWORD) {
      const result = this.unavailable(searchQuery, "Missing credentials");
      await this.writeAudit({
        investigation_id: investigationId,
        source: "bluesky",
        status: "failed",
        latency_ms: Date.now() - startTime,
        error_message: "Missing credentials",
      });
      return result;
    }

    const queries = buildSearchQueries(searchQuery);
    if (queries.length === 0) {
      return this.unavailable(searchQuery, "Empty search query");
    }

    try {
      const token = await this.getAccessToken();
      const resultSets = await Promise.all(queries.map((query) => this.searchPosts(query, token)));
      const posts = [...new Map(resultSets.flat().map((post) => [post.id, post])).values()].slice(0, MAX_RESULTS);
      const hasScamSignals = posts.some((post) =>
        /\b(scam|fraud|fake|phishing|impersonat(?:e|ing|ion)|cheat(?:ing)?)\b/i.test(post.text),
      );

      await this.writeAudit({
        investigation_id: investigationId,
        source: "bluesky",
        status: "success",
        latency_ms: Date.now() - startTime,
      });

      return {
        source: "bluesky",
        query: searchQuery,
        totalFound: posts.length,
        posts,
        hasScamSignals,
        confidence: 0,
        rawPayload: {
          sourceStatus: "available",
          queries,
          postCount: posts.length,
          relevanceVerified: false,
          note: "Unverified public discussion leads only; not proof of impersonation or maliciousness.",
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown Bluesky error";
      await this.writeAudit({
        investigation_id: investigationId,
        source: "bluesky",
        status: "failed",
        latency_ms: Date.now() - startTime,
        error_message: message,
      });
      return this.unavailable(searchQuery, "Bluesky request failed", message);
    }
  }
}

export const blueskyClient = new BlueskyClient();
