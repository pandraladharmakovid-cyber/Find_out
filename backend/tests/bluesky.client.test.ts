import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/config", () => ({
  config: {
    BLUESKY_HANDLE: "tester.bsky.social",
    BLUESKY_APP_PASSWORD: "test-app-password",
    REQUEST_TIMEOUT_MS: 1000,
  },
}));

vi.mock("../src/repositories", () => ({
  AuditLogsRepository: { recordLog: vi.fn().mockResolvedValue(undefined) },
}));

import { BlueskyClient } from "../src/integrations/bluesky.client";
import { config } from "../src/config";

const fetchMock = vi.fn();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("BlueskyClient", () => {
  beforeEach(() => {
    config.BLUESKY_HANDLE = "tester.bsky.social";
    config.BLUESKY_APP_PASSWORD = "test-app-password";
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    fetchMock.mockReset();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    config.BLUESKY_HANDLE = "tester.bsky.social";
    config.BLUESKY_APP_PASSWORD = "test-app-password";
  });

  it("authenticates, normalizes posts, and builds a Bluesky permalink", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ accessJwt: "access-token", did: "did:plc:tester" }))
      .mockResolvedValueOnce(
        jsonResponse({
          posts: [
            {
              uri: "at://did:plc:author/app.bsky.feed.post/abc123",
              author: {
                did: "did:plc:author",
                handle: "author.bsky.social",
                displayName: "Example Author",
              },
              record: {
                text: "This looks like a scam impersonation attempt.",
                createdAt: "2026-10-23T10:00:00.000Z",
              },
              likeCount: 12,
            },
          ],
        }),
      );

    const client = new BlueskyClient();
    const result = await client.searchDiscussions("https://example.com/login");

    expect(result.source).toBe("bluesky");
    expect(result.rawPayload.sourceStatus).toBe("available");
    expect(result.totalFound).toBe(1);
    expect(result.hasScamSignals).toBe(true);
    expect(result.confidence).toBe(0);
    expect(result.posts[0]).toMatchObject({
      author: "author.bsky.social",
      displayName: "Example Author",
      permalink: "https://bsky.app/profile/author.bsky.social/post/abc123",
      likeCount: 12,
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const sessionInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(sessionInit.body))).toEqual({
      identifier: "tester.bsky.social",
      password: "test-app-password",
    });

    const searchUrl = new URL(String(fetchMock.mock.calls[1]?.[0]));
    expect(searchUrl.pathname).toBe("/xrpc/app.bsky.feed.searchPosts");
    expect(searchUrl.searchParams.get("q")).toBe("example.com");
    const searchHeaders = fetchMock.mock.calls[1]?.[1]?.headers as Record<string, string>;
    expect(searchHeaders.Authorization).toBe("Bearer access-token");
    expect(searchHeaders["atproto-proxy"]).toBe("did:web:api.bsky.app#bsky_appview");
  });

  it("returns an explicit unavailable result when authentication fails", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: "Unauthorized" }, 401));

    const client = new BlueskyClient();
    const result = await client.searchDiscussions("Example Brand");

    expect(result.source).toBe("bluesky");
    expect(result.posts).toEqual([]);
    expect(result.totalFound).toBe(0);
    expect(result.rawPayload.sourceStatus).toBe("unavailable");
    expect(result.rawPayload.skipped).toBe(false);
    expect(String(result.rawPayload.error)).toContain("HTTP 401");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports missing credentials as unavailable without making a request", async () => {
    config.BLUESKY_APP_PASSWORD = "";

    const result = await new BlueskyClient().searchDiscussions("Example Brand");

    expect(result.rawPayload.sourceStatus).toBe("unavailable");
    expect(result.rawPayload.skipped).toBe(true);
    expect(result.rawPayload.reason).toBe("Missing credentials");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports request timeouts as unavailable", async () => {
    const timeoutError = new Error("The request was aborted");
    timeoutError.name = "AbortError";
    fetchMock.mockRejectedValueOnce(timeoutError);

    const result = await new BlueskyClient().searchDiscussions("Example Brand");

    expect(result.rawPayload.sourceStatus).toBe("unavailable");
    expect(String(result.rawPayload.error)).toContain("timed out");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports rate limits as unavailable without inventing posts", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ accessJwt: "access-token" }))
      .mockResolvedValueOnce(jsonResponse({ error: "RateLimitExceeded" }, 429));

    const result = await new BlueskyClient().searchDiscussions("Example Brand");

    expect(result.posts).toEqual([]);
    expect(result.totalFound).toBe(0);
    expect(result.rawPayload.sourceStatus).toBe("unavailable");
    expect(String(result.rawPayload.error)).toContain("HTTP 429");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
