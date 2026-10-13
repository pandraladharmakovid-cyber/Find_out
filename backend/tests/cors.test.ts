import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import request from "supertest";

describe("CORS configuration", () => {
  beforeAll(() => {
    vi.stubEnv(
      "FRONTEND_URL",
      "https://find-out.vercel.app,https://find-out-preview.vercel.app",
    );
    vi.resetModules();
  });

  afterAll(() => {
    vi.unstubAllEnvs();
  });

  it("allows configured frontend origins", async () => {
    const { app } = await import("../src/app");
    const response = await request(app)
      .options("/api/health")
      .set("Origin", "https://find-out.vercel.app")
      .set("Access-Control-Request-Method", "GET");

    expect(response.headers["access-control-allow-origin"]).toBe(
      "https://find-out.vercel.app",
    );
    expect(response.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("does not allow unconfigured frontend origins", async () => {
    const { app } = await import("../src/app");
    const response = await request(app)
      .options("/api/health")
      .set("Origin", "https://untrusted.example")
      .set("Access-Control-Request-Method", "GET");

    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });
});
