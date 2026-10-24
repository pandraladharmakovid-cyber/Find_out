import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { rateLimiter } from "../src/middleware";

describe("HTTP security middleware", () => {
  it("returns a JSON 404 through the production Express app", async () => {
    const { app } = await import("../src/app");
    const response = await request(app).get("/api/route-that-does-not-exist");
    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      success: false,
      error: {
        message: "Route not found: GET /api/route-that-does-not-exist",
        details: null,
      },
    });
  });

  it("rejects requests above the configured limit instead of only defining a helper", async () => {
    const app = express();
    app.use(rateLimiter(2, 60_000));
    app.get("/limited", (_req, res) => {
      res.json({ success: true });
    });

    expect((await request(app).get("/limited")).status).toBe(200);
    expect((await request(app).get("/limited")).status).toBe(200);
    const limited = await request(app).get("/limited");
    expect(limited.status).toBe(429);
    expect(limited.body.error.code).toBe("RATE_LIMIT_EXCEEDED");
  });
});
