import request from "supertest";
import sharp from "sharp";
import { beforeAll, describe, expect, it } from "vitest";

describe("Look-alike and logo intelligence endpoints", () => {
  let app: import("express").Express;

  beforeAll(async () => {
    const module = await import("../src/app");
    app = module.app;
  });

  it("generates look-alike domains for a brand", async () => {
    const response = await request(app)
      .post("/api/intelligence/lookalike/generate")
      .send({ brandName: "nexuspay", tld: "com" });

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.data.count).toBeGreaterThan(5);

    const techniques = new Set(
      (response.body.data.permutations as Array<{ technique: string }>).map((entry) => entry.technique),
    );
    expect(techniques.size).toBeGreaterThanOrEqual(3);
    expect(response.body.data.note).toContain("hypotheses");
  });

  it("rejects an invalid TLD", async () => {
    const response = await request(app)
      .post("/api/intelligence/lookalike/generate")
      .send({ brandName: "nexuspay", tld: "not a tld" });

    expect(response.status).toBe(400);
  });

  it("evaluates a single suspect domain", async () => {
    const response = await request(app)
      .post("/api/intelligence/lookalike/evaluate")
      .send({ domain: "nexusp4y.com", brandName: "nexuspay" });

    expect(response.status).toBe(200);
    expect(response.body.data.isLookalike).toBe(true);
    expect(response.body.data.similarityRatio).toBeGreaterThan(0.7);
  });

  it("evaluates a batch without claiming ownership", async () => {
    const response = await request(app)
      .post("/api/intelligence/lookalike/batch")
      .send({ brandName: "nexuspay", domains: ["nexuspay.com", "nexusp4y.com", "unrelated.org"] });

    expect(response.status).toBe(200);
    expect(response.body.data.total).toBe(3);
    expect(response.body.data.lookalikes).toBeGreaterThanOrEqual(1);
  });

  it("compares two uploaded images and returns a perceptual hash score", async () => {
    const image = await sharp({
      create: { width: 64, height: 64, channels: 3, background: { r: 200, g: 30, b: 30 } },
    })
      .png()
      .toBuffer();

    const base64 = `data:image/png;base64,${image.toString("base64")}`;

    const response = await request(app)
      .post("/api/intelligence/logo/compare")
      .send({ referenceBase64: base64, targetBase64: base64 });

    expect(response.status).toBe(200);
    expect(response.body.data.similarityScore).toBe(1);
    expect(response.body.data.isImpersonating).toBe(true);
    expect(response.body.data.method).toContain("average hash");
  });

  it("hashes a single image", async () => {
    const image = await sharp({
      create: { width: 32, height: 32, channels: 3, background: { r: 0, g: 0, b: 0 } },
    })
      .png()
      .toBuffer();

    const response = await request(app)
      .post("/api/intelligence/logo/hash")
      .send({ imageBase64: image.toString("base64") });

    expect(response.status).toBe(200);
    expect(response.body.data.hash).toHaveLength(64);
    expect(response.body.data.bits).toBe(64);
  });

  it("rejects a request that has no images at all", async () => {
    const response = await request(app).post("/api/intelligence/logo/compare").send({});
    expect(response.status).toBe(400);
  });
});
