import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ query: vi.fn(), withTransaction: vi.fn() }));
vi.mock("../src/db", () => ({
  query: mocks.query,
  withTransaction: mocks.withTransaction,
}));
vi.mock("../src/config", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/config")>();
  return {
    ...actual,
    config: {
      ...actual.config,
      ASSET_REGISTRY_ADMIN_KEY: "test-operator-key-with-at-least-32-characters",
    },
  };
});

import { brandsRouter } from "../src/routes/brands.routes";

describe("Official asset API authorization boundary", () => {
  it("rejects a forged self-approval flag before creating or updating an asset", async () => {
    const app = express();
    app.use(express.json());
    app.use("/brands", brandsRouter);

    const response = await request(app)
      .post("/brands/brand-1/assets")
      .send({
        asset_type: "domain",
        platform: "website",
        identifier: "example.com",
        is_verified: true,
      });

    expect(response.status).toBe(403);
    expect(response.body.code).toBe("SELF_APPROVAL_FORBIDDEN");
    expect(mocks.withTransaction).not.toHaveBeenCalled();
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it("rejects the reserved fake domain from the reported screenshot without saving a brand", async () => {
    const app = express();
    app.use(express.json());
    app.use("/brands", brandsRouter);

    const response = await request(app)
      .post("/brands")
      .send({
        name: "NexoraPay Test Corporation",
        primaryDomain: "nexorapay-test.invalid",
        website: "https://nexorapay-test.invalid/",
      });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe("INVALID_PRIMARY_DOMAIN");
    expect(mocks.withTransaction).not.toHaveBeenCalled();
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it("offers no ordinary asset PATCH endpoint for unauthorized approval", async () => {
    const app = express();
    app.use(express.json());
    app.use("/brands", brandsRouter);

    const response = await request(app)
      .patch("/brands/brand-1/assets/asset-1")
      .send({ verification_status: "VERIFIED", is_verified: true });

    expect(response.status).toBe(404);
    expect(mocks.withTransaction).not.toHaveBeenCalled();
    expect(mocks.query).not.toHaveBeenCalled();
  });
  it("rejects unauthenticated asset revocation before touching the database", async () => {
    const app = express();
    app.use(express.json());
    app.use("/brands", brandsRouter);

    const response = await request(app)
      .post("/brands/brand-1/assets/asset-1/revoke")
      .send({ reason: "Unauthenticated attempt" });
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("REGISTRY_OPERATOR_REQUIRED");
    expect(mocks.withTransaction).not.toHaveBeenCalled();
  });

  it("rejects unauthenticated primary-domain changes", async () => {
    const app = express();
    app.use(express.json());
    app.use("/brands", brandsRouter);

    const response = await request(app)
      .patch("/brands/brand-1")
      .send({ primaryDomain: "attacker.example.net" });
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("REGISTRY_OPERATOR_REQUIRED");
    expect(mocks.query).not.toHaveBeenCalled();
  });

});
