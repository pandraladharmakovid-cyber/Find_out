import path from "node:path";

import express, { type Express } from "express";
import cors from "cors";

import { recoveryService } from "./recovery";
import {
  errorHandler,
  notFoundHandler,
  rateLimiter,
  requestIdMiddleware,
  securityHeadersMiddleware,
} from "./middleware";

import brandsRouter from "./routes/brands.routes";
import brandGuardRouter from "./routes/brand-guard.routes";
import externalWatchRouter from "./routes/external-watch.routes";
import agentRouter from "./routes/agent.routes";
import intelligenceRouter from "./routes/intelligence.routes";
import monitoringRouter from "./routes/monitoring.routes";
import investigationsRouter from "./routes/investigations.routes";
import commonRouter from "./routes/common.routes";
import detectionRecordsRouter from "./routes/detection-records.routes";

import { config } from "./config";

export const app: Express = express();

app.disable("x-powered-by");

// Attach request IDs and basic security headers.
app.use(requestIdMiddleware);
app.use(securityHeadersMiddleware);

// Allow only configured frontend origins.
const allowedOrigins = new Set(
  config.FRONTEND_URL
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter(Boolean),
);

app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, !origin || allowedOrigins.has(origin));
    },
    credentials: true,
  }),
);

// Logo comparison accepts base64 images, so this router gets its own larger
// body limit before the global JSON parser runs.
app.use(
  "/api/intelligence",
  express.json({ limit: "8mb" }),
  intelligenceRouter,
);

// Apply the configured request-body limit.
app.use(
  express.json({
    limit: config.MAX_REQUEST_BODY_BYTES,
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: config.MAX_REQUEST_BODY_BYTES,
    parameterLimit: 1000,
  }),
);

// Bound API request volume. Health checks remain outside this limiter.
app.use("/api", rateLimiter(120, 60_000));

// Preserve the existing root health endpoint.
app.get("/health", async (_req, res, next) => {
  try {
    const health = await recoveryService.checkHealth();

    res
      .status(health.status === "unhealthy" ? 503 : 200)
      .json(health);
  } catch (error) {
    next(error);
  }
});

// API routes.
app.use("/api/agent", agentRouter);
app.use("/api/brands", brandsRouter);
app.use("/api/brand-guard", brandGuardRouter);
app.use("/api/external-watch", externalWatchRouter);
app.use("/api/monitoring", monitoringRouter);
app.use("/api/investigations", investigationsRouter);
app.use("/api/detection-records", detectionRecordsRouter);
app.use("/api", commonRouter);

// Optionally serve the built frontend from the same origin (single-process
// deployment and the local demo server). Must be registered before the 404
// handler so client-side routes fall through to index.html.
if (config.SERVE_FRONTEND_DIR) {
  app.use(express.static(config.SERVE_FRONTEND_DIR, { index: "index.html" }));
  app.get(/^(?!\/api|\/health).*/, (_req, res) => {
    res.sendFile(path.join(config.SERVE_FRONTEND_DIR!, "index.html"));
  });
}

// Return API-shaped 404 responses, then keep the error handler last.
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
