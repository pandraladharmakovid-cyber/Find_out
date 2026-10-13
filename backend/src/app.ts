import express, { type Express } from "express";
import cors from "cors";
import { recoveryService } from "./recovery";
import { errorHandler } from "./middleware";

// Import your backend routes
import brandsRouter from "./routes/brands.routes";
import monitoringRouter from "./routes/monitoring.routes";
import investigationsRouter from "./routes/investigations.routes";
import commonRouter from "./routes/common.routes";
import { config } from "./config";

export const app: Express = express();

// Standard middleware
const allowedOrigins = new Set(
  config.FRONTEND_URL.split(",").map((origin) => origin.trim()).filter(Boolean),
);

app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, !origin || allowedOrigins.has(origin));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get("/health", async (_req, res) => {
  const health = await recoveryService.checkHealth();
  res.status(health.status === "unhealthy" ? 503 : 200).json(health);
});

// Mount API routes under /api
app.use("/api/brands", brandsRouter);
app.use("/api/monitoring", monitoringRouter);
app.use("/api/investigations", investigationsRouter);
app.use("/api", commonRouter);

// Global Error Handler
app.use(errorHandler);

export default app;