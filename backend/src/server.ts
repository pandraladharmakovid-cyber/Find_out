import { app } from "./app";
import { config } from "./config";
import { initializeSchema } from "./schema";
import { logger } from "./utils/logger";
import { pool } from "./db";

const PORT = config.PORT || 5000;

async function bootstrap() {
  try {
    logger.info("[server] Initializing database schema...");
    await initializeSchema();
    logger.info("[server] Database schema initialization complete.");

    const server = app.listen(PORT, () => {
      logger.info(`[server] Threat Intelligence Engine running on port ${PORT}`);
    });

    const shutdown = async (signal: string) => {
      logger.info(`[server] ${signal} received, shutting down...`);
      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (error) {
    logger.error("[server] Fatal bootstrap error", {
      error: error instanceof Error ? error.message : "Unknown",
    });
    process.exit(1);
  }
}

bootstrap();