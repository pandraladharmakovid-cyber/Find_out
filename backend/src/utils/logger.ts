import { config } from "../config";

type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function shouldLog(level: LogLevel): boolean {
  const currentConfigLevel = (config.LOG_LEVEL?.toLowerCase() as LogLevel) || "info";
  const configuredPriority = LOG_LEVEL_PRIORITY[currentConfigLevel] ?? 1;
  return LOG_LEVEL_PRIORITY[level] >= configuredPriority;
}

function formatLog(level: LogLevel, message: string, metadata?: Record<string, unknown>): string {
  const payload = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    environment: config.NODE_ENV,
    message,
    ...(metadata ? { metadata } : {}),
  };

  return JSON.stringify(payload);
}

export const logger = {
  debug(message: string, metadata?: Record<string, unknown>): void {
    if (shouldLog("debug")) {
      console.debug(formatLog("debug", message, metadata));
    }
  },

  info(message: string, metadata?: Record<string, unknown>): void {
    if (shouldLog("info")) {
      console.log(formatLog("info", message, metadata));
    }
  },

  warn(message: string, metadata?: Record<string, unknown>): void {
    if (shouldLog("warn")) {
      console.warn(formatLog("warn", message, metadata));
    }
  },

  error(message: string, error?: unknown, metadata?: Record<string, unknown>): void {
    if (shouldLog("error")) {
      const errPayload: Record<string, unknown> = {
        ...metadata,
      };

      if (error instanceof Error) {
        errPayload.error = {
          name: error.name,
          message: error.message,
          stack: error.stack,
        };
      } else if (error) {
        errPayload.error = error;
      }

      console.error(formatLog("error", message, errPayload));
    }
  },
};

export default logger;