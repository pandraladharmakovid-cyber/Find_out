import type { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { config } from "./config";
import { urlSafetyEngine } from "./url-safety";

/**
 * Standard Operational API Error
 */
export class ApiError extends Error {
  public readonly statusCode: number;
  public readonly details?: unknown;

  constructor(statusCode: number, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  static badRequest(message: string, details?: unknown): ApiError {
    return new ApiError(400, message, details);
  }

  static unauthorized(message: string = "Unauthorized"): ApiError {
    return new ApiError(401, message);
  }

  static forbidden(message: string = "Access forbidden"): ApiError {
    return new ApiError(403, message);
  }

  static notFound(message: string = "Resource not found"): ApiError {
    return new ApiError(404, message);
  }

  static conflict(message: string = "Resource conflict"): ApiError {
    return new ApiError(409, message);
  }

  static internal(message: string = "Internal server error"): ApiError {
    return new ApiError(500, message);
  }
}

/**
 * Attaches a unique correlation ID to every incoming request.
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const reqId =
    (req.headers["x-request-id"] as string) ||
    `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  req.headers["x-request-id"] = reqId;
  res.setHeader("X-Request-Id", reqId);
  next();
}

/**
 * Basic security headers middleware.
 */
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (!config.SERVE_FRONTEND_DIR || req.path.startsWith("/api") || req.path === "/health") {
    res.setHeader("X-Frame-Options", "DENY");
  }
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
}

/**
 * Rate Limiter to protect investigation and scan endpoints.
 */
export function rateLimiter(limit: number = 120, windowMs: number = 60000) {
  const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (entry.count >= limit) {
      res.status(429).json({
        success: false,
        error: {
          message: "Rate limit exceeded. Please try again later.",
          code: "RATE_LIMIT_EXCEEDED",
        },
      });
      return;
    }

    entry.count += 1;
    next();
  };
}

/**
 * SSRF Protection Validator for URL investigation targets.
 * Blocks private, localhost, and loopback IP spaces from server-side fetches.
 */
export function validateSafeUrl(rawUrl: string): boolean {
  return urlSafetyEngine.validateTargetUrl(rawUrl).isAllowed;
}

/**
 * 404 Handler for undefined routes.
 */
export function notFoundHandler(req: Request, _res: Response, next: NextFunction): void {
  next(new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`));
}

/**
 * Central Error Handling Middleware.
 */
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof ApiError) {
    res.status(err.statusCode).json({
      success: false,
      error: {
        message: err.message,
        details: err.details ?? null,
      },
    });
    return;
  }

  if (err instanceof ZodError) {
    res.status(400).json({
      success: false,
      error: {
        message: "Request validation failed",
        details: err.issues,
      },
    });
    return;
  }

  const message = err instanceof Error ? err.message : "Internal server error";
  console.error("[unhandled_server_error]", err);

  res.status(500).json({
    success: false,
    error: {
      message,
      details: null,
    },
  });
}
