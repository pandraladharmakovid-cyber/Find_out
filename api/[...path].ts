import app from "../backend/src/app";
import { initializeSchema } from "../backend/src/schema";

let schemaInitialization: Promise<void> | undefined;

export default async function handler(
  req: Parameters<typeof app>[0],
  res: Parameters<typeof app>[1],
): Promise<void> {
  schemaInitialization ??= initializeSchema();

  try {
    await schemaInitialization;
  } catch (error) {
    schemaInitialization = undefined;
    console.error("[vercel] Database schema initialization failed", error);
    res.status(500).json({
      success: false,
      error: "The API could not initialize its database schema.",
    });
    return;
  }

  app(req, res);
}
