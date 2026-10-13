import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";
import { config } from "./config";

export const pool = new Pool({
  connectionString: config.DATABASE_URL,
  ssl: config.DATABASE_SSL ? { rejectUnauthorized: true } : false,
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  max: 10,
  application_name: "find-out-backend",
});

pool.on("error", (error: Error) => {
  console.error("[database] Unexpected idle client error:", error.message);
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values: unknown[] = [],
): Promise<QueryResult<T>> {
  return pool.query<T>(text, values);
}

export async function checkDatabaseConnection(): Promise<{
  connected: boolean;
  latencyMs: number;
}> {
  const startedAt = Date.now();
  try {
    await pool.query("SELECT 1");
    return {
      connected: true,
      latencyMs: Date.now() - startedAt,
    };
  } catch (error) {
    console.error(
      "[database] Connection check failed:",
      error instanceof Error ? error.message : "Unknown database error",
    );
    throw new Error("Database connection check failed");
  }
}

export async function withTransaction<T>(
  callback: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      console.error("[database] Transaction rollback failed");
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function closeDatabase(): Promise<void> {
  await pool.end();
}

export default pool;
