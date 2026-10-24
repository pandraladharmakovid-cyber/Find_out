import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";
import { config } from "./config";

function applyDatabaseSslMode(connectionString: string, ssl: boolean): string {
  if (!connectionString) return connectionString;

  const url = new URL(connectionString);
  url.searchParams.set("sslmode", ssl ? "require" : "disable");
  return url.toString();
}

function isPooledConnection(connectionString: string): boolean {
  if (!connectionString) return false;
  try {
    const parsed = new URL(connectionString);
    return (
      parsed.hostname.includes("-pooler.") ||
      parsed.hostname.includes(".pooler.") ||
      parsed.searchParams.get("pgbouncer") === "true"
    );
  } catch {
    return false;
  }
}

export const pool = new Pool({
  connectionString: applyDatabaseSslMode(config.DATABASE_URL, config.DATABASE_SSL),
  ssl: config.DATABASE_SSL ? { rejectUnauthorized: true } : false,
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  max: 10,
  application_name: "find-out-backend",
  // Bounds runaway queries so the findings page cannot hang a request.
  // PgBouncer / pooled hosts reject startup statement_timeout parameters,
  // so only send statement_timeout on direct PostgreSQL connections.
  ...(isPooledConnection(config.DATABASE_URL)
    ? {}
    : { statement_timeout: config.DB_STATEMENT_TIMEOUT_MS }),
  query_timeout: config.DB_STATEMENT_TIMEOUT_MS + 2000,
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
