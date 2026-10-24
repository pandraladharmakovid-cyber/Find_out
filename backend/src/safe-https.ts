import { request as httpsRequest, type RequestOptions } from "node:https";
import { lookup as dnsLookup } from "node:dns/promises";
import { urlSafetyEngine } from "./url-safety";

export interface ResolvedAddress {
  address: string;
  family: number;
}

export interface PinnedHttpResponse {
  status: number;
  contentType: string;
  body: string;
  url: string;
  /** Value of the Location header when the server answered with a redirect. */
  location: string | null;
}

export interface PinnedBinaryResponse {
  status: number;
  contentType: string;
  body: Buffer;
  url: string;
  location: string | null;
}

type Lookup = (hostname: string) => Promise<ResolvedAddress[]>;
type RequestFn = typeof httpsRequest;

function unbracketHostname(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function isPublicAddress(address: string): boolean {
  const host = address.includes(":") ? `[${address}]` : address;
  return urlSafetyEngine.validateTargetUrl(`https://${host}/`).isAllowed;
}

/**
 * Minimal HTTPS client that validates every DNS answer and pins the connection to
 * a validated address. Redirects are intentionally unsupported.
 */
export class PinnedHttpsClient {
  private readonly lookup: Lookup;
  private readonly request: RequestFn;
  private readonly timeoutMs: number;

  constructor(options?: {
    lookup?: Lookup;
    request?: RequestFn;
    timeoutMs?: number;
  }) {
    this.lookup =
      options?.lookup ??
      (async (hostname: string) =>
        dnsLookup(hostname, { all: true, verbatim: true }));
    this.request = options?.request ?? httpsRequest;
    this.timeoutMs = options?.timeoutMs ?? 10_000;
  }

  /**
   * Node calls the custom lookup with either (host, options, cb) or (host, cb)
   * depending on version/options. Answering the wrong shape produced
   * "Invalid IP address: undefined", so both forms are handled explicitly.
   */
  private pinnedLookup(selected: ResolvedAddress): RequestOptions["lookup"] {
    return ((hostname: string, options: unknown, callback?: unknown) => {
      const cb = (typeof options === "function" ? options : callback) as
        | ((
            error: NodeJS.ErrnoException | null,
            address: string | ResolvedAddress[],
            family?: number,
          ) => void)
        | undefined;

      if (!cb) return;

      const wantsAll = typeof options === "object" && options !== null && (options as { all?: boolean }).all === true;

      if (wantsAll) {
        cb(null, [selected]);
        return;
      }

      cb(null, selected.address, selected.family);
    }) as unknown as RequestOptions["lookup"];
  }

  async get(
    rawUrl: string,
    options?: { accept?: string; maxBytes?: number },
  ): Promise<PinnedHttpResponse> {
    const url = new URL(rawUrl);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      !urlSafetyEngine.validateTargetUrl(url.toString()).isAllowed
    ) {
      throw new Error("Only public HTTPS verification URLs are allowed.");
    }

    const hostname = unbracketHostname(url.hostname.toLowerCase());
    const addresses = await this.lookup(hostname);
    if (
      addresses.length === 0 ||
      addresses.some(({ address }) => !isPublicAddress(address))
    ) {
      throw new Error(
        "Verification host resolves to a private, reserved, or mixed network address.",
      );
    }
    const selected = addresses[0]!;
    const maxBytes = options?.maxBytes ?? 64 * 1024;

    return await new Promise<PinnedHttpResponse>((resolve, reject) => {
      const requestOptions: RequestOptions = {
        protocol: "https:",
        hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        servername: hostname,
        headers: {
          Accept: options?.accept ?? "text/plain, application/json",
          Host: url.host,
          "User-Agent": "Find_out-Asset-Verification/1.0",
        },
        lookup: this.pinnedLookup(selected),
      };

      const req = this.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        const declaredLength = Number(res.headers["content-length"] ?? 0);
        if (declaredLength > maxBytes) {
          req.destroy(new Error("Verification response exceeds the size limit."));
          return;
        }

        res.on("data", (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += bytes.length;
          if (totalBytes > maxBytes) {
            req.destroy(new Error("Verification response exceeds the size limit."));
            return;
          }
          chunks.push(bytes);
        });
        res.on("error", reject);
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            contentType: String(res.headers["content-type"] ?? ""),
            body: Buffer.concat(chunks).toString("utf8"),
            url: url.toString(),
            location: typeof res.headers.location === "string" ? res.headers.location : null,
          });
        });
      });

      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new Error("Verification request timed out."));
      });
      req.on("error", reject);
      req.end();
    });
  }

  /**
   * Same SSRF-pinned transport, but returns the raw bytes. Used by the logo
   * resolver so a brand/favicon image can be fetched and stored/proxied without
   * going through the redirect-prone global fetch.
   */
  async getBinary(
    rawUrl: string,
    options?: { accept?: string; maxBytes?: number },
  ): Promise<PinnedBinaryResponse> {
    const url = new URL(rawUrl);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      !urlSafetyEngine.validateTargetUrl(url.toString()).isAllowed
    ) {
      throw new Error("Only public HTTPS image URLs are allowed.");
    }

    const hostname = unbracketHostname(url.hostname.toLowerCase());
    const addresses = await this.lookup(hostname);
    if (
      addresses.length === 0 ||
      addresses.some(({ address }) => !isPublicAddress(address))
    ) {
      throw new Error(
        "Image host resolves to a private, reserved, or mixed network address.",
      );
    }

    const selected = addresses[0]!;
    const maxBytes = options?.maxBytes ?? 2 * 1024 * 1024;

    return await new Promise<PinnedBinaryResponse>((resolve, reject) => {
      const requestOptions: RequestOptions = {
        protocol: "https:",
        hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        servername: hostname,
        headers: {
          Accept: options?.accept ?? "image/*,*/*;q=0.8",
          Host: url.host,
          "User-Agent":
            "Mozilla/5.0 (compatible; Find_out-LogoResolver/1.0; +https://findout.local)",
        },
        lookup: this.pinnedLookup(selected),
      };

      const req = this.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        const declaredLength = Number(res.headers["content-length"] ?? 0);
        if (declaredLength > maxBytes) {
          req.destroy(new Error("Image exceeds the size limit."));
          return;
        }

        res.on("data", (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += bytes.length;
          if (totalBytes > maxBytes) {
            req.destroy(new Error("Image exceeds the size limit."));
            return;
          }
          chunks.push(bytes);
        });
        res.on("error", reject);
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            contentType: String(res.headers["content-type"] ?? ""),
            body: Buffer.concat(chunks),
            url: url.toString(),
            location: typeof res.headers.location === "string" ? res.headers.location : null,
          });
        });
      });

      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new Error("Image request timed out."));
      });
      req.on("error", reject);
      req.end();
    });
  }
}

export const pinnedHttpsClient = new PinnedHttpsClient();
