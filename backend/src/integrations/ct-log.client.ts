import dns from "node:dns/promises";
import net from "node:net";
import { config } from "../config";
import {
  DECEPTIVE_AFFIXES,
  lookalikeDetectionService,
  normalizeComparableName,
} from "../lookalike.service";
import { logger } from "../utils/logger";

/**
 * External Internet Domain Discovery Client.
 *
 * Discovers live, external look-alike and brand-impersonating domains outside
 * Find_out using two legitimate public internet mechanisms:
 *
 *   1. Certificate Transparency logs (`crt.sh` public JSON feed) — surfaces
 *      newly issued TLS certificates containing brand stems or look-alikes.
 *   2. Bounded public DNS resolution of generated typosquat / homoglyph /
 *      deceptive-affix permutations — confirms whether a candidate domain
 *      actually resolves to a public IP address on the internet.
 *
 * Honesty & safety rules:
 *   - Unregistered permutations (NXDOMAIN / ENODATA) are NEVER reported as
 *     findings.
 *   - Official brand domains and their subdomains are excluded at discovery.
 *   - Private, loopback, link-local, and reserved IPs are rejected.
 *   - Provider timeouts, HTTP errors, or DNS failures are surfaced as
 *     `unavailable` — never as a clean scan.
 */

export interface ExternalSourceCheckStatus {
  source: string;
  status: "available" | "unavailable" | "not_configured";
  candidatesFound: number;
  error?: string;
}

export interface DiscoveredExternalDomain {
  domain: string;
  url: string;
  discoveredVia: "crt_sh_ct_logs" | "dns_lookalike_probe";
  similarity: number;
  detectedTechnique: string | null;
  hasDeceptiveAffix: boolean;
  deceptiveTokens: string[];
  resolvedIps: string[];
  liveResolved: boolean;
  ctIssuer?: string | null;
  ctLoggedAt?: string | null;
}

export interface ExternalDomainDiscoveryInput {
  brandName: string;
  alternateNames?: string[];
  primaryDomain?: string | null;
  associatedDomains?: string[];
  keywords?: string[];
}

export interface ExternalDomainDiscoveryResult {
  domains: DiscoveredExternalDomain[];
  sources: ExternalSourceCheckStatus[];
}

export type PublicDnsResolver = (hostname: string) => Promise<string[]>;

const DOMAIN_SYNTAX =
  /^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const RESERVED_TLDS = new Set([
  "invalid",
  "localhost",
  "test",
  "example",
  "local",
  "internal",
  "onion",
]);

export function isPublicIpAddress(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map((n) => Number.parseInt(n, 10));
    const [a = 0, b = 0] = parts;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return false;
    if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return false;
    }
    if (lower.startsWith("::ffff:")) {
      return isPublicIpAddress(lower.slice("::ffff:".length));
    }
    return true;
  }
  return false;
}

function normalizeHostname(raw: string): string | null {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    ?.split(":")[0]
    ?.replace(/\.+$/, "");

  if (!cleaned || !DOMAIN_SYNTAX.test(cleaned)) return null;
  const tld = cleaned.split(".").pop() ?? "";
  if (RESERVED_TLDS.has(tld)) return null;
  return cleaned;
}

function isOfficialDomainOrSubdomain(hostname: string, officialDomains: string[]): boolean {
  for (const rawOfficial of officialDomains) {
    const official = normalizeHostname(rawOfficial);
    if (!official) continue;
    if (hostname === official || hostname.endsWith(`.${official}`)) {
      return true;
    }
  }
  return false;
}

function extractDeceptiveTokens(hostname: string, brandStems: string[]): string[] {
  const lower = hostname.toLowerCase();
  const brandJoined = brandStems.join(" ");
  return DECEPTIVE_AFFIXES.filter((affix) => {
    if (brandJoined.includes(affix)) return false;
    return (
      lower.includes(`-${affix}`) ||
      lower.includes(`${affix}-`) ||
      lower.includes(`.${affix}.`) ||
      lower.endsWith(`.${affix}`)
    );
  });
}

async function defaultDnsResolver(hostname: string): Promise<string[]> {
  const timeout = <T>(promise: Promise<T>, ms: number): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(Object.assign(new Error("DNS timeout"), { code: "ETIMEOUT" })), ms);
      promise.then(
        (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        (err) => {
          clearTimeout(timer);
          reject(err);
        },
      );
    });

  const [v4, v6] = await Promise.allSettled([
    timeout(dns.resolve4(hostname), 2500),
    timeout(dns.resolve6(hostname), 2500),
  ]);

  const addresses: string[] = [];
  if (v4.status === "fulfilled") addresses.push(...v4.value);
  if (v6.status === "fulfilled") addresses.push(...v6.value);

  if (addresses.length === 0) {
    const firstErr =
      v4.status === "rejected"
        ? (v4.reason as NodeJS.ErrnoException)
        : v6.status === "rejected"
          ? (v6.reason as NodeJS.ErrnoException)
          : null;
    const code = firstErr?.code ?? "";
    if (code && !["ENOTFOUND", "ENODATA", "ESERVFAIL", "EREFUSED"].includes(code)) {
      throw firstErr;
    }
  }

  return Array.from(new Set(addresses.filter(isPublicIpAddress)));
}

export class CtLogDiscoveryClient {
  private readonly fetchFn: typeof fetch;
  private readonly dnsResolver: PublicDnsResolver;

  constructor(options?: { fetchFn?: typeof fetch; dnsResolver?: PublicDnsResolver }) {
    this.fetchFn = options?.fetchFn ?? fetch;
    this.dnsResolver = options?.dnsResolver ?? defaultDnsResolver;
  }

  async discoverExternalDomains(
    input: ExternalDomainDiscoveryInput,
  ): Promise<ExternalDomainDiscoveryResult> {
    const officialDomains = [
      ...(input.primaryDomain ? [input.primaryDomain] : []),
      ...(input.associatedDomains ?? []),
    ].filter(Boolean);

    const brandNames = [input.brandName, ...(input.alternateNames ?? [])]
      .map((entry) => entry.trim())
      .filter((entry) => entry.length >= 3);

    const normalizedStems = Array.from(
      new Set(brandNames.map(normalizeComparableName).filter((stem) => stem.length >= 3)),
    );

    if (normalizedStems.length === 0) {
      return {
        domains: [],
        sources: [
          {
            source: "crt_sh_ct_logs",
            status: "available",
            candidatesFound: 0,
          },
          {
            source: "dns_lookalike_probe",
            status: "available",
            candidatesFound: 0,
          },
        ],
      };
    }

    const [ctOutcome, dnsOutcome] = await Promise.all([
      this.queryCertificateTransparency(input.brandName, normalizedStems, officialDomains),
      this.probeLookalikePermutations(input.brandName, normalizedStems, officialDomains, input.primaryDomain ?? null),
    ]);

    const merged = new Map<string, DiscoveredExternalDomain>();
    for (const entry of [...ctOutcome.domains, ...dnsOutcome.domains]) {
      const existing = merged.get(entry.domain);
      if (!existing) {
        merged.set(entry.domain, entry);
      } else {
        merged.set(entry.domain, {
          ...existing,
          similarity: Math.max(existing.similarity, entry.similarity),
          hasDeceptiveAffix: existing.hasDeceptiveAffix || entry.hasDeceptiveAffix,
          deceptiveTokens: Array.from(new Set([...existing.deceptiveTokens, ...entry.deceptiveTokens])),
          resolvedIps: Array.from(new Set([...existing.resolvedIps, ...entry.resolvedIps])),
          liveResolved: existing.liveResolved || entry.liveResolved,
          ctIssuer: existing.ctIssuer ?? entry.ctIssuer ?? null,
          ctLoggedAt: existing.ctLoggedAt ?? entry.ctLoggedAt ?? null,
        });
      }
    }

    const domains = Array.from(merged.values()).sort((a, b) => {
      if (a.liveResolved !== b.liveResolved) return a.liveResolved ? -1 : 1;
      if (a.hasDeceptiveAffix !== b.hasDeceptiveAffix) return a.hasDeceptiveAffix ? -1 : 1;
      return b.similarity - a.similarity;
    });

    return {
      domains,
      sources: [ctOutcome.status, dnsOutcome.status],
    };
  }

  private async queryCertificateTransparency(
    brandName: string,
    brandStems: string[],
    officialDomains: string[],
  ): Promise<{ domains: DiscoveredExternalDomain[]; status: ExternalSourceCheckStatus }> {
    const primaryStem = brandStems[0]!;
    if (primaryStem.length < 4) {
      return {
        domains: [],
        status: {
          source: "crt_sh_ct_logs",
          status: "available",
          candidatesFound: 0,
        },
      };
    }

    const baseUrl = config.EXTERNAL_WATCH_CT_URL.replace(/\/+$/, "");
    const url = `${baseUrl}/?q=${encodeURIComponent(`%${primaryStem}%`)}&output=json`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.EXTERNAL_WATCH_CT_TIMEOUT_MS);

    try {
      const response = await this.fetchFn(url, {
        method: "GET",
        headers: {
          Accept: "application/json",
          "User-Agent": "Find_out-DRP-Monitor/2.0",
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          domains: [],
          status: {
            source: "crt_sh_ct_logs",
            status: "unavailable",
            candidatesFound: 0,
            error: `Certificate Transparency endpoint responded with HTTP ${response.status}`,
          },
        };
      }

      const rawText = await response.text();
      let entries: Array<Record<string, unknown>> = [];
      if (rawText.trim()) {
        const parsed = JSON.parse(rawText) as unknown;
        if (Array.isArray(parsed)) {
          entries = parsed.slice(0, 250) as Array<Record<string, unknown>>;
        }
      }

      const seenHostnames = new Map<
        string,
        { issuer: string | null; loggedAt: string | null }
      >();

      for (const entry of entries) {
        const namesRaw = [entry.common_name, entry.name_value]
          .filter((v): v is string => typeof v === "string")
          .flatMap((v) => v.split(/\r?\n/));

        for (const candidateRaw of namesRaw) {
          const host = normalizeHostname(candidateRaw);
          if (!host) continue;
          if (isOfficialDomainOrSubdomain(host, officialDomains)) continue;
          if (!seenHostnames.has(host)) {
            seenHostnames.set(host, {
              issuer: typeof entry.issuer_name === "string" ? entry.issuer_name.slice(0, 200) : null,
              loggedAt: typeof entry.entry_timestamp === "string" ? entry.entry_timestamp : null,
            });
          }
          if (seenHostnames.size >= 40) break;
        }
        if (seenHostnames.size >= 40) break;
      }

      const candidates: DiscoveredExternalDomain[] = [];
      const hostEntries = Array.from(seenHostnames.entries()).slice(0, 16);

      await Promise.all(
        hostEntries.map(async ([host, meta]) => {
          const evalResult = lookalikeDetectionService.evaluateLookalike(host, brandName);
          const deceptiveTokens = extractDeceptiveTokens(host, brandStems);
          const containsStem = brandStems.some((stem) =>
            normalizeComparableName(host).includes(stem),
          );

          if (!evalResult.isLookalike && !containsStem) return;

          let resolvedIps: string[] = [];
          try {
            resolvedIps = await this.dnsResolver(host);
          } catch {
            resolvedIps = [];
          }

          // Only keep CT domains that actively resolve on public DNS so stale/expired
          // historical certificates are not misrepresented as active phishing sites.
          if (resolvedIps.length === 0) return;

          const similarity = Math.max(
            evalResult.similarityRatio,
            containsStem ? 0.82 : 0,
          );

          candidates.push({
            domain: host,
            url: `https://${host}`,
            discoveredVia: "crt_sh_ct_logs",
            similarity: Number(Math.min(1, similarity).toFixed(3)),
            detectedTechnique:
              evalResult.detectedTechnique ??
              (deceptiveTokens.length > 0 ? "deceptive_affix" : "certificate_brand_match"),
            hasDeceptiveAffix: deceptiveTokens.length > 0,
            deceptiveTokens,
            resolvedIps,
            liveResolved: true,
            ctIssuer: meta.issuer,
            ctLoggedAt: meta.loggedAt,
          });
        }),
      );

      return {
        domains: candidates,
        status: {
          source: "crt_sh_ct_logs",
          status: "available",
          candidatesFound: candidates.length,
        },
      };
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? `Certificate Transparency lookup timed out after ${Math.round(
              config.EXTERNAL_WATCH_CT_TIMEOUT_MS / 1000,
            )}s`
          : error instanceof Error
            ? error.message
            : "Certificate Transparency lookup failed";

      logger.warn("[ct-log] Certificate Transparency query unavailable", {
        brandName,
        error: message,
      });

      return {
        domains: [],
        status: {
          source: "crt_sh_ct_logs",
          status: "unavailable",
          candidatesFound: 0,
          error: message,
        },
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async probeLookalikePermutations(
    brandName: string,
    brandStems: string[],
    officialDomains: string[],
    primaryDomain: string | null,
  ): Promise<{ domains: DiscoveredExternalDomain[]; status: ExternalSourceCheckStatus }> {
    const primaryTld = primaryDomain?.split(".").pop()?.toLowerCase();
    const tlds = Array.from(
      new Set(
        [primaryTld, "com", "net", "org", "io", "app", "top", "online"].filter(
          (t): t is string => Boolean(t && /^[a-z0-9-]{2,16}$/.test(t)),
        ),
      ),
    );

    const candidateMap = new Map<
      string,
      { domain: string; technique: string; similarity: number }
    >();

    for (const tld of tlds.slice(0, 4)) {
      const generated = lookalikeDetectionService.generatePermutations(brandName, tld);
      for (const perm of generated) {
        const host = normalizeHostname(perm.domain);
        if (!host) continue;
        if (isOfficialDomainOrSubdomain(host, officialDomains)) continue;
        if (!candidateMap.has(host)) {
          candidateMap.set(host, {
            domain: host,
            technique: perm.technique,
            similarity: perm.similarity,
          });
        }
      }
    }

    // High-signal deceptive affix variations across top TLDs — prioritized first
    // because <brand>-login / <brand>-verify / <brand>-secure are top phishing patterns.
    const priorityAffixCandidates: Array<{
      domain: string;
      technique: string;
      similarity: number;
    }> = [];
    const cleanStem = brandName.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (cleanStem.length >= 3) {
      for (const affix of ["login", "secure", "verify", "support", "official", "app"]) {
        for (const tld of tlds.slice(0, 3)) {
          const host = normalizeHostname(`${cleanStem}-${affix}.${tld}`);
          if (host && !isOfficialDomainOrSubdomain(host, officialDomains)) {
            const entry = {
              domain: host,
              technique: "prefix_suffix",
              similarity: 0.92,
            };
            candidateMap.set(host, entry);
            priorityAffixCandidates.push(entry);
          }
        }
      }
    }

    const reservedAffixSlice = priorityAffixCandidates.slice(
      0,
      Math.min(6, config.EXTERNAL_WATCH_DNS_PROBE_LIMIT),
    );
    const reservedDomains = new Set(reservedAffixSlice.map((item) => item.domain));
    const remainingSlots = Math.max(0, config.EXTERNAL_WATCH_DNS_PROBE_LIMIT - reservedAffixSlice.length);
    const typoSlice = Array.from(candidateMap.values())
      .filter((item) => !reservedDomains.has(item.domain))
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, remainingSlots);

    const probeBatch = [...reservedAffixSlice, ...typoSlice];

    const discovered: DiscoveredExternalDomain[] = [];
    let resolverErrors = 0;

    // Run DNS probes in bounded chunks of 6 to avoid resolver saturation
    const chunkSize = 6;
    for (let index = 0; index < probeBatch.length; index += chunkSize) {
      const slice = probeBatch.slice(index, index + chunkSize);
      await Promise.all(
        slice.map(async (item) => {
          try {
            const ips = await this.dnsResolver(item.domain);
            if (ips.length === 0) return;

            const deceptiveTokens = extractDeceptiveTokens(item.domain, brandStems);
            discovered.push({
              domain: item.domain,
              url: `https://${item.domain}`,
              discoveredVia: "dns_lookalike_probe",
              similarity: Number(Math.min(1, item.similarity).toFixed(3)),
              detectedTechnique: item.technique,
              hasDeceptiveAffix: deceptiveTokens.length > 0,
              deceptiveTokens,
              resolvedIps: ips,
              liveResolved: true,
            });
          } catch {
            resolverErrors += 1;
          }
        }),
      );
    }

    if (probeBatch.length > 0 && resolverErrors === probeBatch.length) {
      return {
        domains: [],
        status: {
          source: "dns_lookalike_probe",
          status: "unavailable",
          candidatesFound: 0,
          error: "Public DNS resolver failed for all look-alike permutation probes.",
        },
      };
    }

    return {
      domains: discovered,
      status: {
        source: "dns_lookalike_probe",
        status: "available",
        candidatesFound: discovered.length,
      },
    };
  }
}

export const ctLogClient = new CtLogDiscoveryClient();
export default ctLogClient;
