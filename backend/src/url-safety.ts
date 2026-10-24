import { isIP } from "node:net";

export interface UrlSafetyAnalysis {
  url: string;
  domain: string;
  hostname: string;
  protocol: string;
  isHttps: boolean;
  entropy: number;
  isHighEntropy: boolean;
  suspiciousKeywordsFound: string[];
  hasIpAddressHost: boolean;
  excessiveSubdomains: boolean;
  riskScore: number;
  isSuspicious: boolean;
}

export interface TargetUrlValidation extends UrlSafetyAnalysis {
  safe: boolean;
  isSafe: boolean;
  isAllowed: boolean;
  blocked: boolean;
  reason: string | null;
}

function normalizeHostname(hostname: string): string {
  const withoutTrailingDot = hostname.toLowerCase().replace(/\.$/, "");
  return withoutTrailingDot.startsWith("[") && withoutTrailingDot.endsWith("]")
    ? withoutTrailingDot.slice(1, -1)
    : withoutTrailingDot;
}

const SUSPICIOUS_DOMAIN_KEYWORDS = [
  "login", "signin", "verify", "account", "banking",
  "secure", "update", "wallet", "support", "confirm",
  "auth", "password", "recovery", "security", "claim",
];

export function normalizeTargetUrl(input: string): string {
  const raw = input.trim();

  if (!raw || raw.length > 2048) {
    throw new Error("Target must contain between 1 and 2048 characters.");
  }

  // Strip accidental leading slashes (e.g. "//google.com") or malformed scheme slashes ("https:////google.com")
  const cleaned = raw
    .replace(/^\/+/, "")
    .replace(/^(https?:)\/{2,}/i, "$1//");

  const withProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(cleaned)
    ? cleaned
    : `https://${cleaned}`;

  let parsed: URL;

  try {
    parsed = new URL(withProtocol);
  } catch {
    throw new Error("Target must be a valid URL or domain.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS targets are supported.");
  }

  if (!parsed.hostname || parsed.username || parsed.password) {
    throw new Error(
      "Target hostname is invalid or contains embedded credentials."
    );
  }

  // Collapse multiple consecutive slashes in pathname
  parsed.pathname = parsed.pathname.replace(/\/{2,}/g, "/");
  parsed.hash = "";
  return parsed.href;
}

export class UrlSafetyEngine {
  calculateEntropy(value: string): number {
    if (!value) return 0;

    const frequencies = new Map<string, number>();

    for (const char of value) {
      frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    }

    let entropy = 0;

    for (const count of frequencies.values()) {
      const probability = count / value.length;
      entropy -= probability * Math.log2(probability);
    }

    return Number(entropy.toFixed(3));
  }

  // Compatibility method used by existing tests and callers.
  analyze(rawUrl: string): TargetUrlValidation {
    try {
      const normalizedUrl = normalizeTargetUrl(rawUrl);
      return this.validateTargetUrl(normalizedUrl);
    } catch (error) {
      const reason = error instanceof Error
        ? error.message
        : "Invalid target URL.";

      return this.validationResult(rawUrl, reason);
    }
  }

  analyzeUrl(rawUrl: string): UrlSafetyAnalysis {
    let parsed: URL;

    try {
      parsed = new URL(rawUrl);
    } catch {
      return {
        url: rawUrl,
        domain: "",
        hostname: "",
        protocol: "",
        isHttps: false,
        entropy: 0,
        isHighEntropy: false,
        suspiciousKeywordsFound: [],
        hasIpAddressHost: false,
        excessiveSubdomains: false,
        riskScore: 0,
        isSuspicious: false,
      };
    }

    const hostname = normalizeHostname(parsed.hostname);
    const isIpHost = isIP(hostname) !== 0;
    const labels = hostname.split(".");
    const domain = isIpHost ? hostname : labels.slice(-2).join(".");
    const hasPunycode = labels.some((label) => label.startsWith("xn--"));

    const suspiciousKeywordsFound = SUSPICIOUS_DOMAIN_KEYWORDS.filter(
      (keyword) =>
        hostname.split(/[.-]/).some((part) => part.includes(keyword))
    );

    const domainLabel = isIpHost
      ? hostname
      : labels.length >= 2
        ? labels[labels.length - 2] ?? hostname
        : hostname;

    const entropy = this.calculateEntropy(domainLabel);
    const isHighEntropy = entropy > 3.8;
    const isHttps = parsed.protocol === "https:";
    const excessiveSubdomains = !isIpHost && labels.length > 4;

    let riskScore = 0;

    if (!isHttps) riskScore += 20;
    if (isIpHost) riskScore += 30;
    if (isHighEntropy) riskScore += 20;
    if (excessiveSubdomains) riskScore += 15;
    if (hasPunycode) riskScore += 20;

    riskScore += Math.min(20, suspiciousKeywordsFound.length * 10);
    riskScore = Math.min(100, riskScore);

    return {
      url: rawUrl,
      domain,
      hostname,
      protocol: parsed.protocol,
      isHttps,
      entropy,
      isHighEntropy,
      suspiciousKeywordsFound,
      hasIpAddressHost: isIpHost,
      excessiveSubdomains,
      riskScore,
      isSuspicious: hasPunycode || riskScore >= 50,
    };
  }

  validateTargetUrl(rawUrl: string): TargetUrlValidation {
    let parsed: URL;

    try {
      parsed = new URL(rawUrl);
    } catch {
      return this.validationResult(
        rawUrl,
        "Target must be a valid absolute URL."
      );
    }

    const hostname = normalizeHostname(parsed.hostname);
    let reason: string | null = null;

    if (!["http:", "https:"].includes(parsed.protocol)) {
      reason = "Only HTTP and HTTPS targets are supported.";
    } else if (parsed.username || parsed.password) {
      reason = "URLs containing embedded credentials are not accepted.";
    } else if (
      !hostname ||
      hostname === "localhost" ||
      hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal") ||
      hostname === "metadata.google.internal"
    ) {
      reason = "Local and internal network targets are not allowed.";
    } else if (isIP(hostname) !== 0 && this.isPrivateIp(hostname)) {
      reason =
        "Private, loopback, link-local, or reserved IP targets are not allowed.";
    } else if (
      hostname === "0.0.0.0" ||
      hostname.endsWith(".test") ||
      hostname.endsWith(".invalid") ||
      hostname.endsWith(".example")
    ) {
      reason =
        "Reserved test and example hosts are not valid investigation targets.";
    }

    const analysis = this.analyzeUrl(parsed.href);
    const blocked = reason !== null;
    const safe = !blocked && !analysis.isSuspicious;

    return {
      ...analysis,
      safe,
      isSafe: safe,
      isAllowed: !blocked,
      blocked,
      reason,
    };
  }

  private validationResult(
    rawUrl: string,
    reason: string
  ): TargetUrlValidation {
    return {
      ...this.analyzeUrl(rawUrl),
      safe: false,
      isSafe: false,
      isAllowed: false,
      blocked: true,
      reason,
    };
  }

  private isPrivateIp(address: string): boolean {
    if (isIP(address) === 6) {
      const value = address.toLowerCase();

      if (value.startsWith("::ffff:")) {
        const mapped = value.match(
          /::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/
        )?.[1];

        if (mapped) return this.isPrivateIp(mapped);

        // URL normalizes dotted IPv4-mapped addresses to two hexadecimal hextets.
        const mappedHex = value.match(/^::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/);
        if (mappedHex?.[1] && mappedHex[2]) {
          const high = parseInt(mappedHex[1], 16);
          const low = parseInt(mappedHex[2], 16);
          return this.isPrivateIp(
            [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".")
          );
        }
      }

      const firstHextet = parseInt(value.split(":")[0] || "0", 16);

      return (
        value === "::" ||
        value === "::1" ||
        (firstHextet & 0xfe00) === 0xfc00 ||
        (firstHextet & 0xffc0) === 0xfe80 ||
        (firstHextet & 0xff00) === 0xff00 ||
        value.startsWith("2001:db8:")
      );
    }

    if (isIP(address) !== 4) return true;

    const octets = address.split(".").map(Number);
    const [a = 0, b = 0] = octets;

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51) ||
      (a === 203 && b === 0) ||
      a >= 224
    );
  }
}

export const urlSafetyEngine = new UrlSafetyEngine();
export default urlSafetyEngine;
