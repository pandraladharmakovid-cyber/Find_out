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

const SUSPICIOUS_DOMAIN_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "account",
  "banking",
  "secure",
  "update",
  "wallet",
  "support",
  "confirm",
  "auth",
  "password",
  "recovery",
  "security",
  "claim",
];

export class UrlSafetyEngine {
  /**
   * Calculates Shannon Entropy of a string to detect randomized/generated domain names.
   */
  calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const frequencies: Record<string, number> = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] ?? 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const char in frequencies) {
      const p = (frequencies[char] ?? 0) / len;
      entropy -= p * Math.log2(p);
    }

    return Number(entropy.toFixed(3));
  }

  /**
   * Analyzes an input URL for heuristic indicators of phishing, spoofing, or malicious hosting.
   */
  analyzeUrl(rawUrl: string): UrlSafetyAnalysis {
    try {
      const parsed = new URL(rawUrl);
      const hostname = parsed.hostname.toLowerCase();
      const domainParts = hostname.split(".");

      const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
      const isHttps = parsed.protocol === "https:";
      const excessiveSubdomains = domainParts.length > 3;

      const domainLabel =
        domainParts.length >= 2
          ? (domainParts[domainParts.length - 2] ?? "")
          : hostname;

      const entropy = this.calculateEntropy(domainLabel);
      const isHighEntropy = entropy > 3.8;

      const lowerUrl = rawUrl.toLowerCase();
      const suspiciousKeywordsFound = SUSPICIOUS_DOMAIN_KEYWORDS.filter((keyword) =>
        lowerUrl.includes(keyword)
      );

      let riskScore = 0;
      if (!isHttps) riskScore += 25;
      if (isIpHost) riskScore += 35;
      if (isHighEntropy) riskScore += 20;
      if (excessiveSubdomains) riskScore += 15;
      riskScore += suspiciousKeywordsFound.length * 10;

      riskScore = Math.min(100, Math.max(0, riskScore));
      const isSuspicious =
        hostname.startsWith("xn--") ||
        hostname.split(".").some((label) => label.startsWith("xn--")) ||
        riskScore >= 50;

      return {
        url: rawUrl,
        domain: domainParts.slice(-2).join("."),
        hostname,
        protocol: parsed.protocol,
        isHttps,
        entropy,
        isHighEntropy,
        suspiciousKeywordsFound,
        hasIpAddressHost: isIpHost,
        excessiveSubdomains,
        riskScore,
        isSuspicious,
      };
    } catch {
      return {
        url: rawUrl,
        domain: "invalid",
        hostname: "invalid",
        protocol: "invalid",
        isHttps: false,
        entropy: 0,
        isHighEntropy: false,
        suspiciousKeywordsFound: [],
        hasIpAddressHost: false,
        excessiveSubdomains: false,
        riskScore: 50,
        isSuspicious: true,
      };
    }
  }

  validateTargetUrl(rawUrl: string): TargetUrlValidation {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return this.validationResult(rawUrl, "Target must be a valid absolute URL.");
    }

    const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    let reason: string | null = null;
    if (!["http:", "https:"].includes(parsed.protocol)) {
      reason = "Only HTTP and HTTPS targets are supported.";
    } else if (parsed.username || parsed.password) {
      reason = "URLs containing embedded credentials are not accepted.";
    } else if (
      hostname === "localhost" ||
      hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal") ||
      hostname === "metadata.google.internal"
    ) {
      reason = "Local and internal network targets are not allowed.";
    } else if (isIP(hostname) && this.isPrivateIp(hostname)) {
      reason = "Private, loopback, link-local, or reserved IP targets are not allowed.";
    }

    const analysis = this.analyzeUrl(rawUrl);
    const blocked = reason !== null;
    return {
      ...analysis,
      safe: !blocked && !analysis.isSuspicious,
      isSafe: !blocked && !analysis.isSuspicious,
      isAllowed: !blocked,
      blocked,
      reason,
    };
  }

  private validationResult(rawUrl: string, reason: string): TargetUrlValidation {
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
    if (address.includes(":")) {
      const normalized = address.toLowerCase();
      const mappedIpv4 = normalized.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
      if (mappedIpv4) return this.isPrivateIp(mappedIpv4);
      return (
        normalized === "::" ||
        normalized === "::1" ||
        normalized.startsWith("fc") ||
        normalized.startsWith("fd") ||
        normalized.startsWith("fe8") ||
        normalized.startsWith("fe9") ||
        normalized.startsWith("fea") ||
        normalized.startsWith("feb") ||
        normalized.startsWith("ff") ||
        normalized.startsWith("2001:db8:")
      );
    }
    const octets = address.split(".").map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
      return true;
    }
    const [first = 0, second = 0] = octets;
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 192 && second === 0) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0) ||
      (first >= 224)
    );
  }
}

export const urlSafetyEngine = new UrlSafetyEngine();
export default urlSafetyEngine;