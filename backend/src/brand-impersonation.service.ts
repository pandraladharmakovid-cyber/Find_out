import { lookalikeDetectionService, normalizeComparableName } from "./lookalike.service";

/**
 * Brand-impersonation scoring for a single target URL.
 *
 * The risk engine used to rely only on third-party feeds. When those feeds are
 * unconfigured every investigation collapsed to ~0/100 and an obvious
 * "nexusp4y-login.top" looked harmless. This service scores what can be seen
 * directly on the target itself — the hostname, its shape, and how it relates
 * to the protected brand — and returns a transparent list of signals so the UI
 * can explain every point.
 */

export type ImpersonationSignalCode =
  | "typosquat"
  | "homoglyph"
  | "deceptive_affix"
  | "brand_keyword"
  | "brand_not_in_domain"
  | "deceptive_keyword"
  | "suspicious_tld"
  | "tld_mismatch"
  | "hyphens"
  | "ip_host"
  | "punycode"
  | "long_url"
  | "no_https"
  | "credential_path"
  | "port"
  | "userinfo";

export interface ImpersonationSignal {
  code: ImpersonationSignalCode;
  label: string;
  detail: string;
  points: number;
}

export interface BrandImpersonationResult {
  /** True when the analysis actually ran (a brand name was supplied). */
  evaluated: boolean;
  score: number;
  verdict: "impersonation" | "lookalike" | "similar" | "unrelated";
  isLookalike: boolean;
  technique: string | null;
  hostname: string;
  suspectLabel: string;
  brandLabel: string;
  similarity: number;
  editDistance: number;
  signals: ImpersonationSignal[];
  summary: string;
  /** Set when no brand was supplied, so the score is not silently presented. */
  reason?: string;
}

const SUSPICIOUS_TLDS = new Set([
  "top",
  "xyz",
  "click",
  "info",
  "site",
  "online",
  "zip",
  "mov",
  "live",
  "icu",
  "buzz",
  "rest",
  "cam",
  "sbs",
  "cfd",
  "shop",
  "link",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "work",
  "loan",
  "quest",
  "monster",
  "cyou",
  "su",
]);

const DECEPTIVE_WORDS = [
  "login",
  "logon",
  "signin",
  "signin",
  "verify",
  "verification",
  "secure",
  "security",
  "support",
  "official",
  "account",
  "update",
  "wallet",
  "payment",
  "banking",
  "auth",
  "confirm",
  "recover",
  "unlock",
  "helpdesk",
  "customer",
  "service",
];

const CREDENTIAL_PATH_WORDS = ["login", "signin", "verify", "account", "auth", "password", "secure", "update"];

function clamp(value: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, value));
}

function baseLabel(hostname: string): string {
  return hostname.replace(/^www\./, "").split(".")[0] ?? "";
}

function tldOf(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length > 1 ? (parts.at(-1) ?? "") : "";
}

/** Replaces digits with their alphabet look-alike so "p4y" reads as "pay". */
function deLeet(value: string): string {
  return value.replace(/[0134578]/g, (digit) =>
    ({ "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b" })[digit] ?? digit,
  );
}

export function evaluateBrandImpersonation(params: {
  targetUrl: string;
  brandName?: string | null;
  brandDomains?: string[] | null;
}): BrandImpersonationResult {
  let hostname = "";
  let pathname = "";
  let protocol = "";
  let port = "";
  let hasUserInfo = false;

  try {
    const url = new URL(
      /^https?:\/\//i.test(params.targetUrl) ? params.targetUrl : `https://${params.targetUrl}`,
    );
    hostname = url.hostname.toLowerCase();
    pathname = url.pathname.toLowerCase();
    protocol = url.protocol;
    port = url.port;
    hasUserInfo = Boolean(url.username || url.password);
  } catch {
    return {
      evaluated: Boolean(params.brandName),
      score: 0,
      verdict: "unrelated",
      isLookalike: false,
      technique: null,
      hostname: "",
      suspectLabel: "",
      brandLabel: "",
      similarity: 0,
      editDistance: 0,
      signals: [],
      summary: "The target could not be parsed as a URL.",
      reason: "unparseable_target",
    };
  }

  const signals: ImpersonationSignal[] = [];
  const add = (signal: ImpersonationSignal): void => {
    if (signal.points > 0) signals.push(signal);
  };

  const hostIsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
  const parts = hostname.split(".");
  const label = baseLabel(hostname);
  const tld = tldOf(hostname);
  const hyphenCount = (label.match(/-/g) ?? []).length;

  if (hostIsIp) {
    add({
      code: "ip_host",
      label: "Host is a raw IP address",
      detail: "Brand services are reached through domain names, so a bare IP address is a strong impersonation signal.",
      points: 30,
    });
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    add({
      code: "punycode",
      label: "Internationalised (punycode) hostname",
      detail: "The hostname uses non-Latin characters, a common way to imitate a Latin brand name.",
      points: 20,
    });
  }

  if (protocol === "http:") {
    add({
      code: "no_https",
      label: "No HTTPS",
      detail: "The page was submitted over plain HTTP, which real brand login pages do not do.",
      points: 8,
    });
  }

  if (hasUserInfo) {
    add({
      code: "userinfo",
      label: "Credentials embedded in the URL",
      detail: "The URL contains a user@host section that can disguise the real destination.",
      points: 15,
    });
  }

  if (port && port !== "80" && port !== "443") {
    add({
      code: "port",
      label: "Non-standard port",
      detail: `The target uses port ${port} instead of 443.`,
      points: 8,
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add({
      code: "suspicious_tld",
      label: "High-abuse top-level domain",
      detail: `.${tld} is frequently used for disposable phishing domains.`,
      points: 14,
    });
  }

  if (hyphenCount >= 2) {
    add({
      code: "hyphens",
      label: "Multiple hyphens in the hostname",
      detail: "Official brand domains rarely contain several hyphens.",
      points: 8,
    });
  } else if (hyphenCount === 1) {
    add({
      code: "hyphens",
      label: "Hyphenated hostname",
      detail: "The hostname joins words with a hyphen, a common look-alike pattern.",
      points: 4,
    });
  }

  if (params.targetUrl.length > 90) {
    add({
      code: "long_url",
      label: "Unusually long URL",
      detail: "Long URLs are often used to push the real hostname out of view.",
      points: 4,
    });
  }

  const deceptiveWord = DECEPTIVE_WORDS.find((word) => label.includes(word));
  if (deceptiveWord && !hostIsIp) {
    add({
      code: "deceptive_keyword",
      label: "Deceptive keyword in the hostname",
      detail: `The hostname contains "${deceptiveWord}", a word attackers add to look official.`,
      points: 12,
    });
  }

  const pathWord = CREDENTIAL_PATH_WORDS.find((word) => pathname.includes(word));
  if (pathWord) {
    add({
      code: "credential_path",
      label: "Credential-looking path",
      detail: `The URL path contains "${pathWord}", which suggests a login or verification page.`,
      points: 6,
    });
  }

  // ---------------------------------------------------------------------
  // Brand relationship
  // ---------------------------------------------------------------------
  const brandName = (params.brandName ?? "").trim();
  const brandLabel = normalizeComparableName(brandName);
  let similarity = 0;
  let editDistance = 0;
  let technique: string | null = null;
  let isLookalike = false;

  if (brandName && brandLabel) {
    const evaluation = lookalikeDetectionService.evaluateLookalike(hostname, brandName);
    similarity = evaluation.similarityRatio;
    editDistance = evaluation.levenshteinDistance;
    technique = evaluation.detectedTechnique;
    isLookalike = evaluation.isLookalike;

    const officialDomains = (params.brandDomains ?? [])
      .map((domain) => domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, ""))
      .filter(Boolean);

    const hostIsOfficial = officialDomains.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    );

    if (hostIsOfficial) {
      // Registered assets are never impersonation. The caller still decides
      // whether the path itself is suspicious.
      return {
        evaluated: true,
        score: 0,
        verdict: "unrelated",
        isLookalike: false,
        technique: null,
        hostname,
        suspectLabel: label,
        brandLabel,
        similarity: 1,
        editDistance: 0,
        signals,
        summary: `${hostname} is a registered official domain for ${brandName}, so it is excluded from impersonation scoring.`,
      };
    }

    // The hostname/brand relationship is the dominant signal. A folded homoglyph
    // copy or a brand-plus-deceptive-word hostname *is* impersonation; weaker
    // resemblances start lower and rely on supporting signals.
    const lookalikePoints =
      technique === "homoglyph_substitution"
        ? 82
        : technique === "deceptive_affix_typosquat"
          ? 78
          : technique === "typosquatting_edit_distance"
            ? 72
            : technique === "brand_keyword_embedding"
              ? 62
              : technique === "high_phonetic_lexical_similarity"
                ? 50
                : 0;

    if (isLookalike && lookalikePoints > 0) {
      add({
        code:
          technique === "homoglyph_substitution"
            ? "homoglyph"
            : technique === "deceptive_affix_typosquat"
              ? "deceptive_affix"
              : technique === "brand_keyword_embedding"
                ? "brand_keyword"
                : "typosquat",
        label: "Look-alike hostname",
        detail:
          technique === "homoglyph_substitution"
            ? `"${label}" becomes "${brandLabel}" once look-alike characters are folded, so the hostname is a character-substitution copy of ${brandName}.`
            : technique === "deceptive_affix_typosquat"
              ? `"${label}" is the ${brandName} name with a deceptive word attached.`
              : technique === "brand_keyword_embedding"
                ? `"${label}" embeds the ${brandName} name inside a longer hostname.`
                : `"${label}" differs from "${brandLabel}" by only ${editDistance} character(s).`,
        points: lookalikePoints,
      });
    }

    // The brand name appearing verbatim anywhere in the hostname.
    const compactHost = deLeet(label.replace(/-/g, ""));
    if (!isLookalike && compactHost.includes(brandLabel) && compactHost !== brandLabel) {
      add({
        code: "brand_keyword",
        label: "Brand name inside the hostname",
        detail: `The hostname contains "${brandLabel}" together with other words.`,
        points: 55,
      });
    }

    // A registered brand that is not represented at all on an unrelated domain
    // is not impersonation on its own; only note it when other signals exist.
    const tldMismatch = officialDomains.length > 0 && !officialDomains.some((domain) => tldOf(domain) === tld);
    if (tldMismatch && signals.length > 0) {
      add({
        code: "tld_mismatch",
        label: "Different top-level domain",
        detail: `Official ${brandName} domains use .${tldOf(officialDomains[0] ?? "")} while this target uses .${tld}.`,
        points: 6,
      });
    }

    if (signals.length === 0) {
      add({
        code: "brand_not_in_domain",
        label: "No brand relationship detected",
        detail: `The hostname does not resemble "${brandName}" and contains no deceptive pattern.`,
        points: 0,
      });
    }
  }

  const rawScore = signals.reduce((total, signal) => total + signal.points, 0);
  const score = clamp(rawScore);

  let verdict: BrandImpersonationResult["verdict"] = "unrelated";
  if (score >= 75) verdict = "impersonation";
  else if (score >= 55) verdict = "lookalike";
  else if (score >= 30) verdict = "similar";

  const summary = !brandName
    ? `No brand was supplied, so only generic URL signals were evaluated (${score}/100 from ${signals.length} signal(s)).`
    : verdict === "impersonation"
      ? `${hostname} shows ${signals.length} impersonation signal(s) against ${brandName} and scores ${score}/100.`
      : verdict === "lookalike"
        ? `${hostname} resembles ${brandName} but does not show a full impersonation pattern (${score}/100).`
        : verdict === "similar"
          ? `${hostname} shares some characteristics with ${brandName} (${score}/100).`
          : `${hostname} shows no meaningful resemblance to ${brandName}.`;

  return {
    evaluated: Boolean(brandName),
    score,
    verdict,
    isLookalike,
    technique,
    hostname,
    suspectLabel: label,
    brandLabel,
    similarity,
    editDistance,
    signals,
    summary,
    ...(brandName ? {} : { reason: "no_brand_supplied" }),
  };
}

export default evaluateBrandImpersonation;
