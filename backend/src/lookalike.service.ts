import { logger } from "./utils/logger";
import { domainToUnicode } from "node:url";

export interface LookalikePermutation {
  domain: string;
  technique: "homoglyph" | "omission" | "repetition" | "transposition" | "tld_swap" | "prefix_suffix";
  similarity: number;
}

export interface LookalikeEvaluation {
  targetDomain: string;
  referenceBrand: string;
  levenshteinDistance: number;
  similarityRatio: number;
  isLookalike: boolean;
  detectedTechnique: string | null;
}

const COMMON_HOMOGLYPHS: Record<string, string[]> = {
  a: ["4", "@", "q"],
  b: ["8", "6"],
  c: ["(", "<"],
  e: ["3"],
  g: ["9", "q"],
  i: ["1", "l", "!"],
  l: ["1", "i", "|"],
  o: ["0"],
  s: ["5", "$"],
  t: ["7", "+"],
  v: ["u"],
  w: ["vv"],
};

const UNICODE_CONFUSABLES: Record<string, string> = {
  "а": "a",
  "α": "a",
  "в": "b",
  "ь": "b",
  "с": "c",
  "ϲ": "c",
  "ԁ": "d",
  "е": "e",
  "ε": "e",
  "і": "i",
  "ι": "i",
  "ј": "j",
  "κ": "k",
  "ӏ": "l",
  "ο": "o",
  "о": "o",
  "р": "p",
  "ρ": "p",
  "ԛ": "q",
  "г": "r",
  "ѕ": "s",
  "τ": "t",
  "υ": "u",
  "ν": "v",
  "ԝ": "w",
  "х": "x",
  "χ": "x",
  "у": "y",
  "ζ": "z",
};

export function normalizeComparableName(value: string): string {
  const normalized = value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[аαвьсϲԁеεіιјκӏοорρԛгѕτυνԝхχуζ]/g, (character) =>
      UNICODE_CONFUSABLES[character] ?? character,
    )
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");
  return normalized.replace(/[^\p{L}\p{N}]/gu, "");
}

export class LookalikeDetectionService {
  /**
   * Computes the Levenshtein distance between two strings with strict type safety.
   */
  levenshtein(a: string, b: string): number {
    const s1 = normalizeComparableName(a);
    const s2 = normalizeComparableName(b);
    const m = s1.length;
    const n = s2.length;

    if (m === 0) return n;
    if (n === 0) return m;

    let prevRow = new Int32Array(n + 1);
    let currRow = new Int32Array(n + 1);

    for (let j = 0; j <= n; j++) {
      prevRow[j] = j;
    }

    for (let i = 1; i <= m; i++) {
      currRow[0] = i;
      const char1 = s1.charAt(i - 1);

      for (let j = 1; j <= n; j++) {
        const char2 = s2.charAt(j - 1);
        const cost = char1 === char2 ? 0 : 1;

        const insertion = (currRow[j - 1] ?? 0) + 1;
        const deletion = (prevRow[j] ?? 0) + 1;
        const substitution = (prevRow[j - 1] ?? 0) + cost;

        currRow[j] = Math.min(insertion, deletion, substitution);
      }

      prevRow.set(currRow);
    }

    return prevRow[n] ?? 0;
  }

  /**
   * Computes normalized string similarity (0.0 to 1.0).
   */
  similarityRatio(a: string, b: string): number {
    const normalizedA = normalizeComparableName(a);
    const normalizedB = normalizeComparableName(b);
    const maxLen = Math.max(normalizedA.length, normalizedB.length);
    if (maxLen === 0) return 1.0;
    const dist = this.levenshtein(normalizedA, normalizedB);
    return Number((1 - dist / maxLen).toFixed(3));
  }

  /**
   * Extracts the main domain name label without protocol, port, or top-level domain.
   */
  extractDomainLabel(rawUrlOrDomain: string): string {
    let host = rawUrlOrDomain.toLowerCase().trim();
    try {
      if (!host.startsWith("http://") && !host.startsWith("https://")) {
        host = `https://${host}`;
      }
      const parsed = new URL(host);
      host = domainToUnicode(parsed.hostname);
    } catch {
      // Fallback manual string processing
    }

    const parts = host.split(".").filter(Boolean);
    if (parts.length >= 2) {
      return parts[parts.length - 2] ?? "";
    }
    return parts[0] ?? "";
  }

  /**
   * Generates common typo-squatting and lookalike domain variations for a brand.
   */
  generatePermutations(brandName: string, tld = "com"): LookalikePermutation[] {
    const cleanBrand = brandName.toLowerCase().replace(/[^a-z0-9]/g, "");
    const results: Map<string, LookalikePermutation> = new Map();

    // 1. Character Omission
    for (let i = 0; i < cleanBrand.length; i++) {
      const variant = cleanBrand.slice(0, i) + cleanBrand.slice(i + 1);
      if (variant.length > 2) {
        const domain = `${variant}.${tld}`;
        results.set(domain, {
          domain,
          technique: "omission",
          similarity: this.similarityRatio(cleanBrand, variant),
        });
      }
    }

    // 2. Character Repetition
    for (let i = 0; i < cleanBrand.length; i++) {
      const char = cleanBrand.charAt(i);
      const variant = cleanBrand.slice(0, i) + char + cleanBrand.slice(i);
      const domain = `${variant}.${tld}`;
      results.set(domain, {
        domain,
        technique: "repetition",
        similarity: this.similarityRatio(cleanBrand, variant),
      });
    }

    // 3. Transposition (adjacent character swaps)
    for (let i = 0; i < cleanBrand.length - 1; i++) {
      const arr = cleanBrand.split("");
      const first = arr[i];
      const second = arr[i + 1];
      if (first !== undefined && second !== undefined) {
        arr[i] = second;
        arr[i + 1] = first;
        const variant = arr.join("");
        const domain = `${variant}.${tld}`;
        results.set(domain, {
          domain,
          technique: "transposition",
          similarity: this.similarityRatio(cleanBrand, variant),
        });
      }
    }

    // 4. Homoglyphs
    for (let i = 0; i < cleanBrand.length; i++) {
      const char = cleanBrand.charAt(i);
      const subs = COMMON_HOMOGLYPHS[char] ?? [];
      for (const sub of subs) {
        const variant = cleanBrand.slice(0, i) + sub + cleanBrand.slice(i + 1);
        const domain = `${variant}.${tld}`;
        results.set(domain, {
          domain,
          technique: "homoglyph",
          similarity: this.similarityRatio(cleanBrand, variant),
        });
      }
    }

    // 5. Keyword Affixes
    const affixes = ["login", "verify", "secure", "support", "official"];
    for (const affix of affixes) {
      const pDomain = `${affix}-${cleanBrand}.${tld}`;
      results.set(pDomain, {
        domain: pDomain,
        technique: "prefix_suffix",
        similarity: this.similarityRatio(cleanBrand, `${affix}-${cleanBrand}`),
      });

      const sDomain = `${cleanBrand}-${affix}.${tld}`;
      results.set(sDomain, {
        domain: sDomain,
        technique: "prefix_suffix",
        similarity: this.similarityRatio(cleanBrand, `${cleanBrand}-${affix}`),
      });
    }

    return Array.from(results.values());
  }

  /**
   * Compares an unknown suspect domain against a known official brand.
   */
  evaluateLookalike(suspectDomain: string, officialBrand: string): LookalikeEvaluation {
    const suspectLabel = this.extractDomainLabel(suspectDomain);
    const brandLabel = normalizeComparableName(officialBrand);
    const normalizedSuspectLabel = normalizeComparableName(suspectLabel);

    const distance = this.levenshtein(normalizedSuspectLabel, brandLabel);
    const similarity = this.similarityRatio(normalizedSuspectLabel, brandLabel);

    let isLookalike = false;
    let detectedTechnique: string | null = null;

    if (normalizedSuspectLabel === brandLabel) {
      isLookalike = false; // Exact match, handled by whitelist
    } else if (distance <= 2 && suspectLabel.length >= 4) {
      isLookalike = true;
      detectedTechnique = "typosquatting_edit_distance";
    } else if (similarity >= 0.75) {
      isLookalike = true;
      detectedTechnique = "high_phonetic_lexical_similarity";
    } else if (normalizedSuspectLabel.includes(brandLabel) && normalizedSuspectLabel !== brandLabel) {
      isLookalike = true;
      detectedTechnique = "brand_keyword_embedding";
    }

    logger.debug("[lookalike] Evaluated suspect label against brand", {
      suspectLabel,
      brandLabel,
      distance,
      similarity,
      isLookalike,
    });

    return {
      targetDomain: suspectDomain,
      referenceBrand: officialBrand,
      levenshteinDistance: distance,
      similarityRatio: similarity,
      isLookalike,
      detectedTechnique,
    };
  }
}

export const lookalikeDetectionService = new LookalikeDetectionService();
export default lookalikeDetectionService;