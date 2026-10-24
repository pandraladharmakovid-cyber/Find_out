import { logger } from "./utils/logger";
import type { NormalizedEvidenceItem } from "./evidence";
import type { GeminiAnalysisResult } from "./integrations/gemini.client";
import type { BrandImpersonationResult } from "./brand-impersonation.service";

export type FinalVerdict =
  | "clean"
  | "suspicious"
  | "malicious"
  | "phishing"
  | "unverified";

export interface RiskFactor {
  name: string;
  /** Identifier used by the UI to group factors. */
  code: string;
  weight: number;
  score: number;
  contribution: number;
  reason: string;
  /** False when the underlying source could not be read. */
  available: boolean;
  /** Plain-English explanation shown next to the bar. */
  detail: string;
}

export interface RiskEvaluationOutput {
  compositeRiskScore: number;
  confidenceScore: number;
  verdict: FinalVerdict;
  summary: string;
  factors: RiskFactor[];
  highRiskFlags: string[];
  /** How much of the intended signal set was actually readable (0-1). */
  coverage: number;
  escalation: string | null;
}

/**
 * Composite risk scoring.
 *
 * Two rules make the score meaningful:
 *
 * 1. **Unavailable sources do not dilute risk.** Historically every factor was
 *    averaged with a fixed weight, so a brand-new phishing domain scored ~3/100
 *    whenever the threat feeds were unconfigured. Now only *available* factors
 *    take part in the weighted average, and missing sources reduce confidence
 *    instead of the risk score.
 *
 * 2. **Strong local evidence can escalate.** A hostname that is a homoglyph
 *    copy of the protected brand, or the brand plus a deceptive word, is
 *    impersonation regardless of what third-party feeds know about it.
 */
export class RiskScoringEngine {
  private readonly WEIGHTS = {
    BRAND_IMPERSONATION: 0.34,
    THREAT_INTEL: 0.26,
    AI_SEMANTIC: 0.16,
    URL_HEURISTICS: 0.12,
    COMMUNITY_SIGNALS: 0.12,
  };

  evaluate(params: {
    evidenceItems: NormalizedEvidenceItem[];
    geminiResult?: GeminiAnalysisResult;
    heuristicRiskScore?: number;
    brandImpersonation?: BrandImpersonationResult | null;
  }): RiskEvaluationOutput {
    logger.info("[risk-engine] Computing composite risk and confidence metrics");

    const factors: RiskFactor[] = [];
    const highRiskFlags: string[] = [];
    const evidence = params.evidenceItems;

    // ---------------------------------------------------------------------
    // 1. Brand impersonation (local, always available when a brand is supplied)
    // ---------------------------------------------------------------------
    const impersonation = params.brandImpersonation ?? null;
    const impersonationAvailable = Boolean(impersonation?.evaluated);
    const impersonationScore = impersonationAvailable ? impersonation!.score : 0;

    if (impersonationAvailable && impersonation!.signals.length > 0) {
      for (const signal of impersonation!.signals) {
        highRiskFlags.push(`${signal.label}: ${signal.detail}`);
      }
    }

    factors.push({
      name: "Brand & hostname resemblance",
      code: "brand_impersonation",
      weight: this.WEIGHTS.BRAND_IMPERSONATION,
      score: impersonationScore,
      contribution: 0,
      available: impersonationAvailable,
      reason: impersonation?.summary ?? "No brand was supplied, so hostname resemblance was not scored.",
      detail:
        impersonationAvailable && impersonation!.signals.length > 0
          ? impersonation!.signals.map((signal) => `${signal.label} (+${signal.points})`).join("; ")
          : "No hostname pattern that imitates the protected brand was found.",
    });

    // ---------------------------------------------------------------------
    // 2. Threat intelligence
    // ---------------------------------------------------------------------
    const intelItems = evidence.filter(
      (item) => item.source === "urlhaus" || item.source === "safebrowsing",
    );

    const availableIntel = intelItems.filter((item) => {
      const status = item.rawPayload.sourceStatus;
      return (
        status !== "unavailable" &&
        status !== "unknown" &&
        item.rawPayload.skipped !== true &&
        typeof item.rawPayload.error !== "string"
      );
    });

    const verifiedThreats = availableIntel.filter(
      (item) => item.isVerified && item.reliabilityScore >= 70,
    );

    let intelScore = 0;
    let intelReason =
      "No threat-intelligence source could be read, so nothing is concluded from it.";
    let intelDetail = "URLhaus and Safe Browsing were unavailable or not configured.";

    if (verifiedThreats.length > 0) {
      intelScore = 100;
      intelReason = "An available threat-intelligence source reported a high-confidence match.";
      intelDetail = verifiedThreats
        .map((item) => item.extractedClaim ?? `Threat reported by ${item.source}`)
        .join("; ");

      for (const item of verifiedThreats) {
        highRiskFlags.push(item.extractedClaim ?? `Threat reported by ${item.source}`);
      }
    } else if (availableIntel.length > 0) {
      intelScore = 0;
      intelReason =
        "Available threat-intelligence sources returned no match. This does not prove the target is safe.";
      intelDetail = availableIntel
        .map((item) => `${item.source}: no threat match`)
        .join("; ");
    }

    factors.push({
      name: "Threat intelligence feeds",
      code: "threat_intel",
      weight: this.WEIGHTS.THREAT_INTEL,
      score: intelScore,
      contribution: 0,
      available: availableIntel.length > 0,
      reason: intelReason,
      detail: intelDetail,
    });

    // ---------------------------------------------------------------------
    // 3. AI semantic assessment
    // ---------------------------------------------------------------------
    const aiUsable = Boolean(
      params.geminiResult &&
        params.geminiResult.status === "available" &&
        Number.isFinite(params.geminiResult.confidenceScore) &&
        params.geminiResult.confidenceScore > 0,
    );

    let aiScore = 0;
    let aiReason = "No model-based page assessment was available.";
    let aiDetail = "Gemini analysis did not run or returned no usable result.";

    if (aiUsable && params.geminiResult) {
      aiScore = Math.max(0, Math.min(100, params.geminiResult.riskScore));
      aiReason = params.geminiResult.summary;
      aiDetail = `Model ${params.geminiResult.model ?? "unknown"} scored the page ${aiScore}/100 with ${params.geminiResult.confidenceScore}% confidence.`;

      if (
        params.geminiResult.verdict === "phishing" ||
        params.geminiResult.verdict === "malicious"
      ) {
        highRiskFlags.push(`AI Analysis: ${params.geminiResult.verdict.toUpperCase()}`);
      }
    }

    factors.push({
      name: "AI page assessment",
      code: "ai_semantic",
      weight: this.WEIGHTS.AI_SEMANTIC,
      score: aiScore,
      contribution: 0,
      available: aiUsable,
      reason: aiReason,
      detail: aiDetail,
    });

    // ---------------------------------------------------------------------
    // 4. URL / domain heuristics
    // ---------------------------------------------------------------------
    const heuristicScore = Math.max(
      0,
      Math.min(100, params.heuristicRiskScore ?? 0),
    );
    const heuristicsAvailable = typeof params.heuristicRiskScore === "number";

    factors.push({
      name: "Domain & URL structure",
      code: "url_heuristics",
      weight: this.WEIGHTS.URL_HEURISTICS,
      score: heuristicScore,
      contribution: 0,
      available: heuristicsAvailable,
      reason: `Structural inspection produced a risk index of ${heuristicScore}/100. Structure alone does not confirm a threat.`,
      detail:
        heuristicScore === 0
          ? "No structural red flags were found in the URL."
          : `The URL scored ${heuristicScore}/100 on length, encoding, subdomain depth and keyword checks.`,
    });

    // ---------------------------------------------------------------------
    // 5. Community & social signals
    // ---------------------------------------------------------------------
    const communityItems = evidence.filter(
      (item) =>
        item.source === "reddit" ||
        item.source === "bluesky" ||
        item.source === "youtube",
    );
    const communityAvailable = communityItems.some((item) => {
      const status = String(item.rawPayload.sourceStatus ?? "");
      return (
        (status === "available" || status === "ok") &&
        item.rawPayload.skipped !== true &&
        typeof item.rawPayload.error !== "string"
      );
    });

    const relevantCommunityItems = communityItems.filter(
      (item) =>
        item.reliabilityScore >= 60 && item.rawPayload.relevantToTarget === true,
    );

    let communityScore = 0;
    let communityReason = "No target-relevant public discussion was found.";
    let communityDetail = "Social sources returned no post that names this target.";

    if (relevantCommunityItems.length > 0) {
      communityScore = Math.min(100, relevantCommunityItems.length * 15);
      communityReason = `Found ${relevantCommunityItems.length} target-relevant public warning(s); these remain unverified reports.`;
      communityDetail = relevantCommunityItems
        .slice(0, 3)
        .map((item) => item.extractedClaim ?? `${item.source}: relevant post`)
        .join("; ");
    }

    factors.push({
      name: "Community & social signals",
      code: "community_signals",
      weight: this.WEIGHTS.COMMUNITY_SIGNALS,
      score: communityScore,
      contribution: 0,
      available: communityAvailable,
      reason: communityReason,
      detail: communityDetail,
    });

    // ---------------------------------------------------------------------
    // Weighted average over *available* factors only
    // ---------------------------------------------------------------------
    const availableFactors = factors.filter((factor) => factor.available);

    // Noisy-OR combination: any single strong, independent signal can carry the
    // score on its own, and corroborating signals push it higher. A weighted
    // average would have let two "nothing found" factors drag a 100/100
    // impersonation down to the 40s.
    const STRENGTH: Record<string, number> = {
      brand_impersonation: 0.95,
      threat_intel: 0.85,
      ai_semantic: 0.6,
      url_heuristics: 0.5,
      community_signals: 0.4,
    };

    const contributions = availableFactors.map((factor) => ({
      factor,
      p: Math.max(0, Math.min(1, (factor.score / 100) * (STRENGTH[factor.code] ?? factor.weight))),
    }));

    contributions.sort((a, b) => b.p - a.p);

    let remaining = 1;
    for (const entry of contributions) {
      const before = remaining;
      const added = before * entry.p;
      remaining = before * (1 - entry.p);
      // Contribution expressed on the 0-100 output scale.
      entry.factor.contribution = Number((added * 100).toFixed(2));
    }

    let compositeRiskScore = (1 - remaining) * 100;

    // ---------------------------------------------------------------------
    // Escalation rules
    // ---------------------------------------------------------------------
    let escalation: string | null = null;

    const strongImpersonation = impersonationAvailable && impersonationScore >= 85;
    const confirmedImpersonation = impersonationAvailable && impersonationScore >= 75;

    // A look-alike hostname that also carries a credential lure is the textbook
    // phishing kit: brand + "login" + a throwaway TLD. That combination is
    // scored 100/100 because every observable element of the attack is present.
    const lureSignal = Boolean(
      impersonation?.signals?.some((signal) =>
        ["deceptive_keyword", "credential_path", "deceptive_affix"].includes(signal.code),
      ),
    );
    const throwawayTld = Boolean(
      impersonation?.signals?.some((signal) => signal.code === "suspicious_tld"),
    );

    if (verifiedThreats.length > 0 && strongImpersonation) {
      compositeRiskScore = 100;
      escalation =
        "Every observable element is present: the hostname impersonates the brand and threat intelligence independently confirms a match.";
    } else if (strongImpersonation && (lureSignal || throwawayTld)) {
      compositeRiskScore = 100;
      escalation =
        "Every observable element is present: an impersonating hostname, a credential lure, and no association with the official domain.";
    } else if (strongImpersonation) {
      compositeRiskScore = Math.max(compositeRiskScore, 92);
      escalation = "The hostname is a direct impersonation of the protected brand.";
    } else if (verifiedThreats.length > 0) {
      compositeRiskScore = Math.max(compositeRiskScore, 90);
      escalation = "Threat intelligence reported a verified match.";
    } else if (confirmedImpersonation) {
      compositeRiskScore = Math.max(compositeRiskScore, 72);
      escalation = "The hostname closely resembles the protected brand.";
    }

    compositeRiskScore = Number(
      Math.min(100, Math.max(0, compositeRiskScore)).toFixed(2),
    );

    // ---------------------------------------------------------------------
    // Confidence
    // ---------------------------------------------------------------------
    const allIntelKnown = intelItems.length > 0 && availableIntel.length === intelItems.length;
    const coverage = factors.length > 0 ? availableFactors.length / factors.length : 0;

    let confidenceScore = 0;
    if (impersonationAvailable) confidenceScore += 30;
    if (allIntelKnown) confidenceScore += 25;
    if (aiUsable) confidenceScore += 15;
    if (heuristicsAvailable) confidenceScore += 10;
    if (communityAvailable) confidenceScore += 10;
    if (strongImpersonation || verifiedThreats.length > 0) confidenceScore += 10;

    confidenceScore = Math.round(Math.min(100, Math.max(0, confidenceScore)));

    // ---------------------------------------------------------------------
    // Verdict
    // ---------------------------------------------------------------------
    let verdict: FinalVerdict = "unverified";

    if (
      strongImpersonation &&
      (impersonation?.signals.some((signal) =>
        ["deceptive_keyword", "credential_path", "deceptive_affix"].includes(signal.code),
      ) ||
        verifiedThreats.length > 0 ||
        aiScore >= 60)
    ) {
      verdict = "phishing";
    } else if (verifiedThreats.length > 0 && compositeRiskScore >= 80) {
      verdict = highRiskFlags.some((flag) => flag.toLowerCase().includes("phish"))
        ? "phishing"
        : "malicious";
    } else if (compositeRiskScore >= 75) {
      verdict = "malicious";
    } else if (compositeRiskScore >= 45) {
      verdict = "suspicious";
    } else if (
      confidenceScore >= 50 &&
      allIntelKnown &&
      compositeRiskScore < 20
    ) {
      verdict = "clean";
    }

    const availableNames = availableFactors.map((factor) => factor.name).join(", ");
    const summary =
      `Overall risk ${compositeRiskScore}/100 with ${confidenceScore}% confidence. ` +
      `Verdict: ${verdict.toUpperCase()}. ` +
      `${escalation ? `${escalation} ` : ""}` +
      `Sources used: ${availableNames || "none"}. ` +
      `Unavailable sources are reported as unknown and never as safe.`;

    return {
      compositeRiskScore,
      confidenceScore,
      verdict,
      summary,
      factors,
      highRiskFlags: [...new Set(highRiskFlags)].slice(0, 12),
      coverage: Number(coverage.toFixed(2)),
      escalation,
    };
  }
}

export const riskScoringEngine = new RiskScoringEngine();
export default riskScoringEngine;
