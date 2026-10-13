import { logger } from "./utils/logger";
import type { NormalizedEvidenceItem } from "./evidence";
import type { GeminiAnalysisResult } from "./integrations/gemini.client";

export type FinalVerdict = "clean" | "suspicious" | "malicious" | "phishing" | "unverified";

export interface RiskFactor {
  name: string;
  weight: number;
  score: number;
  contribution: number;
  reason: string;
}

export interface RiskEvaluationOutput {
  compositeRiskScore: number;
  confidenceScore: number;
  verdict: FinalVerdict;
  summary: string;
  factors: RiskFactor[];
  highRiskFlags: string[];
}

export class RiskScoringEngine {
  /**
   * Weights allocated across distinct threat signal families (sum = 1.0)
   */
  private readonly WEIGHTS = {
    THREAT_INTEL: 0.35, // URLhaus & Google Safe Browsing
    AI_SEMANTIC: 0.25,  // Gemini LLM semantic assessment
    URL_HEURISTICS: 0.20, // Shannon entropy, IP hosts, phishing keywords
    COMMUNITY_SIGNALS: 0.20, // Reddit & YouTube scam reports
  };

  /**
   * Calculates the overall risk score, confidence rating, and final verdict
   */
  evaluate(params: {
    evidenceItems: NormalizedEvidenceItem[];
    geminiResult?: GeminiAnalysisResult;
    heuristicRiskScore?: number;
  }): RiskEvaluationOutput {
    logger.info("[risk-engine] Computing composite risk and confidence metrics");

    const factors: RiskFactor[] = [];
    const highRiskFlags: string[] = [];

    // 1. Threat Intelligence Evaluation (URLhaus / SafeBrowsing)
    const intelItems = params.evidenceItems.filter(
      (item) => item.source === "urlhaus" || item.source === "safebrowsing"
    );
    let intelScore = 0;
    let intelReason = "No active threat intelligence matches reported.";

    const verifiedThreat = intelItems.find((item) => item.isVerified);
    if (verifiedThreat) {
      intelScore = 100;
      intelReason = `Threat intelligence verified malicious target via ${verifiedThreat.source.toUpperCase()}.`;
      highRiskFlags.push(verifiedThreat.extractedClaim ?? "Blacklisted domain");
    } else if (intelItems.length > 0) {
      intelScore = 5;
      intelReason = "Scanned against URLhaus and Safe Browsing with zero matches.";
    }

    factors.push({
      name: "Threat Intelligence Feeds",
      weight: this.WEIGHTS.THREAT_INTEL,
      score: intelScore,
      contribution: Number((intelScore * this.WEIGHTS.THREAT_INTEL).toFixed(2)),
      reason: intelReason,
    });

    // 2. AI Semantic & Claim Evaluation (Gemini)
    let aiScore = 0;
    let aiReason = "AI threat evaluation was skipped or returned neutral.";
    if (params.geminiResult && params.geminiResult.confidenceScore > 0) {
      aiScore = params.geminiResult.riskScore;
      aiReason = params.geminiResult.summary;
      if (params.geminiResult.verdict === "phishing" || params.geminiResult.verdict === "malicious") {
        highRiskFlags.push(`AI Analysis: ${params.geminiResult.verdict.toUpperCase()}`);
      }
    }

    factors.push({
      name: "AI Semantic Assessment",
      weight: this.WEIGHTS.AI_SEMANTIC,
      score: aiScore,
      contribution: Number((aiScore * this.WEIGHTS.AI_SEMANTIC).toFixed(2)),
      reason: aiReason,
    });

    // 3. Static & URL Heuristics (Entropy / Domain Keywords)
    const heuristicScore = params.heuristicRiskScore ?? 0;
    factors.push({
      name: "Domain & URL Heuristics",
      weight: this.WEIGHTS.URL_HEURISTICS,
      score: heuristicScore,
      contribution: Number((heuristicScore * this.WEIGHTS.URL_HEURISTICS).toFixed(2)),
      reason: `Structural inspection computed a heuristic risk index of ${heuristicScore}/100.`,
    });

    // 4. Social & Community Signals (Reddit / YouTube)
    const communityItems = params.evidenceItems.filter(
      (item) => item.source === "reddit" || item.source === "youtube"
    );
    let communityScore = 0;
    let communityReason = "No public scam complaints identified in community discussions.";

    const suspiciousSocial = communityItems.filter((item) => item.reliabilityScore >= 60);
    if (suspiciousSocial.length > 0) {
      communityScore = Math.min(100, suspiciousSocial.length * 25);
      communityReason = `Identified ${suspiciousSocial.length} discussion threads with community scam keywords.`;
      highRiskFlags.push("Community scam warnings detected");
    }

    factors.push({
      name: "Community & Social Signals",
      weight: this.WEIGHTS.COMMUNITY_SIGNALS,
      score: communityScore,
      contribution: Number((communityScore * this.WEIGHTS.COMMUNITY_SIGNALS).toFixed(2)),
      reason: communityReason,
    });

    // Calculate Composite Risk Score (0 - 100)
    let compositeRiskScore = factors.reduce((sum, f) => sum + f.contribution, 0);

    // Hard floor override: If a threat intel blacklist confirms the domain, risk must be >= 90
    if (verifiedThreat) {
      compositeRiskScore = Math.max(90, compositeRiskScore);
    }
    compositeRiskScore = Number(Math.min(100, Math.max(0, compositeRiskScore)).toFixed(2));

    // Calculate Confidence Score based on source coverage
    let confidenceScore = 30; // Baseline
    if (intelItems.length > 0) confidenceScore += 30;
    if (params.geminiResult && params.geminiResult.confidenceScore > 0) confidenceScore += 25;
    if (communityItems.length > 0) confidenceScore += 15;
    confidenceScore = Math.min(100, confidenceScore);

    // Determine Final Verdict
    let verdict: FinalVerdict = "clean";
    if (compositeRiskScore >= 80) {
      verdict = highRiskFlags.some((f) => f.toLowerCase().includes("phish")) ? "phishing" : "malicious";
    } else if (compositeRiskScore >= 45) {
      verdict = "suspicious";
    } else if (confidenceScore < 40) {
      verdict = "unverified";
    }

    // Build synthesized executive summary
    const summary = `Investigation completed with risk score ${compositeRiskScore}/100 and ${confidenceScore}% confidence. Verdict: ${verdict.toUpperCase()}. ${intelReason} ${aiReason}`;

    return {
      compositeRiskScore,
      confidenceScore,
      verdict,
      summary,
      factors,
      highRiskFlags,
    };
  }
}

export const riskScoringEngine = new RiskScoringEngine();
export default riskScoringEngine;