import { ExclusionRulesRepository } from "./repositories";
import { urlSafetyEngine, type UrlSafetyAnalysis } from "./url-safety";
import { logger } from "./utils/logger";

export interface DetectionSignal {
  type: "lookalike_domain" | "high_entropy" | "phishing_keywords" | "ip_host" | "brand_impersonation";
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  score: number;
}

export interface DetectionEvaluationResult {
  target: string;
  isExcluded: boolean;
  exclusionReason: string | null;
  safetyAnalysis: UrlSafetyAnalysis;
  signals: DetectionSignal[];
  compositeRiskScore: number;
  detectedAt: string;
}

export class ThreatDetectionEngine {
  /**
   * Evaluates a target URL against heuristic engines and exclusion criteria.
   */
  async evaluateTarget(targetUrl: string): Promise<DetectionEvaluationResult> {
    logger.info("[detection] Evaluating target for threats and lookalike indicators", { targetUrl });

    // 1. Check against active exclusion rules
    const exclusionRules = await ExclusionRulesRepository.listActive();
    const matchedRule = exclusionRules.find((rule) => {
      try {
        const regex = new RegExp(rule.pattern, "i");
        return regex.test(targetUrl);
      } catch {
        return targetUrl.toLowerCase().includes(rule.pattern.toLowerCase());
      }
    });

    const safetyAnalysis = urlSafetyEngine.analyzeUrl(targetUrl);

    if (matchedRule) {
      logger.info("[detection] Target matched exclusion rule", {
        targetUrl,
        pattern: matchedRule.pattern,
      });

      return {
        target: targetUrl,
        isExcluded: true,
        exclusionReason: matchedRule.reason ?? "Matched active exclusion rule",
        safetyAnalysis,
        signals: [],
        compositeRiskScore: 0,
        detectedAt: new Date().toISOString(),
      };
    }

    // 2. Aggregate security signals
    const signals: DetectionSignal[] = [];

    if (safetyAnalysis.hasIpAddressHost) {
      signals.push({
        type: "ip_host",
        severity: "high",
        description: "Target URL utilizes a direct IP address rather than a verified domain name.",
        score: 35,
      });
    }

    if (safetyAnalysis.isHighEntropy) {
      signals.push({
        type: "high_entropy",
        severity: "medium",
        description: `Domain label exhibits high algorithmic entropy (${safetyAnalysis.entropy}), indicating potential DGA generation.`,
        score: 25,
      });
    }

    if (safetyAnalysis.suspiciousKeywordsFound.length > 0) {
      signals.push({
        type: "phishing_keywords",
        severity: "high",
        description: `Target contains high-risk phishing/authentication keywords: ${safetyAnalysis.suspiciousKeywordsFound.join(", ")}`,
        score: Math.min(40, safetyAnalysis.suspiciousKeywordsFound.length * 15),
      });
    }

    if (!safetyAnalysis.isHttps) {
      signals.push({
        type: "lookalike_domain",
        severity: "medium",
        description: "Insecure HTTP transport utilized for target hostname.",
        score: 20,
      });
    }

    // Calculate weighted risk total
    const totalSignalScore = signals.reduce((acc, curr) => acc + curr.score, 0);
    const compositeRiskScore = Math.min(100, Math.max(safetyAnalysis.riskScore, totalSignalScore));

    return {
      target: targetUrl,
      isExcluded: false,
      exclusionReason: null,
      safetyAnalysis,
      signals,
      compositeRiskScore,
      detectedAt: new Date().toISOString(),
    };
  }
}

export const threatDetectionEngine = new ThreatDetectionEngine();
export default threatDetectionEngine;