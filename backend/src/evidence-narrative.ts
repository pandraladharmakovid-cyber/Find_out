import type { NormalizedEvidenceItem } from "./evidence";
import type { BrandImpersonationResult } from "./brand-impersonation.service";
import type { RiskFactor } from "./risk";

/**
 * Turns the raw evidence ledger into sentences an analyst can read.
 *
 * The Investigations screen used to dump `JSON.stringify(details, null, 2)`,
 * which is unreadable during a demo and hides the reasoning. Every statement
 * here is derived from stored evidence — nothing is invented — and carries an
 * explicit status so "we could not check" can never be mistaken for "safe".
 */

export type NarrativeStatus =
  | "verified"
  | "observed"
  | "not_found"
  | "unavailable"
  | "not_configured"
  | "informational";

export interface EvidenceStatement {
  id: string;
  title: string;
  statement: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  status: NarrativeStatus;
}

export interface NarrativeInput {
  targetUrl: string;
  brandName?: string | null;
  brandImpersonation?: BrandImpersonationResult | null;
  evidenceItems?: NormalizedEvidenceItem[];
  factors?: RiskFactor[];
  sourceStatuses?: Record<string, string>;
}

function severityFromScore(score: number): EvidenceStatement["severity"] {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  if (score > 0) return "low";
  return "info";
}

function hostOf(targetUrl: string): string {
  try {
    return new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`).hostname;
  } catch {
    return targetUrl;
  }
}

const SOURCE_LABELS: Record<string, string> = {
  urlhaus: "URLhaus",
  safebrowsing: "Google Safe Browsing",
  gemini: "AI page assessment",
  bluesky: "Bluesky",
  youtube: "YouTube",
  reddit: "Reddit",
  app_store: "App store",
  manual: "Analyst note",
};

export function buildEvidenceNarrative(input: NarrativeInput): EvidenceStatement[] {
  const statements: EvidenceStatement[] = [];
  const host = hostOf(input.targetUrl);
  const brand = (input.brandName ?? "").trim();

  // -------------------------------------------------------------------
  // 1. What the target looks like
  // -------------------------------------------------------------------
  statements.push({
    id: "target-observed",
    title: "Target inspected",
    statement: `The platform inspected ${host}${brand ? ` as a possible imitation of ${brand}` : ""}. Every statement below is derived from what this scan actually observed.`,
    severity: "info",
    source: "Find_out",
    status: "informational",
  });

  const impersonation = input.brandImpersonation;
  if (impersonation?.evaluated) {
    if (impersonation.score === 0) {
      statements.push({
        id: "brand-match-none",
        title: "No brand imitation found",
        statement: `The hostname "${impersonation.hostname}" does not resemble "${brand}" and contains no deceptive pattern. A different hostname is not proof of impersonation, but this one is not impersonating the brand by name.`,
        severity: "info",
        source: "Hostname analysis",
        status: "observed",
      });
    } else {
      for (const [index, signal] of impersonation.signals.entries()) {
        statements.push({
          id: `brand-signal-${index}`,
          title: signal.label,
          statement: signal.detail,
          severity: severityFromScore(signal.points * 1.6),
          source: "Hostname analysis",
          status: "observed",
        });
      }

      if (impersonation.verdict === "impersonation") {
        statements.push({
          id: "brand-verdict",
          title: "Impersonation pattern",
          statement: `Taken together, the hostname imitates ${brand}: it scores ${impersonation.score}/100 on brand resemblance. This is a strong indicator of impersonation, though the operator behind the site is not identified by this scan.`,
          severity: "critical",
          source: "Hostname analysis",
          status: "observed",
        });
      }
    }
  } else if (!brand) {
    statements.push({
      id: "brand-not-supplied",
      title: "No brand supplied",
      statement:
        "No brand was selected for this investigation, so the hostname could not be compared against a known brand. Brand-resemblance scoring was skipped rather than guessed.",
      severity: "info",
      source: "Hostname analysis",
      status: "informational",
    });
  }

  // -------------------------------------------------------------------
  // 2. Third-party reputation
  // -------------------------------------------------------------------
  const items = input.evidenceItems ?? [];
  const reputationSources = ["safebrowsing", "urlhaus"];

  for (const source of reputationSources) {
    const item = items.find((entry) => entry.source === source);
    const label = SOURCE_LABELS[source] ?? source;
    const rawStatus = String(item?.rawPayload?.sourceStatus ?? "unknown");

    if (!item || rawStatus === "not_configured") {
      statements.push({
        id: `reputation-${source}`,
        title: `${label} was not queried`,
        statement: `${label} is not configured for this deployment, so no reputation lookup was performed. This says nothing about the target either way.`,
        severity: "info",
        source: label,
        status: "not_configured",
      });
      continue;
    }

    if (rawStatus === "unavailable" || item.rawPayload?.error) {
      statements.push({
        id: `reputation-${source}`,
        title: `${label} could not be reached`,
        statement: `${label} did not answer (${String(item.rawPayload?.error ?? item.extractedClaim ?? "no response")}). The target is unverified by this source, not cleared by it.`,
        severity: "info",
        source: label,
        status: "unavailable",
      });
      continue;
    }

    if (item.isVerified && item.reliabilityScore >= 70) {
      statements.push({
        id: `reputation-${source}`,
        title: `${label} reported a threat`,
        statement:
          item.extractedClaim ??
          `${label} reported this target as malicious with a reliability of ${item.reliabilityScore}%.`,
        severity: "critical",
        source: label,
        status: "verified",
      });
      continue;
    }

    statements.push({
      id: `reputation-${source}`,
      title: `${label} returned no match`,
      statement: `${label} was queried successfully and returned no threat match for ${host}. A clean result from one reputation source does not guarantee the site is safe.`,
      severity: "info",
      source: label,
      status: "not_found",
    });
  }

  // -------------------------------------------------------------------
  // 3. Model assessment
  // -------------------------------------------------------------------
  const gemini = items.find((entry) => entry.source === "gemini");
  const geminiStatus = String(gemini?.rawPayload?.sourceStatus ?? "unknown");

  if (!gemini || geminiStatus === "not_configured") {
    statements.push({
      id: "ai-not-configured",
      title: "AI page assessment unavailable",
      statement:
        "No model-based page assessment was produced (the Gemini key is not configured). The verdict therefore relies on hostname and reputation evidence only.",
      severity: "info",
      source: "AI page assessment",
      status: "not_configured",
    });
  } else if (geminiStatus === "unavailable") {
    statements.push({
      id: "ai-unavailable",
      title: "AI page assessment could not run",
      statement: `${gemini.extractedClaim ?? "The model call did not complete."} No AI-derived conclusion was used in the score.`,
      severity: "info",
      source: "AI page assessment",
      status: "unavailable",
    });
  } else if (gemini.extractedClaim) {
    statements.push({
      id: "ai-assessment",
      title: "AI page assessment",
      statement: gemini.extractedClaim,
      severity: severityFromScore(Number(gemini.rawPayload?.riskScore ?? 0)),
      source: "AI page assessment",
      status: gemini.isVerified ? "verified" : "observed",
    });
  }

  // -------------------------------------------------------------------
  // 4. Social discussion
  // -------------------------------------------------------------------
  const socialItems = items.filter((entry) =>
    ["bluesky", "youtube", "reddit"].includes(entry.source),
  );
  const socialWarnings = socialItems.filter(
    (entry) => entry.rawPayload?.relevantToTarget === true,
  );

  if (socialItems.length === 0) {
    statements.push({
      id: "social-none",
      title: "No public discussion checked",
      statement:
        "Social sources were not queried for this target, so no community report was considered.",
      severity: "info",
      source: "Social monitoring",
      status: "not_configured",
    });
  } else if (socialWarnings.length === 0) {
    statements.push({
      id: "social-clear",
      title: "No public warning found",
      statement: `Public posts were searched and none referenced ${host}. Absence of discussion is normal for a new domain and is not evidence of safety.`,
      severity: "info",
      source: "Social monitoring",
      status: "not_found",
    });
  } else {
    statements.push({
      id: "social-warning",
      title: "Public posts reference this target",
      statement: `${socialWarnings.length} public post(s) mention ${host}. These are unverified user reports until an analyst confirms them.`,
      severity: "medium",
      source: "Social monitoring",
      status: "observed",
    });
  }

  // -------------------------------------------------------------------
  // 5. Explain the score itself
  // -------------------------------------------------------------------
  for (const factor of input.factors ?? []) {
    if (!factor.available) continue;
    if (factor.score <= 0) continue;
    statements.push({
      id: `factor-${factor.code}`,
      title: `${factor.name} contributed ${factor.contribution}`,
      statement: `${factor.reason} ${factor.detail}`.trim(),
      severity: severityFromScore(factor.score),
      source: factor.name,
      status: factor.score >= 80 ? "verified" : "observed",
    });
  }

  return statements;
}

export default buildEvidenceNarrative;
