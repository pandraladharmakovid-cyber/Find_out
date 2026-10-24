import React, { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ExternalLink,
  FileSearch,
  Gauge,
  Globe,
  Info,
  Loader2,
  Search,
  ShieldAlert,
  ShieldQuestion,
} from 'lucide-react';

import { apiRequest } from './api';
import type { Translator } from './i18n';

/**
 * Investigations.
 *
 * The screen leads with one number — the overall risk score — because that is
 * the only thing an analyst should have to read first. Below it, every point of
 * that score is broken into its contributing factors, and every piece of
 * evidence is rendered as a plain-English sentence with its source and status.
 * The raw JSON is still available, but only for engineers, behind a disclosure
 * that is closed by default.
 */

type EvidenceStatement = {
  id: string;
  title: string;
  statement: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source: string;
  status: 'verified' | 'observed' | 'not_found' | 'unavailable' | 'not_configured' | 'informational';
};

type RiskFactor = {
  name: string;
  code: string;
  weight: number;
  score: number;
  contribution: number;
  reason: string;
  detail: string;
  available: boolean;
};

type BrandImpersonation = {
  evaluated: boolean;
  score: number;
  verdict: string;
  hostname: string;
  summary: string;
  signals?: Array<{ code: string; label: string; detail: string; points: number }>;
};

type InvestigationResult = {
  id?: string;
  target?: string;
  verdict?: string;
  target_type?: string;
  overall_risk_score?: number;
  risk_score?: number;
  confidence_score?: number;
  summary?: string;
  safe_browsing_status?: string | null;
  urlhaus_status?: string | null;
  evidence_narrative?: EvidenceStatement[];
  risk_factors?: RiskFactor[];
  brand_impersonation?: BrandImpersonation | null;
  high_risk_flags?: string[];
  source_statuses?: Record<string, string>;
  details?: unknown;
};

type BrandOption = {
  id: string | number;
  name: string;
  primary_domain?: string | null;
};

type Props = {
  t: Translator;
  defaultTarget?: string;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The investigation failed.';
}

function isWebUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

type Tone = {
  text: string;
  border: string;
  bg: string;
  stroke: string;
  label: string;
};

function toneForScore(score: number): Tone {
  if (score >= 80) {
    return {
      text: 'text-rose-300',
      border: 'border-rose-500/40',
      bg: 'bg-rose-500/10',
      stroke: '#fb7185',
      label: 'Critical',
    };
  }
  if (score >= 60) {
    return {
      text: 'text-orange-300',
      border: 'border-orange-500/40',
      bg: 'bg-orange-500/10',
      stroke: '#fb923c',
      label: 'High',
    };
  }
  if (score >= 35) {
    return {
      text: 'text-amber-300',
      border: 'border-amber-500/40',
      bg: 'bg-amber-500/10',
      stroke: '#fbbf24',
      label: 'Medium',
    };
  }
  if (score > 0) {
    return {
      text: 'text-emerald-300',
      border: 'border-emerald-500/40',
      bg: 'bg-emerald-500/10',
      stroke: '#34d399',
      label: 'Low',
    };
  }
  return {
    text: 'text-slate-300',
    border: 'border-slate-700',
    bg: 'bg-slate-800/60',
    stroke: '#64748b',
    label: 'No evidence',
  };
}

function verdictTone(verdict?: string): Tone {
  switch ((verdict || '').toUpperCase()) {
    case 'PHISHING':
    case 'MALICIOUS':
      return toneForScore(95);
    case 'SUSPICIOUS':
      return toneForScore(60);
    case 'CLEAN':
    case 'SAFE':
      return toneForScore(10);
    default:
      return toneForScore(0);
  }
}

const SEVERITY_STYLES: Record<EvidenceStatement['severity'], string> = {
  critical: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
  high: 'border-orange-500/30 bg-orange-500/10 text-orange-200',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  low: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  info: 'border-slate-700 bg-slate-800/60 text-slate-300',
};

const STATUS_BADGES: Record<EvidenceStatement['status'], { label: string; className: string }> = {
  verified: { label: 'Confirmed by source', className: 'border-rose-500/30 bg-rose-500/10 text-rose-200' },
  observed: { label: 'Observed', className: 'border-blue-500/30 bg-blue-500/10 text-blue-200' },
  not_found: { label: 'No match', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' },
  unavailable: { label: 'Source unavailable', className: 'border-slate-600 bg-slate-800/70 text-slate-300' },
  not_configured: { label: 'Not configured', className: 'border-slate-600 bg-slate-800/70 text-slate-400' },
  informational: { label: 'Context', className: 'border-slate-700 bg-slate-800/50 text-slate-400' },
};

/** Semicircular 0–100 gauge. The number is the primary information. */
const RiskGauge: React.FC<{ score: number; label: string; sublabel: string }> = ({
  score,
  label,
  sublabel,
}) => {
  const clamped = Math.max(0, Math.min(100, score));
  const tone = toneForScore(clamped);
  const radius = 78;
  const circumference = Math.PI * radius;
  const filled = (clamped / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 200 116" className="w-full max-w-[260px]" role="img" aria-label={`Overall risk ${clamped} out of 100`}>
        <path
          d="M 22 100 A 78 78 0 0 1 178 100"
          fill="none"
          stroke="#1e293b"
          strokeWidth="16"
          strokeLinecap="round"
        />
        <path
          d="M 22 100 A 78 78 0 0 1 178 100"
          fill="none"
          stroke={tone.stroke}
          strokeWidth="16"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          style={{ transition: 'stroke-dasharray 700ms ease' }}
        />
        <text
          x="100"
          y="86"
          textAnchor="middle"
          className="fill-white"
          style={{ fontSize: 38, fontWeight: 700 }}
        >
          {Math.round(clamped)}
        </text>
        <text x="100" y="104" textAnchor="middle" fill="#94a3b8" style={{ fontSize: 11 }}>
          / 100
        </text>
      </svg>
      <p className={`-mt-1 text-sm font-semibold capitalize ${tone.text}`}>{label}</p>
      <p className="mt-0.5 text-xs text-slate-500">{sublabel}</p>
    </div>
  );
};

export const InvestigationsView: React.FC<Props> = ({ t, defaultTarget = '' }) => {
  const [input, setInput] = useState(defaultTarget);
  const [brandId, setBrandId] = useState('');
  const [brands, setBrands] = useState<BrandOption[]>([]);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (defaultTarget) setInput(defaultTarget);
  }, [defaultTarget]);

  useEffect(() => {
    let cancelled = false;
    apiRequest<any>('/brands')
      .then((response) => {
        if (cancelled) return;
        const rows = (response?.data ?? response) as BrandOption[];
        if (Array.isArray(rows)) setBrands(rows);
      })
      .catch(() => {
        if (!cancelled) setBrands([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = input.trim();

    if (!target) {
      setError('Enter a URL, domain or supported profile identifier.');
      return;
    }

    if (/^https?:\/\//i.test(target) && !isWebUrl(target)) {
      setError('Enter a valid HTTP or HTTPS URL.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await apiRequest<{ data?: InvestigationResult }>(
        '/investigations/inspect',
        {
          method: 'POST',
          body: JSON.stringify({ target, ...(brandId ? { brandId } : {}) }),
          timeoutMs: 60000,
        },
      );

      if (!response?.data || typeof response.data !== 'object') {
        throw new Error('The investigation API returned no valid result.');
      }

      setResult(response.data);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const overallScore = useMemo(() => {
    if (!result) return 0;
    if (typeof result.overall_risk_score === 'number') return result.overall_risk_score;
    if (typeof result.risk_score === 'number') return result.risk_score;
    return 0;
  }, [result]);

  const factors = result?.risk_factors ?? [];
  const narrative = result?.evidence_narrative ?? [];
  const impersonation = result?.brand_impersonation ?? null;
  const vTone = verdictTone(result?.verdict);

  return (
    <main className="page-enter space-y-6">
      <header className="border-b border-slate-800 pb-5">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
          Threat investigation
        </p>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
          <Search className="text-cyan-400" />
          {t('investigations.title')}
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
          {t('investigations.subtitle')}
        </p>
      </header>

      <form onSubmit={submit} className="surface-card space-y-4 p-4 sm:p-6">
        <label className="block space-y-2 text-sm font-medium text-slate-300" htmlFor="investigation-target">
          URL, domain or supported account identifier
          <input
            id="investigation-target"
            className="w-full"
            value={input}
            onChange={event => setInput(event.target.value)}
            placeholder={t('investigations.inputPlaceholder')}
            autoComplete="off"
            maxLength={2048}
            required
          />
        </label>

        <label className="block space-y-2 text-sm font-medium text-slate-300" htmlFor="investigation-brand">
          Compare against a protected brand <span className="font-normal text-slate-500">(recommended)</span>
          <select
            id="investigation-brand"
            className="w-full"
            value={brandId}
            onChange={event => setBrandId(event.target.value)}
          >
            <option value="">No brand — generic URL checks only</option>
            {brands.map((brand) => (
              <option key={String(brand.id)} value={String(brand.id)}>
                {brand.name}
                {brand.primary_domain ? ` · ${brand.primary_domain}` : ''}
              </option>
            ))}
          </select>
        </label>
        {brands.length === 0 && (
          <p className="text-xs text-slate-500">
            No brand profiles exist yet, so hostname-resemblance scoring will be skipped
            and reported as skipped — not guessed.
          </p>
        )}

        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <p className="text-xs leading-5 text-slate-500">
            Only submit targets you are authorized to investigate. Unavailable sources are
            reported as unknown, never as safe.
          </p>
          <button type="submit" disabled={loading || !input.trim()} className="btn-primary shrink-0">
            {loading ? <><span className="status-dot is-scanning" /> Inspecting…</> : <>{t('investigations.scanBtn')} <ArrowRight size={15} /></>}
          </button>
        </div>
      </form>

      {error && (
        <div role="alert" className="flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold">Investigation unsuccessful</p>
            <p className="mt-1 break-words">{error}</p>
            <p className="mt-2 text-rose-200/75">No verdict has been inferred from a failed request.</p>
          </div>
        </div>
      )}

      {loading && !result && (
        <div className="surface-card flex items-center gap-3 p-6 text-sm text-slate-400">
          <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
          Running hostname analysis, reputation checks and risk scoring…
        </div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Overall risk — the headline number */}
          <section className={`surface-card overflow-hidden border ${vTone.border}`}>
            <div className="grid gap-5 p-4 sm:p-6 lg:grid-cols-[minmax(240px,300px)_minmax(0,1fr)]">
              <div className={`rounded-2xl border ${vTone.border} ${vTone.bg} p-4`}>
                <RiskGauge
                  score={overallScore}
                  label={`${vTone.label} risk`}
                  sublabel={
                    typeof result.confidence_score === 'number'
                      ? `${Math.round(result.confidence_score)}% confidence`
                      : 'confidence not reported'
                  }
                />
                <div className="mt-3 flex justify-center">
                  <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold ${vTone.border} ${vTone.bg} ${vTone.text}`}>
                    {['SAFE', 'CLEAN'].includes((result.verdict || '').toUpperCase()) ? (
                      <CheckCircle2 size={14} />
                    ) : result.verdict?.toUpperCase() === 'UNVERIFIED' ? (
                      <ShieldQuestion size={14} />
                    ) : (
                      <ShieldAlert size={14} />
                    )}
                    {result.verdict || 'Verdict not supplied'}
                  </span>
                </div>
              </div>

              <div className="min-w-0 space-y-4">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Inspected target
                  </p>
                  <p className="mt-1.5 break-all font-mono text-base font-semibold text-white">
                    {result.target || input.trim()}
                  </p>
                  <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                    <span>Target type: {result.target_type || 'Not specified'}</span>
                    {isWebUrl(result.target || input.trim()) && (
                      <a
                        href={result.target || input.trim()}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-300 hover:underline"
                      >
                        Open target <ExternalLink size={12} />
                      </a>
                    )}
                  </div>
                </div>

                {result.summary && (
                  <p className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-sm leading-6 text-slate-300">
                    {result.summary}
                  </p>
                )}

                {impersonation?.evaluated && (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="flex items-center gap-2 text-sm font-medium text-slate-200">
                        <Gauge size={15} className="text-cyan-400" />
                        Brand resemblance
                      </p>
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[impersonation.score >= 75 ? 'critical' : impersonation.score >= 50 ? 'high' : impersonation.score > 0 ? 'medium' : 'low']}`}>
                        {impersonation.score}/100 · {impersonation.verdict}
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-400">{impersonation.summary}</p>
                  </div>
                )}

                <div className="grid gap-3 sm:grid-cols-3">
                  {[
                    { label: 'Google Safe Browsing', value: result.safe_browsing_status },
                    { label: 'URLhaus', value: result.urlhaus_status },
                    {
                      label: 'Evidence statements',
                      value: narrative.length ? `${narrative.length} recorded` : 'none recorded',
                    },
                  ].map(({ label, value }) => (
                    <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3" key={label}>
                      <div className="flex items-center gap-1.5 text-xs text-slate-400">
                        <Globe size={13} className="text-cyan-400" /> {label}
                      </div>
                      <p className="mt-2 break-words text-sm font-medium text-slate-200">
                        {value == null || value === '' ? 'No status supplied' : value}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* Why the score is what it is */}
          {factors.length > 0 && (
            <section className="surface-card p-4 sm:p-6">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
                <Gauge className="h-5 w-5 text-cyan-400 focus:outline-none" />
                {t('investigations.factorsTitle')}
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Each factor contributes to the overall score. Factors whose source could not be
                read are shown as unavailable and add nothing — they are never treated as clean.
              </p>

              <div className="mt-4 space-y-3">
                {factors.map((factor) => {
                  const tone = factor.available ? toneForScore(factor.score) : toneForScore(0);
                  return (
                    <div
                      key={factor.code}
                      className={`rounded-xl border p-3 ${
                        factor.available ? 'border-slate-800 bg-slate-950/50' : 'border-slate-800/60 bg-slate-950/30'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className={`text-sm font-medium ${factor.available ? 'text-slate-200' : 'text-slate-500'}`}>
                          {factor.name}
                        </p>
                        <div className="flex items-center gap-2 text-xs">
                          {factor.available ? (
                            <span className="font-mono text-slate-400">
                              {Math.round(factor.score)}/100
                              {factor.contribution > 0 && (
                                <span className="text-slate-600"> (+{factor.contribution})</span>
                              )}
                            </span>
                          ) : (
                            <span className="rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-400">
                              {t('investigations.factorUnavailable')}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${factor.available ? Math.max(2, Math.min(100, factor.score)) : 0}%`,
                            backgroundColor: factor.available ? tone.stroke : 'transparent',
                          }}
                        />
                      </div>

                      <p className="mt-2 text-xs leading-5 text-slate-400">{factor.reason}</p>
                      {factor.detail && factor.detail !== factor.reason && (
                        <p className="mt-1 text-xs leading-5 text-slate-500">{factor.detail}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* Evidence in plain English */}
          <section className="surface-card p-4 sm:p-6">
            <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
              <FileSearch className="h-5 w-5 text-cyan-400" />
              {t('investigations.evidenceTitle')}
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              {t('investigations.evidenceHint')}
            </p>

            {narrative.length === 0 ? (
              <div className="mt-4 flex items-start gap-3 rounded-xl border border-dashed border-slate-700 p-4 text-sm text-slate-400">
                <Info size={16} className="mt-0.5 shrink-0 text-slate-500" />
                This investigation returned no evidence statements. That is not the same as
                “nothing found” — treat the target as unverified.
              </div>
            ) : (
              <ul className="mt-4 space-y-2">
                {narrative.map((statement) => {
                  const badge = STATUS_BADGES[statement.status] ?? STATUS_BADGES.observed;
                  return (
                    <li
                      key={statement.id}
                      className={`rounded-xl border p-3 ${SEVERITY_STYLES[statement.severity]}`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-semibold">{statement.title}</p>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="rounded-full border border-slate-700/60 bg-slate-900/60 px-2 py-0.5 text-[10px] font-medium text-slate-300">
                            {statement.source}
                          </span>
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${badge.className}`}>
                            {badge.label}
                          </span>
                        </div>
                      </div>
                      <p className="mt-1.5 text-sm leading-6 text-slate-200/90">{statement.statement}</p>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          {/* Engineer view — collapsed, clearly labelled */}
          {result.details !== undefined && result.details !== null && (
            <details className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <summary className="flex cursor-pointer items-center gap-2 text-sm font-medium text-slate-400">
                <ChevronDown size={15} />
                {t('investigations.rawTitle')}
              </summary>
              <p className="mt-2 text-xs text-slate-500">
                Machine-readable payload for debugging only. Analysts should use the statements
                above.
              </p>
              <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-950 p-3 text-[11px] leading-5 text-slate-400">
                {JSON.stringify(result.details, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </main>
  );
};

export default InvestigationsView;
