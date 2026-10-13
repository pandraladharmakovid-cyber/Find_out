import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle2, ExternalLink,
  RefreshCw, Radar, Search, Share2, Smartphone, ShieldAlert,
} from 'lucide-react';
import { apiRequest } from './api';

type Brand = {
  id: string;
  name: string;
};

type CandidateEvidence = {
  name_similarity?: number | null;
  logo_similarity?: number | null;
  publisher_mismatch?: boolean;
  lookalike_technique?: string | null;
};

type SourceEvidence = {
  type: string;
  severity: string;
  details: Record<string, unknown>;
};

type Candidate = {
  id: string;
  name?: string;
  platform?: string;
  source_type?: string;
  url?: string;
  publisher?: string;
  risk_score?: number;
  is_official_excluded?: boolean;
  evidence?: CandidateEvidence;
  source_evidence?: SourceEvidence[];
};

type SourceStatus = {
  source: string;
  status: 'available' | 'unavailable' | 'not_configured';
  candidatesFound: number;
  error?: string;
};

type MonitoringResults = {
  candidates: Candidate[];
  run?: {
    summary?: {
      sourceStatuses?: SourceStatus[];
    };
  } | null;
};

type Props = {
  t: any;
  onDeepInspect?: (target: string) => void;
};

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'The request failed.';
}

function validHttpUrl(value?: string): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

function percentage(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'Not assessed';
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

export const MonitoringView: React.FC<Props> = ({ t, onDeepInspect }) => {
  const [brands, setBrands] = useState<Brand[]>([]);
  const [brandId, setBrandId] = useState('');
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [sources, setSources] = useState<SourceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState<'all' | 'social' | 'app'>('all');
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const loadBrands = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: Brand[] }>('/brands');
      if (!Array.isArray(response?.data)) throw new Error('The brand API returned an unexpected response.');
      setBrands(response.data);
      setBrandId((current) =>
        current && response.data?.some((brand) => String(brand.id) === current)
          ? current
          : String(response.data?.[0]?.id ?? ''),
      );
    } catch (err) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadResults = useCallback(async () => {
    if (!brandId) {
      setCandidates([]);
      setSources([]);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: MonitoringResults }>(
        `/monitoring/results/${encodeURIComponent(brandId)}`,
      );
      if (!Array.isArray(response?.data?.candidates)) {
        throw new Error('The monitoring API returned an unexpected result.');
      }
      setCandidates(response.data.candidates);
      setSources(response.data.run?.summary?.sourceStatuses ?? []);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  }, [brandId]);

  useEffect(() => {
    void loadBrands();
  }, [loadBrands]);

  useEffect(() => {
    if (brandId) void loadResults();
    else if (!loading) {
      setCandidates([]);
      setSources([]);
    }
  }, [brandId, loadResults]);

  const runScan = async () => {
    if (!brandId) {
      setError('Register a brand profile before starting monitoring.');
      return;
    }
    setScanning(true);
    setError('');
    setNotice('');
    try {
      const response = await apiRequest<{
        data?: { sourceStatuses?: SourceStatus[]; candidatesFound?: number; excludedOfficialAssets?: number };
      }>('/monitoring/scan', {
        method: 'POST',
        body: JSON.stringify({ brandId }),
      });
      if (!response?.data) throw new Error('The server did not return a monitoring run.');
      setSources(response.data.sourceStatuses ?? []);
      await loadResults();
      setNotice(
        `Run complete: ${response.data.candidatesFound ?? 0} source result(s), ` +
        `${response.data.excludedOfficialAssets ?? 0} official asset exclusion(s).`,
      );
    } catch (err) {
      setError(`Monitoring did not complete: ${errorText(err)}`);
    } finally {
      setScanning(false);
    }
  };

  const filtered = candidates.filter((item) => {
    const source = (item.source_type || '').toLowerCase();
    const matchesType =
      filter === 'all' ||
      (filter === 'social' && source === 'social') ||
      (filter === 'app' && ['app_store', 'app', 'mobile_app'].includes(source));
    const searchText = `${item.name || ''} ${item.platform || ''} ${item.publisher || ''} ${item.url || ''}`.toLowerCase();
    return matchesType && searchText.includes(query.toLowerCase().trim());
  });

  const monitoring = t?.monitoring || {};

  return (
    <main className="page-enter space-y-6">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-center">
        <div>
          <p className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            <Activity size={14} /> External exposure
          </p>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
            <Radar className={scanning ? 'animate-spin text-cyan-400' : 'text-cyan-400'} />
            {monitoring.title || 'Social & App Monitoring'}
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Run evidence-based searches against configured public sources. A match is a lead for review, not proof of abuse.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <label className="sr-only" htmlFor="monitor-brand">Brand profile</label>
          <select
            id="monitor-brand"
            value={brandId}
            onChange={(event) => setBrandId(event.target.value)}
            disabled={loading || brands.length === 0}
            className="min-w-48 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
          >
            {brands.length === 0
              ? <option value="">Register a brand first</option>
              : brands.map((brand) => <option key={brand.id} value={brand.id}>{brand.name}</option>)}
          </select>
          <button
            type="button"
            onClick={() => void loadResults()}
            disabled={loading || scanning || !brandId}
            className="btn-secondary"
          >
            <RefreshCw size={15} /> Refresh
          </button>
          <button
            type="button"
            onClick={() => void runScan()}
            disabled={scanning || loading || !brandId}
            className="btn-primary"
          >
            <Radar size={16} className={scanning ? 'animate-pulse' : ''} />
            {scanning ? (monitoring.scanning || 'Scanning…') : (monitoring.scanBtn || 'Start monitoring')}
          </button>
        </div>
      </header>

      {error && (
        <div role="alert" className="flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <AlertTriangle className="mt-0.5 shrink-0" size={18} />
          <div>
            <p className="font-semibold">Monitoring unavailable</p>
            <p className="mt-1 break-words">{error}</p>
            <p className="mt-2 text-rose-200/75">No new detection is claimed until the request succeeds.</p>
          </div>
        </div>
      )}

      {notice && (
        <div role="status" className="rounded-xl border border-emerald-400/25 bg-emerald-400/10 p-3 text-sm text-emerald-200">
          {notice}
        </div>
      )}

      {sources.length > 0 && (
        <section aria-label="Source availability" className="grid gap-3 sm:grid-cols-3">
          {sources.map((source) => (
            <article key={source.source} className="surface-card p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="font-medium capitalize text-slate-200">{source.source.replaceAll('_', ' ')}</p>
                <span className={`rounded-full px-2.5 py-1 text-xs ${source.status === 'available' ? 'risk-low' : 'risk-medium'}`}>
                  {source.status.replaceAll('_', ' ')}
                </span>
              </div>
              <p className="mt-2 text-sm text-slate-400">{source.candidatesFound} result(s)</p>
              {source.error && <p className="mt-2 break-words text-xs text-amber-300">{source.error}</p>}
            </article>
          ))}
        </section>
      )}

      <section className="grid gap-3 sm:grid-cols-3">
        {[
          { label: 'Returned candidates', value: candidates.length, icon: Search },
          { label: 'Potential findings', value: candidates.filter((item) => !item.is_official_excluded).length, icon: ShieldAlert },
          { label: 'Official exclusions', value: candidates.filter((item) => item.is_official_excluded).length, icon: CheckCircle2 },
        ].map((metric) => (
          <div key={metric.label} className="surface-card p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-400">{metric.label}</span>
              <metric.icon size={18} className="text-cyan-400" />
            </div>
            <p className="mt-3 text-3xl font-bold tabular-nums text-white">{loading ? '—' : metric.value}</p>
          </div>
        ))}
      </section>

      <section className="surface-card space-y-4 p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row">
          <label className="relative flex-1">
            <Search size={16} className="absolute left-3 top-3 text-slate-500" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search name, platform, publisher or URL"
              className="w-full pl-9"
              aria-label="Search monitoring candidates"
            />
          </label>
          <div className="flex flex-wrap gap-2" aria-label="Filter source type">
            {[
              { id: 'all', label: 'All sources' },
              { id: 'social', label: 'Social media' },
              { id: 'app', label: 'App stores' },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setFilter(item.id as typeof filter)}
                aria-pressed={filter === item.id}
                className={filter === item.id ? 'btn-primary' : 'btn-secondary'}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="space-y-3" aria-live="polite">
            {[1, 2, 3].map((n) => <div key={n} className="skeleton h-24 w-full" />)}
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 px-5 py-12 text-center">
            <Radar className="mx-auto mb-3 text-slate-500" size={28} />
            <p className="font-semibold text-slate-200">
              {candidates.length ? 'No candidates match these filters' : 'No monitoring candidates returned'}
            </p>
            <p className="mx-auto mt-2 max-w-lg text-sm text-slate-400">
              {candidates.length
                ? 'Try another filter or search term.'
                : 'Start a scan after registering a brand and its official assets. Restricted or unconfigured sources are reported above.'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map((candidate) => {
              const excluded = Boolean(candidate.is_official_excluded);
              const risk = typeof candidate.risk_score === 'number' ? candidate.risk_score : null;
              return (
                <article key={candidate.id} className="surface-card stagger-item p-4 sm:p-5">
                  <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                    <div className="flex min-w-0 gap-3">
                      <div className="rounded-xl border border-slate-700 bg-slate-800/70 p-3">
                        {candidate.source_type === 'app_store'
                          ? <Smartphone size={20} className="text-violet-300" />
                          : <Share2 size={20} className="text-cyan-300" />}
                      </div>
                      <div className="min-w-0">
                        <h2 className="break-words font-semibold text-white">{candidate.name || 'Unnamed candidate'}</h2>
                        <p className="mt-1 text-xs text-slate-400">
                          {candidate.platform || 'Unknown platform'} · {candidate.source_type || 'Unknown source'}
                          {candidate.publisher ? ` · Publisher: ${candidate.publisher}` : ''}
                        </p>
                        {validHttpUrl(candidate.url) && (
                          <a
                            className="mt-2 inline-flex max-w-full items-center gap-1 break-all text-xs text-blue-300 hover:underline"
                            href={candidate.url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            Open source <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={excluded ? 'risk-low rounded-full border px-3 py-1 text-xs' : risk !== null && risk >= 70 ? 'risk-high rounded-full border px-3 py-1 text-xs' : 'risk-medium rounded-full border px-3 py-1 text-xs'}>
                        {excluded ? 'Official asset excluded' : risk === null ? 'Risk not assessed' : `Risk ${Math.round(risk)}/100`}
                      </span>
                      {onDeepInspect && (
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => onDeepInspect(candidate.url || candidate.name || '')}
                        >
                          Inspect <ArrowRight size={14} />
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-800 pt-3 sm:grid-cols-4">
                    {[
                      ['Name similarity', percentage(candidate.evidence?.name_similarity)],
                      ['Logo similarity', percentage(candidate.evidence?.logo_similarity)],
                      ['Publisher mismatch', candidate.evidence?.publisher_mismatch === undefined ? 'Not assessed' : candidate.evidence.publisher_mismatch ? 'Mismatch' : 'No mismatch detected'],
                      ['Look-alike technique', candidate.evidence?.lookalike_technique || 'Not recorded'],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg bg-slate-950/50 p-3">
                        <p className="text-xs text-slate-500">{label}</p>
                        <p className="mt-1 break-words text-sm font-medium text-slate-200">{value}</p>
                      </div>
                    ))}
                  </div>
                  {candidate.source_evidence && candidate.source_evidence.length > 0 && (
                    <details className="mt-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                      <summary className="cursor-pointer text-sm font-medium text-slate-300">Evidence and context</summary>
                      <ul className="mt-3 space-y-2 text-sm text-slate-400">
                        {candidate.source_evidence.map((item, index) => {
                          const detail = item.details.statement ?? item.details.reason ?? item.details.context;
                          return (
                            <li key={`${item.type}-${index}`}>
                              <span className="font-medium text-slate-300">{item.type.replaceAll('_', ' ')}:</span>{' '}
                              {typeof detail === 'string' ? detail : `Severity: ${item.severity.toLowerCase()}`}
                            </li>
                          );
                        })}
                      </ul>
                    </details>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
    </main>
  );
};
