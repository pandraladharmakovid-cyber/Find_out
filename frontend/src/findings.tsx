
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, CheckCircle2, ExternalLink, FileText, RefreshCw,
  Search, ShieldAlert,
} from 'lucide-react';
import { apiRequest } from './api';

type Finding = {
  id: string;
  name?: string;
  platform?: string;
  source_type?: string;
  url?: string;
  publisher?: string;
  risk_score?: number;
  is_official_excluded?: boolean;
  evidence?: {
    name_similarity?: number;
    logo_similarity?: number;
    publisher_mismatch?: boolean;
    lookalike_technique?: string;
  };
};

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to load findings.';
}

function safeLink(value?: string): boolean {
  try {
    if (!value) return false;
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function percent(value?: number): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'Not assessed';
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

export const FindingsView: React.FC = () => {
  const [items, setItems] = useState<Finding[]>([]);
  const [filter, setFilter] = useState<'all' | 'flagged' | 'excluded'>('all');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');

    try {
      const response = await apiRequest<{ data?: Finding[] }>('/monitoring/candidates');
      if (!Array.isArray(response?.data)) {
        throw new Error('The findings API returned an unexpected response.');
      }
      setItems(response.data);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => items.filter((item) => {
    const isExcluded = Boolean(item.is_official_excluded);
    const matchesFilter =
      filter === 'all' ||
      (filter === 'excluded' && isExcluded) ||
      (filter === 'flagged' && !isExcluded);

    const search = `${item.name || ''} ${item.platform || ''} ${item.source_type || ''} ${item.publisher || ''} ${item.url || ''}`.toLowerCase();
    return matchesFilter && search.includes(query.trim().toLowerCase());
  }), [items, filter, query]);

  return (
    <main className="page-enter space-y-6">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-center">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            Evidence ledger
          </p>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
            <FileText className="text-cyan-400" /> Findings & Evidence
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Review monitoring candidates, evidence indicators and official-asset exclusions.
            A risk score is an indicator, not proof of malicious intent.
          </p>
        </div>
        <button type="button" onClick={() => void load()} disabled={loading} className="btn-secondary">
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </header>

      {error && (
        <div role="alert" className="flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <AlertTriangle className="shrink-0" size={18} />
          <div>
            <p className="font-semibold">Findings could not be loaded</p>
            <p className="mt-1 break-words">{error}</p>
            <button className="btn-secondary mt-3" onClick={() => void load()} type="button">Retry</button>
          </div>
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-3">
        {[
          { label: 'Total candidates', value: items.length },
          { label: 'Potential findings', value: items.filter(item => !item.is_official_excluded).length },
          { label: 'Official exclusions', value: items.filter(item => item.is_official_excluded).length },
        ].map(metric => (
          <div className="surface-card p-4" key={metric.label}>
            <p className="text-sm text-slate-400">{metric.label}</p>
            <p className="mt-2 text-3xl font-bold tabular-nums text-white">{loading ? '—' : metric.value}</p>
          </div>
        ))}
      </section>

      <section className="surface-card space-y-4 p-4 sm:p-5">
        <div className="flex flex-col gap-3 lg:flex-row">
          <label className="relative flex-1">
            <Search size={16} className="absolute left-3 top-3 text-slate-500" />
            <input
              className="w-full pl-9"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="Search candidates, platforms, publishers…"
              aria-label="Search findings"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            {[
              { id: 'all', label: 'All' },
              { id: 'flagged', label: 'Potential findings' },
              { id: 'excluded', label: 'Official exclusions' },
            ].map(option => (
              <button
                key={option.id}
                type="button"
                aria-pressed={filter === option.id}
                onClick={() => setFilter(option.id as typeof filter)}
                className={filter === option.id ? 'btn-primary' : 'btn-secondary'}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="space-y-3" aria-live="polite">
            {[1, 2, 3].map(n => <div className="skeleton h-28 w-full" key={n} />)}
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 px-5 py-12 text-center">
            {error ? <AlertTriangle className="mx-auto mb-3 text-rose-300" size={28} /> : <ShieldAlert className="mx-auto mb-3 text-slate-500" size={28} />}
            <p className="font-semibold text-slate-200">
              {items.length ? 'No findings match your filters' : 'No findings returned'}
            </p>
            <p className="mt-2 text-sm text-slate-400">
              {items.length ? 'Change the filter or search query.' : 'Run monitoring to retrieve candidates from the configured sources.'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map(item => {
              const excluded = Boolean(item.is_official_excluded);
              const score = typeof item.risk_score === 'number' ? item.risk_score : null;

              return (
                <article className="surface-card stagger-item p-4 sm:p-5" key={item.id}>
                  <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                    <div className="min-w-0">
                      <h2 className="break-words font-semibold text-white">{item.name || 'Unnamed candidate'}</h2>
                      <p className="mt-1 text-xs text-slate-400">
                        {item.platform || 'Unknown platform'} · {item.source_type || 'Unknown source'}
                        {item.publisher ? ` · Publisher: ${item.publisher}` : ''}
                      </p>
                      {safeLink(item.url) && (
                        <a
                          className="mt-2 inline-flex max-w-full items-center gap-1 break-all text-xs text-blue-300 hover:underline"
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          View source <ExternalLink size={12} />
                        </a>
                      )}
                    </div>
                    <span className={excluded ? 'risk-low rounded-full border px-3 py-1 text-xs' : score !== null && score >= 70 ? 'risk-high rounded-full border px-3 py-1 text-xs' : 'risk-medium rounded-full border px-3 py-1 text-xs'}>
                      {excluded ? <><CheckCircle2 className="mr-1 inline" size={13} />Official asset excluded</> : score === null ? 'Risk not assessed' : `Risk ${score}/100`}
                    </span>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-800 pt-3 sm:grid-cols-4">
                    {[
                      ['Name similarity', percent(item.evidence?.name_similarity)],
                      ['Logo similarity', percent(item.evidence?.logo_similarity)],
                      ['Publisher mismatch', item.evidence?.publisher_mismatch === undefined ? 'Not assessed' : item.evidence.publisher_mismatch ? 'Mismatch' : 'No mismatch detected'],
                      ['Look-alike technique', item.evidence?.lookalike_technique || 'Not recorded'],
                    ].map(([label, value]) => (
                      <div className="rounded-lg bg-slate-950/50 p-3" key={label}>
                        <p className="text-xs text-slate-500">{label}</p>
                        <p className="mt-1 break-words text-sm text-slate-200">{value}</p>
                      </div>
                    ))}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </main>
  );
};
