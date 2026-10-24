import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Building2,
  Clock3,
  RefreshCw,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Target,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { apiRequest } from './api';
import { AgentChat } from './agent-chat';
import { BrandLogo } from './brand-logo';
import type { Translator } from './i18n';

type Candidate = {
  id?: string | number;
  name?: string;
  title?: string;
  platform?: string;
  source?: string;
  url?: string;
  candidate_url?: string;
  risk_level?: string;
  risk_score?: number;
  status?: string;
  created_at?: string;
};

type Brand = {
  id: string | number;
  name: string;
  website?: string | null;
  primary_domain?: string | null;
  logo_url?: string | null;
  logo_image_url?: string | null;
  assets?: unknown[];
  official_assets?: unknown[];
};

type DashboardViewProps = {
  t: Translator;
  setActiveTab: (tab: string) => void;
};

type LoadState = {
  loading: boolean;
  error: string;
};

function unwrap<T>(response: any): T {
  return (response?.data ?? response) as T;
}

function countAssets(brands: Brand[]): number {
  return brands.reduce((total, brand) => {
    const assets = brand.assets ?? brand.official_assets ?? [];
    return total + (Array.isArray(assets) ? assets.length : 0);
  }, 0);
}

function riskLabel(candidate: Candidate): string {
  if (candidate.risk_level) return candidate.risk_level.replace(/_/g, ' ');
  if (typeof candidate.risk_score === 'number') {
    if (candidate.risk_score >= 85) return 'critical';
    if (candidate.risk_score >= 65) return 'high';
    if (candidate.risk_score >= 35) return 'medium';
    return 'low';
  }
  return 'unclassified';
}

function riskClass(level: string): string {
  switch (level.toLowerCase()) {
    case 'critical':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300';
    case 'high':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
    case 'medium':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    case 'low':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    default:
      return 'border-slate-700 bg-slate-800/60 text-slate-300';
  }
}

function formatDate(value?: string): string {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Date unavailable';
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function MetricCard({
  title,
  value,
  description,
  icon: Icon,
  tone,
  loading,
  onClick,
}: {
  title: string;
  value: number | string;
  description: string;
  icon: React.ElementType;
  tone: string;
  loading: boolean;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className={`rounded-xl border p-3 ${tone}`}>
          <Icon className="h-5 w-5" />
        </div>
        {onClick && (
          <ArrowUpRight className="h-4 w-4 text-slate-500 transition group-hover:text-blue-300" />
        )}
      </div>
      <p className="mt-5 text-sm text-slate-400">{title}</p>
      {loading ? (
        <div className="skeleton mt-2 h-9 w-20 rounded-lg" />
      ) : (
        <p className="mt-1 text-3xl font-bold tracking-tight text-white">
          {value}
        </p>
      )}
      <p className="mt-2 text-xs leading-5 text-slate-500">{description}</p>
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="surface-card group w-full p-5 text-left transition duration-200 hover:-translate-y-0.5 hover:border-blue-500/40 hover:shadow-lg hover:shadow-blue-950/20"
      >
        {content}
      </button>
    );
  }

  return <div className="surface-card p-5">{content}</div>;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  t,
  setActiveTab,
}) => {
  const [brands, setBrands] = useState<Brand[]>([]);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [brandState, setBrandState] = useState<LoadState>({
    loading: true,
    error: '',
  });
  const [candidateState, setCandidateState] = useState<LoadState>({
    loading: true,
    error: '',
  });
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadDashboard = useCallback(async () => {
    setBrandState({ loading: true, error: '' });
    setCandidateState({ loading: true, error: '' });

    const [brandResult, candidateResult] = await Promise.allSettled([
      apiRequest('/brands'),
      apiRequest('/monitoring/candidates'),
    ]);

    if (brandResult.status === 'fulfilled') {
      const data = unwrap<Brand[]>(brandResult.value);
      if (Array.isArray(data)) {
        setBrands(data);
        setBrandState({ loading: false, error: '' });
      } else {
        setBrandState({
          loading: false,
          error: 'The API returned an unexpected brand response.',
        });
      }
    } else {
      setBrandState({
        loading: false,
        error:
          brandResult.reason instanceof Error
            ? brandResult.reason.message
            : 'Could not load brand profiles.',
      });
    }

    if (candidateResult.status === 'fulfilled') {
      const data = unwrap<Candidate[]>(candidateResult.value);
      if (Array.isArray(data)) {
        setCandidates(data);
        setCandidateState({ loading: false, error: '' });
      } else {
        setCandidateState({
          loading: false,
          error: 'The API returned an unexpected monitoring response.',
        });
      }
    } else {
      setCandidateState({
        loading: false,
        error:
          candidateResult.reason instanceof Error
            ? candidateResult.reason.message
            : 'Could not load monitoring candidates.',
      });
    }

    if (
      brandResult.status === 'fulfilled' &&
      candidateResult.status === 'fulfilled'
    ) {
      setLastUpdated(new Date());
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const loading = brandState.loading || candidateState.loading;
  const failed = Boolean(brandState.error || candidateState.error);
  const assetCount = countAssets(brands);
  const highRiskCount = candidates.filter((candidate) => {
    const level = riskLabel(candidate).toLowerCase();
    return level === 'high' || level === 'critical';
  }).length;

  const recentCandidates = [...candidates]
    .sort((a, b) => {
      const dateA = a.created_at ? new Date(a.created_at).getTime() : 0;
      const dateB = b.created_at ? new Date(b.created_at).getTime() : 0;
      return dateB - dateA;
    })
    .slice(0, 5);

  return (
    <section className="page-enter space-y-6">
      <AgentChat t={t} onNavigate={setActiveTab} />

      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">
            <Activity className="h-4 w-4" />
            Security operations overview
          </div>
          <h1 className="text-2xl font-bold text-white sm:text-3xl">
            {t('dashboard.title')}
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            {t('dashboard.subtitle')}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-400">
            {failed ? (
              <WifiOff className="h-4 w-4 text-amber-400" />
            ) : (
              <Wifi className={`h-4 w-4 ${loading ? 'text-blue-400' : 'text-emerald-400'}`} />
            )}
            {loading ? 'Loading data' : failed ? 'Partial data unavailable' : 'API responses received'}
          </div>
          <button
            type="button"
            onClick={() => void loadDashboard()}
            disabled={loading}
            className="btn-secondary inline-flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            {t('common.refresh')}
          </button>
        </div>
      </header>

      {failed && (
        <div
          role="alert"
          className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" />
            <div className="min-w-0">
              <p className="font-semibold text-amber-200">
                Some dashboard data could not be loaded
              </p>
              <div className="mt-2 space-y-1 text-sm text-amber-100/80">
                {brandState.error && <p>Brands: {brandState.error}</p>}
                {candidateState.error && <p>Monitoring: {candidateState.error}</p>}
              </div>
              <p className="mt-2 text-xs text-amber-100/60">
                Unavailable data is not counted as zero. Check the API endpoint
                and connection before interpreting these metrics.
              </p>
            </div>
          </div>
        </div>
      )}

      {!brandState.error && brands.length > 0 && (
        <section className="surface-card p-4 sm:p-5">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white">{t('dashboard.protectedBrands')}</h2>
              <p className="mt-0.5 text-xs text-slate-500">
                {t('dashboard.protectedBrandsHint')}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setActiveTab('brands')}
              className="inline-flex shrink-0 items-center gap-1.5 text-xs font-medium text-blue-300 hover:text-blue-200"
            >
              {t('dashboard.manageBrands')} <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="flex gap-3 overflow-x-auto pb-1">
            {brands.slice(0, 12).map((brand) => (
              <button
                key={String(brand.id)}
                type="button"
                onClick={() => setActiveTab('brands')}
                className="group flex min-w-[132px] flex-col items-center gap-2 rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-3 transition hover:border-blue-500/40 hover:bg-slate-900/80"
                title={brand.primary_domain ?? brand.name}
              >
                <BrandLogo
                  brandId={brand.id}
                  domain={brand.primary_domain}
                  name={brand.name}
                  size={44}
                  verified
                />
                <span className="max-w-[120px] truncate text-xs font-medium text-slate-200 group-hover:text-white">
                  {brand.name}
                </span>
                <span className="max-w-[120px] truncate text-[10px] text-slate-500">
                  {brand.primary_domain ?? 'no domain'}
                </span>
              </button>
            ))}
          </div>
        </section>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          title={t('dashboard.registeredBrands')}
          value={brandState.error ? '—' : brands.length}
          description="Brand profiles returned by the API"
          icon={Building2}
          tone="border-blue-500/25 bg-blue-500/10 text-blue-300"
          loading={brandState.loading}
          onClick={() => setActiveTab('brands')}
        />
        <MetricCard
          title={t('dashboard.officialAssets')}
          value={brandState.error ? '—' : assetCount}
          description="Assets included in the returned brand records"
          icon={ShieldCheck}
          tone="border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
          loading={brandState.loading}
          onClick={() => setActiveTab('brands')}
        />
        <MetricCard
          title={t('dashboard.candidates')}
          value={candidateState.error ? '—' : candidates.length}
          description="Monitoring candidates returned by the API"
          icon={Radar}
          tone="border-violet-500/25 bg-violet-500/10 text-violet-300"
          loading={candidateState.loading}
          onClick={() => setActiveTab('monitoring')}
        />
        <MetricCard
          title={t('dashboard.highRisk')}
          value={candidateState.error ? '—' : highRiskCount}
          description="Candidates explicitly classified as high or critical"
          icon={ShieldAlert}
          tone="border-rose-500/25 bg-rose-500/10 text-rose-300"
          loading={candidateState.loading}
          onClick={() => setActiveTab('findings')}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.5fr)_minmax(280px,0.8fr)]">
        <section className="surface-card min-w-0 p-5 sm:p-6">
          <div className="mb-5 flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <div>
              <h2 className="text-lg font-semibold text-white">
                {t('dashboard.recentActivity')}
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Latest records available from the monitoring API
              </p>
            </div>
            <button
              type="button"
              onClick={() => setActiveTab('monitoring')}
              className="inline-flex items-center gap-2 text-sm font-medium text-blue-300 hover:text-blue-200"
            >
              Open monitoring <ArrowRight className="h-4 w-4" />
            </button>
          </div>

          {candidateState.loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((item) => (
                <div key={item} className="skeleton h-16 rounded-xl" />
              ))}
            </div>
          ) : candidateState.error ? (
            <div className="rounded-xl border border-dashed border-slate-700 p-6 text-sm text-slate-400">
              Candidate records are unavailable until the monitoring API
              responds successfully.
            </div>
          ) : recentCandidates.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center">
              <Radar className="mx-auto mb-3 h-8 w-8 text-slate-600" />
              <p className="text-sm font-medium text-slate-300">
                No monitoring candidates returned
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Run a monitoring scan to discover records, if a source is configured.
              </p>
              <button
                type="button"
                onClick={() => setActiveTab('monitoring')}
                className="btn-secondary mt-4"
              >
                Go to monitoring
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {recentCandidates.map((candidate, index) => {
                const level = riskLabel(candidate);
                const label =
                  candidate.name ||
                  candidate.title ||
                  candidate.url ||
                  candidate.candidate_url ||
                  'Unnamed candidate';

                return (
                  <button
                    type="button"
                    key={candidate.id ?? `${label}-${index}`}
                    onClick={() => setActiveTab('findings')}
                    className="group flex w-full flex-col justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-left transition hover:border-slate-700 hover:bg-slate-900/80 sm:flex-row sm:items-center"
                  >
                    <div className="flex min-w-0 items-start gap-3">
                      <div className="mt-0.5 rounded-lg border border-slate-800 bg-slate-900 p-2 text-slate-400">
                        <Target className="h-4 w-4" />
                      </div>
                      <div className="min-w-0">
                        <p className="break-all text-sm font-medium text-slate-200 group-hover:text-white">
                          {label}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">
                          {[candidate.platform || candidate.source, formatDate(candidate.created_at)]
                            .filter(Boolean)
                            .join(' · ')}
                        </p>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      {typeof candidate.risk_score === 'number' && (
                        <span className="font-mono text-xs text-slate-400">
                          {candidate.risk_score}/100
                        </span>
                      )}
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-medium capitalize ${riskClass(level)}`}>
                        {level}
                      </span>
                      <ArrowDownRight className="h-4 w-4 text-slate-600 group-hover:text-blue-300" />
                    </div>
                  </button>
                );
              })}
            </div>
          )}

          {!candidateState.error && lastUpdated && (
            <p className="mt-4 flex items-center gap-1.5 text-xs text-slate-600">
              <Clock3 className="h-3.5 w-3.5" />
              Data refreshed {lastUpdated.toLocaleTimeString()}
            </p>
          )}
        </section>

        <aside className="space-y-5">
          <section className="surface-card p-5 sm:p-6">
            <h2 className="text-lg font-semibold text-white">{t('dashboard.quickActions')}</h2>
            <p className="mt-1 text-sm text-slate-500">
              Jump to a workflow
            </p>
            <div className="mt-5 space-y-2">
              {[
                {
                  label: 'Investigate a URL or profile',
                  detail: 'Inspect a suspicious target',
                  icon: Target,
                  tab: 'investigations',
                },
                {
                  label: 'Manage brand registry',
                  detail: 'Register official identities and assets',
                  icon: Building2,
                  tab: 'brands',
                },
                {
                  label: 'Review findings',
                  detail: 'Inspect available risk records',
                  icon: ShieldAlert,
                  tab: 'findings',
                },
                {
                  label: 'View reports and alerts',
                  detail: 'Open incident reporting',
                  icon: AlertTriangle,
                  tab: 'reports',
                },
              ].map((action) => (
                <button
                  key={action.tab}
                  type="button"
                  onClick={() => setActiveTab(action.tab)}
                  className="flex w-full items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/40 p-3.5 text-left transition hover:border-blue-500/30 hover:bg-blue-500/5"
                >
                  <div className="rounded-lg bg-slate-900 p-2 text-blue-300">
                    <action.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-200">
                      {action.label}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {action.detail}
                    </p>
                  </div>
                  <ArrowRight className="h-4 w-4 shrink-0 text-slate-600" />
                </button>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-blue-500/20 bg-gradient-to-br from-blue-500/10 via-slate-900/80 to-violet-500/5 p-5">
            <div className="flex items-center gap-2 text-blue-300">
              <ShieldCheck className="h-5 w-5" />
              <h2 className="font-semibold">Evidence-first workflow</h2>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-400">
              A candidate is a lead, not proof of malicious activity. Use
              available evidence, source status, and risk signals before
              treating a result as a confirmed threat.
            </p>
          </section>
        </aside>
      </div>
    </section>
  );
};

export default DashboardView;
