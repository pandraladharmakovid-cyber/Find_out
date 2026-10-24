import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, Bot, CheckCircle2, ChevronRight, Cpu, Gauge,
  History, ListChecks, Loader2, Play, RefreshCw, ShieldAlert, Sparkles,
  Wrench, XCircle,
} from 'lucide-react';
import { apiRequest } from './api';
import type { Translator } from './i18n';

type ModuleStatus = 'ok' | 'degraded' | 'not_configured' | 'error';

type ModuleDiagnostic = {
  id: string;
  name: string;
  category: string;
  status: ModuleStatus;
  configured: boolean;
  latencyMs: number;
  detail: string;
  remediation?: string;
  metrics?: Record<string, number | string | boolean>;
};

type SystemDiagnostics = {
  generatedAt: string;
  durationMs: number;
  deep: boolean;
  overall: ModuleStatus;
  ready: boolean;
  counts: { ok: number; degraded: number; notConfigured: number; error: number };
  blockers: ModuleDiagnostic[];
  warnings: ModuleDiagnostic[];
  modules: ModuleDiagnostic[];
  ai: {
    configured: boolean;
    primaryModel: string;
    modelChain: string[];
    transportPreference: string;
    usableRoute: { model: string; transport: string } | null;
    lastError: { code: string; message: string } | null;
  };
};

type AgentReport = {
  goal: string;
  mode: string;
  answer: string;
  verdict: string;
  riskScore: number;
  confidenceScore: number;
  summary: string;
  keyFindings: string[];
  moduleStatus: Array<{ id: string; name: string; status: string; detail: string; remediation?: string }>;
  recommendedActions: string[];
  limitations: string[];
  engine: 'llm' | 'deterministic';
  model: string | null;
  transport: string | null;
  fallbackUsed: boolean;
  toolsUsed: string[];
};

type AgentStep = {
  step: number;
  thought: string;
  tool: string | null;
  ok: boolean;
  summary: string;
  durationMs: number;
};

type AgentRunResponse = {
  id: string;
  status: string;
  durationMs: number;
  report: AgentReport;
  trace: AgentStep[];
  error?: string;
};

type AgentStatus = {
  agent: {
    provider: {
      configured: boolean;
      baseUrl: string;
      primaryModel: string;
      modelChain: string[];
      transportPreference: string;
      lastSuccessfulRoute: { model: string; transport: string } | null;
      lastError: { code: string; message: string } | null;
    };
    maxSteps: number;
    timeoutMs: number;
  };
  tools: Array<{ name: string; description: string; readOnly: boolean }>;
};

type Brand = { id: string; name: string };

type Tab = 'copilot' | 'health' | 'history';

const statusStyles: Record<string, string> = {
  ok: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  degraded: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
  not_configured: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  error: 'border-rose-400/30 bg-rose-400/10 text-rose-200',
};

function statusIcon(status: string): React.ReactNode {
  if (status === 'ok') return <CheckCircle2 size={14} />;
  if (status === 'error') return <XCircle size={14} />;
  if (status === 'degraded') return <AlertTriangle size={14} />;
  return <Wrench size={14} />;
}

function verdictStyle(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case 'malicious':
      return 'border-rose-400/40 bg-rose-500/15 text-rose-200';
    case 'phishing':
      return 'border-fuchsia-400/40 bg-fuchsia-500/15 text-fuchsia-200';
    case 'suspicious':
      return 'border-amber-400/40 bg-amber-500/15 text-amber-200';
    case 'clean':
      return 'border-emerald-400/40 bg-emerald-500/15 text-emerald-200';
    default:
      return 'border-slate-500/40 bg-slate-500/10 text-slate-300';
  }
}

export const AgentView: React.FC<{ t: Translator }> = ({ t }) => {
  const [tab, setTab] = useState<Tab>('copilot');
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [brandId, setBrandId] = useState('');
  const [goal, setGoal] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [mode, setMode] = useState<'investigate' | 'ask' | 'audit'>('investigate');
  const [language, setLanguage] = useState<'en' | 'hi' | 'te'>('en');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AgentRunResponse | null>(null);
  const [diagnostics, setDiagnostics] = useState<SystemDiagnostics | null>(null);
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false);
  const [history, setHistory] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState('');
  const abortRef = useRef<AbortController | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const response = await apiRequest<{ data?: AgentStatus }>('/agent/status', { timeoutMs: 20000 });
      if (response?.data) setStatus(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load agent status.');
    }
  }, []);

  const loadBrands = useCallback(async () => {
    try {
      const response = await apiRequest<{ data?: Brand[] }>('/brands', { timeoutMs: 20000 });
      if (Array.isArray(response?.data)) {
        setBrands(response.data);
        setBrandId((current) => current || String(response.data?.[0]?.id ?? ''));
      }
    } catch {
      // The brand list is optional; the agent still answers without it.
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const response = await apiRequest<{ data?: Array<Record<string, unknown>> }>('/agent/runs', {
        timeoutMs: 20000,
      });
      if (Array.isArray(response?.data)) setHistory(response.data);
    } catch {
      // History is best-effort.
    }
  }, []);

  useEffect(() => {
    void loadStatus();
    void loadBrands();
    void loadHistory();
  }, [loadStatus, loadBrands, loadHistory]);

  const runDiagnostics = useCallback(async () => {
    setDiagnosticsLoading(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: SystemDiagnostics }>('/agent/diagnostics?deep=1', {
        timeoutMs: 240000,
      });
      if (!response?.data) throw new Error('The diagnostics endpoint returned no data.');
      setDiagnostics(response.data);
      setTab('health');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Diagnostics failed.');
    } finally {
      setDiagnosticsLoading(false);
    }
  }, []);

  const runAgent = useCallback(async () => {
    const prompt =
      goal.trim() ||
      (mode === 'audit'
        ? 'Audit every module, tell me what is broken and how to fix it.'
        : 'Review the current brand findings and give me a defensible risk assessment.');

    setRunning(true);
    setError('');
    setResult(null);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const response = await apiRequest<{ data?: AgentRunResponse }>('/agent/run', {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          goal: prompt,
          mode,
          language,
          ...(brandId ? { brandId } : {}),
          ...(targetUrl.trim() ? { targetUrl: targetUrl.trim() } : {}),
        }),
        timeoutMs: 300000,
      });
      if (!response?.data) throw new Error('The agent returned no result.');
      setResult(response.data);
      void loadHistory();
      void loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The agent could not complete the run.');
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  }, [brandId, goal, language, loadHistory, loadStatus, mode, targetUrl]);

  const provider = status?.agent.provider;
  const report = result?.report;

  const counters = useMemo(() => {
    if (!diagnostics) return null;
    return [
      { label: t('copilot.ok'), value: diagnostics.counts.ok, tone: 'text-emerald-300' },
      { label: t('copilot.degraded'), value: diagnostics.counts.degraded, tone: 'text-amber-300' },
      { label: t('copilot.notConfigured'), value: diagnostics.counts.notConfigured, tone: 'text-slate-300' },
      { label: t('copilot.failing'), value: diagnostics.counts.error, tone: 'text-rose-300' },
    ];
  }, [diagnostics, t]);

  return (
    <main className="page-enter space-y-6">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 lg:flex-row lg:items-end">
        <div>
          <p className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            <Sparkles size={13} /> {t('copilot.eyebrow')}
          </p>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
            <Bot className="text-cyan-400" /> {t('copilot.title')}
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{t('copilot.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs ${
              provider?.configured ? statusStyles.ok : statusStyles.not_configured
            }`}
          >
            <Cpu size={13} />
            {provider?.configured ? t('copilot.gatewayReady') : t('copilot.gatewayMissing')}
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300">
            {provider?.lastSuccessfulRoute
              ? `${provider.lastSuccessfulRoute.model} · ${provider.lastSuccessfulRoute.transport}`
              : provider?.primaryModel ?? '—'}
          </span>
          <button type="button" className="btn-secondary" onClick={() => void runDiagnostics()} disabled={diagnosticsLoading}>
            {diagnosticsLoading ? <Loader2 size={15} className="animate-spin" /> : <Activity size={15} />}
            {t('copilot.runAudit')}
          </button>
        </div>
      </header>

      <nav className="flex flex-wrap gap-2" aria-label="Copilot sections">
        {[
          { id: 'copilot' as Tab, label: t('copilot.tabChat'), icon: Bot },
          { id: 'health' as Tab, label: t('copilot.tabHealth'), icon: Activity },
          { id: 'history' as Tab, label: t('copilot.tabHistory'), icon: History },
        ].map((entry) => (
          <button
            key={entry.id}
            type="button"
            onClick={() => setTab(entry.id)}
            aria-pressed={tab === entry.id}
            className={tab === entry.id ? 'btn-primary' : 'btn-secondary'}
          >
            <entry.icon size={15} /> {entry.label}
          </button>
        ))}
      </nav>

      {error && (
        <div role="alert" className="flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <AlertTriangle size={18} className="shrink-0" />
          <div className="min-w-0">
            <p className="font-semibold">{t('copilot.errorTitle')}</p>
            <p className="mt-1 break-words">{error}</p>
          </div>
        </div>
      )}

      {tab === 'copilot' && (
        <>
          <section className="surface-card space-y-4 p-4 sm:p-6">
            <div className="grid gap-3 lg:grid-cols-4">
              <label className="space-y-2 text-sm text-slate-300 lg:col-span-2">
                {t('copilot.mode')}
                <select
                  className="w-full"
                  value={mode}
                  onChange={(event) => setMode(event.target.value as typeof mode)}
                >
                  <option value="investigate">{t('copilot.modeInvestigate')}</option>
                  <option value="audit">{t('copilot.modeAudit')}</option>
                  <option value="ask">{t('copilot.modeAsk')}</option>
                </select>
              </label>

              <label className="space-y-2 text-sm text-slate-300">
                {t('copilot.brand')}
                <select className="w-full" value={brandId} onChange={(event) => setBrandId(event.target.value)}>
                  <option value="">{t('copilot.noBrand')}</option>
                  {brands.map((brand) => (
                    <option key={brand.id} value={brand.id}>
                      {brand.name}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-2 text-sm text-slate-300">
                {t('copilot.language')}
                <select
                  className="w-full"
                  value={language}
                  onChange={(event) => setLanguage(event.target.value as typeof language)}
                >
                  <option value="en">English</option>
                  <option value="hi">हिन्दी</option>
                  <option value="te">తెలుగు</option>
                </select>
              </label>
            </div>

            <label className="block space-y-2 text-sm text-slate-300">
              {t('copilot.goal')}
              <textarea
                className="min-h-[92px] w-full"
                value={goal}
                onChange={(event) => setGoal(event.target.value)}
                placeholder={t('copilot.goalPlaceholder')}
              />
            </label>

            <label className="block space-y-2 text-sm text-slate-300">
              {t('copilot.target')}
              <input
                className="w-full"
                value={targetUrl}
                onChange={(event) => setTargetUrl(event.target.value)}
                placeholder="https://suspicious-lookalike.example"
              />
            </label>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="max-w-xl text-xs leading-5 text-slate-500">{t('copilot.disclaimer')}</p>
              <button type="button" className="btn-primary" onClick={() => void runAgent()} disabled={running}>
                {running ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                {running ? t('copilot.running') : t('copilot.run')}
              </button>
            </div>
          </section>

          {running && (
            <section className="surface-card flex items-center gap-3 p-5 text-sm text-slate-300">
              <Loader2 size={18} className="animate-spin text-cyan-400" />
              <div>
                <p className="font-medium text-white">{t('copilot.runningTitle')}</p>
                <p className="mt-1 text-slate-400">{t('copilot.runningDetail')}</p>
              </div>
            </section>
          )}

          {report && (
            <section className="space-y-5">
              <div className="surface-card space-y-4 p-5 sm:p-6">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${verdictStyle(report.verdict)}`}>
                      <ShieldAlert size={13} /> {report.verdict.toUpperCase()}
                    </span>
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300">
                      <Gauge size={12} className="mr-1 inline" /> {t('copilot.risk')} {report.riskScore}/100
                    </span>
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300">
                      {t('copilot.confidence')} {report.confidenceScore}%
                    </span>
                    <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1.5 text-xs text-cyan-200">
                      {report.engine === 'llm' ? `${report.model ?? 'model'} · ${report.transport ?? ''}` : t('copilot.deterministic')}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">
                    {t('copilot.duration')}: {(result?.durationMs ?? 0) / 1000}s · {t('copilot.steps')}: {result?.trace.length ?? 0}
                  </p>
                </div>

                <div>
                  <h2 className="text-lg font-semibold text-white">{t('copilot.answer')}</h2>
                  <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-6 text-slate-200">{report.answer}</p>
                </div>

                {report.summary && report.summary !== report.answer && (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t('copilot.summary')}</p>
                    <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-300">{report.summary}</p>
                  </div>
                )}

                {report.keyFindings.length > 0 && (
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                      <ListChecks size={15} className="text-cyan-400" /> {t('copilot.keyFindings')}
                    </h3>
                    <ul className="mt-2 space-y-2">
                      {report.keyFindings.map((finding, index) => (
                        <li key={index} className="flex gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-sm text-slate-300">
                          <ChevronRight size={15} className="mt-0.5 shrink-0 text-cyan-400" />
                          <span className="break-words">{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {report.recommendedActions.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-white">{t('copilot.actions')}</h3>
                    <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm text-slate-300">
                      {report.recommendedActions.map((action, index) => (
                        <li key={index} className="break-words">{action}</li>
                      ))}
                    </ol>
                  </div>
                )}

                {report.limitations.length > 0 && (
                  <div className="rounded-xl border border-amber-400/25 bg-amber-400/5 p-4">
                    <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-amber-200">
                      <AlertTriangle size={13} /> {t('copilot.limitations')}
                    </p>
                    <ul className="mt-2 space-y-1 text-sm text-amber-100/80">
                      {report.limitations.map((limitation, index) => (
                        <li key={index} className="break-words">• {limitation}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {result && result.trace.length > 0 && (
                <div className="surface-card p-5 sm:p-6">
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                    <Wrench size={15} className="text-cyan-400" /> {t('copilot.trace')}
                  </h3>
                  <div className="mt-3 space-y-2">
                    {result.trace.map((step) => (
                      <div key={step.step} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-300">#{step.step}</span>
                          <span className="font-medium text-cyan-300">{step.tool ?? 'analysis'}</span>
                          <span className={step.ok ? 'text-emerald-300' : 'text-rose-300'}>
                            {step.ok ? t('copilot.toolOk') : t('copilot.toolFailed')}
                          </span>
                          <span className="text-slate-500">{step.durationMs}ms</span>
                        </div>
                        {step.thought && <p className="mt-1.5 text-xs text-slate-400">{step.thought}</p>}
                        <p className="mt-1 break-words text-sm text-slate-300">{step.summary}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}
        </>
      )}

      {tab === 'health' && (
        <section className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {(counters ?? [
              { label: t('copilot.ok'), value: '—', tone: 'text-emerald-300' },
              { label: t('copilot.degraded'), value: '—', tone: 'text-amber-300' },
              { label: t('copilot.notConfigured'), value: '—', tone: 'text-slate-300' },
              { label: t('copilot.failing'), value: '—', tone: 'text-rose-300' },
            ]).map((counter) => (
              <div className="surface-card p-4" key={counter.label}>
                <p className="text-sm text-slate-400">{counter.label}</p>
                <p className={`mt-2 text-3xl font-bold tabular-nums ${counter.tone}`}>{counter.value}</p>
              </div>
            ))}
          </div>

          {!diagnostics ? (
            <div className="surface-card p-8 text-center">
              <Activity size={26} className="mx-auto mb-3 text-cyan-400" />
              <p className="font-semibold text-white">{t('copilot.noAudit')}</p>
              <p className="mx-auto mt-2 max-w-xl text-sm text-slate-400">{t('copilot.noAuditDetail')}</p>
              <button type="button" className="btn-primary mt-4" onClick={() => void runDiagnostics()} disabled={diagnosticsLoading}>
                {diagnosticsLoading ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
                {t('copilot.runAudit')}
              </button>
            </div>
          ) : (
            <div className="surface-card overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 p-4">
                <div>
                  <h2 className="font-semibold text-white">{t('copilot.moduleHealth')}</h2>
                  <p className="text-xs text-slate-500">
                    {t('copilot.generated')} {new Date(diagnostics.generatedAt).toLocaleString()} ·{' '}
                    {(diagnostics.durationMs / 1000).toFixed(1)}s
                  </p>
                </div>
                <button type="button" className="btn-secondary" onClick={() => void runDiagnostics()} disabled={diagnosticsLoading}>
                  {diagnosticsLoading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                  {t('copilot.recheck')}
                </button>
              </div>

              <div className="divide-y divide-slate-800">
                {diagnostics.modules.map((module) => (
                  <div key={module.id} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-start sm:gap-4">
                    <span className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${statusStyles[module.status] ?? statusStyles.not_configured}`}>
                      {statusIcon(module.status)} {module.status}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-slate-100">{module.name}</p>
                      <p className="mt-1 break-words text-sm text-slate-400">{module.detail}</p>
                      {module.remediation && (
                        <p className="mt-1.5 break-words text-xs text-cyan-200/80">→ {module.remediation}</p>
                      )}
                    </div>
                    <span className="text-xs tabular-nums text-slate-500">{module.latencyMs}ms</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {tab === 'history' && (
        <section className="surface-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 p-4">
            <h2 className="font-semibold text-white">{t('copilot.history')}</h2>
            <button type="button" className="btn-secondary" onClick={() => void loadHistory()}>
              <RefreshCw size={14} /> {t('common.refresh')}
            </button>
          </div>

          {history.length === 0 ? (
            <p className="p-6 text-sm text-slate-400">{t('copilot.noHistory')}</p>
          ) : (
            <div className="divide-y divide-slate-800">
              {history.map((run) => (
                <div key={String(run.id)} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-200">{String(run.goal)}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {String(run.mode)} · {String(run.engine)} · {String(run.model ?? 'deterministic')} ·{' '}
                      {new Date(String(run.created_at)).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className={`rounded-full border px-2.5 py-1 ${verdictStyle(String(run.verdict ?? 'unverified'))}`}>
                      {String(run.verdict ?? 'unverified').toUpperCase()}
                    </span>
                    <span className="text-slate-400">{String(run.risk_score ?? 0)}/100</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </main>
  );
};

export default AgentView;
