import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BellRing,
  Check,
  CheckCheck,
  ChevronRight,
  ClipboardCopy,
  Clock3,
  FileText,
  Filter,
  Gauge,
  History,
  Loader2,
  RefreshCw,
  Search,
  ShieldX,
  X,
} from 'lucide-react';

import { apiRequest } from './api';
import type { Translator } from './i18n';

/**
 * Detection records — Rulebook v2.
 *
 * Every detection shows the five required fields:
 *   Source · Suspected asset · Evidence · Similarity/Risk score · Status
 *
 * Analysts confirm or dismiss a record, the change is stored with *who* made it
 * and *when*, the queue is ordered by risk, official assets are excluded, and a
 * confirmed high-risk record produces exactly one alert plus an evidence-based
 * takedown draft.
 */

type DetectionStatus = 'NEW' | 'UNDER_REVIEW' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'CLOSED';

type DetectionRecord = {
  id: string;
  source: string;
  source_label: string;
  suspected_asset: string;
  suspected_url: string;
  suspected_asset_type: string;
  evidence_summary: string[];
  evidence_count: number;
  similarity_risk_score: number;
  confidence_score: number;
  risk_level: string;
  risk_explanation: string;
  status: DetectionStatus;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  assigned_to: string | null;
  is_official_excluded: boolean;
  brand_name: string | null;
  created_at: string;
  updated_at: string;
  decided_at: string | null;
  decided_by: string | null;
};

type HistoryEvent = {
  id: string;
  action: string;
  from_status: DetectionStatus | null;
  to_status: DetectionStatus | null;
  actor: string;
  note: string;
  created_at: string;
};

type TakedownDraft = {
  subject: string;
  body: string;
  evidenceLines: string[];
  generatedAt: string;
};

type HighRiskAlert = {
  id: string;
  record_id: string;
  severity: string;
  title: string;
  message: string;
  acknowledged_by: string | null;
  created_at: string;
};

type Props = { t: Translator };

const STATUS_STYLES: Record<DetectionStatus, string> = {
  NEW: 'border-blue-500/40 bg-blue-500/10 text-blue-200',
  UNDER_REVIEW: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  CONFIRMED: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  FALSE_POSITIVE: 'border-slate-600 bg-slate-800/70 text-slate-300',
  CLOSED: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
};

const PRIORITY_STYLES: Record<DetectionRecord['priority'], string> = {
  CRITICAL: 'border-rose-500/40 bg-rose-500/15 text-rose-200',
  HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-200',
  MEDIUM: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  LOW: 'border-slate-600 bg-slate-800/60 text-slate-300',
};

const STATUS_LABEL: Record<DetectionStatus, string> = {
  NEW: 'New',
  UNDER_REVIEW: 'Under review',
  CONFIRMED: 'Confirmed',
  FALSE_POSITIVE: 'False positive',
  CLOSED: 'Closed',
};

const NEXT_ACTIONS: Record<DetectionStatus, Array<{ status: DetectionStatus; label: string; tone: string; icon: React.ElementType }>> = {
  NEW: [
    { status: 'UNDER_REVIEW', label: 'Start review', tone: 'btn-secondary', icon: Clock3 },
    { status: 'CONFIRMED', label: 'Confirm threat', tone: 'btn-danger', icon: Check },
    { status: 'FALSE_POSITIVE', label: 'Mark false positive', tone: 'btn-secondary', icon: X },
  ],
  UNDER_REVIEW: [
    { status: 'CONFIRMED', label: 'Confirm threat', tone: 'btn-danger', icon: Check },
    { status: 'FALSE_POSITIVE', label: 'Mark false positive', tone: 'btn-secondary', icon: X },
    { status: 'NEW', label: 'Return to new', tone: 'btn-secondary', icon: RefreshCw },
  ],
  CONFIRMED: [
    { status: 'CLOSED', label: 'Close record', tone: 'btn-secondary', icon: CheckCheck },
    { status: 'FALSE_POSITIVE', label: 'Mark false positive', tone: 'btn-secondary', icon: X },
  ],
  FALSE_POSITIVE: [
    { status: 'CLOSED', label: 'Close record', tone: 'btn-secondary', icon: CheckCheck },
    { status: 'UNDER_REVIEW', label: 'Reopen review', tone: 'btn-secondary', icon: Clock3 },
  ],
  CLOSED: [{ status: 'UNDER_REVIEW', label: 'Reopen review', tone: 'btn-secondary', icon: Clock3 }],
};

function scoreTone(score: number): string {
  if (score >= 80) return 'text-rose-300';
  if (score >= 60) return 'text-orange-300';
  if (score >= 35) return 'text-amber-300';
  if (score > 0) return 'text-emerald-300';
  return 'text-slate-400';
}

function formatDate(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const AnalystNameKey = 'findout-analyst-name';

function readAnalyst(): string {
  try {
    return localStorage.getItem(AnalystNameKey) || '';
  } catch {
    return '';
  }
}

export const DetectionsView: React.FC<Props> = ({ t }) => {
  const [records, setRecords] = useState<DetectionRecord[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [queue, setQueue] = useState<DetectionRecord[]>([]);
  const [alerts, setAlerts] = useState<HighRiskAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusFilter, setStatusFilter] = useState<'' | DetectionStatus>('');
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ record: DetectionRecord; history: HistoryEvent[] } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [deciding, setDeciding] = useState('');
  const [note, setNote] = useState('');
  const [analyst, setAnalyst] = useState(readAnalyst);
  const [notice, setNotice] = useState('');
  const [actionError, setActionError] = useState('');
  const [draft, setDraft] = useState<TakedownDraft | null>(null);
  const [draftLoading, setDraftLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const query = new URLSearchParams();
      if (statusFilter) query.set('status', statusFilter);
      if (search.trim()) query.set('search', search.trim());
      query.set('limit', '200');

      const [listResponse, alertResponse] = await Promise.allSettled([
        apiRequest<any>(`/detection-records?${query.toString()}`),
        apiRequest<any>('/detection-records/alerts'),
      ]);

      if (listResponse.status === 'fulfilled') {
        const data = listResponse.value?.data ?? listResponse.value;
        setRecords(Array.isArray(data?.records) ? data.records : []);
        setCounts(data?.counts ?? {});
        setQueue(Array.isArray(data?.priorityQueue) ? data.priorityQueue : []);
        setLoading(false);
      } else {
        setError(
          listResponse.reason instanceof Error
            ? listResponse.reason.message
            : 'Detection records could not be loaded.',
        );
        setLoading(false);
      }

      if (alertResponse.status === 'fulfilled') {
        const data = alertResponse.value?.data ?? alertResponse.value;
        setAlerts(Array.isArray(data) ? data : []);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Detection records could not be loaded.');
      setLoading(false);
    }
  }, [statusFilter, search]);

  useEffect(() => {
    void load();
  }, [load]);

  const openRecord = useCallback(async (id: string) => {
    setSelectedId(id);
    setDetailLoading(true);
    setDetail(null);
    setDraft(null);
    setNotice('');
    setActionError('');
    try {
      const response = await apiRequest<any>(`/detection-records/${id}`);
      const data = response?.data ?? response;
      setDetail(data);
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : 'Could not open the record.');
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const decide = useCallback(
    async (status: DetectionStatus) => {
      if (!detail) return;
      const actor = analyst.trim() || 'demo-analyst';
      try {
        localStorage.setItem(AnalystNameKey, actor);
      } catch {
        // Storage may be disabled; the decision still records the actor.
      }

      setDeciding(status);
      setActionError('');
      setNotice('');
      try {
        const response = await apiRequest<any>(`/detection-records/${detail.record.id}/decision`, {
          method: 'POST',
          body: JSON.stringify({ status, actor, note: note.trim() }),
        });
        const data = response?.data ?? response;
        setDetail(data);
        setNote('');
        setNotice(`Record moved to ${STATUS_LABEL[status]} and recorded against ${actor}.`);
        await load();
        const alertsAfter = await apiRequest<any>('/detection-records/alerts').catch(() => null);
        const alertRows = alertsAfter?.data ?? alertsAfter;
        if (Array.isArray(alertRows)) setAlerts(alertRows);
      } catch (caught) {
        setActionError(caught instanceof Error ? caught.message : 'The decision could not be saved.');
      } finally {
        setDeciding('');
      }
    },
    [analyst, detail, note, load],
  );

  const buildDraft = useCallback(async () => {
    if (!detail) return;
    setDraftLoading(true);
    setActionError('');
    try {
      const response = await apiRequest<any>(`/detection-records/${detail.record.id}/takedown-draft`);
      setDraft(response?.data ?? response);
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : 'Could not build the takedown draft.');
    } finally {
      setDraftLoading(false);
    }
  }, [detail]);

  const acknowledge = useCallback(
    async (id: string) => {
      try {
        await apiRequest(`/detection-records/alerts/${id}/acknowledge`, {
          method: 'POST',
          body: JSON.stringify({ actor: analyst.trim() || 'demo-analyst' }),
        });
        setAlerts((current) => current.filter((alert) => alert.id !== id));
      } catch (caught) {
        setActionError(caught instanceof Error ? caught.message : 'Could not acknowledge the alert.');
      }
    },
    [analyst],
  );

  const totals = useMemo(() => {
    const open = (counts.NEW ?? 0) + (counts.UNDER_REVIEW ?? 0);
    return {
      total: Object.values(counts).reduce((sum, value) => sum + value, 0),
      open,
      confirmed: counts.CONFIRMED ?? 0,
      falsePositive: counts.FALSE_POSITIVE ?? 0,
      closed: counts.CLOSED ?? 0,
    };
  }, [counts]);

  return (
    <main className="page-enter space-y-5">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-end">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-rose-400">
            Rulebook v2 · detection records
          </p>
          <h1 className="text-2xl font-bold text-white">{t('detections.title')}</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">{t('detections.subtitle')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-400">
            {t('detections.analystName')}
            <input
              value={analyst}
              onChange={(event) => setAnalyst(event.target.value)}
              placeholder="your.name"
              className="w-32 border-0 bg-transparent p-0 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none"
            />
          </label>
          <button type="button" onClick={() => void load()} disabled={loading} className="btn-secondary inline-flex items-center gap-2">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            {t('common.refresh')}
          </button>
        </div>
      </header>

      {/* One-time high-risk alerts */}
      {alerts.length > 0 && (
        <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4">
          <div className="flex items-center gap-2 text-rose-200">
            <BellRing className="h-4 w-4" />
            <p className="text-sm font-semibold">
              {alerts.length} high-risk alert{alerts.length === 1 ? '' : 's'} awaiting acknowledgement
            </p>
          </div>
          <ul className="mt-3 space-y-2">
            {alerts.map((alert) => (
              <li key={alert.id} className="flex flex-col justify-between gap-2 rounded-lg border border-rose-500/20 bg-slate-950/60 p-3 sm:flex-row sm:items-center">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-rose-100">{alert.title}</p>
                  <p className="mt-1 line-clamp-2 text-xs text-slate-400">{alert.message}</p>
                  <p className="mt-1 text-[11px] text-slate-500">{formatDate(alert.created_at)} · shown once</p>
                </div>
                <button
                  type="button"
                  onClick={() => void acknowledge(alert.id)}
                  className="btn-secondary shrink-0 text-xs"
                >
                  Acknowledge
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {[
          { label: t('detections.total'), value: totals.total, tone: 'text-slate-200' },
          { label: t('detections.open'), value: totals.open, tone: 'text-blue-300' },
          { label: t('detections.confirmed'), value: totals.confirmed, tone: 'text-rose-300' },
          { label: t('detections.falsePositive'), value: totals.falsePositive, tone: 'text-slate-300' },
          { label: t('detections.closed'), value: totals.closed, tone: 'text-emerald-300' },
        ].map((card) => (
          <div key={card.label} className="surface-card p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">{card.label}</p>
            <p className={`mt-2 text-2xl font-semibold ${card.tone}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Priority queue */}
      {queue.length > 0 && (
        <section className="surface-card p-4 sm:p-5">
          <h2 className="flex items-center gap-2 text-base font-semibold text-white">
            <Gauge className="h-4 w-4 text-rose-400" />
            {t('detections.queue')}
          </h2>
          <p className="mt-1 text-xs text-slate-500">{t('detections.queueHint')}</p>
          <div className="mt-3 flex gap-2 overflow-x-auto pb-1">
            {queue.map((record) => (
              <button
                key={record.id}
                type="button"
                onClick={() => void openRecord(record.id)}
                className="min-w-[210px] rounded-xl border border-slate-800 bg-slate-950/50 p-3 text-left transition hover:border-rose-500/40 hover:bg-slate-900"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${PRIORITY_STYLES[record.priority]}`}>
                    {record.priority}
                  </span>
                  <span className={`font-mono text-xs ${scoreTone(record.similarity_risk_score)}`}>
                    {Math.round(record.similarity_risk_score)}/100
                  </span>
                </div>
                <p className="mt-2 truncate text-sm font-medium text-slate-200">{record.suspected_asset}</p>
                <p className="mt-0.5 truncate text-[11px] text-slate-500">{record.source_label}</p>
              </button>
            ))}
          </div>
        </section>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
        {/* List */}
        <section className="surface-card min-w-0 p-4 sm:p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="flex items-center gap-2 text-base font-semibold text-white">
              <Filter className="h-4 w-4 text-blue-400" />
              {t('detections.records')}
            </h2>
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder={t('detections.search')}
                  className="w-44 rounded-lg border border-slate-700 bg-slate-900 pl-8 pr-2 py-2 text-xs text-slate-200 placeholder:text-slate-500"
                />
              </div>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value as '' | DetectionStatus)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-2 text-xs text-slate-200"
              >
                <option value="">All statuses</option>
                {(Object.keys(STATUS_LABEL) as DetectionStatus[]).map((status) => (
                  <option key={status} value={status}>
                    {STATUS_LABEL[status]}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {error && (
            <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
              {error}
            </div>
          )}

          {loading ? (
            <div className="mt-4 space-y-2">
              {[1, 2, 3].map((row) => (
                <div key={row} className="skeleton h-20 rounded-xl" />
              ))}
            </div>
          ) : records.length === 0 ? (
            <div className="mt-4 rounded-xl border border-dashed border-slate-700 p-6 text-center text-sm text-slate-400">
              {t('detections.empty')}
            </div>
          ) : (
            <ul className="mt-4 space-y-2">
              {records.map((record) => (
                <li key={record.id}>
                  <button
                    type="button"
                    onClick={() => void openRecord(record.id)}
                    className={`w-full rounded-xl border p-3 text-left transition ${
                      selectedId === record.id
                        ? 'border-blue-500/50 bg-blue-500/10'
                        : 'border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-900/70'
                    }`}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-white">{record.suspected_asset}</p>
                        <p className="mt-0.5 truncate text-[11px] text-slate-500">
                          {record.source_label}
                          {record.brand_name ? ` · ${record.brand_name}` : ''}
                          {record.suspected_url ? ` · ${record.suspected_url}` : ''}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${PRIORITY_STYLES[record.priority]}`}>
                          {record.priority}
                        </span>
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${STATUS_STYLES[record.status]}`}>
                          {STATUS_LABEL[record.status] ?? record.status}
                        </span>
                        <ChevronRight className="h-4 w-4 text-slate-600" />
                      </div>
                    </div>

                    <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">
                      {record.evidence_summary[0] ?? 'No evidence recorded yet.'}
                    </p>

                    <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                      <span className={`font-mono ${scoreTone(record.similarity_risk_score)}`}>
                        score {Math.round(record.similarity_risk_score)}/100
                      </span>
                      <span>{record.evidence_summary.length} evidence item(s)</span>
                      <span>{formatDate(record.created_at)}</span>
                      {record.is_official_excluded && (
                        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-300">
                          official · never flagged
                        </span>
                      )}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Detail */}
        <section className="surface-card min-w-0 p-4 sm:p-5">
          {!selectedId ? (
            <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center text-sm text-slate-400">
              {t('detections.selectHint')}
            </div>
          ) : detailLoading ? (
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading record…
            </div>
          ) : detail ? (
            <div className="space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-xs uppercase tracking-wider text-slate-500">{t('detections.record')}</p>
                    <h2 className="mt-1 break-words text-lg font-semibold text-white">
                      {detail.record.suspected_asset}
                    </h2>
                  </div>
                  <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${STATUS_STYLES[detail.record.status]}`}>
                    {STATUS_LABEL[detail.record.status]}
                  </span>
                </div>
                <p className="mt-1 break-all text-xs text-slate-500">
                  {detail.record.suspected_asset_type} · {detail.record.suspected_url || 'no URL recorded'}
                </p>
              </div>

              {/* The five required fields */}
              <dl className="grid gap-2 sm:grid-cols-2">
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <dt className="text-[11px] uppercase tracking-wider text-slate-500">{t('detections.source')}</dt>
                  <dd className="mt-1 text-sm text-slate-200">{detail.record.source_label}</dd>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <dt className="text-[11px] uppercase tracking-wider text-slate-500">{t('detections.asset')}</dt>
                  <dd className="mt-1 break-words text-sm text-slate-200">{detail.record.suspected_asset}</dd>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <dt className="text-[11px] uppercase tracking-wider text-slate-500">{t('detections.score')}</dt>
                  <dd className={`mt-1 font-mono text-sm ${scoreTone(detail.record.similarity_risk_score)}`}>
                    {Math.round(detail.record.similarity_risk_score)}/100 · {detail.record.risk_level}
                    <span className="ml-2 text-slate-500">{Math.round(detail.record.confidence_score)}% conf.</span>
                  </dd>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <dt className="text-[11px] uppercase tracking-wider text-slate-500">{t('detections.priority')}</dt>
                  <dd className="mt-1">
                    <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${PRIORITY_STYLES[detail.record.priority]}`}>
                      {detail.record.priority}
                    </span>
                  </dd>
                </div>
              </dl>

              <div>
                <p className="text-xs uppercase tracking-wider text-slate-500">{t('detections.evidence')}</p>
                <ul className="mt-2 space-y-1.5">
                  {detail.record.evidence_summary.map((line, index) => (
                    <li key={index} className="flex gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs leading-5 text-slate-300">
                      <span className="text-blue-400">{index + 1}.</span>
                      <span>{line}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs leading-5 text-slate-400">
                  <span className="font-medium text-slate-300">{t('detections.assessment')}: </span>
                  {detail.record.risk_explanation}
                </p>
              </div>

              {notice && (
                <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200">
                  {notice}
                </p>
              )}
              {actionError && (
                <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200">
                  {actionError}
                </p>
              )}

              {/* Analyst decision */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <p className="text-sm font-semibold text-slate-200">{t('detections.decision')}</p>
                <input
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder={t('detections.notePlaceholder')}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-2 text-xs text-slate-200 placeholder:text-slate-500"
                />
                <div className="mt-2 flex flex-wrap gap-2">
                  {(NEXT_ACTIONS[detail.record.status] ?? []).map((action) => (
                    <button
                      key={action.status}
                      type="button"
                      disabled={Boolean(deciding)}
                      onClick={() => void decide(action.status)}
                      className={`${action.tone} inline-flex items-center gap-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-50`}
                    >
                      {deciding === action.status ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <action.icon className="h-3.5 w-3.5" />
                      )}
                      {action.label}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-[11px] text-slate-500">
                  {t('detections.decisionHint')} {analyst.trim() || 'demo-analyst'}
                </p>
              </div>

              {/* Takedown draft */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="flex items-center gap-1.5 text-sm font-semibold text-slate-200">
                    <FileText className="h-4 w-4 text-blue-400" />
                    {t('detections.takedown')}
                  </p>
                  <button type="button" onClick={() => void buildDraft()} disabled={draftLoading} className="btn-secondary text-xs">
                    {draftLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : t('detections.generateDraft')}
                  </button>
                </div>

                {draft && (
                  <div className="mt-2 space-y-2">
                    <p className="text-xs font-medium text-slate-300">{draft.subject}</p>
                    <textarea
                      readOnly
                      value={draft.body}
                      rows={12}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 font-mono text-[11px] leading-5 text-slate-300"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        void navigator.clipboard
                          ?.writeText(draft.body)
                          .then(() => {
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                          })
                          .catch(() => setCopied(false));
                      }}
                      className="btn-secondary inline-flex items-center gap-1.5 text-xs"
                    >
                      <ClipboardCopy className="h-3.5 w-3.5" />
                      {copied ? t('detections.copied') : t('detections.copy')}
                    </button>
                  </div>
                )}
              </div>

              {/* Change history with who + when */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <p className="flex items-center gap-1.5 text-sm font-semibold text-slate-200">
                  <History className="h-4 w-4 text-slate-400" />
                  {t('detections.history')}
                </p>
                <ol className="mt-2 space-y-2">
                  {detail.history.map((event) => (
                    <li key={event.id} className="border-l border-slate-700 pl-3 text-xs">
                      <p className="text-slate-300">
                        {event.from_status ? (
                          <>
                            {STATUS_LABEL[event.from_status] ?? event.from_status} →{' '}
                            <span className="font-medium text-white">
                              {STATUS_LABEL[event.to_status ?? 'NEW'] ?? event.to_status}
                            </span>
                          </>
                        ) : (
                          <span className="font-medium text-white">Created as {event.to_status}</span>
                        )}
                      </p>
                      <p className="mt-0.5 text-slate-500">
                        {event.actor} · {formatDate(event.created_at)}
                      </p>
                      {event.note && <p className="mt-0.5 italic text-slate-400">“{event.note}”</p>}
                    </li>
                  ))}
                </ol>
              </div>

              {detail.record.is_official_excluded && (
                <p className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200">
                  <ShieldX className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  {t('detections.officialNote')}
                </p>
              )}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-amber-300">
              <AlertTriangle className="h-4 w-4" /> The record could not be loaded.
            </p>
          )}
        </section>
      </div>
    </main>
  );
};

export default DetectionsView;
