import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  ExternalLink,
  Globe,
  Loader2,
  Mail,
  Play,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sliders,
  Sparkles,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { apiRequest } from './api';
import type { Translator } from './i18n';

type SourceStatus = {
  source: string;
  status: 'available' | 'unavailable' | 'not_configured';
  candidatesFound: number;
  error?: string;
};

type ScheduleItem = {
  id: string;
  brand_id: string;
  brand_name?: string;
  primary_domain?: string;
  contact_email?: string | null;
  is_enabled: boolean;
  interval_minutes: number;
  alert_risk_threshold: number;
  last_run_at: string | null;
  next_run_at: string;
  last_status: string;
};

type WatchRunItem = {
  id: string;
  brand_id: string;
  brand_name?: string;
  trigger_type: 'scheduled' | 'manual' | 'brand_registered';
  status: 'IN_PROGRESS' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
  sources_checked: SourceStatus[];
  candidates_discovered: number;
  new_candidates_count: number;
  changed_candidates_count: number;
  high_risk_count: number;
  alerts_created: number;
  emails_sent: number;
  deduplicated_alerts_skipped: number;
  error_summary: string | null;
  started_at: string;
  completed_at: string | null;
};

type ExternalCandidateItem = {
  id: string;
  brand_id: string;
  brand_name?: string;
  platform: string;
  canonical_id: string;
  target_url: string;
  display_name: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_candidate_id: string | null;
  last_investigation_id: string | null;
  last_risk_score: number;
  last_risk_level: string;
  previous_risk_score: number | null;
  change_state: 'new' | 'escalated' | 'unchanged';
  times_seen: number;
  corroborating_signals: string[];
  evidence_summary?: {
    summary?: string | null;
    reasons?: string[];
    corroborated?: boolean;
  };
  detection_record_id?: string | null;
  analyst_status?: string | null;
};

type NotificationItem = {
  id: string;
  brand_id: string;
  brand_name?: string;
  dedupe_key: string;
  platform: string;
  canonical_id: string;
  target_url: string;
  risk_score: number;
  risk_level: string;
  alert_id: string | null;
  recipient_email: string | null;
  email_status: 'sent' | 'failed' | 'not_configured' | 'no_recipient';
  resend_message_id: string | null;
  email_error: string | null;
  created_at: string;
};

type OverviewPayload = {
  scheduler: {
    enabled: boolean;
    running: boolean;
    tickMs: number;
    defaultIntervalMinutes: number;
    defaultAlertThreshold: number;
    resendConfigured: boolean;
  };
  summary: {
    monitoredBrands: number;
    totalRuns: number;
    newlyDiscoveredCount: number;
    highRiskCount: number;
    confirmedThreatsCount: number;
    alertsSentCount: number;
    emailsDeliveredCount: number;
  };
  schedules: ScheduleItem[];
  recentRuns: WatchRunItem[];
  externalCandidates: ExternalCandidateItem[];
  notifications: NotificationItem[];
};

type ExternalWatchViewProps = {
  t: Translator;
  onInspectUrl?: (targetUrl: string) => void;
  onNavigate?: (tab: string) => void;
};

const SOURCE_LABELS: Record<string, string> = {
  crt_sh_ct_logs: 'Certificate Transparency (crt.sh)',
  dns_lookalike_probe: 'Live Public DNS Look-alike Probe',
  bluesky: 'Bluesky Public Feed',
  youtube: 'YouTube Data API',
  apple_app_store: 'Apple App Store Search',
  google_play: 'Google Play Store',
  google_safe_browsing: 'Google Safe Browsing',
  urlhaus_threat_feed: 'URLhaus Malware Feed',
  reddit_oauth: 'Reddit Official OAuth API',
};

function formatDateTime(value?: string | null): string {
  if (!value) return 'Never';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'Unavailable';
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function riskBadgeStyle(level: string): string {
  switch (level.toUpperCase()) {
    case 'CRITICAL':
      return 'border-rose-500/40 bg-rose-500/15 text-rose-200';
    case 'HIGH':
      return 'border-orange-500/40 bg-orange-500/15 text-orange-200';
    case 'MEDIUM':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-200';
    default:
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
  }
}

function sourceStatusBadge(status: SourceStatus['status']): string {
  switch (status) {
    case 'available':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    case 'not_configured':
      return 'border-slate-700 bg-slate-800/70 text-slate-300';
    default:
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
  }
}

export const ExternalWatchView: React.FC<ExternalWatchViewProps> = ({
  t,
  onInspectUrl,
  onNavigate,
}) => {
  const [selectedBrandId, setSelectedBrandId] = useState<string>('');
  const [overview, setOverview] = useState<OverviewPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [scanningBrandId, setScanningBrandId] = useState<string>('');
  const [runningDue, setRunningDue] = useState<boolean>(false);
  const [updatingScheduleId, setUpdatingScheduleId] = useState<string>('');
  const [decidingRecordId, setDecidingRecordId] = useState<string>('');
  const [bannerMessage, setBannerMessage] = useState<string>('');

  const loadOverview = useCallback(async (brandFilter?: string) => {
    setLoading(true);
    setError('');
    try {
      const targetBrand = brandFilter !== undefined ? brandFilter : selectedBrandId;
      const qs = targetBrand ? `?brandId=${encodeURIComponent(targetBrand)}` : '';
      const res = await apiRequest<{ data: OverviewPayload }>(`/external-watch/overview${qs}`);
      const payload = (res?.data ?? res) as OverviewPayload;
      setOverview(payload);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Unable to load External Brand Watch status.',
      );
    } finally {
      setLoading(false);
    }
  }, [selectedBrandId]);

  useEffect(() => {
    void loadOverview(selectedBrandId);
  }, [selectedBrandId, loadOverview]);

  const triggerBrandScan = async (brandId: string, brandName?: string) => {
    setScanningBrandId(brandId);
    setError('');
    setBannerMessage('');
    try {
      const res = await apiRequest<{ data: WatchRunItem }>(
        `/external-watch/scan/${encodeURIComponent(brandId)}`,
        { method: 'POST', timeoutMs: 90000 },
      );
      const run = (res?.data ?? res) as WatchRunItem;
      setBannerMessage(
        `External scan completed for ${brandName ?? 'brand'}: ${run.candidates_discovered} external candidate(s), ${run.new_candidates_count} newly seen, ${run.alerts_created} alert(s) triggered.`,
      );
      await loadOverview(selectedBrandId);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : 'External Brand Watch scan failed.',
      );
    } finally {
      setScanningBrandId('');
    }
  };

  const triggerDueWatches = async () => {
    setRunningDue(true);
    setError('');
    setBannerMessage('');
    try {
      const res = await apiRequest<{ data: { triggered: number; failed: number } }>(
        '/external-watch/run-due',
        { method: 'POST', timeoutMs: 90000 },
      );
      const out = res?.data ?? (res as unknown as { triggered: number; failed: number });
      setBannerMessage(
        `Scheduled watch cycle executed: ${out.triggered} brand scan(s) completed${out.failed ? `, ${out.failed} degraded` : ''}.`,
      );
      await loadOverview(selectedBrandId);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not run due watches.');
    } finally {
      setRunningDue(false);
    }
  };

  const updateSchedule = async (
    brandId: string,
    patch: { isEnabled?: boolean; intervalMinutes?: number; alertRiskThreshold?: number },
  ) => {
    setUpdatingScheduleId(brandId);
    setError('');
    try {
      await apiRequest(`/external-watch/schedules/${encodeURIComponent(brandId)}`, {
        method: 'PATCH',
        body: JSON.stringify(patch),
      });
      await loadOverview(selectedBrandId);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to update schedule.');
    } finally {
      setUpdatingScheduleId('');
    }
  };

  const recordDecision = async (
    detectionRecordId: string,
    status: 'CONFIRMED' | 'FALSE_POSITIVE',
    assetName: string,
  ) => {
    setDecidingRecordId(detectionRecordId);
    setError('');
    try {
      await apiRequest(`/detection-records/${encodeURIComponent(detectionRecordId)}/decision`, {
        method: 'POST',
        body: JSON.stringify({
          status,
          actor: 'external-watch-analyst',
          note:
            status === 'CONFIRMED'
              ? `Confirmed external brand impersonation asset (${assetName}) from External Brand Watch.`
              : `Dismissed external asset (${assetName}) as false positive / authorized property.`,
        }),
      });
      setBannerMessage(
        status === 'CONFIRMED'
          ? `${assetName} marked CONFIRMED. Open Detections to generate a human-authorized takedown draft.`
          : `${assetName} dismissed as FALSE POSITIVE.`,
      );
      await loadOverview(selectedBrandId);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Analyst decision failed.');
    } finally {
      setDecidingRecordId('');
    }
  };

  const latestSources: SourceStatus[] = overview?.recentRuns?.[0]?.sources_checked ?? [];
  const schedules = overview?.schedules ?? [];
  const candidates = overview?.externalCandidates ?? [];
  const runs = overview?.recentRuns ?? [];
  const notifications = overview?.notifications ?? [];

  return (
    <section className="space-y-6">
      {/* Header Banner */}
      <div className="surface-card p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-300">
                <Globe className="h-3.5 w-3.5" />
                {t('nav.externalWatch')}
              </span>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${
                  overview?.scheduler.enabled
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                    : 'border-slate-700 bg-slate-800/70 text-slate-300'
                }`}
              >
                {overview?.scheduler.enabled ? (
                  <Wifi className="h-3.5 w-3.5" />
                ) : (
                  <WifiOff className="h-3.5 w-3.5" />
                )}
                {overview?.scheduler.enabled
                  ? 'Continuous Background Watch Enabled'
                  : 'Manual Watch Mode'}
              </span>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${
                  overview?.scheduler.resendConfigured
                    ? 'border-violet-500/30 bg-violet-500/10 text-violet-300'
                    : 'border-slate-700 bg-slate-800/70 text-slate-400'
                }`}
              >
                <Mail className="h-3.5 w-3.5" />
                {overview?.scheduler.resendConfigured
                  ? 'Resend Brand Email Ready'
                  : 'Resend Email Not Configured'}
              </span>
            </div>

            <h1 className="mt-3 text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Automatic Internet-Wide Brand Impersonation Watch
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Continuously monitors configured external public sources — Certificate Transparency logs
              (<code className="text-slate-300">crt.sh</code>), live public DNS look-alike resolution,
              Bluesky, YouTube, Apple App Store, and configured URL threat feeds — comparing external
              assets against your verified Brand Profiles while excluding official domains and requiring
              corroborating signals before alerting.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <select
              aria-label="Filter External Watch by Brand"
              value={selectedBrandId}
              onChange={(e) => setSelectedBrandId(e.target.value)}
              className="rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="">All Protected Brands</option>
              {schedules.map((s) => (
                <option key={s.brand_id} value={s.brand_id}>
                  {s.brand_name ?? s.primary_domain ?? s.brand_id}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={() => void triggerDueWatches()}
              disabled={runningDue || loading}
              className="inline-flex items-center gap-2 rounded-xl border border-blue-500/40 bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500 disabled:opacity-50"
            >
              {runningDue ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Run Due Watches
            </button>

            <button
              type="button"
              onClick={() => void loadOverview(selectedBrandId)}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {bannerMessage && (
          <div className="mt-4 flex items-center gap-2.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{bannerMessage}</span>
          </div>
        )}

        {error && (
          <div className="mt-4 flex items-center gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <div className="surface-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Monitored Brands</span>
            <Radar className="h-4 w-4 text-blue-400" />
          </div>
          <p className="mt-3 text-2xl font-bold text-white">
            {loading ? '—' : overview?.summary.monitoredBrands ?? 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">Enrolled official brand profiles</p>
        </div>

        <div className="surface-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Newly Discovered</span>
            <Sparkles className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="mt-3 text-2xl font-bold text-white">
            {loading ? '—' : overview?.summary.newlyDiscoveredCount ?? 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">External candidates first seen recently</p>
        </div>

        <div className="surface-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">High-Risk Corroborated</span>
            <ShieldAlert className="h-4 w-4 text-orange-400" />
          </div>
          <p className="mt-3 text-2xl font-bold text-orange-300">
            {loading ? '—' : overview?.summary.highRiskCount ?? 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">Meets score + corroborating evidence gate</p>
        </div>

        <div className="surface-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Confirmed Threats</span>
            <ShieldCheck className="h-4 w-4 text-rose-400" />
          </div>
          <p className="mt-3 text-2xl font-bold text-rose-300">
            {loading ? '—' : overview?.summary.confirmedThreatsCount ?? 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">Verified by human analyst review</p>
        </div>

        <div className="surface-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Deduplicated Alerts</span>
            <Mail className="h-4 w-4 text-violet-400" />
          </div>
          <p className="mt-3 text-2xl font-bold text-white">
            {loading
              ? '—'
              : `${overview?.summary.alertsSentCount ?? 0} / ${overview?.summary.emailsDeliveredCount ?? 0}`}
          </p>
          <p className="mt-1 text-xs text-slate-500">In-app alerts / Resend emails delivered</p>
        </div>
      </div>

      {/* Per-Brand Continuous Schedules + Sources Checked */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <div className="surface-card p-5 sm:p-6 xl:col-span-2">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Brand Watch Schedules &amp; Scan Controls
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                Every active Brand Profile is enrolled automatically. Run an immediate external scan or tune cadence and alert thresholds.
              </p>
            </div>
            {onNavigate && (
              <button
                type="button"
                onClick={() => onNavigate('brands')}
                className="text-xs font-medium text-blue-400 hover:text-blue-300"
              >
                Manage Brand Profiles &rarr;
              </button>
            )}
          </div>

          {schedules.length === 0 ? (
            <p className="mt-5 rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-400">
              No active Brand Profiles registered yet. Register an official brand in Brand Profiles to begin automatic external monitoring.
            </p>
          ) : (
            <div className="mt-4 space-y-3">
              {schedules.map((sched) => {
                const isScanning = scanningBrandId === sched.brand_id;
                const isUpdating = updatingScheduleId === sched.brand_id;
                return (
                  <div
                    key={sched.id}
                    className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4 lg:flex-row lg:items-center lg:justify-between"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-white">
                          {sched.brand_name ?? 'Protected Brand'}
                        </span>
                        {sched.primary_domain && (
                          <span className="rounded-md border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-300">
                            {sched.primary_domain}
                          </span>
                        )}
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                            sched.is_enabled
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                              : 'border-slate-700 bg-slate-800 text-slate-400'
                          }`}
                        >
                          {sched.is_enabled ? 'Monitoring Active' : 'Paused'}
                        </span>
                      </div>

                      <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
                        <span className="inline-flex items-center gap-1">
                          <Clock3 className="h-3.5 w-3.5 text-slate-500" />
                          Last scan: <strong className="text-slate-300">{formatDateTime(sched.last_run_at)}</strong>
                        </span>
                        <span>
                          Next scan: <strong className="text-slate-300">{formatDateTime(sched.next_run_at)}</strong>
                        </span>
                        <span>
                          Alert email:{' '}
                          <strong className="text-slate-300">
                            {sched.contact_email || 'No contact_email configured'}
                          </strong>
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <label className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300">
                        <Sliders className="h-3.5 w-3.5 text-slate-500" />
                        <span>Every</span>
                        <select
                          aria-label={`Scan interval for ${sched.brand_name ?? sched.brand_id}`}
                          value={sched.interval_minutes}
                          disabled={isUpdating}
                          onChange={(e) =>
                            void updateSchedule(sched.brand_id, {
                              intervalMinutes: Number(e.target.value),
                            })
                          }
                          className="bg-transparent font-medium text-white focus:outline-none"
                        >
                          <option value={15} className="bg-slate-900">15m</option>
                          <option value={30} className="bg-slate-900">30m</option>
                          <option value={60} className="bg-slate-900">60m</option>
                          <option value={180} className="bg-slate-900">3h</option>
                          <option value={360} className="bg-slate-900">6h</option>
                        </select>
                      </label>

                      <button
                        type="button"
                        disabled={isUpdating}
                        onClick={() =>
                          void updateSchedule(sched.brand_id, { isEnabled: !sched.is_enabled })
                        }
                        className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                      >
                        {sched.is_enabled ? 'Pause' : 'Resume'}
                      </button>

                      <button
                        type="button"
                        disabled={isScanning}
                        onClick={() => void triggerBrandScan(sched.brand_id, sched.brand_name)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 bg-blue-500/15 px-3 py-1.5 text-xs font-semibold text-blue-200 hover:bg-blue-500/25 disabled:opacity-50"
                      >
                        {isScanning ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Radar className="h-3.5 w-3.5" />
                        )}
                        {isScanning ? 'Scanning...' : 'Scan External Sources'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Sources Checked & Availability */}
        <div className="surface-card p-5 sm:p-6">
          <h2 className="text-lg font-semibold text-white">External Sources &amp; Availability</h2>
          <p className="mt-1 text-xs text-slate-400">
            Real-time provider reachability from the most recent scan. Unavailable or unconfigured feeds are reported transparently.
          </p>

          {latestSources.length === 0 ? (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-xs leading-5 text-slate-400">
              Trigger <strong className="text-slate-200">Scan External Sources</strong> on any brand to record live source availability across Certificate Transparency logs, public DNS, Bluesky, YouTube, Apple App Store, Safe Browsing, and URLhaus.
            </div>
          ) : (
            <div className="mt-4 space-y-2.5">
              {latestSources.map((src, idx) => (
                <div
                  key={`${src.source}-${idx}`}
                  className="rounded-xl border border-slate-800 bg-slate-950/50 p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-200">
                      {SOURCE_LABELS[src.source] ?? src.source.replace(/_/g, ' ')}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${sourceStatusBadge(
                        src.status,
                      )}`}
                    >
                      {src.status.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                    <span>Candidates returned: {src.candidatesFound}</span>
                  </div>
                  {src.error && (
                    <p className="mt-1 text-[11px] text-slate-500">{src.error}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Discovered External Candidates + Analyst Triage */}
      <div className="surface-card p-5 sm:p-6">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Discovered External Candidates &amp; Evidence Triage
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Similarity of name or logo alone is capped at Medium risk and never triggers fraud alerts without corroborating signals. Confirm or dismiss findings directly below.
            </p>
          </div>
          {onNavigate && (
            <div className="flex items-center gap-3 text-xs">
              <button
                type="button"
                onClick={() => onNavigate('detections')}
                className="font-medium text-blue-400 hover:text-blue-300"
              >
                Open Analyst Queue &rarr;
              </button>
              <button
                type="button"
                onClick={() => onNavigate('findings')}
                className="font-medium text-slate-300 hover:text-white"
              >
                Findings &amp; Evidence &rarr;
              </button>
            </div>
          )}
        </div>

        {candidates.length === 0 ? (
          <p className="mt-5 rounded-xl border border-slate-800 bg-slate-950/50 p-5 text-sm text-slate-400">
            No external impersonation candidates recorded yet for this filter. Run an External Brand Watch scan to query public sources.
          </p>
        ) : (
          <div className="mt-4 space-y-3">
            {candidates.map((cand) => {
              const deciding = decidingRecordId === cand.detection_record_id;
              const corroborated = cand.corroborating_signals.length > 0;
              return (
                <div
                  key={cand.id}
                  className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"
                >
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {cand.change_state === 'new' && (
                          <span className="rounded-full border border-cyan-500/40 bg-cyan-500/15 px-2 py-0.5 text-[11px] font-bold uppercase text-cyan-200">
                            New
                          </span>
                        )}
                        {cand.change_state === 'escalated' && (
                          <span className="rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-bold uppercase text-rose-200">
                            Escalated
                          </span>
                        )}
                        <span className="rounded-md border border-slate-800 bg-slate-900 px-2 py-0.5 text-xs font-medium uppercase text-slate-300">
                          {cand.platform.replace(/_/g, ' ')}
                        </span>
                        <span className="font-mono text-sm font-semibold text-white">
                          {cand.display_name || cand.canonical_id}
                        </span>
                        {cand.brand_name && (
                          <span className="text-xs text-slate-400">
                            targeting <strong className="text-slate-200">{cand.brand_name}</strong>
                          </span>
                        )}
                        <span
                          className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${riskBadgeStyle(
                            cand.last_risk_level,
                          )}`}
                        >
                          {cand.last_risk_score.toFixed(0)}/100 · {cand.last_risk_level}
                        </span>
                        {cand.analyst_status && (
                          <span className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-0.5 text-[11px] font-medium text-slate-300">
                            Status: {cand.analyst_status.replace(/_/g, ' ')}
                          </span>
                        )}
                      </div>

                      <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                        <a
                          href={cand.target_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-blue-400 hover:underline"
                        >
                          {cand.target_url}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        <span>Seen {cand.times_seen}x</span>
                        <span>First seen: {formatDateTime(cand.first_seen_at)}</span>
                        <span>Last seen: {formatDateTime(cand.last_seen_at)}</span>
                      </div>

                      {corroborated ? (
                        <div className="mt-2 flex flex-wrap items-center gap-1.5">
                          <span className="text-[11px] font-medium text-orange-300">
                            Corroborating signals:
                          </span>
                          {cand.corroborating_signals.map((sig, i) => (
                            <span
                              key={`${sig}-${i}`}
                              className="rounded-md border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[11px] text-orange-200"
                            >
                              {sig}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="mt-2 text-xs text-amber-300/90">
                          Similarity-only lead (no corroborating fraud signals yet) — auto-alert suppressed pending human review.
                        </p>
                      )}

                      {cand.evidence_summary?.summary && (
                        <p className="mt-2 text-xs leading-5 text-slate-400">
                          {cand.evidence_summary.summary}
                        </p>
                      )}
                    </div>

                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      {cand.detection_record_id && (
                        <>
                          <button
                            type="button"
                            disabled={deciding || cand.analyst_status === 'CONFIRMED'}
                            onClick={() =>
                              void recordDecision(
                                cand.detection_record_id!,
                                'CONFIRMED',
                                cand.canonical_id,
                              )
                            }
                            className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-500/25 disabled:opacity-40"
                          >
                            <ShieldAlert className="h-3.5 w-3.5" />
                            Confirm Threat
                          </button>

                          <button
                            type="button"
                            disabled={deciding || cand.analyst_status === 'FALSE_POSITIVE'}
                            onClick={() =>
                              void recordDecision(
                                cand.detection_record_id!,
                                'FALSE_POSITIVE',
                                cand.canonical_id,
                              )
                            }
                            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                          >
                            <ShieldX className="h-3.5 w-3.5" />
                            Dismiss
                          </button>
                        </>
                      )}

                      {onInspectUrl && (
                        <button
                          type="button"
                          onClick={() => onInspectUrl(cand.target_url)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-500/20"
                        >
                          Deep Inspect
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Scan History + Deduplicated Alert/Email Audit */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="surface-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-400" />
            <h2 className="text-lg font-semibold text-white">Recent External Watch Runs</h2>
          </div>
          {runs.length === 0 ? (
            <p className="mt-4 text-xs text-slate-400">No watch runs recorded yet.</p>
          ) : (
            <div className="mt-4 space-y-2.5">
              {runs.slice(0, 8).map((run) => (
                <div
                  key={run.id}
                  className="flex flex-col gap-1.5 rounded-xl border border-slate-800 bg-slate-950/50 p-3.5 text-xs sm:flex-row sm:items-center sm:justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-200">
                        {run.brand_name ?? run.brand_id}
                      </span>
                      <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">
                        {run.trigger_type.replace(/_/g, ' ')}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                          run.status === 'COMPLETED'
                            ? 'bg-emerald-500/15 text-emerald-300'
                            : run.status === 'PARTIAL'
                              ? 'bg-amber-500/15 text-amber-300'
                              : 'bg-rose-500/15 text-rose-300'
                        }`}
                      >
                        {run.status}
                      </span>
                    </div>
                    <p className="mt-1 text-slate-400">
                      {run.candidates_discovered} found · {run.new_candidates_count} new ·{' '}
                      {run.high_risk_count} high-risk · {run.alerts_created} alert(s)
                      {run.deduplicated_alerts_skipped > 0
                        ? ` · ${run.deduplicated_alerts_skipped} duplicate(s) suppressed`
                        : ''}
                    </p>
                  </div>
                  <span className="text-slate-500">{formatDateTime(run.started_at)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="surface-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-violet-400" />
            <h2 className="text-lg font-semibold text-white">
              Alert &amp; Official Email Delivery Status
            </h2>
          </div>
          {notifications.length === 0 ? (
            <p className="mt-4 text-xs text-slate-400">
              No automatic high-risk external alerts dispatched yet. Alerts are deduplicated per brand, external asset, and risk band.
            </p>
          ) : (
            <div className="mt-4 space-y-2.5">
              {notifications.slice(0, 8).map((notif) => (
                <div
                  key={notif.id}
                  className="rounded-xl border border-slate-800 bg-slate-950/50 p-3.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-slate-200">
                      {notif.canonical_id}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${
                        notif.email_status === 'sent'
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          : notif.email_status === 'failed'
                            ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                            : 'border-slate-700 bg-slate-800 text-slate-300'
                      }`}
                    >
                      Email: {notif.email_status.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-400">
                    Brand: <strong className="text-slate-300">{notif.brand_name ?? notif.brand_id}</strong>{' '}
                    · Score: {notif.risk_score.toFixed(0)}/100 ({notif.risk_level}) · Recipient:{' '}
                    {notif.recipient_email || 'none'}
                  </p>
                  {notif.email_error && (
                    <p className="mt-1 text-[11px] text-slate-500">{notif.email_error}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default ExternalWatchView;
