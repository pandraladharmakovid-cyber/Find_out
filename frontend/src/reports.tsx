import React, { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Flag,
  Newspaper,
  RefreshCw,
  Send,
} from 'lucide-react';
import { apiRequest } from './api';
import type { Translator } from './i18n';

type Complaint = {
  id: string | number;
  platform?: string;
  target_url?: string;
  reference_id?: string;
  status?: string;
  description?: string;
};

type LiveFeedItem = {
  id: string;
  title: string;
  vendor: string;
  product: string;
  severity: string;
  dateAdded: string;
  knownRansomware: boolean;
  url: string;
};

type LiveFeed = {
  status: 'available' | 'unavailable' | 'not_configured';
  detail: string;
  fetchedAt: string | null;
  totalAvailable: number;
  items: LiveFeedItem[];
};

type ThreatAlert = {
  id: string | number;
  title: string;
  category?: string;
  severity?: string;
  published_at?: string;
  created_at?: string;
  summary?: string;
  description?: string;
  prevention_guidance?: string;
  source_url?: string;
  status?: string;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The request failed.';
}

function safeHttpUrl(value?: string): boolean {
  try {
    if (!value) return false;
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function formatAlertDate(value?: string): string {
  if (!value) return 'Date not supplied';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? 'Date unavailable'
    : date.toLocaleString();
}

function alertSourceName(value?: string): string {
  const sourceUrl = value?.trim();
  if (!sourceUrl || !safeHttpUrl(sourceUrl)) return 'Source not supplied';
  return new URL(sourceUrl).hostname;
}

export const ReportsView: React.FC<{ t: Translator }> = ({ t }) => {
  const [complaints, setComplaints] = useState<Complaint[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [form, setForm] = useState({
    platform: 'web',
    target_url: '',
    description: '',
  });
  const [reference, setReference] = useState('');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [liveFeed, setLiveFeed] = useState<LiveFeed | null>(null);
  const [feedLoading, setFeedLoading] = useState(true);
  const [sendingId, setSendingId] = useState<string | null>(null);
  const [deliveryNotice, setDeliveryNotice] = useState('');

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    setError('');

    try {
      const [complaintResponse, alertResponse] = await Promise.all([
        apiRequest<{ data?: Complaint[] }>('/complaints'),
        apiRequest<{ data?: ThreatAlert[] }>('/alerts'),
      ]);

      if (!Array.isArray(complaintResponse?.data) || !Array.isArray(alertResponse?.data)) {
        throw new Error('The API returned an unexpected complaints or alerts response.');
      }

      setComplaints(complaintResponse.data);
      setAlerts(alertResponse.data);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  const loadLiveFeed = useCallback(async (refresh = false) => {
    setFeedLoading(true);
    try {
      const response = await apiRequest<{ data?: LiveFeed }>(
        `/alerts/feed?limit=8${refresh ? '&refresh=1' : ''}`,
        { timeoutMs: 25000 },
      );
      setLiveFeed(response?.data ?? null);
    } catch (err) {
      // A blocked feed must surface as an explanation, never as fake alarms.
      setLiveFeed({
        status: 'unavailable',
        detail: errorMessage(err),
        fetchedAt: null,
        totalAvailable: 0,
        items: [],
      });
    } finally {
      setFeedLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLiveFeed();
  }, [loadLiveFeed]);

  async function submitComplaintToRecipient(complaint: Complaint) {
    setSendingId(String(complaint.id));
    setDeliveryNotice('');
    setError('');

    try {
      const response = await apiRequest<{ data?: { delivery?: { detail?: string; status?: string } } }>(
        `/complaints/${encodeURIComponent(String(complaint.id))}/send`,
        { method: 'POST', timeoutMs: 40000 },
      );

      const detail = response?.data?.delivery?.detail ?? 'The notice was accepted for delivery.';
      setDeliveryNotice(detail);
      setSuccess(detail);
      await fetchData();
    } catch (err) {
      setError(errorMessage(err));
      await fetchData();
    } finally {
      setSendingId(null);
    }
  }

  async function submitComplaint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    setReference('');

    try {
      const response = await apiRequest<{ data?: Complaint }>('/complaints', {
        method: 'POST',
        body: JSON.stringify({
          platform: form.platform.trim(),
          target_url: form.target_url.trim(),
          description: form.description.trim(),
        }),
      });

      const id = response?.data?.reference_id;
      if (!id) {
        throw new Error('The server did not return a complaint reference. Check the complaints endpoint before retrying.');
      }

      setReference(id);
      setSuccess('Report saved for review. No external platform takedown was submitted.');
      setForm({ platform: 'web', target_url: '', description: '' });

      await fetchData();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page-enter space-y-6">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-center">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-rose-400">
            Incident reporting
          </p>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
            <Flag className="text-rose-400" />
            {t('reports.title')}
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">          {t('reports.subtitle')}</p>
        </div>

        <button
          type="button"
          onClick={() => void fetchData()}
          disabled={refreshing}
          className="btn-secondary"
        >
          <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
          {t('common.refresh')}
        </button>
      </header>

      {error && (
        <div role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <div className="flex items-start gap-2">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold">Request unsuccessful</p>
              <p className="mt-1 break-words">{error}</p>
            </div>
          </div>
        </div>
      )}

      {deliveryNotice && (
        <div role="status" className="rounded-xl border border-emerald-400/30 bg-emerald-400/10 p-4 text-sm text-emerald-200">
          <div className="flex items-start gap-3">
            <CheckCircle2 size={19} className="shrink-0" />
            <p className="font-semibold">{deliveryNotice}</p>
          </div>
        </div>
      )}

      {success && reference && (
        <div role="status" className="rounded-xl border border-emerald-400/30 bg-emerald-400/10 p-4 text-sm text-emerald-200">
          <div className="flex items-start gap-3">
            <CheckCircle2 size={19} className="shrink-0" />
            <div>
              <p className="font-semibold">{success}</p>
              <p className="mt-2">
                Reference: <span className="font-mono font-bold">{reference}</span>
              </p>
            </div>
          </div>
        </div>
      )}

      <form onSubmit={submitComplaint} className="surface-card space-y-4 p-4 sm:p-6">
        <h2 className="font-semibold text-white">Submit an impersonation report</h2>

        <div className="grid gap-4 sm:grid-cols-2">
          <label className="space-y-2 text-sm text-slate-300">
            Platform
            <select
              className="w-full"
              value={form.platform}
              onChange={event => setForm({ ...form, platform: event.target.value })}
              required
            >
              <option value="web">Website</option>
              <option value="instagram">Instagram</option>
              <option value="facebook">Facebook</option>
              <option value="x">X</option>
              <option value="youtube">YouTube</option>
              <option value="bluesky">Bluesky</option>
              <option value="google_play">Google Play</option>
              <option value="apple_app_store">Apple App Store</option>
              <option value="other">Other</option>
            </select>
          </label>

          <label className="space-y-2 text-sm text-slate-300">
            Suspicious URL or account identifier
            <input
              className="w-full"
              value={form.target_url}
              onChange={event => setForm({ ...form, target_url: event.target.value })}
              placeholder="https://example.com or @account"
              maxLength={2048}
              required
            />
          </label>
        </div>

        <label className="block space-y-2 text-sm text-slate-300">
          Evidence and incident details
          <textarea
            className="w-full"
            rows={4}
            value={form.description}
            onChange={event => setForm({ ...form, description: event.target.value })}
            placeholder="Describe the suspected impersonation and the evidence you observed."
            maxLength={10000}
            required
          />
        </label>

        <button type="submit" disabled={loading} className="btn-primary">
          <Send size={15} />
          {loading ? 'Submitting…' : t('reports.submitBtn')}
        </button>
      </form>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
          Complaint history
        </h2>

        {refreshing ? (
          <div className="skeleton h-24 w-full" />
        ) : complaints.length === 0 ? (
          <div className="surface-card p-6 text-sm text-slate-400">
            No complaint records were returned by the backend.
          </div>
        ) : (
          complaints.map(complaint => (
            <article className="surface-card p-4" key={complaint.id}>
              <div className="flex flex-col justify-between gap-3 sm:flex-row">
                <div className="min-w-0">
                  <h3 className="break-all font-semibold text-white">
                    {complaint.target_url || 'Target not supplied'}
                  </h3>
                  <p className="mt-1 text-xs text-slate-400">
                    Platform: {complaint.platform || 'Unknown'}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Reference: {complaint.reference_id || 'Not supplied'}
                  </p>
                  {complaint.description && (
                    <p className="mt-3 whitespace-pre-wrap break-words text-sm text-slate-400">
                      {complaint.description}
                    </p>
                  )}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-2">
                  <span className="w-fit rounded-full border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-slate-300">
                    {complaint.status || 'Status unavailable'}
                  </span>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => void submitComplaintToRecipient(complaint)}
                    disabled={sendingId === String(complaint.id)}
                  >
                    <Send size={14} />
                    {sendingId === String(complaint.id) ? 'Submitting…' : 'Submit to recipient'}
                  </button>
                </div>
              </div>
            </article>
          ))
        )}
      </section>

      <section className="space-y-3 border-t border-slate-800 pt-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-emerald-300">
            <Newspaper size={17} />
            Live threat feed · CISA KEV
          </h2>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => void loadLiveFeed(true)}
            disabled={feedLoading}
          >
            <RefreshCw size={14} className={feedLoading ? 'animate-spin' : ''} /> Refresh feed
          </button>
        </div>

        {liveFeed?.status === 'available' ? (
          <>
            <p className="text-xs leading-5 text-slate-500">
              {liveFeed.totalAvailable} known-exploited vulnerabilities in the catalogue · fetched{' '}
              {liveFeed.fetchedAt ? new Date(liveFeed.fetchedAt).toLocaleString() : 'just now'}
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              {liveFeed.items.map((item) => (
                <article className="surface-card space-y-2 p-4" key={item.id}>
                  <div className="flex items-center justify-between gap-3">
                    <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-xs text-emerald-300">
                      {item.severity}
                    </span>
                    <span className="text-xs text-slate-500">{item.dateAdded}</span>
                  </div>
                  <h3 className="font-semibold text-white">{item.id}</h3>
                  <p className="text-sm leading-6 text-slate-400">{item.title}</p>
                  <p className="text-xs text-slate-500">
                    {item.vendor} · {item.product}
                    {item.knownRansomware ? ' · known ransomware use' : ''}
                  </p>
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-blue-300 hover:underline"
                  >
                    Open in CISA catalogue <ExternalLink size={12} />
                  </a>
                </article>
              ))}
            </div>
          </>
        ) : (
          <div className="surface-card p-5 text-sm text-slate-400">
            {feedLoading
              ? 'Loading the live CISA catalogue…'
              : liveFeed?.status === 'not_configured'
                ? 'The live threat feed is disabled in the backend configuration.'
                : `The live feed could not be read: ${liveFeed?.detail ?? 'unknown error'}. No placeholder bulletins are shown.`}
          </div>
        )}
      </section>

      <section className="space-y-3 border-t border-slate-800 pt-5">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-amber-300">
          <Newspaper size={17} />
          Saved security alerts
        </h2>
        <p className="text-xs leading-5 text-slate-500">
          Alert details are displayed as saved; verify them with the linked source before acting.
        </p>

        {refreshing ? (
          <div className="skeleton h-28 w-full" />
        ) : alerts.length === 0 ? (
          <div className="surface-card p-6 text-sm text-slate-400">
            No alert records were returned. No placeholder threat bulletins are being presented as real news.
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {alerts.map(alert => (
              <article className="surface-card space-y-3 p-4" key={alert.id}>
                <div className="flex items-center justify-between gap-3">
                  <span className="rounded-full border border-amber-400/20 bg-amber-400/10 px-2.5 py-1 text-xs text-amber-300">
                    {alert.severity || 'Severity not supplied'}
                  </span>
                  <span className="text-xs text-slate-500">
                    {formatAlertDate(alert.published_at || alert.created_at)}
                  </span>
                </div>
                <h3 className="font-semibold text-white">
                  {alert.title}
                </h3>
                <p className="text-sm leading-6 text-slate-400">
                  {alert.summary || alert.description || 'No summary supplied by the alert source.'}
                </p>
                {alert.category && (
                  <p className="text-xs text-slate-500">Category: {alert.category}</p>
                )}
                {alert.status && (
                  <p className="text-xs text-slate-500">Record status: {alert.status}</p>
                )}
                {alert.prevention_guidance && (
                  <p className="rounded-lg bg-slate-950/60 p-3 text-sm text-slate-300">
                    Prevention: {alert.prevention_guidance}
                  </p>
                )}
                {safeHttpUrl(alert.source_url) && (
                  <a
                    href={alert.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-blue-300 hover:underline"
                  >
                    Source site: {alertSourceName(alert.source_url)} <ExternalLink size={12} />
                  </a>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
};
