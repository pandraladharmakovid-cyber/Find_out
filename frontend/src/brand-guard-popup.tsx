import React, { useEffect, useState } from 'react';
import {
  CircleAlert,
  LoaderCircle,
  Mail,
  MailCheck,
  ShieldAlert,
  X,
} from 'lucide-react';
import { apiRequest } from './api';

/**
 * Brand Guard pop-up.
 *
 * Shown when somebody tries to register a brand profile that is confusingly
 * similar to an already-registered official brand. Lists every conflicting
 * official brand and offers a "Notify official brand" button that e-mails the
 * registered company (through the backend's Resend integration).
 */

export type GuardConflict = {
  brandId: string;
  brandName: string;
  primaryDomain: string;
  website?: string | null;
  logoUrl?: string | null;
  canNotify: boolean;
  matchType: 'name' | 'alternate_name' | 'domain';
  matchedValue: string;
  similarity: number;
  verdict: 'exact' | 'impersonation' | 'lookalike';
  summary: string;
};

type NotifyState = {
  status: 'idle' | 'sending' | 'sent' | 'failed';
  message: string;
};

function verdictBadge(verdict: GuardConflict['verdict']): {
  label: string;
  classes: string;
} {
  switch (verdict) {
    case 'exact':
      return {
        label: 'EXACT MATCH',
        classes: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
      };
    case 'impersonation':
      return {
        label: 'LIKELY IMPERSONATION',
        classes: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
      };
    default:
      return {
        label: 'LOOKALIKE',
        classes: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
      };
  }
}

export const BrandGuardPopup: React.FC<{
  suspectName: string;
  suspectDomain: string;
  conflicts: GuardConflict[];
  onClose: () => void;
  onRegisterAnyway: () => void;
  registering: boolean;
}> = ({ suspectName, suspectDomain, conflicts, onClose, onRegisterAnyway, registering }) => {
  const [notifyStates, setNotifyStates] = useState<Record<string, NotifyState>>({});
  const [emailConfigured, setEmailConfigured] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiRequest<{ data?: { emailConfigured?: boolean } }>('/brand-guard/status')
      .then((response) => {
        if (!cancelled) setEmailConfigured(Boolean(response?.data?.emailConfigured));
      })
      .catch(() => {
        if (!cancelled) setEmailConfigured(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const notifyBrand = async (conflict: GuardConflict) => {
    setNotifyStates((current) => ({
      ...current,
      [conflict.brandId]: { status: 'sending', message: '' },
    }));

    try {
      const response = await apiRequest<{
        data?: { recipient_email?: string; provider_message_id?: string | null };
        meta?: { recipient?: string };
      }>('/brand-guard/alert', {
        method: 'POST',
        body: JSON.stringify({
          brandId: conflict.brandId,
          suspectName,
          suspectDomain: suspectDomain || undefined,
          matchType: conflict.matchType,
          similarity: conflict.similarity,
          verdict: conflict.verdict,
          note: `Flagged automatically during a registration attempt on the Find_out web dashboard.`,
        }),
      });

      const recipient =
        response?.meta?.recipient ?? response?.data?.recipient_email ?? 'the registered contact';

      setNotifyStates((current) => ({
        ...current,
        [conflict.brandId]: {
          status: 'sent',
          message: `Alert e-mail delivered to ${recipient}. ${conflict.brandName} has been notified of this impersonation attempt.`,
        },
      }));
    } catch (error) {
      setNotifyStates((current) => ({
        ...current,
        [conflict.brandId]: {
          status: 'failed',
          message:
            error instanceof Error
              ? error.message
              : 'The alert e-mail could not be sent. Try again.',
        },
      }));
    }
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center overflow-y-auto bg-black/80 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="brand-guard-title"
        className="my-auto w-full max-w-2xl rounded-2xl border border-rose-500/40 bg-slate-950 p-5 shadow-2xl sm:p-7"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 rounded-xl border border-rose-500/40 bg-rose-500/15 p-2.5">
              <ShieldAlert className="h-6 w-6 text-rose-400" />
            </span>
            <div>
              <h2 id="brand-guard-title" className="text-xl font-bold text-white">
                Possible brand impersonation detected
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                “{suspectName}”
                {suspectDomain ? ` (${suspectDomain})` : ''} is confusingly similar to{' '}
                {conflicts.length === 1
                  ? 'an officially registered brand'
                  : `${conflicts.length} officially registered brands`}{' '}
                on this platform.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close impersonation warning"
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {emailConfigured === false && (
          <div className="mb-4 flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
            <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              E-mail delivery is not configured on this server (RESEND_API_KEY is empty).
              The notify button will record the attempt but cannot deliver the e-mail.
            </span>
          </div>
        )}

        <div className="max-h-[50vh] space-y-3 overflow-y-auto pr-1">
          {conflicts.map((conflict) => {
            const badge = verdictBadge(conflict.verdict);
            const notify = notifyStates[conflict.brandId] ?? {
              status: 'idle' as const,
              message: '',
            };
            return (
              <article
                key={conflict.brandId}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="truncate text-base font-semibold text-white">
                      {conflict.brandName}
                      <span className="ml-2 text-xs font-normal text-slate-400">
                        {conflict.primaryDomain}
                      </span>
                    </h3>
                  </div>
                  <span
                    className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-wide ${badge.classes}`}
                  >
                    {badge.label} · {(conflict.similarity * 100).toFixed(1)}%
                  </span>
                </div>

                <p className="mt-2 text-sm leading-relaxed text-slate-300">{conflict.summary}</p>

                {notify.status === 'sent' ? (
                  <div className="mt-3 flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">
                    <MailCheck className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{notify.message}</span>
                  </div>
                ) : (
                  <div className="mt-3 space-y-2">
                    {notify.status === 'failed' && (
                      <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
                        <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{notify.message}</span>
                      </div>
                    )}
                    <button
                      type="button"
                      disabled={notify.status === 'sending' || !conflict.canNotify}
                      onClick={() => void notifyBrand(conflict)}
                      className="inline-flex items-center gap-2 rounded-xl border border-rose-500/50 bg-rose-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {notify.status === 'sending' ? (
                        <LoaderCircle className="h-4 w-4 animate-spin" />
                      ) : (
                        <Mail className="h-4 w-4" />
                      )}
                      {notify.status === 'sending'
                        ? 'Sending alert…'
                        : `Notify official brand (${conflict.brandName})`}
                    </button>
                    {!conflict.canNotify && (
                      <p className="text-xs text-slate-500">
                        {conflict.brandName} has no registered contact e-mail yet. Edit that
                        brand profile and add one to enable alert delivery.
                      </p>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </div>

        <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-slate-800 pt-4">
          <button type="button" onClick={onClose} className="btn-secondary" disabled={registering}>
            Cancel registration
          </button>
          <button
            type="button"
            onClick={onRegisterAnyway}
            disabled={registering}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-slate-700 disabled:opacity-50"
          >
            {registering && <LoaderCircle className="h-4 w-4 animate-spin" />}
            Register anyway (flagged)
          </button>
        </div>
      </section>
    </div>
  );
};

export default BrandGuardPopup;
