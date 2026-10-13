
import React, { useEffect, useState, type FormEvent } from 'react';
import {
  AlertTriangle, ArrowRight, CheckCircle2, ExternalLink, Globe,
  Search, ShieldAlert,
} from 'lucide-react';
import { apiRequest } from './api';

type InvestigationResult = {
  target?: string;
  verdict?: string;
  target_type?: string;
  safe_browsing_status?: string | null;
  urlhaus_status?: string | null;
  details?: unknown;
};

type Props = {
  t: any;
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

function verdictStyle(verdict?: string): string {
  switch ((verdict || '').toUpperCase()) {
    case 'MALICIOUS':
      return 'risk-critical';
    case 'SUSPICIOUS':
      return 'risk-medium';
    case 'SAFE':
    case 'CLEAN':
      return 'risk-low';
    default:
      return 'border border-slate-700 bg-slate-800 text-slate-300';
  }
}

export const InvestigationsView: React.FC<Props> = ({ t, defaultTarget = '' }) => {
  const [input, setInput] = useState(defaultTarget);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (defaultTarget) setInput(defaultTarget);
  }, [defaultTarget]);

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
          body: JSON.stringify({ target }),
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

  const translations = t?.investigations || {};

  return (
    <main className="page-enter space-y-6">
      <header className="border-b border-slate-800 pb-5">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
          Threat investigation
        </p>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
          <Search className="text-cyan-400" />
          {translations.title || 'URL & Account Investigation'}
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
          {translations.subtitle || 'Inspect a submitted target using the security checks available in this deployment.'}
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
            placeholder={translations.inputPlaceholder || 'https://example.com or a supported profile'}
            autoComplete="off"
            maxLength={2048}
            required
          />
        </label>

        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <p className="text-xs leading-5 text-slate-500">
            Only submit targets you are authorized to investigate. A result is limited to the checks reported by the backend.
          </p>
          <button type="submit" disabled={loading || !input.trim()} className="btn-primary shrink-0">
            {loading ? <><span className="status-dot is-scanning" /> Inspecting…</> : <>{translations.scanBtn || 'Analyze target'} <ArrowRight size={15} /></>}
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

      {result && (
        <section className="surface-card space-y-5 p-4 sm:p-6">
          <div className="flex flex-col justify-between gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-start">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Inspected target</p>
              <p className="mt-2 break-all font-mono text-base font-semibold text-white">
                {result.target || input.trim()}
              </p>
              <p className="mt-1 text-xs text-slate-400">
                Target type: {result.target_type || 'Not specified'}
              </p>
              {isWebUrl(result.target || input.trim()) && (
                <a
                  href={result.target || input.trim()}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-2 inline-flex items-center gap-1 text-xs text-blue-300 hover:underline"
                >
                  Open target <ExternalLink size={12} />
                </a>
              )}
            </div>
            <span className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold ${verdictStyle(result.verdict)}`}>
              {['SAFE', 'CLEAN'].includes((result.verdict || '').toUpperCase())
                ? <CheckCircle2 size={14} />
                : <ShieldAlert size={14} />}
              {result.verdict || 'Verdict not supplied'}
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            {[
              ['Google Safe Browsing', result.safe_browsing_status],
              ['URLhaus', result.urlhaus_status],
            ].map(([label, value]) => (
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4" key={label}>
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Globe size={15} className="text-cyan-400" /> {label}
                </div>
                <p className="mt-3 break-words font-medium text-slate-200">
                  {value == null || value === '' ? 'No status supplied by the API' : value}
                </p>
              </div>
            ))}
          </div>

          {result.details !== undefined && result.details !== null && (
            <details className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <summary className="cursor-pointer text-sm font-semibold text-slate-200">
                View returned evidence details
              </summary>
              <pre className="mt-4 overflow-x-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">
                {JSON.stringify(result.details, null, 2)}
              </pre>
            </details>
          )}
        </section>
      )}
    </main>
  );
};
