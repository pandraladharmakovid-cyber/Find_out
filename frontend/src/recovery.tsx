import React, { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CheckSquare,
  ClipboardCheck,
  Copy,
  Square,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldCheck,
  Smartphone,
  UserRound,
} from 'lucide-react';
import { apiRequest } from './api';
import type { Translator } from './i18n';

type RecoveryResult = {
  safety_verdict?: string;
  compromised_count?: number | null;
  click_consequences?: string;
  victim_details?: string;
  immediate_safety?: string;
  existing_access_check?: string;
  complete_solution?: string;
  delivery_channel?: string;
  device_risk?: string;
  recovery_steps?: string[];
  evidence_note?: string;
};

const scenarios = [
  { value: 'opened_link', label: 'Opened or clicked a suspicious link', icon: ArrowRight },
  { value: 'entered_password', label: 'Entered a password or credentials', icon: KeyRound },
  { value: 'installed_app', label: 'Installed an APK or application', icon: Smartphone },
  { value: 'granted_permissions', label: 'Granted permissions or OAuth access', icon: LockKeyhole },
];

const recoveryFields: {
  key: keyof RecoveryResult;
  title: string;
  icon: React.ElementType;
}[] = [
  { key: 'safety_verdict', title: 'Security assessment', icon: ShieldCheck },
  { key: 'click_consequences', title: 'Potential consequences', icon: AlertTriangle },
  { key: 'victim_details', title: 'Documented victim information', icon: UserRound },
  { key: 'immediate_safety', title: 'Immediate safety actions', icon: LockKeyhole },
  { key: 'existing_access_check', title: 'Account access review', icon: KeyRound },
  { key: 'complete_solution', title: 'Prevention recommendations', icon: ClipboardCheck },
  { key: 'delivery_channel', title: 'Delivery channel', icon: Network },
  { key: 'device_risk', title: 'Device risk assessment', icon: Smartphone },
];

function verdictTone(verdict?: string): { className: string; label: string } {
  switch ((verdict || '').toLowerCase()) {
    case 'compromised':
      return { className: 'border-rose-500/40 bg-rose-500/10 text-rose-200', label: 'Act now' };
    case 'safe':
    case 'not_compromised':
      return { className: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200', label: 'No compromise established' };
    default:
      return {
        className: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
        label: 'Unverified — follow the steps anyway',
      };
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The assessment request failed.';
}

export const RecoveryView: React.FC<{ t: Translator }> = ({ t }) => {
  const [target, setTarget] = useState('');
  const [scenario, setScenario] = useState('opened_link');
  const [result, setResult] = useState<RecoveryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [doneSteps, setDoneSteps] = useState<Record<number, boolean>>({});
  const [copied, setCopied] = useState(false);

  async function handleTriage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const identifier = target.trim();
    if (!identifier) {
      setError('Enter a URL, account identifier, or application identifier.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setDoneSteps({});
    setCopied(false);

    try {
      const response = await apiRequest<{ data?: RecoveryResult }>(
        '/recovery/assess',
        {
          method: 'POST',
          body: JSON.stringify({
            identifier,
            incident_type: scenario,
          }),
        },
      );

      if (!response?.data || typeof response.data !== 'object') {
        throw new Error('The backend returned no valid assessment.');
      }

      setResult(response.data);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const steps = result?.recovery_steps;
  const validSteps = Array.isArray(steps)
    ? steps.filter((step): step is string => typeof step === 'string' && step.trim().length > 0)
    : [];

  return (
    <main className="page-enter space-y-6">
      <header className="border-b border-slate-800 pb-5">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-400">
          Incident response
        </p>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
          <ShieldCheck className="text-emerald-400" />
          {t('recovery.title')}
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          {t('recovery.subtitle')}
        </p>
      </header>

      <form onSubmit={handleTriage} className="surface-card space-y-5 p-4 sm:p-6">
        <div>
          <label htmlFor="recovery-target" className="mb-2 block text-sm font-medium text-slate-300">
            Target URL, account or application
          </label>
          <input
            id="recovery-target"
            value={target}
            onChange={event => setTarget(event.target.value)}
            placeholder="https://example.com or @account"
            maxLength={2048}
            autoComplete="off"
            required
            className="w-full"
          />
        </div>

        <fieldset>
          <legend className="mb-3 text-sm font-medium text-slate-300">
            What happened?
          </legend>
          <div className="grid gap-3 sm:grid-cols-2">
            {scenarios.map(option => {
              const Icon = option.icon;
              return (
                <label
                  key={option.value}
                  className={`flex cursor-pointer items-center gap-3 rounded-xl border p-4 transition-colors ${
                    scenario === option.value
                      ? 'border-cyan-500/60 bg-cyan-500/10'
                      : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'
                  }`}
                >
                  <input
                    type="radio"
                    name="incident-scenario"
                    value={option.value}
                    checked={scenario === option.value}
                    onChange={() => setScenario(option.value)}
                    className="accent-cyan-400"
                  />
                  <Icon size={18} className="shrink-0 text-cyan-400" />
                  <span className="text-sm text-slate-200">{option.label}</span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <button type="submit" disabled={loading} className="btn-primary">
          {loading ? 'Assessing incident…' : t('recovery.runBtn')}
          {!loading && <ArrowRight size={16} />}
        </button>
      </form>

      {error && (
        <div role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <div className="flex items-start gap-2">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold">Assessment unsuccessful</p>
              <p className="mt-1 break-words">{error}</p>
              <p className="mt-2 text-rose-200/75">
                No assessment result is being inferred from a failed request.
              </p>
            </div>
          </div>
        </div>
      )}

      {result && (
        <section className="space-y-4" aria-live="polite">
          <div className={`surface-card border p-5 ${verdictTone(result.safety_verdict).className}`}>
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wider opacity-70">
                  Security assessment
                </p>
                <p className="mt-1.5 text-lg font-bold capitalize">
                  {(result.safety_verdict || 'no verdict supplied').replace(/_/g, ' ')}
                </p>
                <p className="mt-1 break-words text-sm opacity-80">{target.trim()}</p>
              </div>
              <span className="shrink-0 rounded-full border border-white/20 bg-black/20 px-3 py-1.5 text-xs font-semibold">
                {verdictTone(result.safety_verdict).label}
              </span>
            </div>

            <div className="mt-4 grid gap-3 border-t border-white/10 pt-4 sm:grid-cols-3">
              <div>
                <p className="text-[11px] uppercase tracking-wider opacity-70">Documented compromises</p>
                <p className="mt-1 text-xl font-semibold">
                  {typeof result.compromised_count === 'number' ? result.compromised_count : 'Not determined'}
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider opacity-70">Checklist</p>
                <p className="mt-1 text-xl font-semibold">
                  {Object.values(doneSteps).filter(Boolean).length}/{validSteps.length || 0} done
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider opacity-70">Scenario</p>
                <p className="mt-1 text-sm font-semibold capitalize">
                  {scenarios.find(option => option.value === scenario)?.label ?? scenario}
                </p>
              </div>
            </div>
          </div>

          {result.evidence_note && (
            <p className="flex items-start gap-2 rounded-xl border border-slate-700 bg-slate-900/60 p-3 text-xs leading-5 text-slate-400">
              <AlertTriangle size={15} className="mt-0.5 shrink-0 text-amber-400" />
              {result.evidence_note}
            </p>
          )}

          <div className="grid gap-3 sm:grid-cols-2">
            {recoveryFields.map(field => {
              const value = result[field.key];
              if (typeof value !== 'string' || !value.trim()) return null;

              const Icon = field.icon;

              return (
                <article className="surface-card p-4" key={field.key}>
                  <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                    <Icon size={17} className="text-cyan-400" />
                    {field.title}
                  </h2>
                  <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-400">
                    {value}
                  </p>
                </article>
              );
            })}
          </div>

          {validSteps.length > 0 && (
            <section className="surface-card p-5">
              <h2 className="flex items-center gap-2 font-semibold text-white">
                <ClipboardCheck className="text-emerald-400" size={19} />
                Recovery checklist
              </h2>
              <div className="mt-2 flex items-center gap-3">
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full bg-emerald-500 transition-all duration-300"
                    style={{
                      width: `${validSteps.length ? (Object.values(doneSteps).filter(Boolean).length / validSteps.length) * 100 : 0}%`,
                    }}
                  />
                </div>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard
                      ?.writeText(validSteps.map((step, index) => `${index + 1}. ${step}`).join('\n'))
                      .then(() => {
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      })
                      .catch(() => setCopied(false));
                  }}
                  className="btn-secondary inline-flex items-center gap-1.5 text-xs"
                >
                  <Copy size={13} />
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>

              <ol className="mt-4 space-y-2">
                {validSteps.map((step, index) => {
                  const done = Boolean(doneSteps[index]);
                  return (
                    <li key={`${index}-${step}`}>
                      <button
                        type="button"
                        onClick={() =>
                          setDoneSteps(current => ({ ...current, [index]: !current[index] }))
                        }
                        aria-pressed={done}
                        className={`flex w-full items-start gap-3 rounded-xl border p-3 text-left transition ${
                          done
                            ? 'border-emerald-500/30 bg-emerald-500/5'
                            : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'
                        }`}
                      >
                        {done ? (
                          <CheckSquare size={18} className="mt-0.5 shrink-0 text-emerald-400" />
                        ) : (
                          <Square size={18} className="mt-0.5 shrink-0 text-slate-500" />
                        )}
                        <span
                          className={`text-sm leading-6 ${
                            done ? 'text-slate-500 line-through' : 'text-slate-300'
                          }`}
                        >
                          {step}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ol>
            </section>
          )}

          <p className="flex items-start gap-2 text-xs leading-5 text-slate-500">
            <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
            Follow recommendations appropriate to the incident. Backend-provided findings are not independent proof that an account or device is safe.
          </p>
        </section>
      )}
    </main>
  );
};
