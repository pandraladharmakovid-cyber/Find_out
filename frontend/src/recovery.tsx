
import React, { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldCheck,
  Smartphone,
  UserRound,
} from 'lucide-react';
import { apiRequest } from './api';

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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The assessment request failed.';
}

export const RecoveryView: React.FC<{ t: (key: string) => string }> = ({ t }) => {
  const [target, setTarget] = useState('');
  const [scenario, setScenario] = useState('opened_link');
  const [result, setResult] = useState<RecoveryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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
          <div className="surface-card p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Backend assessment
            </p>
            <p className="mt-3 text-lg font-semibold text-white">
              {result.safety_verdict || 'No verdict supplied'}
            </p>
            <p className="mt-2 break-words text-sm text-slate-400">{target.trim()}</p>

            {typeof result.compromised_count === 'number' && (
              <div className="mt-4 border-t border-slate-800 pt-4">
                <p className="text-xs text-slate-500">Documented compromise count</p>
                <p className="mt-1 text-2xl font-bold text-white">
                  {result.compromised_count}
                </p>
              </div>
            )}
          </div>

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
              <ol className="mt-4 space-y-3">
                {validSteps.map((step, index) => (
                  <li key={`${index}-${step}`} className="flex items-start gap-3">
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-xs font-bold text-cyan-300">
                      {index + 1}
                    </span>
                    <span className="pt-1 text-sm leading-6 text-slate-300">{step}</span>
                  </li>
                ))}
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
