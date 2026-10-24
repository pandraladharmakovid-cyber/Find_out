import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, CheckCircle2, Copy, ExternalLink, Image as ImageIcon,
  Loader2, Play, ScanSearch, ShieldQuestion, Upload,
} from 'lucide-react';
import { apiRequest } from './api';
import type { Translator } from './i18n';

type Brand = { id: string; name: string; primary_domain?: string };

type Permutation = {
  domain: string;
  technique: string;
  similarity: number;
};

type Evaluation = {
  targetDomain: string;
  referenceBrand: string;
  levenshteinDistance: number;
  similarityRatio: number;
  isLookalike: boolean;
  detectedTechnique: string | null;
};

type LogoResult = {
  targetImageUri: string;
  referenceAssetUri: string;
  hammingDistance: number;
  similarityScore: number;
  isImpersonating: boolean;
  confidence: number;
  method?: string;
  note?: string;
};

type Props = {
  t: Translator;
  onInvestigate?: (target: string) => void;
};

function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    if (file.size > 2 * 1024 * 1024) {
      reject(new Error('Images must be 2 MB or smaller.'));
      return;
    }
    if (!/^image\/(png|jpe?g|webp)$/i.test(file.type)) {
      reject(new Error('Use a PNG, JPEG or WebP image.'));
      return;
    }
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(new Error('The image could not be read.'));
    reader.readAsDataURL(file);
  });
}

function percent(value: number): string {
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'The request failed.';
}

export const IntelligenceView: React.FC<Props> = ({ t, onInvestigate }) => {
  const [brands, setBrands] = useState<Brand[]>([]);
  const [brandId, setBrandId] = useState('');
  const [brandName, setBrandName] = useState('');
  const [tld, setTld] = useState('com');

  const [permutations, setPermutations] = useState<Permutation[]>([]);
  const [generating, setGenerating] = useState(false);

  const [suspect, setSuspect] = useState('');
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  const [referenceImage, setReferenceImage] = useState('');
  const [targetImage, setTargetImage] = useState('');
  const [referenceUrl, setReferenceUrl] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [logoResult, setLogoResult] = useState<LogoResult | null>(null);
  const [comparing, setComparing] = useState(false);

  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');

  const loadBrands = useCallback(async () => {
    try {
      const response = await apiRequest<{ data?: Brand[] }>('/brands', { timeoutMs: 20000 });
      if (Array.isArray(response?.data)) {
        setBrands(response.data);
        const first = response.data[0];
        if (first) {
          setBrandId(String(first.id));
          setBrandName((current) => current || first.name);
        }
      }
    } catch {
      // Brand list is optional.
    }
  }, []);

  useEffect(() => {
    void loadBrands();
  }, [loadBrands]);

  const selectBrand = (id: string) => {
    setBrandId(id);
    const brand = brands.find((entry) => String(entry.id) === id);
    if (brand) setBrandName(brand.name);
  };

  const generate = async () => {
    if (!brandName.trim()) {
      setError(t('lookalike.brandRequired'));
      return;
    }
    setGenerating(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: { permutations?: Permutation[] } }>(
        '/intelligence/lookalike/generate',
        {
          method: 'POST',
          body: JSON.stringify({ brandName: brandName.trim(), tld }),
          timeoutMs: 30000,
        },
      );
      setPermutations(Array.isArray(response?.data?.permutations) ? response.data.permutations : []);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setGenerating(false);
    }
  };

  const evaluate = async () => {
    if (!suspect.trim() || !brandName.trim()) {
      setError(t('lookalike.domainRequired'));
      return;
    }
    setEvaluating(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: Evaluation }>('/intelligence/lookalike/evaluate', {
        method: 'POST',
        body: JSON.stringify({ domain: suspect.trim(), brandName: brandName.trim() }),
        timeoutMs: 20000,
      });
      setEvaluation(response?.data ?? null);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setEvaluating(false);
    }
  };

  const compareLogos = async () => {
    if ((!referenceImage && !referenceUrl.trim()) || (!targetImage && !targetUrl.trim())) {
      setError(t('lookalike.logoRequired'));
      return;
    }
    setComparing(true);
    setError('');
    try {
      const response = await apiRequest<{ data?: LogoResult }>('/intelligence/logo/compare', {
        method: 'POST',
        body: JSON.stringify({
          ...(referenceImage ? { referenceBase64: referenceImage } : { referenceUrl: referenceUrl.trim() }),
          ...(targetImage ? { targetBase64: targetImage } : { targetUrl: targetUrl.trim() }),
        }),
        timeoutMs: 60000,
      });
      setLogoResult(response?.data ?? null);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setComparing(false);
    }
  };

  const copyDomain = async (domain: string) => {
    try {
      await navigator.clipboard.writeText(domain);
      setCopied(domain);
      setTimeout(() => setCopied(''), 1500);
    } catch {
      setCopied('');
    }
  };

  const techniqueCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of permutations) {
      counts.set(entry.technique, (counts.get(entry.technique) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [permutations]);

  return (
    <main className="page-enter space-y-6">
      <header className="border-b border-slate-800 pb-5">
        <p className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
          <ScanSearch size={13} /> {t('lookalike.eyebrow')}
        </p>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
          <ScanSearch className="text-cyan-400" /> {t('lookalike.title')}
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{t('lookalike.subtitle')}</p>
      </header>

      {error && (
        <div role="alert" className="flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
          <AlertTriangle size={18} className="shrink-0" />
          <p className="break-words">{error}</p>
        </div>
      )}

      <section className="surface-card space-y-4 p-4 sm:p-6">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="space-y-2 text-sm text-slate-300">
            {t('lookalike.brand')}
            <select className="w-full" value={brandId} onChange={(event) => selectBrand(event.target.value)}>
              <option value="">{t('copilot.noBrand')}</option>
              {brands.map((brand) => (
                <option key={brand.id} value={String(brand.id)}>
                  {brand.name}
                </option>
              ))}
            </select>
          </label>

          <label className="space-y-2 text-sm text-slate-300">
            {t('lookalike.brandName')}
            <input
              className="w-full"
              value={brandName}
              onChange={(event) => setBrandName(event.target.value)}
              placeholder="NexusPay"
            />
          </label>

          <label className="space-y-2 text-sm text-slate-300">
            TLD
            <input className="w-full" value={tld} onChange={(event) => setTld(event.target.value)} placeholder="com" />
          </label>

          <div className="flex items-end">
            <button type="button" className="btn-primary w-full" onClick={() => void generate()} disabled={generating}>
              {generating ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
              {t('lookalike.generate')}
            </button>
          </div>
        </div>

        {techniqueCounts.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {techniqueCounts.map(([technique, count]) => (
              <span key={technique} className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300">
                {technique.replace(/_/g, ' ')}: <span className="font-semibold text-cyan-300">{count}</span>
              </span>
            ))}
          </div>
        )}

        {permutations.length > 0 && (
          <div className="max-h-[420px] overflow-auto rounded-xl border border-slate-800">
            <table className="w-full min-w-[520px] text-left text-sm">
              <thead className="sticky top-0 bg-slate-900/95 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2">{t('lookalike.domain')}</th>
                  <th className="px-3 py-2">{t('lookalike.technique')}</th>
                  <th className="px-3 py-2">{t('lookalike.similarity')}</th>
                  <th className="px-3 py-2 text-right">{t('lookalike.actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {permutations.map((entry) => (
                  <tr key={entry.domain} className="hover:bg-slate-900/60">
                    <td className="px-3 py-2 font-mono text-xs text-slate-200">{entry.domain}</td>
                    <td className="px-3 py-2 text-xs text-slate-400">{entry.technique.replace(/_/g, ' ')}</td>
                    <td className="px-3 py-2 text-xs tabular-nums text-slate-300">{percent(entry.similarity)}</td>
                    <td className="px-3 py-2 text-right">
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          className="rounded-md border border-slate-700 p-1.5 text-slate-400 hover:text-cyan-300"
                          onClick={() => void copyDomain(entry.domain)}
                          aria-label={`Copy ${entry.domain}`}
                          title={copied === entry.domain ? t('lookalike.copied') : t('lookalike.copy')}
                        >
                          <Copy size={13} />
                        </button>
                        {onInvestigate && (
                          <button
                            type="button"
                            className="rounded-md border border-slate-700 p-1.5 text-slate-400 hover:text-cyan-300"
                            onClick={() => onInvestigate(entry.domain)}
                            aria-label={`Investigate ${entry.domain}`}
                            title={t('lookalike.investigate')}
                          >
                            <ExternalLink size={13} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs leading-5 text-slate-500">{t('lookalike.note')}</p>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="surface-card space-y-4 p-4 sm:p-6">
          <h2 className="flex items-center gap-2 font-semibold text-white">
            <ShieldQuestion size={16} className="text-cyan-400" /> {t('lookalike.evaluateTitle')}
          </h2>
          <label className="block space-y-2 text-sm text-slate-300">
            {t('lookalike.suspect')}
            <input
              className="w-full"
              value={suspect}
              onChange={(event) => setSuspect(event.target.value)}
              placeholder="nexusp4y.com/login"
            />
          </label>
          <button type="button" className="btn-secondary" onClick={() => void evaluate()} disabled={evaluating}>
            {evaluating ? <Loader2 size={15} className="animate-spin" /> : <ScanSearch size={15} />}
            {t('lookalike.evaluate')}
          </button>

          {evaluation && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
                    evaluation.isLookalike
                      ? 'border-amber-400/40 bg-amber-400/10 text-amber-200'
                      : 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
                  }`}
                >
                  {evaluation.isLookalike ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
                  {evaluation.isLookalike ? t('lookalike.flagged') : t('lookalike.clear')}
                </span>
                <span className="rounded-full border border-slate-700 px-2.5 py-1 text-xs text-slate-300">
                  {t('lookalike.distance')}: {evaluation.levenshteinDistance}
                </span>
                <span className="rounded-full border border-slate-700 px-2.5 py-1 text-xs text-slate-300">
                  {t('lookalike.similarity')}: {percent(evaluation.similarityRatio)}
                </span>
              </div>
              <p className="mt-3 text-sm text-slate-300">
                {evaluation.isLookalike
                  ? `${evaluation.targetDomain} ${t('lookalike.looksLike')} ${evaluation.referenceBrand} (${evaluation.detectedTechnique?.replace(/_/g, ' ')}).`
                  : `${evaluation.targetDomain} ${t('lookalike.notLookalike')} ${evaluation.referenceBrand}.`}
              </p>
            </div>
          )}
        </div>

        <div className="surface-card space-y-4 p-4 sm:p-6">
          <h2 className="flex items-center gap-2 font-semibold text-white">
            <ImageIcon size={16} className="text-cyan-400" /> {t('lookalike.logoTitle')}
          </h2>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-2 text-sm text-slate-300">
              {t('lookalike.referenceImage')}
              <div className="rounded-xl border border-dashed border-slate-700 p-3">
                {referenceImage ? (
                  <img src={referenceImage} alt="Registered logo preview" className="mx-auto h-20 w-20 rounded-lg object-contain" />
                ) : (
                  <div className="flex h-20 items-center justify-center text-slate-600">
                    <ImageIcon size={22} />
                  </div>
                )}
                <label className="mt-2 flex cursor-pointer items-center justify-center gap-1.5 text-xs text-cyan-300">
                  <Upload size={13} /> {t('lookalike.upload')}
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    className="hidden"
                    onChange={async (event) => {
                      const file = event.target.files?.[0];
                      if (!file) return;
                      try {
                        setReferenceImage(await readAsDataUrl(file));
                        setError('');
                      } catch (err) {
                        setError(errorText(err));
                      }
                    }}
                  />
                </label>
              </div>
            </label>

            <label className="space-y-2 text-sm text-slate-300">
              {t('lookalike.targetImage')}
              <div className="rounded-xl border border-dashed border-slate-700 p-3">
                {targetImage ? (
                  <img src={targetImage} alt="Suspect icon preview" className="mx-auto h-20 w-20 rounded-lg object-contain" />
                ) : (
                  <div className="flex h-20 items-center justify-center text-slate-600">
                    <ImageIcon size={22} />
                  </div>
                )}
                <label className="mt-2 flex cursor-pointer items-center justify-center gap-1.5 text-xs text-cyan-300">
                  <Upload size={13} /> {t('lookalike.upload')}
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    className="hidden"
                    onChange={async (event) => {
                      const file = event.target.files?.[0];
                      if (!file) return;
                      try {
                        setTargetImage(await readAsDataUrl(file));
                        setError('');
                      } catch (err) {
                        setError(errorText(err));
                      }
                    }}
                  />
                </label>
              </div>
            </label>
          </div>

          <details className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-sm text-slate-300">
            <summary className="cursor-pointer text-xs font-medium text-slate-400">{t('lookalike.useUrls')}</summary>
            <div className="mt-3 grid gap-2">
              <input
                className="w-full"
                value={referenceUrl}
                onChange={(event) => setReferenceUrl(event.target.value)}
                placeholder="https://brand.example/logo.png"
              />
              <input
                className="w-full"
                value={targetUrl}
                onChange={(event) => setTargetUrl(event.target.value)}
                placeholder="https://suspect.example/icon.png"
              />
            </div>
          </details>

          <button type="button" className="btn-primary" onClick={() => void compareLogos()} disabled={comparing}>
            {comparing ? <Loader2 size={15} className="animate-spin" /> : <ImageIcon size={15} />}
            {t('lookalike.compare')}
          </button>

          {logoResult && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                    logoResult.isImpersonating
                      ? 'border-rose-400/40 bg-rose-400/10 text-rose-200'
                      : 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
                  }`}
                >
                  {t('lookalike.score')}: {percent(logoResult.similarityScore)}
                </span>
                <span className="rounded-full border border-slate-700 px-2.5 py-1 text-xs text-slate-300">
                  {t('lookalike.hamming')}: {logoResult.hammingDistance}/64
                </span>
                <span className="rounded-full border border-slate-700 px-2.5 py-1 text-xs text-slate-300">
                  {t('lookalike.confidence')}: {percent(logoResult.confidence)}
                </span>
              </div>
              <p className="mt-3 text-sm text-slate-300">
                {logoResult.isImpersonating ? t('lookalike.logoMatch') : t('lookalike.logoNoMatch')}
              </p>
              <p className="mt-2 text-xs text-slate-500">{logoResult.note ?? t('lookalike.logoNote')}</p>
            </div>
          )}
        </div>
      </section>
    </main>
  );
};

export default IntelligenceView;
