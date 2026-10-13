
import React, { useCallback, useEffect, useState } from 'react';
import {
  Building2,
  CheckCircle2,
  CircleAlert,
  Globe,
  LoaderCircle,
  Plus,
  RefreshCw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { apiRequest } from './api';

type OfficialAsset = {
  id: string | number;
  asset_type?: string;
  platform?: string;
  identifier?: string;
  url?: string;
  canonical_url?: string | null;
  value?: string;
  is_verified?: boolean;
  verified?: boolean;
};

type Brand = {
  id: string | number;
  name: string;
  website?: string | null;
  primary_domain?: string | null;
  domains?: string[] | string | null;
  associated_domains?: string[] | string | null;
  keywords?: string[] | string | null;
  alternate_names?: string[] | null;
  assets?: OfficialAsset[];
  official_assets?: OfficialAsset[];
};

type BrandForm = {
  name: string;
  website: string;
  domains: string;
  keywords: string;
  alternateNames: string;
};

type AssetForm = {
  asset_type: string;
  platform: string;
  identifier: string;
  url: string;
  publisher: string;
  confirmOwnership: boolean;
  imageBase64: string;
  imageMime: string;
  imageFileName: string;
};

const emptyBrandForm: BrandForm = {
  name: '',
  website: '',
  domains: '',
  keywords: '',
  alternateNames: '',
};

const emptyAssetForm: AssetForm = {
  asset_type: 'social_profile',
  platform: 'instagram',
  identifier: '',
  url: '',
  publisher: '',
  confirmOwnership: false,
  imageBase64: '',
  imageMime: '',
  imageFileName: '',
};

function getData<T>(response: any): T {
  return (response?.data ?? response) as T;
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function displayList(value?: string[] | string | null): string {
  if (Array.isArray(value)) return value.join(', ');
  return value || '';
}

function normalizeWebsite(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';

  const withProtocol = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  const parsed = new URL(withProtocol);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Enter a valid HTTP or HTTPS website.');
  }

  return parsed.toString();
}

function readLogoFile(file: File): Promise<string> {
  if (file.size === 0 || file.size > 2 * 1024 * 1024) {
    return Promise.reject(new Error('Choose a logo image no larger than 2 MB.'));
  }
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
    return Promise.reject(new Error('Use a PNG, JPEG, or WebP logo image.'));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('The selected logo image could not be read.'));
    reader.onload = () => {
      const dataUrl = typeof reader.result === 'string' ? reader.result : '';
      const base64 = dataUrl.split(',')[1];
      if (!base64) reject(new Error('The selected logo image could not be encoded.'));
      else resolve(base64);
    };
    reader.readAsDataURL(file);
  });
}

function ErrorNotice({
  message,
  onDismiss,
}: {
  message: string;
  onDismiss: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200"
    >
      <CircleAlert className="mt-0.5 h-5 w-5 shrink-0" />
      <p className="min-w-0 flex-1">{message}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss error"
        className="rounded-md p-1 hover:bg-rose-500/15"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

export const BrandsView: React.FC<{ t: any }> = ({ t }) => {
  const [brands, setBrands] = useState<Brand[]>([]);
  const [selectedBrandId, setSelectedBrandId] = useState<string | number | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [showBrandForm, setShowBrandForm] = useState(false);
  const [showAssetForm, setShowAssetForm] = useState(false);
  const [brandForm, setBrandForm] = useState<BrandForm>(emptyBrandForm);
  const [assetForm, setAssetForm] = useState<AssetForm>(emptyAssetForm);

  const selectedBrand =
    brands.find((brand) => String(brand.id) === String(selectedBrandId)) ?? null;

  const fetchBrands = useCallback(async (preserveSelection = true) => {
    setLoading(true);
    setError('');

    try {
      const response = await apiRequest('/brands');
      const result = getData<Brand[]>(response);

      if (!Array.isArray(result)) {
        throw new Error('The server returned an unexpected brand list.');
      }

      setBrands(result);
      setSelectedBrandId((currentId) => {
        if (
          preserveSelection &&
          currentId !== null &&
          result.some((brand) => String(brand.id) === String(currentId))
        ) {
          return currentId;
        }
        return result[0]?.id ?? null;
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load brand profiles. Check the API connection.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchBrands(false);
  }, [fetchBrands]);

  const handleCreateBrand = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setNotice('');

    try {
      const website = normalizeWebsite(brandForm.website);
      const domains = splitList(brandForm.domains);

      if (!brandForm.name.trim()) {
        throw new Error('Enter a brand name.');
      }
      if (!website && domains.length === 0) {
        throw new Error('Enter the official website or at least one official domain.');
      }

      const response = await apiRequest('/brands', {
        method: 'POST',
        body: JSON.stringify({
          name: brandForm.name.trim(),
          website: website || undefined,
          primaryDomain: domains[0] || website,
          domains,
          keywords: splitList(brandForm.keywords),
          alternateNames: splitList(brandForm.alternateNames),
        }),
      });

      const created = getData<Brand>(response);

      setBrandForm(emptyBrandForm);
      setShowBrandForm(false);
      await fetchBrands(false);

      if (created?.id !== undefined) {
        setSelectedBrandId(created.id);
      }

      setNotice('Brand profile saved.');
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to create this brand.',
      );
    } finally {
      setSaving(false);
    }
  };

  const handleAddAsset = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!selectedBrand) {
      setError('Select a brand before adding an official asset.');
      return;
    }

    setSaving(true);
    setError('');
    setNotice('');

    try {
      const identifier = assetForm.identifier.trim();
      if (!identifier) throw new Error('Enter the official asset identifier.');

      const url = assetForm.url.trim()
        ? normalizeWebsite(assetForm.url)
        : undefined;
      if (assetForm.asset_type === 'logo' && url && new URL(url).protocol !== 'https:') {
        throw new Error('Logo URLs must use HTTPS.');
      }

      await apiRequest(`/brands/${encodeURIComponent(String(selectedBrand.id))}/assets`, {
        method: 'POST',
        body: JSON.stringify({
          asset_type: assetForm.asset_type,
          platform: assetForm.platform.trim(),
          identifier,
          url,
          is_verified: assetForm.confirmOwnership,
          ...(assetForm.imageBase64
            ? { imageBase64: assetForm.imageBase64, imageMime: assetForm.imageMime }
            : {}),
          metadata: assetForm.publisher.trim()
            ? { publisher: assetForm.publisher.trim() }
            : {},
        }),
      });

      setAssetForm(emptyAssetForm);
      setShowAssetForm(false);
      await fetchBrands();
      setNotice(
        'Official asset submitted. Verification status is shown only when returned by the server.',
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to register this asset.',
      );
    } finally {
      setSaving(false);
    }
  };

  const assets = selectedBrand?.assets ?? selectedBrand?.official_assets ?? [];

  return (
    <section className="page-enter space-y-6">
      <header className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-center">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">
            <ShieldCheck className="h-4 w-4" />
            Trust registry
          </div>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white sm:text-3xl">
            <Building2 className="h-7 w-7 text-blue-400" />
            {t?.brand?.title ?? 'Brand profiles'}
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Register legitimate brand identities and their official digital
            assets so monitoring can compare discovered accounts against them.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void fetchBrands()}
            disabled={loading}
            className="btn-secondary inline-flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => {
              setError('');
              setShowBrandForm(true);
            }}
            className="btn-primary inline-flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            {t?.brand?.createBtn ?? 'Register brand'}
          </button>
        </div>
      </header>

      {error && <ErrorNotice message={error} onDismiss={() => setError('')} />}
      {notice && (
        <div
          role="status"
          className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300"
        >
          {notice}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[minmax(260px,0.85fr)_minmax(0,1.6fr)]">
        <aside className="surface-card min-w-0 p-4 sm:p-5">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <h2 className="font-semibold text-white">Registered brands</h2>
              <p className="mt-1 text-xs text-slate-500">
                {loading ? 'Loading records…' : `${brands.length} server record(s)`}
              </p>
            </div>
            <Building2 className="h-5 w-5 text-slate-500" />
          </div>

          {loading ? (
            <div className="space-y-3" aria-label="Loading brands">
              {[1, 2, 3].map((item) => (
                <div key={item} className="skeleton h-20 rounded-xl" />
              ))}
            </div>
          ) : brands.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center">
              <Building2 className="mx-auto mb-3 h-8 w-8 text-slate-600" />
              <p className="text-sm font-medium text-slate-300">
                No brand profiles found
              </p>
              <p className="mt-1 text-xs leading-5 text-slate-500">
                Register a brand to start building its official asset registry.
              </p>
              <button
                type="button"
                onClick={() => setShowBrandForm(true)}
                className="btn-primary mt-4"
              >
                Register first brand
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {brands.map((brand) => {
                const active =
                  String(selectedBrandId) === String(brand.id);
                return (
                  <button
                    type="button"
                    key={brand.id}
                    onClick={() => setSelectedBrandId(brand.id)}
                    aria-pressed={active}
                    className={`w-full rounded-xl border p-4 text-left transition duration-200 ${
                      active
                        ? 'border-blue-500/50 bg-blue-500/10 shadow-lg shadow-blue-950/20'
                        : 'border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-slate-700 bg-slate-900 text-blue-300">
                        <Building2 className="h-5 w-5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-semibold text-white">
                          {brand.name}
                        </p>
                        <p className="mt-1 flex items-center gap-1.5 truncate text-xs text-slate-400">
                          <Globe className="h-3 w-3 shrink-0" />
                          {brand.website || brand.primary_domain || 'Website not provided'}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </aside>

        <div className="surface-card min-w-0 p-4 sm:p-6">
          {selectedBrand ? (
            <>
              <div className="flex flex-col justify-between gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-start">
                <div className="min-w-0">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-400">
                    Brand record
                  </p>
                  <h2 className="mt-2 break-words text-2xl font-bold text-white">
                    {selectedBrand.name}
                  </h2>
                  <p className="mt-2 break-all text-sm text-slate-400">
                    {selectedBrand.website ||
                      selectedBrand.primary_domain ||
                      'No official website recorded'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setError('');
                    setShowAssetForm(true);
                  }}
                  className="btn-primary inline-flex shrink-0 items-center justify-center gap-2"
                >
                  <Plus className="h-4 w-4" />
                  Add official asset
                </button>
              </div>

              <div className="grid gap-3 py-5 sm:grid-cols-2">
                <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-500">
                    Official assets
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-white">
                    {assets.length}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-500">
                    Registered domains
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-white">
                    {displayList(selectedBrand.domains ?? selectedBrand.associated_domains) ||
                      selectedBrand.primary_domain ||
                      '—'}
                  </p>
                </div>
              </div>

              <div>
                <div className="mb-3 flex items-center justify-between gap-3">
                  <h3 className="font-semibold text-white">
                    Official asset registry
                  </h3>
                  <span className="text-xs text-slate-500">
                    {assets.length} asset(s)
                  </span>
                </div>

                {assets.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center">
                    <ShieldCheck className="mx-auto mb-3 h-8 w-8 text-slate-600" />
                    <p className="text-sm font-medium text-slate-300">
                      No assets registered
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Add official domains, social profiles, or app listings.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {assets.map((asset, index) => {
                      const verified =
                        asset.is_verified === true || asset.verified === true;
                      return (
                        <div
                          key={asset.id ?? `${asset.platform}-${asset.identifier}-${index}`}
                          className="flex flex-col justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/40 p-4 sm:flex-row sm:items-center"
                        >
                          <div className="flex min-w-0 items-start gap-3">
                            <div className="rounded-lg border border-slate-700 bg-slate-900 p-2 text-blue-300">
                              <ShieldCheck className="h-5 w-5" />
                            </div>
                            <div className="min-w-0">
                              <p className="break-all font-mono text-sm text-slate-200">
                                {asset.identifier || asset.url || 'Identifier unavailable'}
                              </p>
                              <p className="mt-1 text-xs capitalize text-slate-500">
                                {[asset.platform, asset.asset_type]
                                  .filter(Boolean)
                                  .join(' · ') || 'Asset type unavailable'}
                              </p>
                              {(asset.url || asset.canonical_url) && asset.identifier !== (asset.url || asset.canonical_url) && (
                                <a
                                  href={asset.url || asset.canonical_url || undefined}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="mt-1 inline-block break-all text-xs text-blue-400 hover:underline"
                                >
                                  Open asset URL
                                </a>
                              )}
                            </div>
                          </div>
                          <span
                            className={`inline-flex w-fit shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
                              verified
                                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                            }`}
                          >
                            {verified ? (
                              <CheckCircle2 className="h-3.5 w-3.5" />
                            ) : (
                              <CircleAlert className="h-3.5 w-3.5" />
                            )}
                            {verified ? 'Registered as official' : 'Pending review'}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex min-h-72 flex-col items-center justify-center text-center">
              <Building2 className="mb-3 h-10 w-10 text-slate-600" />
              <h2 className="font-semibold text-white">Select a brand</h2>
              <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500">
                Choose a registered profile from the left or create a new brand
                to manage its official digital assets.
              </p>
            </div>
          )}
        </div>
      </div>

      {showBrandForm && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/75 p-4 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setShowBrandForm(false);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="brand-dialog-title"
            className="my-auto w-full max-w-xl rounded-2xl border border-slate-700 bg-slate-950 p-5 shadow-2xl sm:p-7"
          >
            <div className="mb-5 flex items-start justify-between gap-3">
              <div>
                <h2 id="brand-dialog-title" className="text-xl font-bold text-white">
                  Register brand profile
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  Record the official identity used for monitoring comparisons.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowBrandForm(false)}
                aria-label="Close dialog"
                className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateBrand} className="space-y-4">
              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Brand name *</span>
                <input
                  required
                  maxLength={160}
                  value={brandForm.name}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, name: event.target.value })
                  }
                  placeholder="Example: Example Technologies"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Official website</span>
                <input
                  type="text"
                  value={brandForm.website}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, website: event.target.value })
                  }
                  placeholder="https://example.com"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">
                  Official domains (comma-separated)
                </span>
                <input
                  value={brandForm.domains}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, domains: event.target.value })
                  }
                  placeholder="example.com, example.org"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">
                  Brand keywords (comma-separated)
                </span>
                <input
                  value={brandForm.keywords}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, keywords: event.target.value })
                  }
                  placeholder="brand name, product name"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">
                  Alternate brand names (comma-separated)
                </span>
                <input
                  value={brandForm.alternateNames}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, alternateNames: event.target.value })
                  }
                  placeholder="Example Holdings, Example Wallet"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
              </label>

              <div className="flex justify-end gap-2 border-t border-slate-800 pt-4">
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => setShowBrandForm(false)}
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" disabled={saving} className="btn-primary inline-flex items-center gap-2">
                  {saving && <LoaderCircle className="h-4 w-4 animate-spin" />}
                  Save brand
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {showAssetForm && selectedBrand && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/75 p-4 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setShowAssetForm(false);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-dialog-title"
            className="my-auto w-full max-w-xl rounded-2xl border border-slate-700 bg-slate-950 p-5 shadow-2xl sm:p-7"
          >
            <div className="mb-5 flex items-start justify-between gap-3">
              <div>
                <h2 id="asset-dialog-title" className="text-xl font-bold text-white">
                  Add official asset
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  For {selectedBrand.name}. Ownership is not independently verified. Only confirmed assets are used for automatic exclusions.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowAssetForm(false)}
                aria-label="Close dialog"
                className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleAddAsset} className="space-y-4">
              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Asset category *</span>
                <select
                  value={assetForm.asset_type}
                  onChange={(event) =>
                    setAssetForm({ ...assetForm, asset_type: event.target.value })
                  }
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none focus:border-blue-500"
                >
                  <option value="social_profile">Social profile</option>
                  <option value="mobile_app">Mobile app</option>
                  <option value="domain">Domain</option>
                  <option value="logo">Logo</option>
                </select>
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Platform *</span>
                <select
                  required
                  value={assetForm.platform}
                  onChange={(event) =>
                    setAssetForm({ ...assetForm, platform: event.target.value })
                  }
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none focus:border-blue-500"
                >
                  <option value="website">Website</option>
                  <option value="instagram">Instagram</option>
                  <option value="facebook">Facebook</option>
                  <option value="x">X</option>
                  <option value="youtube">YouTube</option>
                  <option value="linkedin">LinkedIn</option>
                  <option value="tiktok">TikTok</option>
                  <option value="play_store">Google Play</option>
                  <option value="app_store">Apple App Store</option>
                  <option value="other">Other</option>
                </select>
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Identifier *</span>
                <input
                  required
                  maxLength={1000}
                  value={assetForm.identifier}
                  onChange={(event) =>
                    setAssetForm({ ...assetForm, identifier: event.target.value })
                  }
                  placeholder="Official handle, domain, or package ID"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none focus:border-blue-500"
                />
              </label>

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">Asset URL (optional)</span>
                <input
                  value={assetForm.url}
                  onChange={(event) =>
                    setAssetForm({ ...assetForm, url: event.target.value })
                  }
                  placeholder="https://..."
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none focus:border-blue-500"
                />
              </label>

              {assetForm.asset_type === 'logo' && (
                <label className="block space-y-1.5">
                  <span className="text-sm text-slate-300">Upload logo (PNG, JPEG, or WebP; max 2 MB)</span>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    onChange={async (event) => {
                      const input = event.currentTarget;
                      const file = input.files?.[0];
                      if (!file) return;
                      try {
                        const imageBase64 = await readLogoFile(file);
                        setAssetForm((current) => ({
                          ...current,
                          imageBase64,
                          imageMime: file.type,
                          imageFileName: file.name,
                        }));
                        setError('');
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'The logo image could not be read.');
                        input.value = '';
                      }
                    }}
                    className="w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-sm file:text-slate-200"
                  />
                  {assetForm.imageFileName && (
                    <span className="block text-xs text-emerald-300">Selected: {assetForm.imageFileName}</span>
                  )}
                </label>
              )}

              {assetForm.asset_type === 'mobile_app' && (
                <label className="block space-y-1.5">
                  <span className="text-sm text-slate-300">Official app publisher (optional)</span>
                  <input
                    value={assetForm.publisher}
                    onChange={(event) =>
                      setAssetForm({ ...assetForm, publisher: event.target.value })
                    }
                    placeholder="Publisher name shown in the store"
                    className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none focus:border-blue-500"
                  />
                </label>
              )}

              <label className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={assetForm.confirmOwnership}
                  onChange={(event) =>
                    setAssetForm({ ...assetForm, confirmOwnership: event.target.checked })
                  }
                  className="mt-0.5 accent-cyan-400"
                />
                <span>I confirm that this is an organization-owned official asset. Unconfirmed entries stay pending and are not excluded.</span>
              </label>

              <div className="flex justify-end gap-2 border-t border-slate-800 pt-4">
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => setShowAssetForm(false)}
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" disabled={saving} className="btn-primary inline-flex items-center gap-2">
                  {saving && <LoaderCircle className="h-4 w-4 animate-spin" />}
                  Save asset
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </section>
  );
};

export default BrandsView;
