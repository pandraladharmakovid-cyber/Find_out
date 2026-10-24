import React, { useCallback, useEffect, useState } from 'react';
import {
  Building2,
  CheckCircle2,
  CircleAlert,
  Globe,
  Loader2,
  LoaderCircle,
  Mail,
  Plus,
  Search,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { apiRequest, getApiBaseUrl } from './api';
import { BrandLogo } from './brand-logo';
import { BrandGuardPopup, type GuardConflict } from './brand-guard-popup';
import type { Translator } from './i18n';

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
  verification_status?: 'PENDING_VERIFICATION' | 'VERIFIED' | 'VERIFIED_LEGACY' | 'REJECTED' | 'REVOKED';
  verification_method?: string | null;
  verification_evidence?: Record<string, unknown>;
  verified_at?: string | null;
  verified_by?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  safety_status?: 'NOT_ASSESSED' | 'NO_THREAT_MATCH' | 'THREAT_DETECTED';
  safety_evidence?: Record<string, unknown>;
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
  logo_url?: string | null;
  logo_asset_url?: string | null;
  logo_domain?: string | null;
  logo_image_url?: string | null;
  contact_email?: string | null;
};

type BrandGuardAlert = {
  id: string;
  brand_id: string;
  suspect_name: string;
  suspect_domain?: string | null;
  match_type: string;
  similarity?: string | number | null;
  verdict: string;
  recipient_email: string;
  status: 'pending' | 'sent' | 'failed' | 'not_configured';
  created_at: string;
};

type BrandForm = {
  name: string;
  website: string;
  domains: string;
  keywords: string;
  alternateNames: string;
  contactEmail: string;
};

type BrandCreatePayload = {
  name: string;
  website?: string;
  primaryDomain: string;
  domains: string[];
  keywords: string[];
  alternateNames: string[];
  contactEmail?: string;
};

type GuardPopupState = {
  suspectName: string;
  suspectDomain: string;
  conflicts: GuardConflict[];
  payload: BrandCreatePayload;
};

type AssetForm = {
  asset_type: string;
  platform: string;
  identifier: string;
  url: string;
  publisher: string;
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
  contactEmail: '',
};

const emptyAssetForm: AssetForm = {
  asset_type: 'social_profile',
  platform: 'instagram',
  identifier: '',
  url: '',
  publisher: '',
  imageBase64: '',
  imageMime: '',
  imageFileName: '',
};

type DomainChallenge = {
  assetId: string;
  challengeId: string;
  token: string;
  method: 'DNS_TXT' | 'WELL_KNOWN';
  expiresAt: string;
  domain: string;
  dnsName: string;
  wellKnownUrl: string;
  dnsValue: string;
  fileContents: string;
};

function isDomainAsset(asset: OfficialAsset): boolean {
  return ['domain', 'subdomain', 'website'].includes((asset.asset_type ?? '').toLowerCase());
}

function isTrustedAsset(asset: OfficialAsset): boolean {
  const status = asset.verification_status ??
    (asset.is_verified === true || asset.verified === true ? 'VERIFIED_LEGACY' : 'PENDING_VERIFICATION');
  return (asset.is_verified === true || asset.verified === true) &&
    ['VERIFIED', 'VERIFIED_LEGACY'].includes(status);
}

function verificationLabel(asset: OfficialAsset): string {
  const status = asset.verification_status ??
    (asset.is_verified === true || asset.verified === true ? 'VERIFIED_LEGACY' : 'PENDING_VERIFICATION');
  switch (status) {
    case 'VERIFIED': return 'Proof verified';
    case 'VERIFIED_LEGACY': return 'Legacy verified · re-verify recommended';
    case 'REJECTED': return 'Rejected · not trusted';
    case 'REVOKED': return 'Revoked · not trusted';
    default: return 'Pending · not trusted';
  }
}

function safetyLabel(asset: OfficialAsset): string {
  switch (asset.safety_status) {
    case 'NO_THREAT_MATCH': return 'No threat match in configured checks · not a safety guarantee';
    case 'THREAT_DETECTED': return 'Threat reported by a configured reputation source';
    default: return 'Safety not assessed by a reputation source';
  }
}


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

function assertEligiblePublicHostname(parsed: URL): void {
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const labels = hostname.split('.');
  const reservedTlds = new Set(['localhost', 'local', 'internal', 'test', 'invalid', 'example']);
  if (reservedTlds.has(labels[labels.length - 1] ?? '')) {
    throw new Error('Reserved/local/test domains such as .invalid, .test, .example, and localhost cannot be used.');
  }
  const validLabel = (label: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  const validTld = (label: string) => /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  if (
    hostname.length > 253 ||
    labels.length < 2 ||
    labels.some((label) => !validLabel(label)) ||
    !validTld(labels[labels.length - 1] ?? '')
  ) {
    throw new Error('Enter an eligible public domain name, not an IP address, local name, or malformed hostname.');
  }
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
  assertEligiblePublicHostname(parsed);

  return parsed.toString();
}

type BrandTrustState = 'INELIGIBLE' | 'UNVERIFIED' | 'LEGACY' | 'VERIFIED';

function primaryDomainForBrand(brand: Brand): string {
  if (brand.primary_domain?.trim()) {
    return brand.primary_domain.trim().toLowerCase().replace(/\.$/, '');
  }
  if (!brand.website) return '';
  try {
    const value = /^https?:\/\//i.test(brand.website) ? brand.website : `https://${brand.website}`;
    return new URL(value).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return '';
  }
}

function brandTrustState(brand: Brand): BrandTrustState {
  const primaryDomain = primaryDomainForBrand(brand);
  if (!primaryDomain) return 'INELIGIBLE';
  try {
    normalizeWebsite(primaryDomain);
  } catch {
    return 'INELIGIBLE';
  }
  const assets = brand.assets ?? brand.official_assets ?? [];
  const primaryAsset = assets.find((asset) =>
    isDomainAsset(asset) &&
    [asset.value, asset.identifier].some((value) =>
      typeof value === 'string' && value.trim().toLowerCase().replace(/\.$/, '') === primaryDomain,
    ),
  );
  if (primaryAsset && isTrustedAsset(primaryAsset)) {
    return primaryAsset.verification_status === 'VERIFIED' ? 'VERIFIED' : 'LEGACY';
  }
  return 'UNVERIFIED';
}

function brandTrustLabel(brand: Brand): string {
  switch (brandTrustState(brand)) {
    case 'VERIFIED': return 'Primary domain verified';
    case 'LEGACY': return 'Legacy primary · re-verify';
    case 'INELIGIBLE': return 'Ineligible · not official';
    default: return 'Unverified profile';
  }
}

function brandTrustClasses(brand: Brand): string {
  switch (brandTrustState(brand)) {
    case 'VERIFIED': return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    case 'LEGACY': return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300';
    case 'INELIGIBLE': return 'border-rose-500/30 bg-rose-500/10 text-rose-300';
    default: return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
  }
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

export const BrandsView: React.FC<{ t: Translator }> = ({ t }) => {
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
  const [verificationBusy, setVerificationBusy] = useState('');
  const [challenge, setChallenge] = useState<DomainChallenge | null>(null);
  const [guardPopup, setGuardPopup] = useState<GuardPopupState | null>(null);
  const [brandAlerts, setBrandAlerts] = useState<BrandGuardAlert[]>([]);
  const [contactDraft, setContactDraft] = useState('');
  const [contactSaving, setContactSaving] = useState(false);
  const [logoCheck, setLogoCheck] = useState<{
    loading: boolean;
    error: string;
    result: any | null;
  }>({ loading: false, error: '', result: null });

  const checkLogo = useCallback(async (domain: string) => {
    setLogoCheck({ loading: true, error: '', result: null });
    try {
      const response = await apiRequest<any>(
        `/intelligence/logo/domain/${encodeURIComponent(domain)}/meta`,
        { timeoutMs: 30000 },
      );
      setLogoCheck({ loading: false, error: '', result: response?.data ?? response });
    } catch (caught) {
      setLogoCheck({
        loading: false,
        error:
          caught instanceof Error
            ? caught.message
            : 'The logo could not be resolved for this domain.',
        result: null,
      });
    }
  }, []);

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

  const loadBrandAlerts = useCallback(async (brandId: string | number) => {
    try {
      const response = await apiRequest<{ data?: BrandGuardAlert[] }>(
        `/brand-guard/alerts?brandId=${encodeURIComponent(String(brandId))}&limit=5`,
      );
      setBrandAlerts(Array.isArray(response?.data) ? response.data : []);
    } catch {
      setBrandAlerts([]);
    }
  }, []);

  useEffect(() => {
    setContactDraft('');
    setLogoCheck({ loading: false, error: '', result: null });
    if (selectedBrandId !== null) {
      void loadBrandAlerts(selectedBrandId);
    } else {
      setBrandAlerts([]);
    }
  }, [selectedBrandId, loadBrandAlerts]);

  const handleSaveContactEmail = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedBrand || !contactDraft.trim()) return;
    setContactSaving(true);
    setError('');
    setNotice('');
    try {
      await apiRequest(`/brand-guard/brands/${encodeURIComponent(String(selectedBrand.id))}/contact`, {
        method: 'POST',
        body: JSON.stringify({ contactEmail: contactDraft.trim() }),
      });
      setContactDraft('');
      await fetchBrands(true);
      setNotice('Brand Guard alert contact e-mail saved for this profile.');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Could not save the Brand Guard alert contact e-mail.',
      );
    } finally {
      setContactSaving(false);
    }
  };

  const submitBrandPayload = async (payload: BrandCreatePayload) => {
    const response = await apiRequest('/brands', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    const created = getData<Brand>(response);

    setBrandForm(emptyBrandForm);
    setShowBrandForm(false);
    setGuardPopup(null);
    await fetchBrands(false);

    if (created?.id !== undefined) {
      setSelectedBrandId(created.id);
    }

    setNotice('Brand profile saved as UNVERIFIED. Add the exact primary domain as an asset and complete proof before treating this profile as official.');
  };

  const handleCreateBrand = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setNotice('');

    try {
      const website = normalizeWebsite(brandForm.website);
      const domains = splitList(brandForm.domains).map((domain) =>
        new URL(normalizeWebsite(domain)).hostname.toLowerCase(),
      );

      if (!brandForm.name.trim()) {
        throw new Error('Enter a brand name.');
      }
      if (!website && domains.length === 0) {
        throw new Error('Enter the official website or at least one official domain.');
      }

      const payload: BrandCreatePayload = {
        name: brandForm.name.trim(),
        website: website || undefined,
        primaryDomain: domains[0] || website,
        domains,
        keywords: splitList(brandForm.keywords),
        alternateNames: splitList(brandForm.alternateNames),
        contactEmail: brandForm.contactEmail.trim() || undefined,
      };

      // Brand Guard: before saving, ask the backend whether this submission
      // collides with an already-registered official brand. A conflict opens
      // the impersonation pop-up instead of silently registering.
      try {
        const guardResponse = await apiRequest<{
          data?: { conflict?: boolean; conflicts?: GuardConflict[] };
        }>('/brand-guard/check', {
          method: 'POST',
          body: JSON.stringify({
            name: payload.name,
            domain: payload.primaryDomain
              ? new URL(normalizeWebsite(payload.primaryDomain)).hostname.toLowerCase()
              : undefined,
          }),
        });

        const conflicts = guardResponse?.data?.conflicts ?? [];
        if (guardResponse?.data?.conflict && conflicts.length > 0) {
          setGuardPopup({
            suspectName: payload.name,
            suspectDomain:
              domains[0] || (website ? new URL(website).hostname.toLowerCase() : ''),
            conflicts,
            payload,
          });
          setSaving(false);
          return;
        }
      } catch {
        // The guard check is advisory; registration still goes through the
        // server, which repeats the same check and records the warning.
      }

      await submitBrandPayload(payload);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to create this brand.',
      );
    } finally {
      setSaving(false);
    }
  };

  const handleRegisterAnyway = async () => {
    if (!guardPopup) return;
    setSaving(true);
    setError('');
    try {
      await submitBrandPayload(guardPopup.payload);
      setNotice('Brand profile saved as UNVERIFIED and FLAGGED: it is confusingly similar to a registered official brand. The conflict was recorded server-side.');
    } catch (err) {
      setGuardPopup(null);
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
        'Asset saved as PENDING_VERIFICATION. It is visible in the registry, but it is not trusted and creates no official exclusion.',
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to register this asset.',
      );
    } finally {
      setSaving(false);
    }
  };

  const createDomainChallenge = async (
    asset: OfficialAsset,
    method: 'DNS_TXT' | 'WELL_KNOWN',
  ) => {
    if (!selectedBrand || !asset.id) return;
    setVerificationBusy(`${asset.id}:challenge`);
    setError('');
    setNotice('');
    try {
      const response = await apiRequest<{ data?: Omit<DomainChallenge, 'assetId'> }>(
        `/brands/${encodeURIComponent(String(selectedBrand.id))}/assets/${encodeURIComponent(String(asset.id))}/verification-challenges`,
        { method: 'POST', body: JSON.stringify({ method }), timeoutMs: 30000 },
      );
      if (!response.data?.token || !response.data.challengeId) {
        throw new Error('The server did not return a usable verification challenge.');
      }
      setChallenge({ ...response.data, assetId: String(asset.id) });
      setNotice('Challenge created. Publish the token, then run the verification check before it expires.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create the verification challenge.');
    } finally {
      setVerificationBusy('');
    }
  };

  const verifyDomain = async (asset: OfficialAsset) => {
    if (!selectedBrand || !asset.id || !challenge || challenge.assetId !== String(asset.id)) return;
    setVerificationBusy(`${asset.id}:verify`);
    setError('');
    setNotice('');
    try {
      await apiRequest(
        `/brands/${encodeURIComponent(String(selectedBrand.id))}/assets/${encodeURIComponent(String(asset.id))}/verification-challenges/${encodeURIComponent(challenge.challengeId)}/verify`,
        { method: 'POST', body: JSON.stringify({ token: challenge.token }), timeoutMs: 120000 },
      );
      setChallenge(null);
      await fetchBrands();
      setNotice('Domain proof verified for this brand record. Only its linked same-brand exclusion was activated; this is not a safety guarantee.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Domain verification failed.');
    } finally {
      setVerificationBusy('');
    }
  };

  const verifyAssociation = async (asset: OfficialAsset) => {
    if (!selectedBrand || !asset.id) return;
    setVerificationBusy(`${asset.id}:associate`);
    setError('');
    setNotice('');
    try {
      await apiRequest(
        `/brands/${encodeURIComponent(String(selectedBrand.id))}/assets/${encodeURIComponent(String(asset.id))}/verify-association`,
        { method: 'POST', body: JSON.stringify({}), timeoutMs: 120000 },
      );
      await fetchBrands();
      setNotice('Asset association verified from an exact declaration on a verified brand domain.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Asset association verification failed.');
    } finally {
      setVerificationBusy('');
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
            {t('brand.title')}
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            {t('brand.subtitle')}
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
            {t('common.refresh')}
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
            {t('brand.createBtn')}
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
              <h2 className="font-semibold text-white">Brand profiles</h2>
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
                Add a reviewable profile, then prove its primary domain and official assets.
              </p>
              <button
                type="button"
                onClick={() => setShowBrandForm(true)}
                className="btn-primary mt-4"
              >
                Add first brand profile
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {brands.map((brand) => {
                const active =
                  String(selectedBrandId) === String(brand.id);
                const trustState = brandTrustState(brand);
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
                      <BrandLogo
                        brandId={brand.id}
                        domain={brand.primary_domain}
                        name={brand.name}
                        size={40}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-semibold text-white">
                          {brand.name}
                        </p>
                        <p className="mt-1 flex items-center gap-1.5 truncate text-xs text-slate-400">
                          <Globe className="h-3 w-3 shrink-0" />
                          {brand.website || brand.primary_domain || 'Website not provided'}
                        </p>
                        <span className={`mt-2 inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${brandTrustClasses(brand)}`}>
                          {trustState === 'INELIGIBLE' ? 'Ineligible · not official' : brandTrustLabel(brand)}
                        </span>
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
                <div className="flex min-w-0 items-start gap-4">
                  <BrandLogo
                    brandId={selectedBrand.id}
                    domain={selectedBrand.primary_domain}
                    name={selectedBrand.name}
                    size={64}
                    verified={brandTrustState(selectedBrand) !== 'INELIGIBLE'}
                  />
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
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${brandTrustClasses(selectedBrand)}`}>
                    {brandTrustLabel(selectedBrand)}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setError('');
                      setShowAssetForm(true);
                    }}
                    className="btn-primary inline-flex items-center justify-center gap-2"
                  >
                    <Plus className="h-4 w-4" />
                    Add registry asset
                  </button>
                </div>
              </div>

              {brandTrustState(selectedBrand) === 'INELIGIBLE' && (
                <div role="alert" className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs leading-5 text-rose-200">
                  This previously saved profile has an ineligible or reserved primary domain. It is not official and cannot pass domain verification. New submissions with this domain are now rejected.
                </div>
              )}

              <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
                  <div>
                    <p className="text-sm font-semibold text-white">Brand logo</p>
                    <p className="mt-1 text-xs text-slate-500">
                      Resolved live from the official site (apple-touch-icon, Open Graph
                      image or web manifest) — not a placeholder.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={logoCheck.loading || !selectedBrand.primary_domain}
                    onClick={() =>
                      selectedBrand.primary_domain &&
                      void checkLogo(selectedBrand.primary_domain)
                    }
                    className="btn-secondary inline-flex items-center justify-center gap-2 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {logoCheck.loading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4" />
                    )}
                    Check logo
                  </button>
                </div>

                {logoCheck.error && (
                  <p className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                    {logoCheck.error}
                  </p>
                )}

                {logoCheck.result && (
                  <div className="mt-3 flex items-start gap-3 rounded-lg border border-slate-700 bg-slate-900/60 p-3">
                    <img
                      src={
                        logoCheck.result.imageUrl
                          ? logoCheck.result.imageUrl.replace(/^\/api(?=\/)/, getApiBaseUrl())
                          : `${getApiBaseUrl()}/intelligence/logo/domain/${encodeURIComponent(
                              String(selectedBrand.primary_domain),
                            )}/image`
                      }
                      alt="Resolved brand logo"
                      className="h-14 w-14 rounded-lg border border-slate-700 bg-white object-contain p-1"
                      onError={(event) => {
                        (event.target as HTMLImageElement).style.display = 'none';
                      }}
                    />
                    <div className="min-w-0 text-xs text-slate-400">
                      <p className="font-medium text-slate-200">
                        {logoCheck.result.status === 'resolved'
                          ? `Logo found (${logoCheck.result.width}×${logoCheck.result.height})`
                          : 'No usable logo found'}
                      </p>
                      <p className="mt-1 break-all">
                        Declared in: {logoCheck.result.declaredIn ?? 'unknown'}
                      </p>
                      <p className="mt-0.5 break-all">
                        Source: {logoCheck.result.sourceUrl ?? 'n/a'}
                      </p>
                      {Array.isArray(logoCheck.result.attempts) &&
                        logoCheck.result.attempts.length > 0 && (
                          <p className="mt-1 text-slate-500">
                            Tried {logoCheck.result.attempts.length} candidate URL(s).
                          </p>
                        )}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                  <div>
                    <p className="flex items-center gap-2 text-sm font-semibold text-white">
                      <ShieldAlert className="h-4 w-4 text-rose-400" />
                      Brand Guard · Impersonation Alerts
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Notifies the official brand via Resend whenever a confusingly similar
                      profile registration is attempted.
                    </p>
                  </div>
                  {selectedBrand.contact_email ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
                      <Mail className="h-3.5 w-3.5" />
                      {selectedBrand.contact_email}
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-300">
                      No alert e-mail set
                    </span>
                  )}
                </div>

                {!selectedBrand.contact_email && (
                  <form
                    onSubmit={handleSaveContactEmail}
                    className="mt-3 flex flex-col gap-2 sm:flex-row"
                  >
                    <input
                      type="email"
                      required
                      maxLength={320}
                      value={contactDraft}
                      onChange={(event) => setContactDraft(event.target.value)}
                      placeholder="security@officialbrand.com"
                      className="flex-1 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs text-white outline-none transition focus:border-blue-500"
                    />
                    <button
                      type="submit"
                      disabled={contactSaving || !contactDraft.trim()}
                      className="btn-secondary inline-flex items-center justify-center gap-2 text-xs disabled:opacity-50"
                    >
                      {contactSaving ? (
                        <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Mail className="h-3.5 w-3.5" />
                      )}
                      Save alert e-mail
                    </button>
                  </form>
                )}

                {brandAlerts.length > 0 && (
                  <div className="mt-3 space-y-2 border-t border-slate-800/80 pt-3">
                    <p className="text-xs font-medium text-slate-400">
                      Recent impersonation alerts ({brandAlerts.length})
                    </p>
                    {brandAlerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-medium text-slate-200">
                            {alert.suspect_name}
                          </span>
                          {alert.suspect_domain && (
                            <span className="ml-1.5 text-slate-500">
                              ({alert.suspect_domain})
                            </span>
                          )}
                          {alert.similarity !== null && alert.similarity !== undefined && (
                            <span className="ml-2 text-slate-400">
                              {(Number(alert.similarity) * 100).toFixed(1)}% match
                            </span>
                          )}
                        </div>
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                            alert.status === 'sent'
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                              : alert.status === 'not_configured'
                                ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                : 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                          }`}
                        >
                          {alert.status.replace(/_/g, ' ')}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="grid gap-3 py-5 sm:grid-cols-2">
                <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-500">
                    Registry submissions
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-white">
                    {assets.length}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-500">
                    Declared domains
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
                  <div>
                    <h3 className="font-semibold text-white">Official asset registry</h3>
                    <p className="mt-1 text-xs text-slate-500">Technical proof establishes registry association, not legal identity or guaranteed safety.</p>
                  </div>
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
                      const trusted = isTrustedAsset(asset);
                      const status = asset.verification_status ??
                        (trusted ? 'VERIFIED_LEGACY' : 'PENDING_VERIFICATION');
                      const busy = verificationBusy.startsWith(`${asset.id}:`);
                      const domain = isDomainAsset(asset);
                      return (
                        <div
                          key={asset.id ?? `${asset.platform}-${asset.identifier}-${index}`}
                          className="rounded-xl border border-slate-800 bg-slate-950/40 p-4"
                        >
                          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                            <div className="flex min-w-0 items-start gap-3">
                              <div className={`rounded-lg border p-2 ${trusted ? 'border-emerald-700 bg-emerald-950/30 text-emerald-300' : 'border-slate-700 bg-slate-900 text-amber-300'}`}>
                                <ShieldCheck className="h-5 w-5" />
                              </div>
                              <div className="min-w-0">
                                <p className="break-all font-mono text-sm text-slate-200">
                                  {asset.identifier || asset.url || 'Identifier unavailable'}
                                </p>
                                <p className="mt-1 text-xs capitalize text-slate-500">
                                  {[asset.platform, asset.asset_type].filter(Boolean).join(' · ') || 'Asset type unavailable'}
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
                                <p className="mt-2 text-xs leading-5 text-slate-500">{safetyLabel(asset)}</p>
                                {asset.verification_method && (
                                  <p className="mt-1 text-xs text-slate-500">Method: {asset.verification_method}</p>
                                )}
                              </div>
                            </div>
                            <div className="flex shrink-0 flex-wrap items-center gap-2">
                              <span
                                className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
                                  trusted
                                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                    : status === 'REJECTED' || status === 'REVOKED'
                                      ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                                      : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                }`}
                              >
                                {trusted ? <CheckCircle2 className="h-3.5 w-3.5" /> : <CircleAlert className="h-3.5 w-3.5" />}
                                {verificationLabel(asset)}
                              </span>
                              {domain ? (
                                <>
                                  <button type="button" disabled={busy} onClick={() => void createDomainChallenge(asset, 'DNS_TXT')} className="btn-secondary px-2.5 py-1 text-xs">
                                    DNS challenge
                                  </button>
                                  <button type="button" disabled={busy} onClick={() => void createDomainChallenge(asset, 'WELL_KNOWN')} className="btn-secondary px-2.5 py-1 text-xs">
                                    File challenge
                                  </button>
                                </>
                              ) : (asset.asset_type ?? '') !== 'trademark' && (
                                <button type="button" disabled={busy} onClick={() => void verifyAssociation(asset)} className="btn-secondary px-2.5 py-1 text-xs">
                                  {trusted ? 'Re-verify association' : 'Verify association'}
                                </button>
                              )}
                            </div>
                          </div>

                          {!domain && !trusted && (
                            <p className="mt-3 rounded-lg bg-slate-900/70 p-3 text-xs leading-5 text-slate-400">
                              Verification requires an exact declaration for this asset in <code>/.well-known/findout-assets.json</code> on the freshly verified (not legacy-only) primary domain. A public listing, matching name, or logo is not association proof.
                            </p>
                          )}

                          {domain && (
                            <p className="mt-3 rounded-lg bg-slate-900/70 p-3 text-xs leading-5 text-slate-400">
                              If this is not the brand primary domain, publish both this challenge and an exact domain entry in the asset manifest on the freshly verified primary domain.
                            </p>
                          )}

                          {challenge?.assetId === String(asset.id) && (
                            <div className="mt-4 space-y-3 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 text-xs">
                              <p className="font-semibold text-cyan-200">
                                {challenge.method === 'DNS_TXT' ? 'Publish this DNS TXT record' : 'Publish this verification file'}
                              </p>
                              {challenge.method === 'DNS_TXT' ? (
                                <>
                                  <p className="text-slate-400">Host/name: <code className="break-all text-slate-200">{challenge.dnsName}</code></p>
                                  <p className="text-slate-400">TXT value:</p>
                                  <code className="block break-all rounded bg-slate-950 p-2 text-cyan-100">{challenge.dnsValue}</code>
                                </>
                              ) : (
                                <>
                                  <p className="text-slate-400">URL: <code className="break-all text-slate-200">{challenge.wellKnownUrl}</code></p>
                                  <p className="text-slate-400">File contents:</p>
                                  <code className="block break-all rounded bg-slate-950 p-2 text-cyan-100">{challenge.fileContents}</code>
                                </>
                              )}
                              <p className="text-slate-500">Expires: {new Date(challenge.expiresAt).toLocaleString()}. The token is shown here, not stored as plaintext by the backend.</p>
                              <button type="button" disabled={busy} onClick={() => void verifyDomain(asset)} className="btn-primary px-3 py-1.5 text-xs">
                                {busy ? 'Checking proof…' : 'Check domain proof'}
                              </button>
                            </div>
                          )}
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

              <label className="block space-y-1.5">
                <span className="text-sm text-slate-300">
                  Official contact e-mail (impersonation alerts)
                </span>
                <input
                  type="email"
                  maxLength={320}
                  value={brandForm.contactEmail}
                  onChange={(event) =>
                    setBrandForm({ ...brandForm, contactEmail: event.target.value })
                  }
                  placeholder="security@example.com"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-3 text-sm text-white outline-none transition focus:border-blue-500"
                />
                <span className="block text-xs text-slate-500">
                  When somebody tries to register a brand similar to this one, the
                  impersonation alert is e-mailed to this address.
                </span>
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
                  Add registry asset
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  For {selectedBrand.name}. Every submission starts pending. Backend proof is required before official trust or exclusions.
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
                  onChange={(event) => {
                    const nextType = event.target.value;
                    setAssetForm({
                      ...assetForm,
                      asset_type: nextType,
                      platform: nextType === 'domain' || nextType === 'logo'
                        ? 'website'
                        : nextType === 'mobile_app'
                          ? 'app_store'
                          : assetForm.platform,
                    });
                  }}
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
                  <option value="bluesky">Bluesky</option>
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

              <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs leading-5 text-slate-400">
                Submission alone never marks an asset official. The primary domain uses DNS/file proof. Additional domains also need an exact declaration on the freshly verified primary domain; social, app, and logo assets use that same declaration model.
              </p>

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
                  Submit for verification
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {guardPopup && (
        <BrandGuardPopup
          suspectName={guardPopup.suspectName}
          suspectDomain={guardPopup.suspectDomain}
          conflicts={guardPopup.conflicts}
          registering={saving}
          onClose={() => {
            setGuardPopup(null);
            if (selectedBrandId !== null) void loadBrandAlerts(selectedBrandId);
          }}
          onRegisterAnyway={() => void handleRegisterAnyway()}
        />
      )}
    </section>
  );
};

export default BrandsView;
