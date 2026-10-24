import React, { useEffect, useState } from 'react';
import { Building2, ShieldCheck } from 'lucide-react';

import { getApiBaseUrl } from './api';

/**
 * Real brand logos.
 *
 * The backend resolves a logo from (in order) the uploaded asset, a verified
 * asset URL, the stored logo URL, and finally the brand's primary domain —
 * discovering `apple-touch-icon`, `og:image` and the manifest on the live site.
 * This component streams that image from
 * `GET /api/intelligence/logo/brand/:brandId/image`, and degrades to a labelled
 * initials badge when there is genuinely nothing to show. It never renders a
 * broken-image icon, and it says "no logo" rather than pretending.
 */

type BrandLogoProps = {
  brandId?: string | number | null;
  domain?: string | null;
  name?: string;
  size?: number;
  className?: string;
  /** Show a small verified tick when the brand has a verified asset. */
  verified?: boolean;
};

function initialsOf(name?: string): string {
  if (!name) return '—';
  const words = name
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (words.length === 0) return '—';
  if (words.length === 1) return words[0]!.slice(0, 2).toUpperCase();
  return `${words[0]![0]}${words[1]![0]}`.toUpperCase();
}

/** Stable pastel colour per brand so the fallback badge is recognisable. */
function toneFor(seed: string): string {
  const tones = [
    'from-blue-500/30 to-violet-500/20 text-blue-200 border-blue-500/30',
    'from-emerald-500/30 to-teal-500/20 text-emerald-200 border-emerald-500/30',
    'from-amber-500/30 to-orange-500/20 text-amber-200 border-amber-500/30',
    'from-rose-500/30 to-pink-500/20 text-rose-200 border-rose-500/30',
    'from-cyan-500/30 to-sky-500/20 text-cyan-200 border-cyan-500/30',
    'from-fuchsia-500/30 to-purple-500/20 text-fuchsia-200 border-fuchsia-500/30',
  ];
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) % 997;
  }
  return tones[hash % tones.length]!;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  brandId,
  domain,
  name,
  size = 40,
  className = '',
  verified = false,
}) => {
  const [failed, setFailed] = useState(false);

  const src = brandId
    ? `${getApiBaseUrl()}/intelligence/logo/brand/${encodeURIComponent(String(brandId))}/image`
    : domain
      ? `${getApiBaseUrl()}/intelligence/logo/domain/${encodeURIComponent(domain)}/image`
      : '';

  // A different brand must not inherit the previous brand's failure state.
  useEffect(() => {
    setFailed(false);
  }, [brandId, domain]);

  const dimension = { width: size, height: size };

  if (!src || failed) {
    return (
      <div
        style={dimension}
        title={name ? `${name} — no logo published` : 'No logo available'}
        className={`flex shrink-0 items-center justify-center rounded-xl border bg-gradient-to-br font-semibold ${toneFor(
          String(brandId ?? domain ?? name ?? 'brand'),
        )} ${className}`}
      >
        {name ? (
          <span style={{ fontSize: Math.max(10, Math.round(size * 0.34)) }}>
            {initialsOf(name)}
          </span>
        ) : (
          <Building2 style={{ width: size * 0.45, height: size * 0.45 }} />
        )}
      </div>
    );
  }

  return (
    <div className={`relative shrink-0 ${className}`} style={dimension}>
      <img
        src={src}
        alt={name ? `${name} logo` : 'Brand logo'}
        width={size}
        height={size}
        loading="lazy"
        onError={() => setFailed(true)}
        className="h-full w-full rounded-xl border border-slate-700 bg-white object-contain p-1"
      />
      {verified && (
        <span
          title="Verified official brand"
          className="absolute -bottom-1 -right-1 rounded-full border border-slate-900 bg-emerald-500 p-0.5 text-slate-950"
        >
          <ShieldCheck className="h-3 w-3" />
        </span>
      )}
    </div>
  );
};

export default BrandLogo;
