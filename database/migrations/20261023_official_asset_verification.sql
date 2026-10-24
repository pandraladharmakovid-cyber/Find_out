-- Find_out official asset verification and trust-boundary migration.
-- PostgreSQL 13+; additive and safe to re-run after the base Find_out schema exists.
-- Back up first and certify on a staging copy before production use.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS official_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
  asset_type VARCHAR(64) NOT NULL,
  platform VARCHAR(64) NOT NULL DEFAULT 'unknown',
  identifier TEXT NOT NULL,
  value TEXT NOT NULL,
  canonical_url TEXT,
  hash_signature TEXT,
  image_data BYTEA,
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_status VARCHAR(32) NOT NULL DEFAULT 'PENDING_VERIFICATION',
  verification_method TEXT,
  verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  verified_at TIMESTAMPTZ,
  verified_by TEXT,
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT,
  safety_status VARCHAR(32) NOT NULL DEFAULT 'NOT_ASSESSED',
  safety_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (brand_id, asset_type, platform, identifier)
);

ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS image_data BYTEA;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_status VARCHAR(32);
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_method TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verified_by TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS safety_status VARCHAR(32) NOT NULL DEFAULT 'NOT_ASSESSED';
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS safety_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Preserve rows from the historical brand_assets table when present. Existing
-- verified rows become LEGACY, not freshly proof-verified. Unverified rows stay pending.
DO $$
BEGIN
  IF to_regclass('public.brand_assets') IS NOT NULL THEN
    INSERT INTO official_assets (
      brand_id, asset_type, platform, identifier, value, canonical_url, is_verified,
      verification_status, verification_method, verification_evidence, metadata
    )
    SELECT
      (asset.fields->>'brand_id')::uuid,
      lower(COALESCE(asset.fields->>'asset_type', 'unknown')),
      lower(COALESCE(asset.fields->>'platform', 'unknown')),
      COALESCE(asset.fields->>'identifier', asset.fields->>'value', asset.fields->>'handle'),
      COALESCE(asset.fields->>'identifier', asset.fields->>'value', asset.fields->>'handle'),
      COALESCE(asset.fields->>'official_url', asset.fields->>'canonical_url', asset.fields->>'url'),
      COALESCE((asset.fields->>'is_verified')::boolean, false),
      CASE WHEN COALESCE((asset.fields->>'is_verified')::boolean, false)
        THEN 'VERIFIED_LEGACY' ELSE 'PENDING_VERIFICATION' END,
      CASE WHEN COALESCE((asset.fields->>'is_verified')::boolean, false)
        THEN 'LEGACY_RECORD' ELSE NULL END,
      jsonb_build_object(
        'requiresReverification', COALESCE((asset.fields->>'is_verified')::boolean, false),
        'note', 'Legacy row migrated without creating new ownership proof.'
      ),
      jsonb_build_object('publisher', COALESCE(asset.fields->>'publisher_name', asset.fields->>'publisher'))
    FROM brand_assets AS legacy
    CROSS JOIN LATERAL (SELECT to_jsonb(legacy) AS fields) AS asset
    WHERE NULLIF(asset.fields->>'brand_id', '') IS NOT NULL
      AND NULLIF(COALESCE(asset.fields->>'identifier', asset.fields->>'value', asset.fields->>'handle'), '') IS NOT NULL
    ON CONFLICT (brand_id, asset_type, platform, identifier) DO NOTHING;
  END IF;
END $$;

UPDATE official_assets
SET verification_status = CASE
  WHEN is_verified THEN 'VERIFIED_LEGACY'
  ELSE 'PENDING_VERIFICATION'
END
WHERE verification_status IS NULL;

UPDATE official_assets
SET verification_method = COALESCE(verification_method, 'LEGACY_RECORD'),
    verified_by = COALESCE(verified_by, 'legacy-preserved'),
    verified_at = COALESCE(verified_at, updated_at, created_at),
    verification_evidence = verification_evidence || jsonb_build_object(
      'note', 'Existing verified row preserved during verification-gate migration; fresh re-verification is recommended.',
      'requiresReverification', true
    )
WHERE verification_status = 'VERIFIED_LEGACY';

ALTER TABLE official_assets ALTER COLUMN verification_status SET DEFAULT 'PENDING_VERIFICATION';
ALTER TABLE official_assets ALTER COLUMN verification_status SET NOT NULL;

CREATE TABLE IF NOT EXISTS exclusion_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern TEXT NOT NULL UNIQUE,
  reason TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE exclusion_rules
  ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES official_assets(id) ON DELETE CASCADE;
ALTER TABLE exclusion_rules
  ADD COLUMN IF NOT EXISTS brand_id UUID REFERENCES brands(id) ON DELETE CASCADE;

-- Unlinked or currently untrusted rules cannot suppress findings.
UPDATE exclusion_rules SET is_active = FALSE WHERE asset_id IS NULL;
UPDATE exclusion_rules r
SET is_active = FALSE
WHERE r.asset_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM official_assets a
    WHERE a.id = r.asset_id
      AND a.brand_id = r.brand_id
      AND a.is_verified = TRUE
      AND a.verification_status IN ('VERIFIED', 'VERIFIED_LEGACY')
  );

-- Restore only same-brand rules backed by verified/legacy domain assets.
-- DISTINCT ON avoids duplicate-pattern conflicts during a single backfill.
INSERT INTO exclusion_rules (pattern, reason, is_active, asset_id, brand_id)
SELECT value,
       'Verified or legacy-verified domain asset ' || id::text,
       TRUE,
       id,
       brand_id
FROM (
  SELECT DISTINCT ON (value) value, id, brand_id, verified_at, created_at
  FROM official_assets
  WHERE is_verified = TRUE
    AND verification_status IN ('VERIFIED', 'VERIFIED_LEGACY')
    AND asset_type IN ('domain', 'subdomain', 'website')
  ORDER BY value, verified_at DESC NULLS LAST, created_at ASC, id
) AS verified_domains
ON CONFLICT (pattern) DO UPDATE SET
  asset_id = EXCLUDED.asset_id,
  brand_id = EXCLUDED.brand_id,
  reason = EXCLUDED.reason,
  is_active = TRUE;

CREATE TABLE IF NOT EXISTS asset_verification_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID NOT NULL REFERENCES official_assets(id) ON DELETE CASCADE,
  method VARCHAR(32) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_verification_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID NOT NULL REFERENCES official_assets(id) ON DELETE CASCADE,
  event_type VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  method VARCHAR(64),
  actor TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_official_assets_verification
  ON official_assets(brand_id, verification_status, is_verified);
CREATE INDEX IF NOT EXISTS idx_exclusion_rules_asset ON exclusion_rules(asset_id);
CREATE INDEX IF NOT EXISTS idx_exclusion_rules_brand ON exclusion_rules(brand_id);
CREATE INDEX IF NOT EXISTS idx_asset_challenges_active
  ON asset_verification_challenges(asset_id, expires_at)
  WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_asset_verification_events_asset
  ON asset_verification_events(asset_id, created_at DESC);

COMMIT;
