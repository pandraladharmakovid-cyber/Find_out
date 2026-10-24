import { pool } from "./db";

export const INIT_SCHEMA_SQL = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS brands (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  primary_domain TEXT NOT NULL,
  industry TEXT,
  alternate_names TEXT[] NOT NULL DEFAULT '{}',
  associated_domains TEXT[] NOT NULL DEFAULT '{}',
  keywords TEXT[] NOT NULL DEFAULT '{}',
  website TEXT,
  logo_url TEXT,
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  lookalike_threshold NUMERIC(4, 3) NOT NULL DEFAULT 0.75
    CHECK (lookalike_threshold >= 0 AND lookalike_threshold <= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE brands ADD COLUMN IF NOT EXISTS slug TEXT;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS industry TEXT;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS alternate_names TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE brands ADD COLUMN IF NOT EXISTS associated_domains TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE brands ADD COLUMN IF NOT EXISTS keywords TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE brands ADD COLUMN IF NOT EXISTS website TEXT;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS logo_url TEXT;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'active';
ALTER TABLE brands ADD COLUMN IF NOT EXISTS lookalike_threshold NUMERIC(4, 3) NOT NULL DEFAULT 0.75;
ALTER TABLE brands ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE brands SET slug = regexp_replace(lower(trim(name)), '[^a-z0-9]+', '-', 'g')
WHERE slug IS NULL OR slug = '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_brands_slug ON brands(slug);

CREATE TABLE IF NOT EXISTS investigations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  target_url TEXT,
  query_text TEXT,
  brand_id UUID REFERENCES brands(id) ON DELETE SET NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  summary TEXT,
  risk_score NUMERIC(5, 2) DEFAULT 0.00,
  confidence_score NUMERIC(5, 2) DEFAULT 0.00,
  verdict VARCHAR(64) DEFAULT 'unverified',
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE investigations ADD COLUMN IF NOT EXISTS brand_id UUID REFERENCES brands(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS evidence_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  source VARCHAR(64) NOT NULL,
  source_url TEXT,
  raw_payload JSONB DEFAULT '{}'::jsonb,
  is_verified BOOLEAN DEFAULT false,
  reliability_score NUMERIC(5, 2) DEFAULT 0.00,
  extracted_claim TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS source_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
  source VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  latency_ms INTEGER DEFAULT 0,
  error_message TEXT,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS exclusion_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern TEXT NOT NULL UNIQUE,
  reason TEXT,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_status VARCHAR(32);
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_method TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS verified_by TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS safety_status VARCHAR(32) NOT NULL DEFAULT 'NOT_ASSESSED';
ALTER TABLE official_assets ADD COLUMN IF NOT EXISTS safety_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;

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

-- Preserve previously verified rows as legacy-verified; never promote legacy
-- unverified rows. New submissions always start PENDING_VERIFICATION.
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

ALTER TABLE exclusion_rules
  ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES official_assets(id) ON DELETE CASCADE;
ALTER TABLE exclusion_rules
  ADD COLUMN IF NOT EXISTS brand_id UUID REFERENCES brands(id) ON DELETE CASCADE;

-- Unlinked historical rules are retained for audit but cannot suppress findings.
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

-- Restore exclusions only for domain assets already marked verified/legacy-verified.
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

CREATE TABLE IF NOT EXISTS monitoring_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
  job_type VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  findings_count INTEGER NOT NULL DEFAULT 0,
  threats_detected INTEGER NOT NULL DEFAULT 0,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS monitoring_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
  target_type VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'IN_PROGRESS',
  source_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS discovered_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES monitoring_runs(id) ON DELETE CASCADE,
  brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  candidate_identifier VARCHAR(255) NOT NULL,
  candidate_url TEXT NOT NULL,
  display_name VARCHAR(255),
  developer_publisher VARCHAR(255),
  description TEXT,
  icon_or_logo_url TEXT,
  is_excluded_official BOOLEAN NOT NULL DEFAULT FALSE,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS candidate_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
  evidence_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  similarity_score NUMERIC(5, 4),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE candidate_evidence
  ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES discovered_candidates(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS risk_assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
  risk_level VARCHAR(20) NOT NULL,
  risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
  confidence_score NUMERIC(5, 4) NOT NULL DEFAULT 0,
  primary_reasons TEXT[] NOT NULL DEFAULT '{}',
  ai_summary TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'UNRESOLVED',
  assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES discovered_candidates(id) ON DELETE CASCADE;
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20) NOT NULL DEFAULT 'UNASSESSED';
ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0;
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS confidence_score NUMERIC(5, 4) NOT NULL DEFAULT 0;
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS primary_reasons TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS overall_score NUMERIC(5, 2);
ALTER TABLE risk_assessments
  ADD COLUMN IF NOT EXISTS severity VARCHAR(20);
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'risk_assessments'
      AND column_name = 'finding_id'
      AND is_nullable = 'NO'
  ) THEN
    ALTER TABLE risk_assessments ALTER COLUMN finding_id DROP NOT NULL;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS official_asset_matches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES official_assets(id) ON DELETE CASCADE,
  matched_by VARCHAR(50) NOT NULL,
  matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS complaints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
  brand_id UUID REFERENCES brands(id) ON DELETE SET NULL,
  platform VARCHAR(64) NOT NULL DEFAULT 'unknown',
  target_identifier TEXT NOT NULL DEFAULT '',
  target_url TEXT NOT NULL DEFAULT '',
  complaint_category VARCHAR(100) NOT NULL DEFAULT 'impersonation',
  description TEXT NOT NULL DEFAULT '',
  evidence_attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
  submission_status VARCHAR(50) NOT NULL DEFAULT 'DRAFT',
  reference_number VARCHAR(100),
  reporter_email TEXT,
  claim_description TEXT NOT NULL DEFAULT '',
  complaint_type VARCHAR(64),
  recipient_email TEXT,
  subject TEXT,
  body_text TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  sent_at TIMESTAMPTZ,
  status VARCHAR(32) DEFAULT 'received',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE complaints ADD COLUMN IF NOT EXISTS brand_id UUID REFERENCES brands(id) ON DELETE SET NULL;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS platform VARCHAR(64) NOT NULL DEFAULT 'unknown';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS target_identifier TEXT NOT NULL DEFAULT '';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS target_url TEXT NOT NULL DEFAULT '';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS complaint_category VARCHAR(100) NOT NULL DEFAULT 'impersonation';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS evidence_attachments JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS submission_status VARCHAR(50) NOT NULL DEFAULT 'DRAFT';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS reference_number VARCHAR(100);
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS reporter_email TEXT;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS claim_description TEXT NOT NULL DEFAULT '';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS complaint_type VARCHAR(64);
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS recipient_email TEXT;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'received';
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS subject TEXT;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS body_text TEXT;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
ALTER TABLE complaints ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE complaints ALTER COLUMN platform SET DEFAULT 'unknown';
ALTER TABLE complaints ALTER COLUMN target_identifier SET DEFAULT '';
ALTER TABLE complaints ALTER COLUMN target_url SET DEFAULT '';
ALTER TABLE complaints ALTER COLUMN complaint_category SET DEFAULT 'impersonation';
ALTER TABLE complaints ALTER COLUMN description SET DEFAULT '';

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id UUID REFERENCES brands(id) ON DELETE CASCADE,
  investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
  severity VARCHAR(20) NOT NULL DEFAULT 'medium',
  status VARCHAR(32) NOT NULL DEFAULT 'open',
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  evidence_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  category VARCHAR(100) NOT NULL DEFAULT 'IMPERSONATION',
  summary TEXT NOT NULL DEFAULT '',
  prevention_guidance TEXT NOT NULL DEFAULT '',
  source_url TEXT NOT NULL DEFAULT '',
  published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS brand_id UUID REFERENCES brands(id) ON DELETE CASCADE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'open';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS evidence_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN category SET DEFAULT 'IMPERSONATION';
ALTER TABLE alerts ALTER COLUMN summary SET DEFAULT '';
ALTER TABLE alerts ALTER COLUMN prevention_guidance SET DEFAULT '';
ALTER TABLE alerts ALTER COLUMN source_url SET DEFAULT '';
ALTER TABLE alerts ALTER COLUMN published_at SET DEFAULT NOW();
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_severity_check;

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
  source VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  format VARCHAR(20) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id ON evidence_items(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_source ON source_audit_logs(source);
CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
CREATE INDEX IF NOT EXISTS idx_assets_brand_id ON official_assets(brand_id);
CREATE INDEX IF NOT EXISTS idx_monitoring_jobs_brand_id ON monitoring_jobs(brand_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_discovered_candidates_brand_id ON discovered_candidates(brand_id);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate_id ON candidate_evidence(candidate_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_candidate_id ON risk_assessments(candidate_id);

-- ---------------------------------------------------------------------
-- Findings performance: the evidence page filters by brand/run and sorts by
-- discovered_at, so those predicates need covering indexes.
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_candidates_brand_discovered
  ON discovered_candidates(brand_id, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_candidates_run_discovered
  ON discovered_candidates(run_id, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate_recorded
  ON candidate_evidence(candidate_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_type
  ON candidate_evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_candidate_assessed
  ON risk_assessments(candidate_id, assessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitoring_runs_brand_started
  ON monitoring_runs(brand_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_items_investigation_created
  ON evidence_items(investigation_id, created_at ASC);

-- ---------------------------------------------------------------------
-- AI agent (Find_out Copilot)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  goal TEXT NOT NULL,
  mode VARCHAR(32) NOT NULL DEFAULT 'investigate',
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  brand_id UUID REFERENCES brands(id) ON DELETE SET NULL,
  target TEXT,
  model VARCHAR(160),
  transport VARCHAR(32),
  steps INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  verdict VARCHAR(64),
  risk_score NUMERIC(5, 2),
  confidence NUMERIC(5, 2),
  engine VARCHAR(32) NOT NULL DEFAULT 'llm',
  report JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace JSONB NOT NULL DEFAULT '[]'::jsonb,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS agent_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  step INTEGER NOT NULL DEFAULT 0,
  role VARCHAR(24) NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  tool_name VARCHAR(80),
  tool_result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_created ON agent_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_runs_brand ON agent_runs(brand_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_messages_run ON agent_messages(run_id, step ASC);

-- =====================================================================
-- Rulebook v2: every detection is a record with a lifecycle, an owner and
-- a full change history (who changed it, when, and why).
-- =====================================================================
CREATE TABLE IF NOT EXISTS detection_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID REFERENCES discovered_candidates(id) ON DELETE CASCADE,
  investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
  brand_id UUID REFERENCES brands(id) ON DELETE SET NULL,
  -- Where the detection came from (app store, social, domain inspection...).
  source VARCHAR(64) NOT NULL DEFAULT 'unknown',
  source_label VARCHAR(120) NOT NULL DEFAULT 'Unknown source',
  -- The thing that was suspected.
  suspected_asset VARCHAR(512) NOT NULL DEFAULT '',
  suspected_url TEXT NOT NULL DEFAULT '',
  suspected_asset_type VARCHAR(48) NOT NULL DEFAULT 'unknown',
  -- Plain-English evidence, one sentence per item.
  evidence_summary TEXT[] NOT NULL DEFAULT '{}',
  evidence_count INTEGER NOT NULL DEFAULT 0,
  -- Graded similarity risk.
  similarity_risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
  confidence_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'UNASSESSED',
  risk_explanation TEXT NOT NULL DEFAULT '',
  -- Lifecycle: NEW, UNDER_REVIEW, CONFIRMED, FALSE_POSITIVE, CLOSED.
  status VARCHAR(24) NOT NULL DEFAULT 'NEW',
  priority VARCHAR(16) NOT NULL DEFAULT 'MEDIUM',
  assigned_to VARCHAR(120),
  is_official_excluded BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ,
  decided_by VARCHAR(120)
);

CREATE INDEX IF NOT EXISTS idx_detection_records_status ON detection_records(status, similarity_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_detection_records_priority ON detection_records(priority, similarity_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_detection_records_brand ON detection_records(brand_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_records_candidate
  ON detection_records(candidate_id) WHERE candidate_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS detection_record_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id UUID NOT NULL REFERENCES detection_records(id) ON DELETE CASCADE,
  action VARCHAR(32) NOT NULL DEFAULT 'STATUS_CHANGE',
  from_status VARCHAR(24),
  to_status VARCHAR(24),
  actor VARCHAR(120) NOT NULL DEFAULT 'system',
  note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_record_events_record
  ON detection_record_events(record_id, created_at ASC);

-- One-time high-risk alerts: the dedupe key guarantees an analyst is told once
-- per record instead of on every scan.
CREATE TABLE IF NOT EXISTS high_risk_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id UUID NOT NULL REFERENCES detection_records(id) ON DELETE CASCADE,
  dedupe_key VARCHAR(160) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'HIGH',
  title VARCHAR(240) NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by VARCHAR(120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_high_risk_alerts_dedupe ON high_risk_alerts(dedupe_key);
`;

export async function initializeSchema(): Promise<void> {
  const client = await pool.connect();
  try {
    console.log("[database] Checking and applying database schema...");
    await client.query("BEGIN");
    await client.query(INIT_SCHEMA_SQL);
    await client.query("COMMIT");
    console.log("[database] Schema initialized successfully.");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("[database] Failed to initialize schema:", error);
    throw error;
  } finally {
    client.release();
  }
}
