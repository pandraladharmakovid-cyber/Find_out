-- PostgreSQL Migration Script for Find_out DRP Platform
-- Creates schema and tables according to master plan requirements

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Brands Table
CREATE TABLE IF NOT EXISTS brands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    alternate_names TEXT[],
    primary_domain VARCHAR(255) NOT NULL,
    associated_domains TEXT[],
    logo_url TEXT,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Official Brand Assets Registry (Crucial for Exclusion Engine)
CREATE TABLE IF NOT EXISTS brand_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN ('SOCIAL_ACCOUNT', 'MOBILE_APP', 'DOMAIN', 'LOGO')),
    platform VARCHAR(50) NOT NULL, -- 'BLUESKY', 'YOUTUBE', 'PLAY_STORE', 'APP_STORE', 'WEB'
    identifier VARCHAR(255) NOT NULL, -- username, package_name/app_id, domain
    official_url TEXT NOT NULL,
    publisher_name VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE, -- Legacy table: never trust submission alone
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_brand_asset UNIQUE (brand_id, platform, identifier)
);

-- 3. Monitoring Runs
CREATE TABLE IF NOT EXISTS monitoring_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    target_type VARCHAR(50) NOT NULL, -- 'SOCIAL', 'APP_STORE', 'UNIVERSAL_URL'
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED')),
    source_errors JSONB DEFAULT '[]'::jsonb, -- Graceful failure tracking
    summary JSONB DEFAULT '{}'::jsonb,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- 4. Discovered Candidates
CREATE TABLE IF NOT EXISTS discovered_candidates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id UUID NOT NULL REFERENCES monitoring_runs(id) ON DELETE CASCADE,
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    candidate_identifier VARCHAR(255) NOT NULL,
    candidate_url TEXT NOT NULL,
    display_name VARCHAR(255),
    developer_publisher VARCHAR(255),
    description TEXT,
    icon_or_logo_url TEXT,
    is_excluded_official BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Candidate Evidence
CREATE TABLE IF NOT EXISTS candidate_evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
    evidence_type VARCHAR(100) NOT NULL, -- 'NAME_LOOKALIKE', 'LOGO_SIMILARITY', 'PUBLISHER_MISMATCH', 'DESCRIPTION_OVERLAP', 'MALICIOUS_LINK'
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    details JSONB NOT NULL,
    similarity_score NUMERIC(5, 4), -- e.g. 0.8520
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Risk Assessments
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('BENIGN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence_score NUMERIC(5, 4) NOT NULL,
    primary_reasons TEXT[] NOT NULL,
    ai_summary TEXT,
    status VARCHAR(50) DEFAULT 'UNRESOLVED' CHECK (status IN ('UNRESOLVED', 'INVESTIGATING', 'TAKEDOWN_REQUESTED', 'RESOLVED', 'FALSE_POSITIVE')),
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Official Asset Matches (Audit trail of exclusions)
CREATE TABLE IF NOT EXISTS official_asset_matches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    candidate_id UUID NOT NULL REFERENCES discovered_candidates(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES brand_assets(id) ON DELETE CASCADE,
    matched_by VARCHAR(50) NOT NULL, -- 'URL', 'APP_ID', 'EXACT_IDENTIFIER'
    matched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Complaints & Official Reports
CREATE TABLE IF NOT EXISTS complaints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    platform VARCHAR(50) NOT NULL,
    target_identifier VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    complaint_category VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    evidence_attachments JSONB DEFAULT '[]'::jsonb,
    submission_status VARCHAR(50) DEFAULT 'DRAFT' CHECK (submission_status IN ('DRAFT', 'SUBMITTED', 'ACKNOWLEDGED', 'RESOLVED')),
    reference_number VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Cybersecurity Alerts & News
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'PHISHING', 'IMPERSONATION', 'MALWARE'
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    summary TEXT NOT NULL,
    prevention_guidance TEXT NOT NULL,
    source_url TEXT NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 10. Recovery Checklists (Incident-Specific Workflows)
CREATE TABLE IF NOT EXISTS recovery_checklists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_type VARCHAR(100) NOT NULL, -- 'CLICKED_LINK', 'SUBMITTED_CREDENTIALS', 'INSTALLED_UNKNOWN_APP'
    step_order INTEGER NOT NULL,
    action_text TEXT NOT NULL,
    guidance_en TEXT NOT NULL,
    guidance_te TEXT NOT NULL,
    guidance_hi TEXT NOT NULL,
    is_completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_brand_assets_brand_id ON brand_assets(brand_id);
CREATE INDEX IF NOT EXISTS idx_discovered_candidates_brand_id ON discovered_candidates(brand_id);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate_id ON candidate_evidence(candidate_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_candidate_id ON risk_assessments(candidate_id);

-- 11. Brand Guard — Impersonation-registration alerts (Resend)
ALTER TABLE brands ADD COLUMN IF NOT EXISTS contact_email TEXT;

CREATE TABLE IF NOT EXISTS impersonation_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    suspect_name TEXT NOT NULL,
    suspect_domain TEXT,
    suspect_website TEXT,
    match_type VARCHAR(32) NOT NULL DEFAULT 'name',
    similarity NUMERIC(4, 3) CHECK (similarity IS NULL OR (similarity >= 0 AND similarity <= 1)),
    verdict VARCHAR(32) NOT NULL DEFAULT 'lookalike',
    recipient_email TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'not_configured')),
    provider VARCHAR(32) NOT NULL DEFAULT 'resend',
    provider_message_id TEXT,
    error_detail TEXT,
    reporter_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_impersonation_alerts_brand ON impersonation_alerts(brand_id, created_at DESC);

-- 12. External Brand Watch — Continuous Internet Impersonation Detection
CREATE TABLE IF NOT EXISTS external_watch_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_id UUID NOT NULL UNIQUE REFERENCES brands(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_minutes INTEGER NOT NULL DEFAULT 60,
    alert_risk_threshold NUMERIC(5, 2) NOT NULL DEFAULT 65.00,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_external_watch_schedules_due ON external_watch_schedules(is_enabled, next_run_at ASC);

CREATE TABLE IF NOT EXISTS external_watch_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    trigger_type VARCHAR(32) NOT NULL DEFAULT 'scheduled',
    status VARCHAR(32) NOT NULL DEFAULT 'IN_PROGRESS',
    monitoring_run_id UUID REFERENCES monitoring_runs(id) ON DELETE SET NULL,
    sources_checked JSONB NOT NULL DEFAULT '[]'::jsonb,
    candidates_discovered INTEGER NOT NULL DEFAULT 0,
    new_candidates_count INTEGER NOT NULL DEFAULT 0,
    changed_candidates_count INTEGER NOT NULL DEFAULT 0,
    high_risk_count INTEGER NOT NULL DEFAULT 0,
    alerts_created INTEGER NOT NULL DEFAULT 0,
    emails_sent INTEGER NOT NULL DEFAULT 0,
    deduplicated_alerts_skipped INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_external_watch_runs_brand ON external_watch_runs(brand_id, started_at DESC);

CREATE TABLE IF NOT EXISTS external_watch_seen_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    platform VARCHAR(64) NOT NULL,
    canonical_id VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    display_name VARCHAR(255),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_candidate_id UUID REFERENCES discovered_candidates(id) ON DELETE SET NULL,
    last_investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
    last_risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
    last_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
    previous_risk_score NUMERIC(5, 2),
    change_state VARCHAR(24) NOT NULL DEFAULT 'new',
    times_seen INTEGER NOT NULL DEFAULT 1,
    corroborating_signals JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (brand_id, platform, canonical_id)
);

CREATE INDEX IF NOT EXISTS idx_external_watch_seen_brand ON external_watch_seen_assets(brand_id, last_risk_score DESC, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS external_watch_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_id UUID NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    dedupe_key VARCHAR(320) NOT NULL UNIQUE,
    platform VARCHAR(64) NOT NULL,
    canonical_id VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'HIGH',
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    recipient_email TEXT,
    email_status VARCHAR(32) NOT NULL DEFAULT 'not_configured',
    resend_message_id TEXT,
    email_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_external_watch_notifications_brand ON external_watch_notifications(brand_id, created_at DESC);
