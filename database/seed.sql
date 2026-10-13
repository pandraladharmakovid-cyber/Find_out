-- Seed script for Find_out DRP Platform
-- Populates baseline entities for automated rubric tests & demo

-- 1. Seed a sample Brand
INSERT INTO brands (id, name, alternate_names, primary_domain, associated_domains, logo_url, description)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'TechCorp Global',
    ARRAY['TechCorp', 'TechCorp Inc', 'TechCorpOfficial'],
    'techcorp.com',
    ARRAY['techcorp-security.com', 'techcorp.io'],
    'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=200',
    'Official corporate entity for TechCorp Global software solutions.'
) ON CONFLICT (id) DO NOTHING;

-- 2. Seed Official Assets (Must be excluded during scans)
INSERT INTO brand_assets (brand_id, asset_type, platform, identifier, official_url, publisher_name, is_verified)
VALUES 
(
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'SOCIAL_ACCOUNT',
    'REDDIT',
    'TechCorpOfficial',
    'https://reddit.com/user/TechCorpOfficial',
    'TechCorp Inc',
    TRUE
),
(
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'MOBILE_APP',
    'PLAY_STORE',
    'com.techcorp.app',
    'https://play.google.com/store/apps/details?id=com.techcorp.app',
    'TechCorp Technologies LLC',
    TRUE
) ON CONFLICT DO NOTHING;

-- 3. Seed Cybersecurity Alerts
INSERT INTO alerts (title, category, severity, summary, prevention_guidance, source_url, published_at)
VALUES (
    'Credential Phishing Campaign Mimicking TechCorp Customer Portal',
    'PHISHING',
    'HIGH',
    'Attackers are distributing lookalike domains (e.g., techc0rp-login.com) targeting enterprise customers.',
    'Verify SSL certificates, ensure domains match techcorp.com directly, and enforce MFA.',
    'https://cisa.gov/news-events/cybersecurity-advisories',
    NOW() - INTERVAL '2 days'
);

-- 4. Seed Multilingual Recovery Steps (English, Telugu, Hindi)
INSERT INTO recovery_checklists (incident_type, step_order, action_text, guidance_en, guidance_te, guidance_hi)
VALUES 
(
    'CLICKED_LINK',
    1,
    'Disconnect device from network',
    'Disconnect your device from Wi-Fi or mobile data immediately to halt ongoing command-and-control communication.',
    'కమాండ్-అండ్-కంట్రోల్ డేటా బదిలీని ఆపడానికి మీ పరికరాన్ని వెంటనే Wi-Fi లేదా మొబైల్ డేటా నుండి డిస్‌కనెక్ట్ చేయండి.',
    'संदिग्ध संचार को रोकने के लिए अपने डिवाइस को तुरंत वाई-फाई या मोबाइल डेटा से डिस्कनेक्ट करें।'
),
(
    'CLICKED_LINK',
    2,
    'Reset account credentials',
    'From a separate known-secure device, reset passwords for any accounts accessed recently.',
    'మరొక సురక్షితమైన పరికరం నుండి మీ ఖాతా పాస్‌వర్డ్‌లను వెంటనే మార్చండి.',
    'किसी अन्य सुरक्षित डिवाइस से अपने खातों के पासवर्ड तुरंत बदलें।'
);