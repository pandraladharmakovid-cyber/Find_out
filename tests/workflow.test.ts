import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockQuery, mockTransaction, mockClientQuery } = vi.hoisted(() => ({
  mockQuery: vi.fn(),
  mockTransaction: vi.fn(),
  mockClientQuery: vi.fn(),
}));

vi.mock('../backend/src/db', () => ({
  query: mockQuery,
  withTransaction: mockTransaction,
}));

import { BrandService } from '../backend/src/brands';
import { matchesOfficialAsset } from '../backend/src/exclusion-engine.service';
import { LookalikeDetectionService } from '../backend/src/lookalike.service';
import { ComplaintService } from '../backend/src/complaints';

const brand = {
  id: 'brand-uuid-101',
  name: 'NexusPay',
  slug: 'nexuspay',
  primary_domain: 'nexuspay.io',
  alternate_names: ['Nexus Pay', 'NexusPay Global'],
};

const socialAsset = {
  id: 'asset-social',
  brand_id: brand.id,
  asset_type: 'social_profile',
  platform: 'x',
  identifier: 'nexuspay_official',
  value: 'nexuspay_official',
  canonical_url: 'https://x.com/nexuspay_official',
  is_verified: true,
  metadata: {},
  created_at: new Date().toISOString(),
};

const officialApp = {
  id: 'asset-app',
  brand_id: brand.id,
  asset_type: 'mobile_app',
  platform: 'app_store',
  identifier: 'io.nexuspay.wallet',
  value: 'io.nexuspay.wallet',
  canonical_url: 'https://apps.apple.com/app/nexuspay/id12345',
  is_verified: true,
  metadata: {},
  created_at: new Date().toISOString(),
};

describe('Brand registration and monitoring workflow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockTransaction.mockImplementation(async (callback) => callback({ query: mockClientQuery }));
    mockClientQuery.mockResolvedValue({ rows: [brand] });
    mockQuery.mockImplementation(async (sql: string) => {
      if (sql.includes('INSERT INTO official_assets')) return { rows: [socialAsset] };
      if (sql.includes('INSERT INTO exclusion_rules')) return { rows: [{ pattern: brand.primary_domain }] };
      if (sql.includes('INSERT INTO complaints')) return { rows: [{ id: 'complaint-1', status: 'generated' }] };
      return { rows: [] };
    });
  });

  it('persists brand profile input without trusting its unverified primary domain', async () => {
    const service = new BrandService();
    const registered = await service.createBrand({
      name: brand.name,
      primaryDomain: brand.primary_domain,
      alternateNames: brand.alternate_names,
      keywords: ['wallet'],
    });

    expect(registered.name).toBe(brand.name);
    expect(mockClientQuery).toHaveBeenCalledWith(
      expect.stringContaining('alternate_names, associated_domains, keywords'),
      expect.arrayContaining([brand.name, brand.slug, brand.primary_domain]),
    );
    expect(mockQuery).not.toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO exclusion_rules'),
      expect.any(Array),
    );
  });

  it('excludes only the exact registered official social account or app listing', () => {
    expect(matchesOfficialAsset(
      {
        platform: 'x',
        identifier: 'NexusPay_Official',
        url: 'https://x.com/nexuspay_official/',
      },
      socialAsset,
    )).toBe(true);

    expect(matchesOfficialAsset(
      {
        platform: 'app_store',
        identifier: 'io.nexuspay.wallet',
        url: 'https://apps.apple.com/app/nexuspay/id12345',
      },
      officialApp,
    )).toBe(true);

    expect(matchesOfficialAsset(
      {
        platform: 'x',
        identifier: 'nexuspay_support_help',
        url: 'https://x.com/nexuspay_support_help',
      },
      socialAsset,
    )).toBe(false);
  });

  it('detects spacing, character transposition, and Unicode look-alikes without matching unrelated names', () => {
    const service = new LookalikeDetectionService();
    expect(service.similarityRatio('Nexus Pay', 'NexusPay')).toBe(1);
    expect(service.similarityRatio('nexuspay', 'nexuspya')).toBeGreaterThan(0.6);
    expect(service.similarityRatio('paypal', 'раypal')).toBe(1);
    expect(service.similarityRatio('nexuspay', 'globex')).toBeLessThan(0.5);
  });

  it('stores a complaint as generated instead of claiming an external takedown', async () => {
    const service = new ComplaintService();
    const result = await service.createComplaint({
      investigationId: 'investigation-1',
      brandId: brand.id,
      brandName: brand.name,
      brandContactEmail: 'security@example.com',
      complaintType: 'app_store_violation',
      recipientEmail: 'report@example.com',
      targetUrl: 'https://apps.apple.com/app/suspicious/id9000',
      infringingEvidenceSummary: 'Lookalike name and unrecognized publisher.',
    });

    expect(result.status).toBe('generated');
    // The complaint is stored as a draft with status 'generated'. Assert the
    // stored contract (not an exact SQL string, which made this test break on
    // every legitimate query change): a row is inserted into `complaints` with
    // the 'generated' status and the reporter/recipient values.
    const insertCall = mockQuery.mock.calls.find(
      (call: unknown[]) =>
        typeof call[0] === 'string' &&
        call[0].includes('INSERT INTO complaints') &&
        call[0].includes("'generated'"),
    );
    expect(insertCall).toBeDefined();
    expect(insertCall?.[1]).toEqual(
      expect.arrayContaining(['investigation-1', 'report@example.com']),
    );
  });
});
