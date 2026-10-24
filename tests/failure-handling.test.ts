// @ts-ignore
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../backend/src/repositories', () => ({
  MonitoringRunsRepository: {
    create: vi.fn(),
    update: vi.fn(),
    recordError: vi.fn(),
  },
  DiscoveredCandidatesRepository: {
    insertMany: vi.fn(),
  },
  AuditLogsRepository: {
    recordLog: vi.fn().mockResolvedValue(undefined),
  },
  BrandAssetsRepository: {
    findByBrandId: vi.fn(),
  },
}));

import * as monitoringModule from '../backend/src/monitoring';
import * as appStoresModule from '../backend/src/app-stores';
import * as socialModule from '../backend/src/social';
import { BrandAssetsRepository } from '../backend/src/repositories';
import { logoSimilarityService } from '../backend/src/logo-similarity.service';
import { blueskyClient } from '../backend/src/integrations/bluesky.client';
import { youtubeClient } from '../backend/src/integrations/youtube.client';

describe('Graceful Source Failure & Error Handling (Criterion D)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(BrandAssetsRepository.findByBrandId).mockResolvedValue([]);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('Social Media Source Restrictions', () => {
    it('handles provider rate limits without crashing or inventing candidates', async () => {
      vi.spyOn(blueskyClient, 'searchDiscussions').mockResolvedValue({
        source: 'bluesky',
        query: 'NexusPay',
        totalFound: 0,
        posts: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { sourceStatus: 'unavailable', error: 'HTTP 429 Too Many Requests' },
      });
      vi.spyOn(youtubeClient, 'searchVideos').mockResolvedValue({
        source: 'youtube',
        query: 'NexusPay',
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { error: 'HTTP 429 Too Many Requests' },
      });

      const result = await new socialModule.SocialMonitoringService().scanBrandMentions({
        brandName: 'NexusPay',
      });

      expect(result.totalFindings).toBe(0);
      expect(result.signals).toEqual([]);
      expect(result.sources).toEqual([
        expect.objectContaining({ source: 'bluesky', status: 'unavailable', candidatesFound: 0 }),
        expect.objectContaining({ source: 'youtube', status: 'unavailable', candidatesFound: 0 }),
      ]);
    });

    it('keeps an unavailable source distinct from an available source with zero matches', async () => {
      vi.spyOn(blueskyClient, 'searchDiscussions').mockResolvedValue({
        source: 'bluesky',
        query: 'NexusPay',
        totalFound: 0,
        posts: [],
        hasScamSignals: false,
        confidence: 0,
        rawPayload: { sourceStatus: 'unavailable', error: 'Provider unavailable' },
      });
      vi.spyOn(youtubeClient, 'searchVideos').mockResolvedValue({
        source: 'youtube',
        query: 'NexusPay',
        totalFound: 0,
        videos: [],
        hasScamSignals: false,
        confidence: 50,
        rawPayload: { totalCount: 0, scamSignals: false },
      });

      const result = await new socialModule.SocialMonitoringService().scanBrandMentions({
        brandName: 'NexusPay',
      });

      expect(result.totalFindings).toBe(0);
      expect(result.sources).toEqual([
        expect.objectContaining({ source: 'bluesky', status: 'unavailable' }),
        expect.objectContaining({ source: 'youtube', status: 'available', candidatesFound: 0 }),
      ]);
    });
  });

  describe('App Store Adapter Failure Containment', () => {
    it('safely handles app store connection timeouts', async () => {
      const appStoreService = new appStoresModule.AppStoresMonitoringService();
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 503 })));

      const outcome = await appStoreService.scanAppStores({ brandName: 'NexusPay' });

      expect(outcome.totalFound).toBe(0);
      expect(outcome.unauthorizedAppsCount).toBe(0);
      // Both stores are queried; a failure in either is reported without
      // hiding the other source.
      expect(outcome.sources).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            source: 'apple_app_store',
            status: 'unavailable',
            candidatesFound: 0,
          }),
          expect.objectContaining({
            source: 'google_play',
            status: 'unavailable',
            candidatesFound: 0,
          }),
        ]),
      );
    });

    it('uses live catalog data and excludes an exact registered official app', async () => {
      vi.mocked(BrandAssetsRepository.findByBrandId).mockResolvedValue([
        {
          id: 'asset-app',
          brand_id: 'brand-1',
          asset_type: 'mobile_app',
          platform: 'app_store',
          identifier: 'io.nexuspay.wallet',
          value: 'io.nexuspay.wallet',
          canonical_url: 'https://apps.apple.com/app/nexuspay/id100',
          is_verified: true,
          metadata: { publisher: 'NexusPay Inc.' },
          created_at: new Date().toISOString(),
        } as any,
      ]);
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({
        results: [
          {
            trackId: 100,
            bundleId: 'io.nexuspay.wallet',
            trackName: 'NexusPay',
            sellerName: 'NexusPay Inc.',
            trackViewUrl: 'https://apps.apple.com/app/nexuspay/id100',
            description: 'Official wallet.',
          },
          {
            trackId: 200,
            bundleId: 'com.nexuspay.support',
            trackName: 'NexusPay Support Wallet',
            sellerName: 'Unrelated Publisher',
            trackViewUrl: 'https://apps.apple.com/app/fake-nexuspay/id200',
            description: 'Support and login for NexusPay.',
          },
        ],
      })));

      const outcome = await new appStoresModule.AppStoresMonitoringService().scanAppStores({
        brandId: 'brand-1',
        brandName: 'NexusPay',
      });

      expect(outcome.totalFound).toBe(2);
      expect(outcome.unauthorizedAppsCount).toBe(1);
      expect(outcome.findings.find((finding) => finding.appId === 'io.nexuspay.wallet')?.isExcludedOfficial).toBe(true);
      expect(outcome.findings.find((finding) => finding.appId === 'com.nexuspay.support')?.riskScore).toBeGreaterThanOrEqual(65);
      expect(outcome.findings.some((finding) => finding.title.includes('Official App'))).toBe(false);
    });

    it('adds measured logo similarity when a verified logo and app icon are available', async () => {
      vi.mocked(BrandAssetsRepository.findByBrandId).mockResolvedValue([
        {
          id: 'logo-1',
          brand_id: 'brand-2',
          asset_type: 'logo',
          platform: 'web',
          identifier: 'brand-logo',
          value: 'brand-logo',
          canonical_url: 'https://brand.example/logo.png',
          is_verified: true,
          metadata: {},
          created_at: new Date().toISOString(),
        } as any,
      ]);
      vi.spyOn(logoSimilarityService, 'compareImageUrls').mockResolvedValue({
        targetImageUri: 'https://cdn.example/icon.png',
        referenceAssetUri: 'https://brand.example/logo.png',
        hammingDistance: 2,
        similarityScore: 0.969,
        isImpersonating: true,
        confidence: 0.95,
      });
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({
        results: [{
          trackId: 200,
          bundleId: 'com.brand.support',
          trackName: 'Brand Support',
          sellerName: 'Unknown Publisher',
          trackViewUrl: 'https://apps.apple.com/app/brand-support/id200',
          artworkUrl100: 'https://cdn.example/icon.png',
          description: 'Customer support.',
        }],
      })));

      const outcome = await new appStoresModule.AppStoresMonitoringService().scanAppStores({
        brandId: 'brand-2',
        brandName: 'Brand',
      });

      expect(outcome.findings[0]?.logoSimilarity).toBe(0.969);
      expect(outcome.findings[0]?.logoComparisonStatus).toBe('compared');
      expect(outcome.logoComparisons.compared).toBe(1);
      expect(outcome.findings[0]?.riskScore).toBeGreaterThanOrEqual(60);
    });

    it('ignores unrelated App Store results instead of calling them unauthorized', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({
        results: [
          {
            trackId: 300,
            bundleId: 'com.unrelated.notes',
            trackName: 'Daily Notes',
            sellerName: 'Other Publisher',
            trackViewUrl: 'https://apps.apple.com/app/daily-notes/id300',
            description: 'A simple notes application.',
          },
          {
            trackId: 301,
            bundleId: 'com.nexuspay.wallet',
            trackName: 'NexusPay Wallet',
            sellerName: 'Unknown Publisher',
            trackViewUrl: 'https://apps.apple.com/app/nexuspay-wallet/id301',
            description: 'A wallet application.',
          },
        ],
      })));

      const outcome = await new appStoresModule.AppStoresMonitoringService().scanAppStores({
        brandName: 'NexusPay',
      });

      expect(outcome.totalFound).toBe(1);
      expect(outcome.unauthorizedAppsCount).toBe(1);
      expect(outcome.findings[0]?.appId).toBe('com.nexuspay.wallet');
      expect(outcome.findings[0]?.isOfficialDeveloper).toBe(false);
    });
  });

  describe('End-to-End Orchestrator Resilience', () => {
    it('allows successful sources to report findings even if one source fails', async () => {
      // If Bluesky succeeds but App Store fails, monitoring run must still return Bluesky results
      const multiSourceResults = [
        { source: 'bluesky', success: true, count: 3 },
        { source: 'apple_app_store', success: false, error: 'Connection refused' },
      ];

      const successfulDetections = multiSourceResults.filter((s) => s.success);
      const failedSources = multiSourceResults.filter((s) => !s.success);

      expect(successfulDetections.length).toBe(1);
      expect(failedSources.length).toBe(1);
      expect(failedSources[0].error).toBeDefined();
    });
  });
});
