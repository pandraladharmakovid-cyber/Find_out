import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import { ExclusionRulesRepository } from "./repositories";
import { logoSimilarityService } from "./logo-similarity.service";
import type { QueryResultRow } from "pg";

export type AssetType = "domain" | "subdomain" | "logo" | "trademark" | "social_handle" | "app_store_id";

export interface OfficialAssetRecord extends QueryResultRow {
  id: string;
  brand_id: string;
  asset_type: AssetType;
  value: string;
  canonical_url: string | null;
  hash_signature: string | null;
  is_verified: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface RegisterAssetDTO {
  brandId: string;
  assetType: AssetType;
  value: string;
  canonicalUrl?: string | null;
  assetContent?: string;
  metadata?: Record<string, unknown>;
}

export class AssetService {
  async registerAsset(dto: RegisterAssetDTO): Promise<OfficialAssetRecord> {
    const cleanValue = dto.value.trim();
    let hashSignature: string | null = null;
    let imageData: Buffer | null = null;

    if (dto.assetType === "logo" && dto.assetContent) {
      imageData = Buffer.from(dto.assetContent, "base64");
      if (!imageData.length) throw new Error("Logo image data must be non-empty base64.");
      hashSignature = await logoSimilarityService.computeImageHash(imageData);
    }

    logger.info("[assets] Registering official brand asset", {
      brandId: dto.brandId,
      assetType: dto.assetType,
      value: cleanValue,
    });

    return await withTransaction(async (client) => {
      const text = `
        INSERT INTO official_assets (
          brand_id, asset_type, value, canonical_url, 
          hash_signature, image_data, is_verified, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, true, $7)
        RETURNING id, brand_id, asset_type, value, canonical_url, hash_signature,
                  is_verified, metadata, created_at, updated_at;
      `;
      const res = await client.query<OfficialAssetRecord>(text, [
        dto.brandId,
        dto.assetType,
        cleanValue,
        dto.canonicalUrl ?? null,
        hashSignature,
        imageData,
        JSON.stringify(dto.metadata ?? {}),
      ]);

      const asset = res.rows[0];
      if (!asset) {
        throw new Error("Failed to persist official asset record");
      }

      if (dto.assetType === "domain" || dto.assetType === "subdomain") {
        await ExclusionRulesRepository.addRule(
          cleanValue,
          `Official ${dto.assetType} asset (${asset.id})`
        );
      }

      return asset;
    });
  }

  async listAssetsByBrand(brandId: string): Promise<OfficialAssetRecord[]> {
    const res = await query<OfficialAssetRecord>(
      `SELECT id, brand_id, asset_type, value, canonical_url, hash_signature,
              is_verified, metadata, created_at, updated_at
       FROM official_assets WHERE brand_id = $1 ORDER BY created_at ASC;`,
      [brandId]
    );
    return res.rows;
  }

  async getAssetsByType(brandId: string, assetType: AssetType): Promise<OfficialAssetRecord[]> {
    const res = await query<OfficialAssetRecord>(
      `SELECT id, brand_id, asset_type, value, canonical_url, hash_signature,
              is_verified, metadata, created_at, updated_at
       FROM official_assets WHERE brand_id = $1 AND asset_type = $2;`,
      [brandId, assetType]
    );
    return res.rows;
  }

  async deleteAsset(id: string): Promise<void> {
    const res = await query<OfficialAssetRecord>(
      `SELECT id, brand_id, asset_type, value, canonical_url, hash_signature,
              is_verified, metadata, created_at, updated_at
       FROM official_assets WHERE id = $1;`,
      [id]
    );
    const asset = res.rows[0];

    if (!asset) {
      throw new Error(`Asset with ID ${id} not found`);
    }

    logger.info("[assets] Deleting official asset", { id, type: asset.asset_type });

    await withTransaction(async (client) => {
      await client.query(`DELETE FROM official_assets WHERE id = $1;`, [id]);
      if (asset.asset_type === "domain" || asset.asset_type === "subdomain") {
        await client.query(
          `DELETE FROM exclusion_rules WHERE pattern = $1;`,
          [asset.value]
        );
      }
    });
  }
}

export const assetService = new AssetService();
export default assetService;
