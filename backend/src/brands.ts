import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import { ExclusionRulesRepository } from "./repositories";
import type { QueryResultRow } from "pg";

export interface BrandRecord extends QueryResultRow {
  id: string;
  name: string;
  slug: string;
  primary_domain: string;
  industry: string | null;
  status: "active" | "archived" | "paused";
  lookalike_threshold: number;
  created_at: string;
  updated_at: string;
}

export interface CreateBrandDTO {
  name: string;
  primaryDomain: string;
  industry?: string | null;
  lookalikeThreshold?: number;
  alternateNames?: string[];
  associatedDomains?: string[];
  keywords?: string[];
  website?: string | null;
  logoUrl?: string | null;
  description?: string | null;
}

export interface UpdateBrandDTO {
  name?: string;
  primaryDomain?: string;
  industry?: string | null;
  status?: "active" | "archived" | "paused";
  lookalikeThreshold?: number;
  alternateNames?: string[];
  associatedDomains?: string[];
  keywords?: string[];
  website?: string | null;
  logoUrl?: string | null;
  description?: string | null;
}

export class BrandService {
  /**
   * Generates a URL-friendly slug from a brand name.
   */
  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  /**
   * Normalizes a domain name (strips protocol and trailing paths).
   */
  private normalizeDomain(domainInput: string): string {
    let clean = domainInput.toLowerCase().trim();
    try {
      if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
        clean = `https://${clean}`;
      }
      const parsed = new URL(clean);
      return parsed.hostname;
    } catch {
      return domainInput.toLowerCase().trim();
    }
  }

  /**
   * Registers a new brand and automatically enrolls its primary domain into exclusion rules.
   */
  async createBrand(dto: CreateBrandDTO): Promise<BrandRecord> {
    const slug = this.generateSlug(dto.name);
    const primaryDomain = this.normalizeDomain(dto.primaryDomain);
    const threshold = dto.lookalikeThreshold ?? 0.75;

    logger.info("[brands] Registering new official brand", {
      name: dto.name,
      primaryDomain,
    });

    return await withTransaction(async (client) => {
      const text = `
        INSERT INTO brands (
          name, slug, primary_domain, industry, lookalike_threshold, status,
          alternate_names, associated_domains, keywords, website, logo_url, description
        )
        VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11)
        RETURNING *;
      `;
      const res = await client.query<BrandRecord>(text, [
        dto.name,
        slug,
        primaryDomain,
        dto.industry ?? null,
        threshold,
        dto.alternateNames ?? [],
        dto.associatedDomains ?? [],
        dto.keywords ?? [],
        dto.website ?? null,
        dto.logoUrl ?? null,
        dto.description ?? null,
      ]);

      const brand = res.rows[0];
      if (!brand) {
        throw new Error("Failed to persist brand registration record");
      }

      // Automatically register the primary domain into exclusion whitelist
      await ExclusionRulesRepository.addRule(
        primaryDomain,
        `Official primary domain for ${brand.name}`
      );

      return brand;
    });
  }

  /**
   * Retrieves a brand by its unique database ID.
   */
  async getBrandById(id: string): Promise<BrandRecord | null> {
    const res = await query<BrandRecord>(
      `SELECT * FROM brands WHERE id = $1;`,
      [id]
    );
    return res.rows[0] ?? null;
  }

  /**
   * Retrieves a brand by its slug identifier.
   */
  async getBrandBySlug(slug: string): Promise<BrandRecord | null> {
    const res = await query<BrandRecord>(
      `SELECT * FROM brands WHERE slug = $1;`,
      [slug]
    );
    return res.rows[0] ?? null;
  }

  /**
   * Lists all registered brands with pagination.
   */
  async listBrands(limit = 50, offset = 0): Promise<BrandRecord[]> {
    const res = await query<BrandRecord>(
      `SELECT * FROM brands ORDER BY created_at DESC LIMIT $1 OFFSET $2;`,
      [limit, offset]
    );
    return res.rows;
  }

  /**
   * Updates an existing brand configuration.
   */
  async updateBrand(id: string, dto: UpdateBrandDTO): Promise<BrandRecord> {
    const existing = await this.getBrandById(id);
    if (!existing) {
      throw new Error(`Brand with ID ${id} not found`);
    }

    const name = dto.name ?? existing.name;
    const primaryDomain = dto.primaryDomain
      ? this.normalizeDomain(dto.primaryDomain)
      : existing.primary_domain;
    const industry = dto.industry !== undefined ? dto.industry : existing.industry;
    const status = dto.status ?? existing.status;
    const threshold = dto.lookalikeThreshold ?? existing.lookalike_threshold;
    const alternateNames = dto.alternateNames ?? existing.alternate_names ?? [];
    const associatedDomains = dto.associatedDomains ?? existing.associated_domains ?? [];
    const keywords = dto.keywords ?? existing.keywords ?? [];
    const website = dto.website !== undefined ? dto.website : existing.website;
    const logoUrl = dto.logoUrl !== undefined ? dto.logoUrl : existing.logo_url;
    const description = dto.description !== undefined ? dto.description : existing.description;

    const text = `
      UPDATE brands
      SET name = $2,
          primary_domain = $3,
          industry = $4,
          status = $5,
          lookalike_threshold = $6,
          slug = $7,
          alternate_names = $8,
          associated_domains = $9,
          keywords = $10,
          website = $11,
          logo_url = $12,
          description = $13,
          updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await query<BrandRecord>(text, [
      id,
      name,
      primaryDomain,
      industry,
      status,
      threshold,
      this.generateSlug(name),
      alternateNames,
      associatedDomains,
      keywords,
      website,
      logoUrl,
      description,
    ]);

    const updated = res.rows[0];
    if (!updated) {
      throw new Error("Failed to update brand record");
    }

    // Ensure updated primary domain is also whitelisted
    if (dto.primaryDomain && dto.primaryDomain !== existing.primary_domain) {
      await ExclusionRulesRepository.addRule(
        primaryDomain,
        `Updated official domain for ${updated.name}`
      );
    }

    return updated;
  }

  /**
   * Archives a brand entity.
   */
  async archiveBrand(id: string): Promise<void> {
    logger.info("[brands] Archiving brand", { id });
    await query(`UPDATE brands SET status = 'archived', updated_at = NOW() WHERE id = $1;`, [id]);
  }
}

export const brandService = new BrandService();
export default brandService;