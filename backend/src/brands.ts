import { query, withTransaction } from "./db";
import { logger } from "./utils/logger";
import type { QueryResultRow } from "pg";
import { isIP } from "node:net";
import { normalizeTargetUrl, urlSafetyEngine } from "./url-safety";

export class BrandProfileError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "BrandProfileError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Validates the public domain eligibility required before a profile can be saved.
 * This is not an ownership assertion; primary-domain proof happens afterwards.
 */
export function normalizeBrandPrimaryDomain(domainInput: string): string {
  let normalized: string;
  try {
    normalized = normalizeTargetUrl(domainInput);
  } catch (error) {
    throw new BrandProfileError(
      400,
      "INVALID_PRIMARY_DOMAIN",
      error instanceof Error ? error.message : "Enter a valid primary domain.",
    );
  }
  const validation = urlSafetyEngine.validateTargetUrl(normalized);
  if (!validation.isAllowed) {
    throw new BrandProfileError(
      400,
      "INVALID_PRIMARY_DOMAIN",
      validation.reason ?? "The primary domain is not eligible for a public brand profile.",
    );
  }
  const hostname = validation.hostname.toLowerCase().replace(/\.$/, "");
  const labels = hostname.split(".");
  const validLabel = (label: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  const validTld = (label: string) => /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  if (
    isIP(hostname) !== 0 ||
    hostname.length > 253 ||
    labels.length < 2 ||
    labels.some((label) => !validLabel(label)) ||
    !validTld(labels[labels.length - 1] ?? "")
  ) {
    throw new BrandProfileError(
      400,
      "INVALID_PRIMARY_DOMAIN",
      "Enter an eligible public domain name, not an IP address, local name, or malformed hostname.",
    );
  }
  return hostname;
}

export function normalizeBrandWebsite(websiteInput: string): string {
  try {
    const normalized = normalizeTargetUrl(websiteInput);
    normalizeBrandPrimaryDomain(normalized);
    return new URL(normalized).origin;
  } catch (error) {
    if (error instanceof BrandProfileError) {
      throw new BrandProfileError(error.statusCode, "INVALID_BRAND_WEBSITE", error.message);
    }
    throw new BrandProfileError(
      400,
      "INVALID_BRAND_WEBSITE",
      error instanceof Error ? error.message : "Enter a valid public brand website.",
    );
  }
}

/**
 * Validates the optional official contact e-mail used by the Brand Guard
 * module to deliver impersonation alerts to the registered company.
 */
export function normalizeBrandContactEmail(emailInput: string): string {
  const email = emailInput.trim().toLowerCase();
  if (email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    throw new BrandProfileError(
      400,
      "INVALID_CONTACT_EMAIL",
      "Enter a valid contact e-mail address for impersonation alerts.",
    );
  }
  return email;
}

export interface BrandRecord extends QueryResultRow {
  id: string;
  name: string;
  slug: string;
  primary_domain: string;
  industry: string | null;
  status: "active" | "archived" | "paused";
  lookalike_threshold: number;
  logo_url?: string | null;
  website?: string | null;
  alternate_names?: string[] | null;
  associated_domains?: string[] | null;
  keywords?: string[] | null;
  description?: string | null;
  contact_email?: string | null;
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
  contactEmail?: string | null;
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
  contactEmail?: string | null;
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
   * Creates a reviewable profile without asserting ownership of its primary domain.
   */
  async createBrand(dto: CreateBrandDTO): Promise<BrandRecord> {
    const slug = this.generateSlug(dto.name);
    const primaryDomain = normalizeBrandPrimaryDomain(dto.primaryDomain);
    const threshold = dto.lookalikeThreshold ?? 0.75;

    const associatedDomains = (dto.associatedDomains ?? []).map(normalizeBrandPrimaryDomain);
    const website = dto.website?.trim()
      ? normalizeBrandWebsite(dto.website)
      : `https://${primaryDomain}`;
    const contactEmail = dto.contactEmail?.trim()
      ? normalizeBrandContactEmail(dto.contactEmail)
      : null;

    logger.info("[brands] Creating unverified brand profile", {
      name: dto.name,
      primaryDomain,
    });

    return await withTransaction(async (client) => {
      const text = `
        INSERT INTO brands (
          name, slug, primary_domain, industry, lookalike_threshold, status,
          alternate_names, associated_domains, keywords, website, logo_url, description,
          contact_email
        )
        VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11, $12)
        RETURNING *;
      `;
      const res = await client.query<BrandRecord>(text, [
        dto.name,
        slug,
        primaryDomain,
        dto.industry ?? null,
        threshold,
        dto.alternateNames ?? [],
        associatedDomains,
        dto.keywords ?? [],
        website,
        dto.logoUrl ?? null,
        dto.description ?? null,
        contactEmail,
      ]);

      const brand = res.rows[0];
      if (!brand) {
        throw new Error("Failed to persist brand registration record");
      }

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
      ? normalizeBrandPrimaryDomain(dto.primaryDomain)
      : existing.primary_domain;
    const industry = dto.industry !== undefined ? dto.industry : existing.industry;
    const status = dto.status ?? existing.status;
    const threshold = dto.lookalikeThreshold ?? existing.lookalike_threshold;
    const alternateNames = dto.alternateNames ?? existing.alternate_names ?? [];
    const associatedDomains = dto.associatedDomains
      ? dto.associatedDomains.map(normalizeBrandPrimaryDomain)
      : existing.associated_domains ?? [];
    const keywords = dto.keywords ?? existing.keywords ?? [];
    const website = dto.website !== undefined
      ? dto.website?.trim()
        ? normalizeBrandWebsite(dto.website)
        : null
      : existing.website;
    const logoUrl = dto.logoUrl !== undefined ? dto.logoUrl : existing.logo_url;
    const description = dto.description !== undefined ? dto.description : existing.description;
    const contactEmail = dto.contactEmail !== undefined
      ? dto.contactEmail?.trim()
        ? normalizeBrandContactEmail(dto.contactEmail)
        : null
      : existing.contact_email ?? null;

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
          contact_email = $14,
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
      contactEmail,
    ]);

    const updated = res.rows[0];
    if (!updated) {
      throw new Error("Failed to update brand record");
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
