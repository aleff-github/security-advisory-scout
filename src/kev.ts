import type { KevRecord } from "./types";

interface RawKevCatalog {
  catalogVersion?: string;
  dateReleased?: string;
  vulnerabilities?: Array<{
    cveID?: string;
    vendorProject?: string;
    product?: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    shortDescription?: string;
    requiredAction?: string;
    dueDate?: string;
    knownRansomwareCampaignUse?: string;
    notes?: string;
  }>;
}

const KEV_SOURCES = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
];

async function fetchCatalog(url: string): Promise<RawKevCatalog> {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "security-advisory-scout-mcp"
    }
  });

  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }

  return (await response.json()) as RawKevCatalog;
}

export async function lookupKevEntries(cveIds: string[]): Promise<{
  source: string;
  catalogVersion: string | null;
  dateReleased: string | null;
  entries: Record<string, KevRecord>;
}> {
  const wanted = new Set(
    cveIds
      .map((value) => value.toUpperCase())
      .filter((value) => /^CVE-\d{4}-\d{4,}$/.test(value))
  );

  if (wanted.size === 0) {
    return {
      source: KEV_SOURCES[0],
      catalogVersion: null,
      dateReleased: null,
      entries: {}
    };
  }

  let lastError: unknown;

  for (const source of KEV_SOURCES) {
    try {
      const catalog = await fetchCatalog(source);
      const entries: Record<string, KevRecord> = {};

      for (const item of catalog.vulnerabilities ?? []) {
        const id = item.cveID?.toUpperCase();
        if (!id || !wanted.has(id)) continue;

        entries[id] = {
          cveId: id,
          vendorProject: item.vendorProject ?? null,
          product: item.product ?? null,
          vulnerabilityName: item.vulnerabilityName ?? null,
          dateAdded: item.dateAdded ?? null,
          shortDescription: item.shortDescription ?? null,
          requiredAction: item.requiredAction ?? null,
          dueDate: item.dueDate ?? null,
          knownRansomwareCampaignUse:
            item.knownRansomwareCampaignUse ?? null,
          notes: item.notes ?? null
        };
      }

      return {
        source,
        catalogVersion: catalog.catalogVersion ?? null,
        dateReleased: catalog.dateReleased ?? null,
        entries
      };
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(
    "CISA KEV sources were unavailable: " +
      (lastError instanceof Error ? lastError.message : String(lastError))
  );
}

