import type {
  NvdCpeMatch,
  NvdCveRecord,
  NvdCvss
} from "./types";

interface RawNvdResponse {
  vulnerabilities?: Array<{
    cve?: RawNvdCve;
  }>;
}

interface RawNvdCve {
  id?: string;
  sourceIdentifier?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: Record<string, Array<{
    source?: string;
    type?: string;
    cvssData?: {
      version?: string;
      vectorString?: string;
      baseScore?: number;
      baseSeverity?: string;
    };
    baseSeverity?: string;
  }>>;
  weaknesses?: Array<{
    description?: Array<{ lang?: string; value?: string }>;
  }>;
  references?: Array<{
    url?: string;
    source?: string;
    tags?: string[];
  }>;
  configurations?: Array<{
    nodes?: RawNvdNode[];
  }>;
}

interface RawNvdNode {
  cpeMatch?: Array<{
    vulnerable?: boolean;
    criteria?: string;
    versionStartIncluding?: string;
    versionStartExcluding?: string;
    versionEndIncluding?: string;
    versionEndExcluding?: string;
  }>;
  nodes?: RawNvdNode[];
}

interface NormalizeNvdOptions {
  includeCpeMatches?: boolean;
  referenceLimit?: number;
}

function englishDescription(cve: RawNvdCve): string | null {
  return cve.descriptions?.find((entry) => entry.lang === "en")?.value ??
    cve.descriptions?.[0]?.value ??
    null;
}

function cvssMetrics(cve: RawNvdCve): NvdCvss[] {
  const output: NvdCvss[] = [];

  for (const entries of Object.values(cve.metrics ?? {})) {
    for (const entry of entries ?? []) {
      output.push({
        version: entry.cvssData?.version ?? null,
        baseScore: entry.cvssData?.baseScore ?? null,
        baseSeverity:
          entry.cvssData?.baseSeverity ?? entry.baseSeverity ?? null,
        vectorString: entry.cvssData?.vectorString ?? null,
        source: entry.source ?? null,
        type: entry.type ?? null
      });
    }
  }

  return output
    .sort((a, b) => {
      const aPrimary = a.type === "Primary" ? 1 : 0;
      const bPrimary = b.type === "Primary" ? 1 : 0;
      return bPrimary - aPrimary;
    })
    .slice(0, 8);
}

function collectCpeMatches(nodes: RawNvdNode[] | undefined): NvdCpeMatch[] {
  const output: NvdCpeMatch[] = [];

  const visit = (node: RawNvdNode) => {
    for (const match of node.cpeMatch ?? []) {
      output.push({
        criteria: match.criteria ?? null,
        vulnerable:
          typeof match.vulnerable === "boolean" ? match.vulnerable : null,
        versionStartIncluding: match.versionStartIncluding ?? null,
        versionStartExcluding: match.versionStartExcluding ?? null,
        versionEndIncluding: match.versionEndIncluding ?? null,
        versionEndExcluding: match.versionEndExcluding ?? null
      });
    }
    for (const child of node.nodes ?? []) visit(child);
  };

  for (const node of nodes ?? []) visit(node);
  return output.slice(0, 100);
}

function normalizeNvdCve(
  cve: RawNvdCve,
  options: NormalizeNvdOptions = {}
): NvdCveRecord | null {
  if (!cve.id) return null;

  const referenceLimit = Math.min(
    Math.max(options.referenceLimit ?? 20, 0),
    20
  );

  const weaknesses = (cve.weaknesses ?? [])
    .flatMap((weakness) => weakness.description ?? [])
    .filter((entry) => entry.lang === "en" && typeof entry.value === "string")
    .map((entry) => entry.value as string);

  return {
    id: cve.id,
    sourceIdentifier: cve.sourceIdentifier ?? null,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    vulnStatus: cve.vulnStatus ?? null,
    description: englishDescription(cve),
    cvss: cvssMetrics(cve),
    weaknesses: [...new Set(weaknesses)].slice(0, 20),
    references: (cve.references ?? [])
      .filter((entry): entry is { url: string; source?: string; tags?: string[] } =>
        typeof entry.url === "string" && entry.url.length > 0
      )
      .slice(0, referenceLimit)
      .map((entry) => ({
        url: entry.url,
        source: entry.source ?? null,
        tags: entry.tags ?? []
      })),
    cpeMatches: options.includeCpeMatches === false
      ? []
      : (cve.configurations ?? [])
          .flatMap((configuration) => collectCpeMatches(configuration.nodes))
          .slice(0, 100)
  };
}

async function nvdRequest(url: string): Promise<RawNvdResponse> {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "security-advisory-scout-mcp"
    }
  });

  if (!response.ok) {
    throw new Error("NVD request failed with HTTP " + response.status + ".");
  }

  return (await response.json()) as RawNvdResponse;
}

export async function fetchNvdCve(
  cveId: string
): Promise<NvdCveRecord | null> {
  const data = await nvdRequest(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" +
      encodeURIComponent(cveId.toUpperCase())
  );

  const cve = data.vulnerabilities?.[0]?.cve;
  return cve ? normalizeNvdCve(cve) : null;
}

export async function searchNvd(
  query: string,
  limit = 10
): Promise<NvdCveRecord[]> {
  const boundedLimit = Math.min(Math.max(limit, 1), 20);
  const data = await nvdRequest(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
      encodeURIComponent(query) +
      "&resultsPerPage=" +
      boundedLimit
  );

  return (data.vulnerabilities ?? [])
    .map((item) =>
      item.cve
        ? normalizeNvdCve(item.cve, {
            includeCpeMatches: false,
            referenceLimit: 8
          })
        : null
    )
    .filter((item): item is NvdCveRecord => item !== null)
    .slice(0, boundedLimit);
}

