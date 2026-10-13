import type {
  AdvisoryAffectedPackage,
  AdvisoryRange,
  AdvisoryRecord,
  SupportedEcosystem
} from "./types";

interface RawOsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    package?: {
      ecosystem?: string;
      name?: string;
      purl?: string;
    };
    ranges?: Array<{
      type?: string;
      repo?: string;
      events?: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
        limit?: string;
      }>;
    }>;
    versions?: string[];
  }>;
}

interface RawOsvQueryResponse {
  vulns?: RawOsvVulnerability[];
  next_page_token?: string;
}

const MAX_ADVISORIES = 20;
const MAX_ALIASES = 20;
const MAX_AFFECTED_PACKAGES = 5;
const MAX_RANGES_PER_PACKAGE = 3;
const MAX_RANGE_EVENTS = 10;
const MAX_VERSIONS_PER_PACKAGE = 50;
const MAX_SEVERITY_ENTRIES = 5;
const MAX_REFERENCES = 10;

function compactText(
  value: string | undefined,
  limit: number
): string | null {
  if (!value) return null;
  return value.length <= limit ? value : value.slice(0, limit) + "…";
}

function normalizeRange(
  raw: NonNullable<NonNullable<RawOsvVulnerability["affected"]>[number]["ranges"]>[number]
): AdvisoryRange {
  return {
    type: compactText(raw.type, 100) ?? "UNKNOWN",
    repo: compactText(raw.repo, 500),
    events: (raw.events ?? []).slice(0, MAX_RANGE_EVENTS).map((event) => ({
      introduced: compactText(event.introduced, 200) ?? undefined,
      fixed: compactText(event.fixed, 200) ?? undefined,
      lastAffected: compactText(event.last_affected, 200) ?? undefined,
      limit: compactText(event.limit, 200) ?? undefined
    }))
  };
}

function normalizeAffected(
  raw: NonNullable<RawOsvVulnerability["affected"]>[number]
): AdvisoryAffectedPackage {
  return {
    ecosystem: compactText(raw.package?.ecosystem, 100),
    name: compactText(raw.package?.name, 300),
    purl: compactText(raw.package?.purl, 500),
    ranges: (raw.ranges ?? []).slice(0, MAX_RANGES_PER_PACKAGE).map(normalizeRange),
    versions: (raw.versions ?? [])
      .slice(0, MAX_VERSIONS_PER_PACKAGE)
      .map((version) => compactText(version, 200) ?? "")
      .filter((version) => version.length > 0)
  };
}

export function normalizeOsvAdvisory(
  raw: RawOsvVulnerability
): AdvisoryRecord | null {
  if (!raw.id) return null;

  return {
    id: raw.id,
    aliases: [...new Set(raw.aliases ?? [])]
      .slice(0, MAX_ALIASES)
      .map((alias) => compactText(alias, 200) ?? "")
      .filter((alias) => alias.length > 0),
    summary: compactText(raw.summary, 500),
    details: compactText(raw.details, 3000),
    published: raw.published ?? null,
    modified: raw.modified ?? null,
    withdrawn: raw.withdrawn ?? null,
    severity: (raw.severity ?? []).slice(0, MAX_SEVERITY_ENTRIES).map((entry) => ({
      type: compactText(entry.type, 100),
      score: compactText(entry.score, 500)
    })),
    references: (raw.references ?? [])
      .filter((entry): entry is { type?: string; url: string } =>
        typeof entry.url === "string" && entry.url.length > 0
      )
      .slice(0, MAX_REFERENCES)
      .map((entry) => ({
        type: compactText(entry.type, 100),
        url: compactText(entry.url, 1000) ?? ""
      })),
    affected: (raw.affected ?? [])
      .slice(0, MAX_AFFECTED_PACKAGES)
      .map(normalizeAffected)
  };
}

export async function fetchOsvAdvisory(
  advisoryId: string
): Promise<AdvisoryRecord | null> {
  const response = await fetch(
    "https://api.osv.dev/v1/vulns/" + encodeURIComponent(advisoryId),
    {
      headers: {
        Accept: "application/json",
        "User-Agent": "security-advisory-scout-mcp"
      }
    }
  );

  if (response.status === 404) return null;

  if (!response.ok) {
    throw new Error(
      "OSV advisory request failed with HTTP " + response.status + "."
    );
  }

  return normalizeOsvAdvisory(
    (await response.json()) as RawOsvVulnerability
  );
}

export async function queryPackageVersion(input: {
  ecosystem: SupportedEcosystem;
  name: string;
  version: string;
  maxAdvisories?: number;
}): Promise<{ advisories: AdvisoryRecord[]; truncated: boolean }> {
  const maxAdvisories = Math.min(
    Math.max(input.maxAdvisories ?? 20, 1),
    MAX_ADVISORIES
  );

  const advisories: AdvisoryRecord[] = [];
  let pageToken: string | undefined;

  for (let page = 0; page < 10; page += 1) {
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "security-advisory-scout-mcp"
      },
      body: JSON.stringify({
        version: input.version,
        package: {
          name: input.name,
          ecosystem: input.ecosystem
        },
        ...(pageToken ? { page_token: pageToken } : {})
      })
    });

    if (!response.ok) {
      throw new Error(
        "OSV package query failed with HTTP " + response.status + "."
      );
    }

    const data = (await response.json()) as RawOsvQueryResponse;
    const pageVulnerabilities = data.vulns ?? [];

    for (let index = 0; index < pageVulnerabilities.length; index += 1) {
      const advisory = normalizeOsvAdvisory(pageVulnerabilities[index]);
      if (!advisory) continue;

      advisories.push(advisory);

      if (advisories.length >= maxAdvisories) {
        return {
          advisories: advisories.slice(0, maxAdvisories),
          truncated:
            index < pageVulnerabilities.length - 1 ||
            Boolean(data.next_page_token)
        };
      }
    }

    pageToken = data.next_page_token;
    if (!pageToken) {
      return { advisories, truncated: false };
    }
  }

  return {
    advisories,
    truncated: Boolean(pageToken)
  };
}

export function fixedVersions(
  advisory: AdvisoryRecord,
  ecosystem?: string,
  packageName?: string
): string[] {
  const values: string[] = [];

  for (const affected of advisory.affected) {
    if (ecosystem && affected.ecosystem !== ecosystem) continue;
    if (packageName && affected.name !== packageName) continue;

    for (const range of affected.ranges) {
      for (const event of range.events) {
        if (event.fixed) values.push(event.fixed);
      }
    }
  }

  return [...new Set(values)];
}

