export const SUPPORTED_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "crates.io",
  "RubyGems",
  "NuGet",
  "Packagist"
] as const;

export type SupportedEcosystem = (typeof SUPPORTED_ECOSYSTEMS)[number];

export interface AdvisoryRangeEvent {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
  limit?: string;
}

export interface AdvisoryRange {
  type: string;
  repo: string | null;
  events: AdvisoryRangeEvent[];
}

export interface AdvisoryAffectedPackage {
  ecosystem: string | null;
  name: string | null;
  purl: string | null;
  ranges: AdvisoryRange[];
  versions: string[];
}

export interface AdvisoryRecord {
  id: string;
  aliases: string[];
  summary: string | null;
  details: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  severity: Array<{
    type: string | null;
    score: string | null;
  }>;
  references: Array<{
    type: string | null;
    url: string;
  }>;
  affected: AdvisoryAffectedPackage[];
}

export interface EpssRecord {
  cve: string;
  probability: number;
  percentile: number;
  date: string | null;
}

export interface KevRecord {
  cveId: string;
  vendorProject: string | null;
  product: string | null;
  vulnerabilityName: string | null;
  dateAdded: string | null;
  shortDescription: string | null;
  requiredAction: string | null;
  dueDate: string | null;
  knownRansomwareCampaignUse: string | null;
  notes: string | null;
}

export interface NvdCvss {
  version: string | null;
  baseScore: number | null;
  baseSeverity: string | null;
  vectorString: string | null;
  source: string | null;
  type: string | null;
}

export interface NvdCpeMatch {
  criteria: string | null;
  vulnerable: boolean | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
}

export interface NvdCveRecord {
  id: string;
  sourceIdentifier: string | null;
  published: string | null;
  lastModified: string | null;
  vulnStatus: string | null;
  description: string | null;
  cvss: NvdCvss[];
  weaknesses: string[];
  references: Array<{
    url: string;
    source: string | null;
    tags: string[];
  }>;
  cpeMatches: NvdCpeMatch[];
}

export interface CveEvidence {
  cveId: string;
  epss: EpssRecord | null;
  kev: KevRecord | null;
}

export interface EnrichedAdvisory extends AdvisoryRecord {
  cveEvidence: CveEvidence[];
}

