import { fetchEpss } from "./epss";
import { lookupKevEntries } from "./kev";
import { fetchNvdCve, searchNvd } from "./nvd";
import { fetchOsvAdvisory, fixedVersions, queryPackageVersion } from "./osv";
import type {
  AdvisoryRecord,
  EnrichedAdvisory,
  SupportedEcosystem
} from "./types";

export function normalizeAdvisoryId(advisoryId: string): string {
  const trimmed = advisoryId.trim();

  if (/^cve-\d{4}-\d{4,}$/i.test(trimmed)) {
    return trimmed.toUpperCase();
  }

  const ghsaMatch = /^ghsa-(.+)$/i.exec(trimmed);
  if (ghsaMatch) {
    return "GHSA-" + ghsaMatch[1].toLowerCase();
  }

  const osvMatch = /^osv-(.+)$/i.exec(trimmed);
  if (osvMatch) {
    return "OSV-" + osvMatch[1];
  }

  return trimmed;
}

export function extractCveIds(advisory: AdvisoryRecord): string[] {
  return [...new Set([advisory.id, ...advisory.aliases]
    .map((value) => value.toUpperCase())
    .filter((value) => /^CVE-\d{4}-\d{4,}$/.test(value)))];
}

export function advisoryRecordKey(advisory: AdvisoryRecord): string {
  return advisory.id;
}

function dedupeAdvisoriesById(
  advisories: AdvisoryRecord[]
): AdvisoryRecord[] {
  const seen = new Set<string>();
  const output: AdvisoryRecord[] = [];

  for (const advisory of advisories) {
    const key = advisoryRecordKey(advisory);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(advisory);
  }

  return output;
}

export function compareAdvisorySets(
  current: AdvisoryRecord[],
  target: AdvisoryRecord[]
): {
  resolved: string[];
  persisting: string[];
  introduced: string[];
} {
  const currentKeys = new Set(current.map(advisoryRecordKey));
  const targetKeys = new Set(target.map(advisoryRecordKey));

  return {
    resolved: [...currentKeys].filter((key) => !targetKeys.has(key)).sort(),
    persisting: [...currentKeys].filter((key) => targetKeys.has(key)).sort(),
    introduced: [...targetKeys].filter((key) => !currentKeys.has(key)).sort()
  };
}

async function enrichAdvisories(advisories: AdvisoryRecord[]): Promise<{
  advisories: EnrichedAdvisory[];
  evidenceErrors: string[];
  kevCatalog: {
    source: string;
    catalogVersion: string | null;
    dateReleased: string | null;
  } | null;
}> {
  const cveIds = [...new Set(advisories.flatMap(extractCveIds))];

  if (cveIds.length === 0) {
    return {
      advisories: advisories.map((advisory) => ({
        ...advisory,
        cveEvidence: []
      })),
      evidenceErrors: [],
      kevCatalog: null
    };
  }

  const [epssResult, kevResult] = await Promise.allSettled([
    fetchEpss(cveIds),
    lookupKevEntries(cveIds)
  ]);

  const evidenceErrors: string[] = [];
  const epss = epssResult.status === "fulfilled" ? epssResult.value : {};
  const kev = kevResult.status === "fulfilled" ? kevResult.value : null;

  if (epssResult.status === "rejected") {
    evidenceErrors.push(
      "FIRST EPSS: " +
        (epssResult.reason instanceof Error
          ? epssResult.reason.message
          : String(epssResult.reason))
    );
  }

  if (kevResult.status === "rejected") {
    evidenceErrors.push(
      "CISA KEV: " +
        (kevResult.reason instanceof Error
          ? kevResult.reason.message
          : String(kevResult.reason))
    );
  }

  return {
    advisories: advisories.map((advisory) => ({
      ...advisory,
      cveEvidence: extractCveIds(advisory).map((cveId) => ({
        cveId,
        epss: epss[cveId] ?? null,
        kev: kev?.entries[cveId] ?? null
      }))
    })),
    evidenceErrors,
    kevCatalog: kev ? {
      source: kev.source,
      catalogVersion: kev.catalogVersion,
      dateReleased: kev.dateReleased
    } : null
  };
}

export async function searchAdvisories(query: string, limit: number) {
  return {
    query,
    source: "NVD CVE API 2.0",
    interpretation:
      "Keyword matches are advisory candidates only and do not prove applicability to a supplied product version.",
    results: await searchNvd(query, limit)
  };
}

export async function triageAdvisory(advisoryId: string) {
  const normalized = normalizeAdvisoryId(advisoryId);
  const isCve = /^CVE-\d{4}-\d{4,}$/.test(normalized);
  const evidenceErrors: string[] = [];

  let osv: AdvisoryRecord | null = null;

  try {
    osv = await fetchOsvAdvisory(normalized);
  } catch (error) {
    evidenceErrors.push(
      "OSV: " + (error instanceof Error ? error.message : String(error))
    );
  }

  const cveIds = isCve
    ? [normalized]
    : osv
      ? extractCveIds(osv)
      : [];

  const enrichment = osv
    ? await enrichAdvisories([osv])
    : { advisories: [], evidenceErrors: [], kevCatalog: null };

  evidenceErrors.push(...enrichment.evidenceErrors);

  let epss: Awaited<ReturnType<typeof fetchEpss>> = {};
  let kev: Awaited<ReturnType<typeof lookupKevEntries>> | null = null;

  if (!osv && cveIds.length > 0) {
    const [epssResult, kevResult] = await Promise.allSettled([
      fetchEpss(cveIds),
      lookupKevEntries(cveIds)
    ]);

    if (epssResult.status === "fulfilled") epss = epssResult.value;
    else evidenceErrors.push(
      "FIRST EPSS: " +
        (epssResult.reason instanceof Error
          ? epssResult.reason.message
          : String(epssResult.reason))
    );

    if (kevResult.status === "fulfilled") kev = kevResult.value;
    else evidenceErrors.push(
      "CISA KEV: " +
        (kevResult.reason instanceof Error
          ? kevResult.reason.message
          : String(kevResult.reason))
    );
  }

  const nvdRecords = [];
  for (const cveId of cveIds.slice(0, 3)) {
    try {
      const record = await fetchNvdCve(cveId);
      nvdRecords.push({ cveId, record });
    } catch (error) {
      evidenceErrors.push(
        "NVD " + cveId + ": " +
          (error instanceof Error ? error.message : String(error))
      );
    }
  }

  const standaloneCveEvidence = !osv
    ? cveIds.map((cveId) => ({
        cveId,
        epss: epss[cveId] ?? null,
        kev: kev?.entries[cveId] ?? null
      }))
    : [];

  const enrichedOsv = enrichment.advisories[0] ?? null;

  return {
    queryId: normalized,
    foundInOsv: Boolean(osv),
    osvRecordStatus: !osv
      ? "not-found"
      : osv.withdrawn
        ? "withdrawn"
        : "active-or-not-marked-withdrawn",
    osv: enrichedOsv,
    nvd: nvdRecords,
    cveEvidence: standaloneCveEvidence,
    kevCatalog: enrichment.kevCatalog ?? (kev ? {
      source: kev.source,
      catalogVersion: kev.catalogVersion,
      dateReleased: kev.dateReleased
    } : null),
    evidenceErrors,
    interpretation: {
      kev:
        "CISA KEV presence is evidence of known exploitation for the listed CVE. Absence from KEV is not proof that exploitation has never occurred.",
      epss:
        "EPSS is exploitation-probability context, not a severity score or proof of exploitation.",
      cvss:
        "CVSS describes severity characteristics and should not be treated as exploitation likelihood.",
      osvWithdrawal:
        "OSV direct lookups can return withdrawn records. A withdrawn timestamp must be surfaced and the record must not be presented as a current advisory without qualification."
    }
  };
}

export async function checkPackageVersion(input: {
  ecosystem: SupportedEcosystem;
  name: string;
  version: string;
  maxAdvisories: number;
}) {
  const result = await queryPackageVersion(input);
  const unique = dedupeAdvisoriesById(result.advisories);
  const enrichment = await enrichAdvisories(unique);

  return {
    package: {
      ecosystem: input.ecosystem,
      name: input.name,
      version: input.version
    },
    matchingSemantics:
      "OSV package/version query. The supplied version is explicit, but OSV documents fuzzy matching against upstream versions.",
    status:
      unique.length > 0
        ? "known-advisories-returned"
        : "no-known-advisories-returned",
    advisoryCount: unique.length,
    truncated: result.truncated,
    advisories: enrichment.advisories.map((advisory) => ({
      ...advisory,
      fixedVersions: fixedVersions(
        advisory,
        input.ecosystem,
        input.name
      )
    })),
    kevCatalog: enrichment.kevCatalog,
    evidenceErrors: enrichment.evidenceErrors,
    limitation:
      "No returned advisory does not prove that the package version is secure. OSV version matching is source-defined and may normalize or fuzzily match upstream version strings."
  };
}

export async function comparePackageVersions(input: {
  ecosystem: SupportedEcosystem;
  name: string;
  currentVersion: string;
  targetVersion: string;
}) {
  const [currentResult, targetResult] = await Promise.all([
    queryPackageVersion({
      ecosystem: input.ecosystem,
      name: input.name,
      version: input.currentVersion,
      maxAdvisories: 20
    }),
    queryPackageVersion({
      ecosystem: input.ecosystem,
      name: input.name,
      version: input.targetVersion,
      maxAdvisories: 20
    })
  ]);

  const current = dedupeAdvisoriesById(currentResult.advisories);
  const target = dedupeAdvisoriesById(targetResult.advisories);
  const comparison = compareAdvisorySets(current, target);
  const all = dedupeAdvisoriesById([...current, ...target]);
  const enrichment = await enrichAdvisories(all);
  const byKey = new Map(
    enrichment.advisories.map((advisory) => [
      advisoryRecordKey(advisory),
      advisory
    ])
  );

  const materialize = (keys: string[]): EnrichedAdvisory[] =>
    keys
      .map((key) => byKey.get(key))
      .filter(
        (advisory): advisory is EnrichedAdvisory => advisory !== undefined
      );

  return {
    package: {
      ecosystem: input.ecosystem,
      name: input.name
    },
    currentVersion: input.currentVersion,
    targetVersion: input.targetVersion,
    matchingSemantics:
      "Each supplied version is queried independently through OSV. OSV documents fuzzy matching against upstream versions.",
    comparisonBasis:
      "Exact OSV record IDs returned for each queried package version. Alias overlap is retained as evidence but is not used to collapse records with potentially different affected ranges.",
    counts: {
      current: current.length,
      target: target.length,
      resolved: comparison.resolved.length,
      persisting: comparison.persisting.length,
      introduced: comparison.introduced.length
    },
    resolved: materialize(comparison.resolved),
    persisting: materialize(comparison.persisting),
    introduced: materialize(comparison.introduced),
    truncated: {
      current: currentResult.truncated,
      target: targetResult.truncated
    },
    kevCatalog: enrichment.kevCatalog,
    evidenceErrors: enrichment.evidenceErrors,
    limitation:
      "This comparison covers OSV records returned for the two supplied package-version queries. Alias relationships can overlap across records, and OSV's source-defined version matching is not an independent exact-version guarantee. The result is not a general security guarantee."
  };
}

