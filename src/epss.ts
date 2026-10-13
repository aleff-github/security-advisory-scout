import type { EpssRecord } from "./types";

interface RawEpssResponse {
  data?: Array<{
    cve?: string;
    epss?: string;
    percentile?: string;
    date?: string;
  }>;
}

export async function fetchEpss(
  cveIds: string[]
): Promise<Record<string, EpssRecord>> {
  const unique = [...new Set(cveIds.map((value) => value.toUpperCase()))]
    .filter((value) => /^CVE-\d{4}-\d{4,}$/.test(value))
    .slice(0, 100);

  if (unique.length === 0) return {};

  const response = await fetch(
    "https://api.first.org/data/v1/epss?cve=" +
      encodeURIComponent(unique.join(",")),
    {
      headers: {
        Accept: "application/json",
        "User-Agent": "security-advisory-scout-mcp"
      }
    }
  );

  if (!response.ok) {
    throw new Error(
      "FIRST EPSS request failed with HTTP " + response.status + "."
    );
  }

  const data = (await response.json()) as RawEpssResponse;
  const output: Record<string, EpssRecord> = {};

  for (const item of data.data ?? []) {
    if (!item.cve || item.epss === undefined || item.percentile === undefined) {
      continue;
    }

    const probability = Number(item.epss);
    const percentile = Number(item.percentile);
    if (!Number.isFinite(probability) || !Number.isFinite(percentile)) {
      continue;
    }

    output[item.cve.toUpperCase()] = {
      cve: item.cve.toUpperCase(),
      probability,
      percentile,
      date: item.date ?? null
    };
  }

  return output;
}

