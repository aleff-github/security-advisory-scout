import { describe, expect, it } from "vitest";
import {
  checkPackageVersion,
  comparePackageVersions,
  searchAdvisories,
  triageAdvisory
} from "../src/triage";

const runtimeProcess = globalThis as typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};
const runLive = runtimeProcess.process?.env?.RUN_LIVE_ADVISORY_TESTS === "1";
const liveIt = runLive ? it : it.skip;
const liveTimeoutMs = 30_000;

async function probe(url: string): Promise<{ host: string; status: number }> {
  const response = await fetch(url, {
    headers: { "user-agent": "security-advisory-scout-live-validation" }
  });
  const host = new URL(url).host;
  await response.body?.cancel();
  return { host, status: response.status };
}

describe("live upstream diagnostics (opt-in)", () => {
  liveIt("resolves and connects to every configured upstream hostname from Node", async () => {
    const results = await Promise.all([
      probe("https://api.osv.dev/v1/vulns/CVE-2021-44228"),
      probe("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"),
      probe("https://api.first.org/data/v1/epss?cve=CVE-2021-44228"),
      probe("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
      probe("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json")
    ]);

    console.info("Security Advisory Scout live upstream statuses:", results);
    expect(results).toHaveLength(5);
  }, liveTimeoutMs);
});

describe("Security Advisory Scout live golden cases (opt-in)", () => {
  liveIt("A: triages CVE-2021-44228 without conflating evidence dimensions", async () => {
    const result = await triageAdvisory("CVE-2021-44228");
    const cveEvidence = result.osv?.cveEvidence ?? result.cveEvidence;

    expect(result.queryId).toBe("CVE-2021-44228");
    expect(result.interpretation.cvss).toMatch(/severity/i);
    expect(result.interpretation.epss).toMatch(/probability/i);
    expect(result.interpretation.kev).toMatch(/known exploitation/i);
    expect(result.nvd[0]?.record?.id ?? result.evidenceErrors.join(" ")).toContain(
      "CVE-2021-44228"
    );
    expect(cveEvidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          cveId: "CVE-2021-44228",
          epss: expect.objectContaining({ probability: expect.any(Number) }),
          kev: expect.objectContaining({ cveId: "CVE-2021-44228" })
        })
      ])
    );
    console.info("Case A summary:", {
      nvdIds: result.nvd.map((item) => item.record?.id ?? item.cveId),
      cveEvidence: cveEvidence.map((item) => ({
        cveId: item.cveId,
        hasEpss: item.epss !== null,
        hasKev: item.kev !== null
      })),
      evidenceErrors: result.evidenceErrors
    });
  }, liveTimeoutMs);

  liveIt("B: triages the canonical GHSA record through OSV", async () => {
    const result = await triageAdvisory("GHSA-jfh8-c2jp-5v3q");

    expect(result.queryId).toBe("GHSA-jfh8-c2jp-5v3q");
    expect(result.foundInOsv).toBe(true);
    expect(result.osv?.id).toBe("GHSA-jfh8-c2jp-5v3q");
    expect(result.interpretation.cvss).toMatch(/severity/i);
    expect(result.interpretation.kev).toMatch(/known exploitation/i);
    console.info("Case B summary:", {
      osvId: result.osv?.id,
      aliases: result.osv?.aliases,
      nvdIds: result.nvd.map((item) => item.record?.id ?? item.cveId),
      evidenceErrors: result.evidenceErrors
    });
  }, liveTimeoutMs);

  liveIt("C: preserves source-defined lodash version evidence", async () => {
    const result = await checkPackageVersion({
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.21",
      maxAdvisories: 20
    });

    expect(result.matchingSemantics).toMatch(/OSV package\/version query/i);
    expect(result.advisoryCount).toBe(result.advisories.length);
    expect(result.advisories).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: expect.any(String),
          aliases: expect.any(Array),
          affected: expect.any(Array),
          fixedVersions: expect.any(Array),
          cveEvidence: expect.any(Array)
        })
      ])
    );
    expect(JSON.stringify(result)).not.toMatch(/riskScore|aggregateRisk/i);
    console.info("Case C summary:", {
      advisoryIds: result.advisories.map((item) => item.id),
      fixedVersions: result.advisories.map((item) => ({
        id: item.id,
        fixedVersions: item.fixedVersions
      })),
      evidenceErrors: result.evidenceErrors
    });
  }, liveTimeoutMs);

  liveIt("D: compares lodash versions by exact OSV record IDs", async () => {
    const result = await comparePackageVersions({
      ecosystem: "npm",
      name: "lodash",
      currentVersion: "4.17.21",
      targetVersion: "4.18.1"
    });
    const groups = [result.resolved, result.persisting, result.introduced];

    expect(result.matchingSemantics).toMatch(/queried independently/i);
    expect(result.comparisonBasis).toMatch(/Exact OSV record IDs/i);
    expect(result.counts.resolved).toBe(result.resolved.length);
    expect(result.counts.persisting).toBe(result.persisting.length);
    expect(result.counts.introduced).toBe(result.introduced.length);
    expect(groups.flat().every((record) => typeof record.id === "string")).toBe(true);
    expect(result.limitation).toMatch(/not a general security guarantee/i);
    console.info("Case D summary:", {
      counts: result.counts,
      resolved: result.resolved.map((item) => item.id),
      persisting: result.persisting.map((item) => item.id),
      introduced: result.introduced.map((item) => item.id),
      evidenceErrors: result.evidenceErrors
    });
  }, liveTimeoutMs);

  liveIt("E: returns bounded NVD discovery candidates without CPE applicability data", async () => {
    const result = await searchAdvisories("Apache Log4j2", 10);

    expect(result.results.length).toBeLessThanOrEqual(10);
    expect(result.interpretation).toMatch(/candidates only/i);
    expect(result.results.every((record) => record.cpeMatches.length === 0)).toBe(true);
    console.info("Case E summary:", {
      count: result.results.length,
      ids: result.results.map((item) => item.id),
      cpeMatchCounts: result.results.map((item) => item.cpeMatches.length)
    });
  }, liveTimeoutMs);
});

