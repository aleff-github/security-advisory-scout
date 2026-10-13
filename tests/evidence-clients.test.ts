import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchEpss } from "../src/epss";
import { lookupKevEntries } from "../src/kev";
import { fetchNvdCve, searchNvd } from "../src/nvd";
import { fetchOsvAdvisory, queryPackageVersion } from "../src/osv";
import { compareAdvisorySets, extractCveIds } from "../src/triage";
import type { AdvisoryRecord } from "../src/types";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("upstream evidence failure handling", () => {
  it("does not manufacture CVE enrichment identifiers for an advisory without CVE aliases", () => {
    const advisory: AdvisoryRecord = {
      id: "GHSA-no-cve",
      aliases: ["PYSEC-2026-1"],
      summary: null,
      details: null,
      published: null,
      modified: null,
      withdrawn: null,
      severity: [],
      references: [],
      affected: []
    };

    expect(extractCveIds(advisory)).toEqual([]);
  });

  it("treats an OSV advisory 404 as a missing record", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 404 })));

    await expect(fetchOsvAdvisory("GHSA-missing")).resolves.toBeNull();
  });

  it("surfaces OSV package-query failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

    await expect(
      queryPackageVersion({
        ecosystem: "npm",
        name: "demo",
        version: "1.0.0"
      })
    ).rejects.toThrow("OSV package query failed with HTTP 503.");
  });

  it("surfaces NVD rate limits instead of returning candidate results", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 429 })));

    await expect(searchNvd("demo", 10)).rejects.toThrow(
      "NVD request failed with HTTP 429."
    );
  });

  it("surfaces NVD server failures instead of treating them as no candidates", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

    await expect(fetchNvdCve("CVE-2026-10000")).rejects.toThrow(
      "NVD request failed with HTTP 503."
    );
  });

  it("keeps different OSV records separate when aliases overlap but ranges differ", () => {
    const current: AdvisoryRecord = {
      id: "GHSA-range-a",
      aliases: ["CVE-2026-10001"],
      summary: null,
      details: null,
      published: null,
      modified: null,
      withdrawn: null,
      severity: [],
      references: [],
      affected: [{
        ecosystem: "npm",
        name: "demo",
        purl: null,
        versions: [],
        ranges: [{ type: "SEMVER", repo: null, events: [{ introduced: "0", fixed: "1.0.0" }] }]
      }]
    };
    const target: AdvisoryRecord = {
      ...current,
      id: "GHSA-range-b",
      affected: [{
        ecosystem: "npm",
        name: "demo",
        purl: null,
        versions: [],
        ranges: [{ type: "SEMVER", repo: null, events: [{ introduced: "1.0.0", fixed: "2.0.0" }] }]
      }]
    };

    expect(compareAdvisorySets([current], [target])).toEqual({
      resolved: ["GHSA-range-a"],
      persisting: [],
      introduced: ["GHSA-range-b"]
    });
  });

  it("preserves rejected NVD record status when an NVD record is returned", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            vulnerabilities: [{
              cve: {
                id: "CVE-2026-10000",
                vulnStatus: "Rejected",
                descriptions: [{ lang: "en", value: "Rejected record" }]
              }
            }]
          }),
          { status: 200 }
        )
      )
    );

    await expect(fetchNvdCve("cve-2026-10000")).resolves.toMatchObject({
      id: "CVE-2026-10000",
      vulnStatus: "Rejected"
    });
  });

  it("returns no EPSS evidence for an empty response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ data: [] }), { status: 200 })
      )
    );

    await expect(fetchEpss(["CVE-2026-10000"])).resolves.toEqual({});
  });

  it("surfaces FIRST EPSS server failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

    await expect(fetchEpss(["CVE-2026-10000"])).rejects.toThrow(
      "FIRST EPSS request failed with HTTP 503."
    );
  });

  it("uses the official GitHub KEV fallback if the primary CISA feed fails", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            catalogVersion: "2026.10.07",
            vulnerabilities: [{
              cveID: "CVE-2026-10000",
              vendorProject: "Example",
              product: "Demo"
            }]
          }),
          { status: 200 }
        )
      );
    vi.stubGlobal("fetch", fetchMock);

    const result = await lookupKevEntries(["CVE-2026-10000"]);

    expect(result.source).toContain("raw.githubusercontent.com/cisagov/kev-data");
    expect(result.entries["CVE-2026-10000"]).toMatchObject({
      cveId: "CVE-2026-10000",
      vendorProject: "Example"
    });
  });

  it("surfaces failure when both CISA KEV sources are unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

    await expect(lookupKevEntries(["CVE-2026-10000"])).rejects.toThrow(
      "CISA KEV sources were unavailable: HTTP 503"
    );
  });
});

