import { describe, expect, it } from "vitest";
import {
  advisoryRecordKey,
  compareAdvisorySets,
  extractCveIds,
  normalizeAdvisoryId
} from "../src/triage";
import type { AdvisoryRecord } from "../src/types";

function advisory(id: string, aliases: string[] = []): AdvisoryRecord {
  return {
    id,
    aliases,
    summary: null,
    details: null,
    published: null,
    modified: null,
    withdrawn: null,
    severity: [],
    references: [],
    affected: []
  };
}

describe("advisory identifier normalization", () => {
  it("canonicalizes CVE identifiers", () => {
    expect(normalizeAdvisoryId(" cve-2021-44228 ")).toBe(
      "CVE-2021-44228"
    );
  });

  it("preserves the canonical lower-case GHSA suffix", () => {
    expect(normalizeAdvisoryId("ghsa-JFH8-C2JP-5V3Q")).toBe(
      "GHSA-jfh8-c2jp-5v3q"
    );
  });

  it("preserves case-sensitive nonstandard OSV source identifiers", () => {
    expect(normalizeAdvisoryId("openSUSE-SU-2021:4094-1")).toBe(
      "openSUSE-SU-2021:4094-1"
    );
  });
});

describe("advisory identity", () => {
  it("uses the exact OSV record ID as the comparison key", () => {
    expect(
      advisoryRecordKey(
        advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-12345"])
      )
    ).toBe("GHSA-aaaa-bbbb-cccc");
  });

  it("extracts unique CVE identifiers", () => {
    expect(
      extractCveIds(
        advisory("GHSA-aaaa-bbbb-cccc", [
          "CVE-2026-12345",
          "cve-2026-12345"
        ])
      )
    ).toEqual(["CVE-2026-12345"]);
  });

  it("separates resolved, persisting, and introduced OSV records", () => {
    const current = [
      advisory("GHSA-old", ["CVE-2026-10001"]),
      advisory("GHSA-stay", ["CVE-2026-10002"])
    ];
    const target = [
      advisory("GHSA-stay", ["CVE-2026-10002"]),
      advisory("GHSA-new", ["CVE-2026-10003"])
    ];

    expect(compareAdvisorySets(current, target)).toEqual({
      resolved: ["GHSA-old"],
      persisting: ["GHSA-stay"],
      introduced: ["GHSA-new"]
    });
  });

  it("does not collapse different OSV records merely because aliases overlap", () => {
    const current = [
      advisory("GHSA-source-a", ["CVE-2026-10001"])
    ];
    const target = [
      advisory("GHSA-source-b", ["CVE-2026-10001"])
    ];

    expect(compareAdvisorySets(current, target)).toEqual({
      resolved: ["GHSA-source-a"],
      persisting: [],
      introduced: ["GHSA-source-b"]
    });
  });
});

