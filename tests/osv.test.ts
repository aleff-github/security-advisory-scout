import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fixedVersions,
  normalizeOsvAdvisory,
  queryPackageVersion
} from "../src/osv";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OSV normalization", () => {
  it("extracts fixed versions for the selected package", () => {
    const advisory = normalizeOsvAdvisory({
      id: "GHSA-test",
      aliases: ["CVE-2026-99999"],
      affected: [
        {
          package: {
            ecosystem: "npm",
            name: "demo"
          },
          ranges: [
            {
              type: "SEMVER",
              events: [
                { introduced: "0" },
                { fixed: "2.0.1" }
              ]
            }
          ]
        }
      ]
    });

    expect(advisory).not.toBeNull();
    expect(fixedVersions(advisory!, "npm", "demo")).toEqual(["2.0.1"]);
  });

  it("preserves the withdrawn timestamp from direct OSV records", () => {
    const advisory = normalizeOsvAdvisory({
      id: "GHSA-withdrawn",
      withdrawn: "2026-01-02T03:04:05Z"
    });

    expect(advisory?.withdrawn).toBe("2026-01-02T03:04:05Z");
  });

  it("bounds nested OSV evidence before it reaches an MCP response", () => {
    const advisory = normalizeOsvAdvisory({
      id: "GHSA-bounded",
      aliases: Array.from({ length: 30 }, (_, index) => "ALIAS-" + index),
      details: "x".repeat(4000),
      severity: Array.from({ length: 10 }, () => ({ type: "CVSS_V3", score: "x" })),
      references: Array.from({ length: 20 }, (_, index) => ({
        type: "WEB",
        url: "https://example.test/" + index
      })),
      affected: Array.from({ length: 8 }, () => ({
        package: { ecosystem: "npm", name: "demo" },
        ranges: Array.from({ length: 5 }, () => ({
          type: "SEMVER",
          events: Array.from({ length: 12 }, () => ({ introduced: "0" }))
        })),
        versions: Array.from({ length: 60 }, (_, index) => "1.0." + index)
      }))
    });

    expect(advisory?.aliases).toHaveLength(20);
    expect(advisory?.details).toHaveLength(3001);
    expect(advisory?.severity).toHaveLength(5);
    expect(advisory?.references).toHaveLength(10);
    expect(advisory?.affected).toHaveLength(5);
    expect(advisory?.affected[0]?.ranges).toHaveLength(3);
    expect(advisory?.affected[0]?.ranges[0]?.events).toHaveLength(10);
    expect(advisory?.affected[0]?.versions).toHaveLength(50);
  });
});

describe("OSV pagination", () => {
  it("does not mark a fully consumed paginated query as truncated", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            vulns: [],
            next_page_token: "next-page"
          }),
          { status: 200 }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            vulns: [{ id: "GHSA-second-page" }]
          }),
          { status: 200 }
        )
      );

    vi.stubGlobal("fetch", fetchMock);

    const result = await queryPackageVersion({
      ecosystem: "npm",
      name: "demo",
      version: "1.0.0",
      maxAdvisories: 20
    });

    expect(result.truncated).toBe(false);
    expect(result.advisories.map((item) => item.id)).toEqual([
      "GHSA-second-page"
    ]);

    const secondRequest = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(JSON.parse(String(secondRequest.body))).toMatchObject({
      page_token: "next-page"
    });
  });

  it("marks a query as truncated when the configured advisory cap is hit", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          vulns: [
            { id: "GHSA-first" },
            { id: "GHSA-second" }
          ]
        }),
        { status: 200 }
      )
    );

    vi.stubGlobal("fetch", fetchMock);

    const result = await queryPackageVersion({
      ecosystem: "npm",
      name: "demo",
      version: "1.0.0",
      maxAdvisories: 1
    });

    expect(result.truncated).toBe(true);
    expect(result.advisories.map((item) => item.id)).toEqual([
      "GHSA-first"
    ]);
  });

  it("caps requested package advisories at the response-safe limit", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          vulns: Array.from({ length: 25 }, (_, index) => ({
            id: "GHSA-" + index
          }))
        }),
        { status: 200 }
      )
    );

    vi.stubGlobal("fetch", fetchMock);

    const result = await queryPackageVersion({
      ecosystem: "npm",
      name: "demo",
      version: "1.0.0",
      maxAdvisories: 50
    });

    expect(result.advisories).toHaveLength(20);
    expect(result.truncated).toBe(true);
  });
});

