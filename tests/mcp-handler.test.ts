import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { searchAdvisories } from "../src/triage";

// This fixture tests the real MCP transport and tool routing without making
// any live NVD request. Upstream client behavior is tested separately.
vi.mock("../src/triage", () => ({
  searchAdvisories: vi.fn(async (query: string) => ({
    query,
    source: "mock-nvd",
    results: [{ id: "CVE-2026-9999", description: "test fixture only" }]
  })),
  triageAdvisory: vi.fn(),
  checkPackageVersion: vi.fn(),
  comparePackageVersions: vi.fn()
}));

describe("standalone stateless MCP transport", () => {
  it("returns a successful tools/call response with stubbed upstream evidence", async () => {
    const response = await worker.fetch(
      new Request("https://scout.example.test/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-protocol-version": "2025-11-25"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "search_advisories",
            arguments: { query: "Apache Log4j2", limit: 3 }
          }
        })
      })
    );

    expect(response.status).toBe(200);
    const payload = await response.text();

    // The Streamable HTTP handler may return JSON or an SSE envelope.
    expect(payload).toContain("CVE-2026-9999");
    expect(payload).not.toContain('"isError":true');
    expect(searchAdvisories).toHaveBeenCalledWith("Apache Log4j2", 3);
  });

  it("keeps the HTTP route restricted to /mcp", async () => {
    const response = await worker.fetch(
      new Request("https://scout.example.test/")
    );

    expect(response.status).toBe(404);
  });
});

