import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { z } from "zod";
import { SUPPORTED_ECOSYSTEMS } from "./types";
import {
  checkPackageVersion,
  comparePackageVersions,
  searchAdvisories,
  triageAdvisory
} from "./triage";

function asTextPayload(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

function errorPayload(error: unknown) {
  return {
    ...asTextPayload({
      error: error instanceof Error ? error.message : String(error)
    }),
    isError: true
  };
}

const ecosystemSchema = z.enum(SUPPORTED_ECOSYSTEMS);

function createServer() {
  const server = new McpServer({
    name: "security-advisory-scout",
    version: "0.1.0"
  });

  server.registerTool(
    "search_advisories",
    {
      description:
        "Search NVD by free-text product, vendor, or vulnerability terms. Results are discovery candidates only and do not prove version applicability.",
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
        destructiveHint: false
      },
      inputSchema: z.object({
        query: z.string().min(2).max(300),
        limit: z.number().int().min(1).max(20).default(10)
      })
    },
    async ({ query, limit }) => {
      try {
        return asTextPayload(await searchAdvisories(query, limit));
      } catch (error) {
        return errorPayload(error);
      }
    }
  );

  server.registerTool(
    "triage_advisory",
    {
      description:
        "Triage one CVE or OSV-family advisory identifier such as GHSA. Combines OSV/NVD advisory evidence with FIRST EPSS probability and CISA KEV known-exploitation evidence when a CVE identifier is available.",
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
        destructiveHint: false
      },
      inputSchema: z.object({
        advisoryId: z
          .string()
          .min(5)
          .max(100)
          .describe("CVE, GHSA, or OSV-family advisory identifier.")
      })
    },
    async ({ advisoryId }) => {
      try {
        return asTextPayload(await triageAdvisory(advisoryId));
      } catch (error) {
        return errorPayload(error);
      }
    }
  );

  server.registerTool(
    "check_package_version",
    {
      description:
        "Query OSV for one supplied package version, then enrich returned CVEs with EPSS and CISA KEV evidence. OSV may normalize or fuzzily match upstream version strings, so results are version-specific source evidence rather than an independent exact-version proof.",
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
        destructiveHint: false
      },
      inputSchema: z.object({
        ecosystem: ecosystemSchema,
        name: z.string().min(1).max(300),
        version: z.string().min(1).max(200),
        maxAdvisories: z.number().int().min(1).max(20).default(20)
      })
    },
    async ({ ecosystem, name, version, maxAdvisories }) => {
      try {
        return asTextPayload(
          await checkPackageVersion({
            ecosystem,
            name,
            version,
            maxAdvisories
          })
        );
      } catch (error) {
        return errorPayload(error);
      }
    }
  );

  server.registerTool(
    "compare_package_versions",
    {
      description:
        "Compare OSV advisory results for two supplied versions of the same supported package. Separates resolved, persisting, and introduced OSV records without treating the source's version matching as an independent exact-version guarantee.",
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
        destructiveHint: false
      },
      inputSchema: z.object({
        ecosystem: ecosystemSchema,
        name: z.string().min(1).max(300),
        currentVersion: z.string().min(1).max(200),
        targetVersion: z.string().min(1).max(200)
      })
    },
    async ({ ecosystem, name, currentVersion, targetVersion }) => {
      try {
        return asTextPayload(
          await comparePackageVersions({
            ecosystem,
            name,
            currentVersion,
            targetVersion
          })
        );
      } catch (error) {
        return errorPayload(error);
      }
    }
  );

  return server;
}

// Official MCP SDK stateless Fetch handler: no Agents SDK client/OAuth peers.
const mcpHandler = createMcpHandler(createServer);

export default {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname !== "/mcp") {
      return new Response("Not Found", { status: 404 });
    }
    return mcpHandler.fetch(request);
  }
};

