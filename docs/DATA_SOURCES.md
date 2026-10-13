# Data sources and scope

Security Advisory Scout consults public evidence from these providers:

| Source | Use | Important limitation |
| --- | --- | --- |
| NVD CVE API 2.0 | CVE metadata, CVSS scoring and keyword discovery | Keyword search finds candidates; CPE/configuration review may be needed |
| OSV | Advisories, packages and affected-version records | Version matching is source-defined and can involve normalization or fuzzy matching |
| FIRST EPSS | CVE-level probability/percentile of exploitation in the following 30 days | Not CVSS severity, exploit proof, or probability that your host is compromised |
| CISA KEV | Official catalog of known exploited CVEs | Not being listed is not proof of no exploitation |

The server does not collect machine telemetry, scan networks, read local files or remediate systems.

Tool identifiers are `search_advisories`, `triage_advisory`, `check_package_version` and `compare_package_versions`. Their MCP annotations indicate read-only operation and externally accessed data sources.

