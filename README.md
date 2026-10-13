# Security Advisory Scout

**Evidence-first security advisory intelligence for ChatGPT and MCP.**

Security Advisory Scout is a free, read-only tool for investigating CVEs, GitHub Security Advisories (GHSA), and other OSV-family advisories. It separates **severity**, **probability of exploitation**, **known exploitation**, and **version-specific vulnerability evidence** instead of treating them as interchangeable conclusions.

## What it does

- Searches NVD for candidate CVEs by product, vendor, or vulnerability terms.
- Triages a supplied CVE, GHSA, or supported OSV advisory identifier.
- Provides CVSS severity context from source advisories and NVD.
- Uses FIRST EPSS for CVE-level exploitation probability and percentile.
- Checks CISA Known Exploited Vulnerabilities (KEV) for cataloged exploitation.
- Checks OSV advisories for a supplied package name and version.
- Compares two versions, separating resolved, persisting, and introduced OSV records.

## Available MCP tools

| Tool | Purpose |
| --- | --- |
| `search_advisories` | Find NVD keyword candidates, not guaranteed applicability |
| `triage_advisory` | Investigate a CVE or OSV-family advisory with exploitation evidence |
| `check_package_version` | Query OSV for known advisory records involving one package/version |
| `compare_package_versions` | Compare exact returned OSV record IDs for two package versions |

Supported OSV package ecosystems: npm, PyPI, Maven, Go, crates.io, RubyGems, NuGet, and Packagist.

## Example prompts

> Triage CVE-2021-44228. Separate CVSS severity, FIRST EPSS probability, CISA KEV exploitation evidence, affected products, and remediation.

> Check published advisories for npm lodash 4.17.21. Explain how OSV matches the supplied version.

> Compare OSV advisories for npm lodash 4.17.21 and 4.18.1. Separate resolved, persisting, and newly returned records.

## Evidence limits

Advisory matching does **not** establish that a particular device is compromised, vulnerable, or secure. An empty advisory result is not proof of safety. EPSS is a predictive probability signal, CVSS describes severity, and KEV catalogs known exploited CVEs. Product keyword matches are discovery candidates, while OSV package/version results use the source's matching rules and may require vendor configuration checks.

This plugin cannot scan a computer, enumerate network ports, patch source code, modify GitHub repositories, or deploy changes. Data comes from third-party services and can be incomplete, rate-limited, or unavailable. Results are informational and require independent verification before operational decisions.

## Data sources

- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [OSV](https://osv.dev/)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Development

Node.js 22 or later is recommended.

```sh
npm ci
npm run check
npm test
npm audit
npm run dev
```

The service is a Cloudflare Worker serving Streamable HTTP MCP at `/mcp`. A production Worker deployment and review-portal registration are separate actions. Never put API tokens, credentials, reviewer-only recordings, or private development information in this repository.

## Legal, support and reporting

- [Privacy Policy](PRIVACY.md)
- [Terms of Service](TERMS.md)
- [Security Policy](SECURITY.md)
- Support: use this repository's **Issues** page after the public repository is created.
- Security disclosures: follow the private-reporting procedure in [SECURITY.md](SECURITY.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).

