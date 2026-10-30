# Privacy Policy — Security Advisory Scout

Security Advisory Scout is a read-only security advisory and package-version research service. It is provided through a remote Model Context Protocol (MCP) server.

## Information processed

When a tool is invoked, the service receives structured arguments required for the requested task, such as:

- advisory IDs (CVE, GHSA, or OSV identifiers);
- product, vendor, or vulnerability search terms;
- package ecosystem, package name, and supplied package version(s).

These arguments may contain information that users enter themselves. Avoid including passwords, authentication tokens, personal information, private source code, or other confidential material in tool inputs.

## How requests are handled

The server requests public security information from third-party services as needed:

- NVD CVE API, for vulnerability records and discovery;
- OSV, for advisories and package-version queries;
- FIRST EPSS, for exploitation probability data associated with CVE identifiers;
- CISA's KEV catalog; when needed, its public GitHub-hosted catalog mirror.

These services receive the relevant query parameters or advisory identifiers. The service returns results to the requesting ChatGPT/MCP client.

## Storage and infrastructure

The application is designed as a stateless Worker and does not intentionally store tool inputs, conversation histories, or advisory results in an application database. This does **not** mean that no logging or processing occurs: Cloudflare, connected clients, and external API operators may process technical request, security, and operational information under their own applicable policies.

We make no unverified promise about infrastructure log retention or deletion schedules. This policy describes the application-level behavior; operational settings should be rechecked if the service configuration changes.

## Use of data

Security Advisory Scout does not sell user data, provide advertising, or intentionally profile users based on their tool requests. No payment processing or account registration is required by the MCP service.

## Contact, corrections, and updates

Non-sensitive privacy questions may be raised through the [public repository's GitHub Issues page](https://github.com/aleff-github/security-advisory-scout/issues). Do not disclose passwords or sensitive vulnerability reports publicly; see [SECURITY.md](SECURITY.md).

This policy may change when data processing, hosting, or integrated upstream services change.

_Last updated: October 2026._
