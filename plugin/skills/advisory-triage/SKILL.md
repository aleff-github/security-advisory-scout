---
name: advisory-triage
description: Triage CVEs and security advisories using version-specific OSV package evidence, NVD metadata, FIRST EPSS probability, and CISA known-exploitation evidence.
---

Use this skill when the user wants to investigate a vulnerability/advisory, search for likely CVEs affecting a named product, check a supplied open-source package version, or compare two package versions from a vulnerability perspective.

## Scope and safety boundaries

- This skill and its MCP tools are **read-only vulnerability-intelligence workflows**. They do not scan hosts or networks, inspect running processes, access local files or endpoint telemetry, assess live compromise, edit dependency manifests, patch code, create commits, push branches, or deploy software.
- If the request is only about whether a device is compromised, exposed, patched, or safe, and contains no relevant advisory ID, product/vendor search target, or supported package/version, do **not** invoke advisory-search tools just to manufacture a result. State the evidence gap and the specific information required.
- If asked to scan a host, explain that active scanning is outside this skill; do not invent scan findings. General guidance for a user-authorized assessment is fine, but it is not a scan performed by this plugin.
- If asked to patch, commit, push, or deploy, provide advisory evidence and a proposed remediation plan only. Do not invoke GitHub, shell, deployment, or other write-capable integrations on behalf of this skill. A separate, explicitly approved workflow is necessary to perform changes, and host-level permissions must enforce approval.
- If asked to determine whether compromise occurred, never answer "confirmed" or "ruled out" without concrete endpoint, log, or forensic evidence. Advisory, CVSS, EPSS, and KEV evidence cannot alone establish an individual host's compromise status.
- These scope instructions are **not** an access-control mechanism. Other ChatGPT integrations must independently require authorization for writes.

## Workflow

1. Check that the user's request is in scope, and handle out-of-scope requests without an MCP call.
2. If the user supplies a CVE, GHSA, or OSV-family advisory identifier, call `triage_advisory`.
3. If the user supplies specific product/vendor vulnerability search terms, call `search_advisories`. Treat results as candidates, then triage relevant CVEs if appropriate; do not use generic searches as a substitute for host inspection.
4. If the user asks whether a supplied supported package version has known advisory records, call `check_package_version`.
5. If the user is considering an upgrade between two supplied supported package versions, call `compare_package_versions`.
6. Base conclusions on returned evidence. Never infer version applicability from a keyword match alone.

## Interpretation rules

- Never describe software as safe merely because no advisory was returned.
- Distinguish version-specific OSV package evidence from product-name or keyword relevance.
- OSV documents fuzzy matching against upstream version strings. Say that OSV returned an advisory for the supplied package/version query; do not describe the result as independent proof of exact semantic-version applicability.
- Treat CISA KEV presence as evidence of known exploitation for that CVE.
- Treat absence from CISA KEV only as "not present in the queried KEV catalog"; it is not proof that exploitation has never occurred.
- Treat FIRST EPSS as CVE-level probability context for exploitation in the next 30 days, not severity, proof of exploitation, a per-asset compromise probability, or a guarantee of future exploitation. Show the observation date when available.
- Treat CVSS as severity evidence, not exploitation likelihood.
- If an OSV direct lookup has a non-null `withdrawn` timestamp, explicitly identify the record as withdrawn and do not present it as a current advisory without qualification.
- If NVD reports a rejected or otherwise non-active CVE status, surface that status explicitly.
- If an advisory lists configuration or environmental prerequisites, state them separately from version evidence.
- If an upstream source fails, report the missing evidence source instead of converting the failure into a negative result.
- When NVD keyword search returns a CVE, call it a candidate until stronger applicability evidence is available.
- When mentioning remediations, distinguish a historical first fix from a currently maintained recommended version; cite upstream vendor evidence and identify subsequent superseding advisories where relevant.
- For version comparisons, use the exact OSV record IDs returned for each query. Preserve aliases as evidence but do not collapse different records solely because aliases overlap; overlapping identifiers can coexist with different affected ranges.

## Output format

Prefer:

### Assessment
A compact statement of what is confirmed, what is likely, and what remains uncertain.

### Applicability evidence
OSV package/version query evidence, affected ranges, fixed versions, or candidate-only discovery status.

### Exploitation evidence
CISA KEV status and FIRST EPSS probability/percentile, clearly labelled as different signals.

### Severity and advisory evidence
NVD/OSV severity, record status, description, identifiers, dates, and authoritative references.

### Remediation evidence
Fixed versions or vendor/source remediation information when returned.

### Limitations
Missing sources, ambiguous products, version-matching semantics, configuration prerequisites, overlapping advisory aliases, and point-in-time limitations.

Do not produce an opaque numeric risk score or a security guarantee.

