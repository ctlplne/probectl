# Security Policy

probectl is a self-hosted network observability platform — with a native
security-signal layer — that many operators run in regulated or air-gapped
environments, so we hold its own posture to a high bar. This page tells you how to report a vulnerability privately, what we treat
as most serious, and what's in and out of scope. Thank you for helping keep
probectl and its users safe.

## Reporting a vulnerability

**Please report suspected vulnerabilities privately — do not open a public
issue.**

- Preferred: open a [GitHub private security advisory](https://github.com/imfeelingtheagi/probectl/security/advisories/new)
  ("Report a vulnerability") — GitHub's private reporting channel, visible only
  to you and the maintainer until a fix ships.
- Each deployment also advertises a contact at `/.well-known/security.txt`
  (RFC 9116 — a small text file at a standard path that tells researchers where
  to report for *that* installation), configurable via
  `PROBECTL_SECURITY_CONTACT`.

Please include: affected version/commit, component (control plane, agent,
analyzer, deploy), a description and impact, and reproduction steps or a proof of
concept. If you have a suggested fix, even better.

We support coordinated disclosure — you report privately, we fix, then the
details go public together rather than before a fix exists — and will credit
reporters who wish to be named.

## How reports are handled

Confirmed reports run the **incident response plan**
([docs/security/incident-response.md](docs/security/incident-response.md)):
a severity matrix — the lookup table that converts impact into response speed,
where cross-tenant exposure is SEV-1 by definition — response SLAs, evidence
preservation via the signed audit/WORM tooling (WORM — Write Once, Read Many:
exported copies a database owner cannot rewrite), operator notification flow,
and post-incident review. The threat model — the written map of which attacks
the design expects and what stops each one — behind the severity judgments is
[docs/security/threat-model.md](docs/security/threat-model.md).
Please give us a reasonable window to remediate before any public disclosure.

### Highest-severity classes

We treat these as critical and ask for extra care in handling:

- **Cross-tenant data leakage** — any path where one tenant (one isolated
  customer/organization in a deployment) can read, write, or infer another
  tenant's data is the highest-severity class in this codebase (the first of
  the project's [non-negotiables](CONTRIBUTING.md)). The control plane enforces
  tenant isolation at the storage + query layer (Postgres RLS — row-level
  security, where the database itself filters every row by tenant, so a
  forgotten `WHERE` clause cannot leak) with a CI isolation gate; a bypass is
  critical.
- **Authentication / RBAC bypass** (RBAC — role-based access control, the
  permission system), **audit-log tampering** that evades the tamper-evident
  chain (each record's hash covers the previous record's, so an edit or
  deletion breaks every later link), **secret disclosure**, and
  **agent-transport (mTLS) compromise** (mTLS — mutual TLS, where both ends
  prove their identity with certificates, not just the server).

## Supported versions

probectl is pre-1.0. The **latest tagged release** receives security fixes;
older tags do not. Formal long-term-support windows will be published as the
project reaches GA.

## Scope

In scope: the control plane (`probectl-control`), agents, the Python BGP analyzer,
the web UI, the shipped Docker images, Helm chart, and compose deploys.

### A note on "operator" privilege (in scope vs out of scope)

probectl has **two distinct privilege domains**, and they are treated very
differently here:

- A **tenant-scoped administrator** is the most-privileged user *inside a single
  tenant*. Issues that require such an admin acting *within their own tenant's*
  legitimate scope are generally out of scope.
- A **provider / MSP operator** runs the shared platform across many tenants.
  This operator is explicitly **not** trusted with tenant telemetry. Per the
  project [non-negotiables](CONTRIBUTING.md) (§7.1/§7.7), the following are
  **IN SCOPE and high severity**, even though they involve a privileged
  operator:
  - **Break-glass-gate bypass** — any path that lets a provider operator read
    tenant telemetry without an explicit, time-bounded, tenant-consented,
    separately-audited break-glass grant.
  - **Implicit operator telemetry reads** — any path granting the provider
    plane silent/default read access to a tenant's data.
  - **Missing or evadable provider-audit records** — provider-plane and
    break-glass actions that are not written to the separate, tamper-evident
    provider audit stream (or that can evade it).

Out of scope: issues requiring a malicious **tenant-scoped** administrator
acting within that tenant's own legitimate scope (provider/MSP-operator abuse of
the kind listed above is IN scope); vulnerabilities in third-party dependencies
already tracked upstream (report those upstream, and tell us so we can bump);
and findings against the intentionally non-production
`deploy/compose/dev.yml` dependency stack.

## Our commitments

- We acknowledge reports promptly and keep you updated through remediation.
- Dependencies and images are scanned in CI; we patch known CVEs (publicly
  catalogued vulnerabilities) on a priority basis.
- Releases carry provenance (the signed record of where and how an artifact was
  built) and an SBOM (software bill of materials — the machine-readable parts
  list of a release); see `docs/releasing.md`.
