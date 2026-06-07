# Security Policy

probectl is a network *security and observability* product, so we hold its own
posture to a high bar. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please report suspected vulnerabilities privately — do not open a public
issue.**

- Preferred: open a [GitHub private security advisory](https://github.com/imfeelingtheagi/probectl/security/advisories/new)
  ("Report a vulnerability").
- Each deployment also advertises a contact at `/.well-known/security.txt`
  (RFC 9116), configurable via `PROBECTL_SECURITY_CONTACT`.

Please include: affected version/commit, component (control plane, agent,
analyzer, deploy), a description and impact, and reproduction steps or a proof of
concept. If you have a suggested fix, even better.

We support coordinated disclosure and will credit reporters who wish to be named.

## How reports are handled

Confirmed reports run the **incident response plan**
([docs/security/incident-response.md](docs/security/incident-response.md)):
severity matrix (cross-tenant exposure is SEV-1 by definition), response
SLAs, evidence preservation via the signed audit/WORM tooling, operator
notification flow, and post-incident review. The threat model behind the
severity judgments is [docs/security/threat-model.md](docs/security/threat-model.md).
Please give us a reasonable window to remediate before any public disclosure.

### Highest-severity classes

We treat these as critical and ask for extra care in handling:

- **Cross-tenant data leakage** — any path where one tenant can read, write, or
  infer another tenant's data is the highest-severity class in this codebase
  (CLAUDE.md §7 guardrail 1). The control plane enforces tenant isolation at the
  storage + query layer (Postgres RLS) with a CI isolation gate; a bypass is
  critical.
- **Authentication / RBAC bypass**, **audit-log tampering** that evades the
  tamper-evident chain, **secret disclosure**, and **agent-transport (mTLS)
  compromise**.

## Supported versions

During Phase 1, the latest tagged release on `main` receives security fixes.
Long-term support windows will be published as the project matures.

## Scope

In scope: the control plane (`probectl-control`), agents, the Python BGP analyzer,
the web UI, the shipped Docker images, Helm chart, and compose deploys.

Out of scope: issues requiring a malicious operator with existing administrative
access; vulnerabilities in third-party dependencies already tracked upstream
(report those upstream, and tell us so we can bump); and findings against the
intentionally non-production `deploy/compose/dev.yml` dependency stack.

## Our commitments

- We acknowledge reports promptly and keep you updated through remediation.
- Dependencies and images are scanned in CI; we patch known CVEs on a priority
  basis.
- Releases carry provenance and an SBOM (see `docs/releasing.md`).
