# Incident response plan (U-066)

v1.0 — 2026-06-07. How a probectl security incident is detected, triaged,
handled, evidenced, and disclosed. Companion to [SECURITY.md](../../SECURITY.md)
(intake + coordinated disclosure) and
[threat-model.md](threat-model.md). Two scopes, kept distinct:

- **Product/vendor incidents** — a vulnerability or compromise in probectl
  code, releases, or build infrastructure. Vendor-led; affects all
  deployments.
- **Deployment incidents** — a compromise inside one operator's
  installation. Operator-led under their own IR; probectl's job is to give
  them the evidence tooling and this playbook's deployment sections.

## 1. Severity matrix

| Sev | Definition | Examples | Acknowledge | Mitigation target |
|---|---|---|---|---|
| **SEV-1** | Cross-tenant data exposure (guardrail §7.1 — the declared highest-severity failure); RCE in agent/control plane; compromised release artifact or signing path | tenant A reads B; malicious artifact signed | 4h | fix or kill-switch ≤ 24h; advisory ≤ 72h |
| **SEV-2** | Auth/RBAC bypass within a tenant; audit-chain integrity break; secret exposure; AI egress gate bypass | consent gate skipped; WORM verify fails | 24h | ≤ 7 days |
| **SEV-3** | Vulnerability with significant mitigating factors; DoS of a plane; dependency CVE in a reachable path | fairness bypass; exploitable parser crash | 72h | next patch release |
| **SEV-4** | Hardening gap, defense-in-depth finding, non-reachable dep CVE | scanner findings | 7 days | scheduled |

Cross-tenant anything starts at SEV-1 until proven otherwise. When in
doubt, classify up.

## 2. Roles

Solo-founder reality, stated plainly: the **maintainer is Incident
Commander, investigator, and fixer**. Compensating structure: this written
plan; predefined external deputies (counsel for notification duty
questions; the affected operator's security team for deployment incidents,
who are co-responders by design since they hold the infrastructure); and
an immutable trail (signed WORM audit export, U-041) so actions are
reviewable after the fact. Role table to be re-cut at first security hire.

| Role | Holder today | Duties |
|---|---|---|
| Incident Commander | maintainer | declare sev, run timeline, own comms |
| Investigator/fixer | maintainer (+ operator's team for deployment scope) | root cause, patch, verify |
| Counsel | external (engaged per incident) | notification obligations, advisory wording |

## 3. Response flow

1. **Intake.** SECURITY.md channels (private advisory / `security.txt`
   contact), CI security gates (`security-scan.yml`), the WORM
   chain-verification alarm, or an operator report.
2. **Declare + log.** Assign SEV; open a private timeline doc; record
   UTC timestamps for every action from this point.
3. **Contain.** Product scope: pull/revoke affected artifacts (cosign
   identities make "which artifact" provable), gate the release lane.
   Deployment scope: the operator isolates per the runbooks — agents
   halt-on-error via the rollout machinery (U-031), credentials rotate,
   `insecure` overrides audited (C10).
4. **Preserve evidence — before remediation mutates state.**
   - Export the audit chains: the provider stream's **signed WORM
     segments** are already off-DB and chain-verified (U-041,
     `internal/audit/worm.go`); snapshot tenant streams.
   - `scripts/backup_postgres.sh` / `backup_clickhouse.sh` to capture
     store state with SHA-256 manifests (U-030).
   - Support bundle (`internal/support`) for config/version posture.
   - Hash and retain agent binaries/objects in question (compare against
     the U-014 manifest and release signatures).
5. **Eradicate + recover.** Fix forward; release through the normal lane
   (red-CI refusal stays on, U-083); fleet upgrade as **staged waves of
   signed artifacts with halt-on-error** (U-031) — emergencies change the
   wave sizes, not the verification.
6. **Notify** (§4) and **disclose** (§5).
7. **Post-incident review** within 7 days: timeline, root cause, the
   register gets a U-id for every systemic gap found, threat model
   re-reviewed if a boundary was involved.

## 4. Customer notification

Self-hosted nuance: the vendor cannot see deployments, so notification =
telling **operators** what to check and ship, fast.

- **Channels:** GitHub Security Advisory (the canonical record) + release
  notes; direct contact for known enterprise/MSP operators.
- **SEV-1:** initial notice within **72h of confirmation** — even if
  incomplete: affected versions, severity, interim mitigations, IOCs (how
  an operator checks *their* audit chains/registry for the pattern).
  Update cadence ≥ every 72h until resolved.
- **SEV-2:** notice with the fix release.
- **Content discipline:** facts, affected versions, upgrade path
  (`docs/ops/fleet-rollout.md`), verification steps
  (`docs/ops/verify-artifacts.md`). MSP operators re-notify *their*
  tenants under their own obligations; the per-tenant audit trail gives
  them the evidence to do it.

## 5. Disclosure

Coordinated disclosure per [SECURITY.md](../../SECURITY.md): reporter
credit, advisory published when a fix is available, CVE requested via
GitHub for qualifying issues. Embargo target ≤ 90 days, shorter when
exploitation is observed.

## 6. Drill

Tabletop this plan twice yearly (one product-scope, one
deployment-scope using the backup/failover drills as the recovery legs)
and after any SEV-1/2. Record outcomes in the review log below.

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-06-07 | Initial plan |
