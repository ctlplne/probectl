# SOC 2 / ISO 27001 control evidence

*EXC-ORG-01. This maps the SOC 2 Trust Services Criteria (the "CC" common
criteria) and ISO/IEC 27001:2022 Annex A controls that probectl's platform
already meets to the **code that implements them** and the **test that proves
it**. It is the auditor's starting index: every row points at a file an auditor
can open and a test that fails if the control regresses. probectl is the
*subject* of these controls when self-hosted; for an MSP the same evidence
supports the tenant-facing attestation.*

> This is an engineering evidence map, **not** a certification. A SOC 2 report or
> ISO certificate is issued by an accredited auditor against a defined system
> boundary and observation period; this table gives that auditor the technical
> artifacts. Organizational controls (HR screening, vendor management, the risk
> assessment program) live outside the codebase and are out of scope here.

## How to read a row

- **Control** — the SOC 2 CC reference and/or the ISO 27001 Annex A control.
- **What probectl does** — the implemented behavior.
- **Code** — the file(s) that implement it.
- **Test / gate** — the test that proves it, and the CI gate it rides.

## Logical access — authentication & authorization

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC6.1**, ISO **A.5.15 / A.8.3** (logical access, least privilege) | RBAC baseline + ABAC overlay, evaluated tenant-boundary-first in one place (`Authorize`) | `internal/auth/abac.go`, `internal/auth/middleware.go` | `internal/auth/authz_matrix_test.go` (in-tenant grant, RBAC baseline, ABAC deny, **cross-tenant deny**, least-priv provider role) — `lint-go`/`test-go` |
| SOC 2 **CC6.1**, ISO **A.5.16** (identity lifecycle) | SSO (OIDC, per-tenant IdP) + SCIM provisioning/deprovisioning + MFA step-up | `internal/auth/oidc.go`, `internal/scim/`, `internal/control/scim.go` | `internal/auth/oidc_test.go`, `internal/auth/oidc_mfa_test.go`, `internal/scim/scim_test.go`, `internal/control/scim_integration_test.go` |
| SOC 2 **CC6.1**, ISO **A.5.3** (segregation of duties) | The provider/MSP plane is a separate privilege domain with **no implicit read** of tenant telemetry; access only via audited break-glass | `ee/provider/`, `internal/tenancy/` | `ee/provider/*_test.go`, provider audit stream tests |
| SOC 2 **CC6.6** (boundary protection) | TLS on every listener; mTLS agent↔control-plane (SPIFFE-style, tenant-bound); HTTPS-by-default packaging | `internal/crypto/`, `internal/agenttransport/`, `deploy/` | `internal/agenttransport/transport_integration_test.go`, the unified-TLS lint guard (`lint-go`) |

## Tenant isolation (the outermost control)

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC6.1 / CC6.7**, ISO **A.8.3** (data segregation) | Every data path scoped by `tenant_id` at the storage/query layer (Postgres RLS FORCE; ClickHouse partition key; per-tenant object prefix) — defense-in-depth above RBAC | `internal/tenancy/`, `internal/store/`, migrations | `internal/tenancy/isolation_gate_test.go`, `internal/pipeline/isolation_ingest_test.go` — the **cross-tenant-isolation** CI job (fail-not-skip under `PROBECTL_TEST_REQUIRE_SERVICES=1`) |
| SOC 2 **CC6.7** (data in transit) | Datastore + bus connections support TLS in transit (default-on in mt/regulated) | `internal/store/`, `internal/bus/security.go` | `internal/bus/*_test.go`, integration TLS Postgres (`scripts/ci_pg_tls.sh`) |

## Cryptography & key management

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC6.1**, ISO **A.8.24** (cryptographic controls) | All crypto through one FIPS-swappable abstraction; a FIPS 140-3 validated module compiles in | `internal/crypto/` | `internal/crypto/*_test.go`; **fips-gate** (`make build-fips fips-gate` — validated module active, KATs pass) |
| ISO **A.8.24** (key lifecycle / BYOK) | Per-tenant keys + BYOK with no-downtime rotation, bounded revocation, and cryptographic destruction (KEK zeroization) | `ee/tenantkeys/`, `internal/tenantcrypto/`, `internal/crypto/revocation.go` | `ee/tenantkeys/lifecycle_e2e_test.go` (rotate→revoke→zeroize e2e), `ee/tenantkeys/tenantkeys_test.go` |
| SOC 2 **CC6.1**, ISO **A.8.24** (secrets at rest) | Sensitive config/credentials envelope-encrypted at rest; no plaintext private keys for managed-host flows; no secrets in logs/URLs/git | `internal/crypto/envelope.go`, `internal/secrets/` | `internal/secrets/*_test.go`; the **secret-scan** (gitleaks) CI job |

## Audit logging & monitoring (the evidence trail itself)

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC7.2 / CC7.3**, ISO **A.8.15** (logging) | Immutable, tamper-EVIDENT, hash-chained audit log; config changes + data-access actions recorded; provider/break-glass on a **separate** stream | `internal/audit/audit.go`, migration `0005_audit.sql` (RLS, no UPDATE/DELETE) | `internal/audit/audit_integration_test.go` (tamper detection, concurrency), `internal/audit/worm_test.go` |
| ISO **A.8.15 / A.5.28** (log protection / evidence integrity) | WORM export: provider chain exported as Ed25519-signed, append-only segments to object-locked storage; chain re-verified, gaps alert loudly | `internal/audit/worm.go` | `internal/audit/worm_test.go` |
| SOC 2 **CC7.2**, ISO **A.8.15 / A.5.33** (log retention) | **Configurable retention** (`PROBECTL_AUDIT_RETENTION`): prune only events older than the window AND already durably exported — fail closed, chain never gapped | `internal/audit/retention.go` | `internal/audit/retention_test.go` (policy + fail-closed guards), `internal/audit/retention_integration_test.go` (real-PG prune respects watermark, kept suffix still verifies) |
| SOC 2 **CC7.2**, ISO **A.8.16** (SIEM forwarding) | Audit + detections forwarded to the customer SIEM (syslog/CEF/OTLP), retrying, never dropping | `internal/audit/export.go`, `internal/siem/` | `internal/siem/siem_test.go`, `internal/control/siem_integration_test.go` |
| SOC 2 **CC7.1**, ISO **A.8.16** (self-monitoring) | probectl observes probectl — RED/USE metrics on its own pipelines + self-alerts | `internal/perf/`, `internal/otel/`, alerting wiring | self-observability tests + the `perf-smoke` gate |

## Change management & SDLC

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC8.1**, ISO **A.8.32 / A.8.25** (change management) | Every change gates on the green **verify-all** umbrella; releases gate on `require-green-ci`; branch protection runbook | `.github/workflows/ci.yml`, `release.yml`, `docs/ops/branch-protection.md` | `internal/cipolicy/cipolicy_test.go` (backstop + umbrella assertions) |
| SOC 2 **CC8.1**, ISO **A.8.28 / A.8.31** (secure development, supply chain) | SHA-pinned actions; SBOM + signed artifacts (cosign); dependency + image vulnerability scans; migrations idempotent + expand/contract | `.github/workflows/`, `migrations/`, `buf.*` | `action-pins`, `sbom`, `image-scan`, `dependency-scan`, `migration-gate` CI jobs |

## Availability & resilience

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **CC7.4 / A1.2**, ISO **A.8.13 / A.5.30** (backup, recovery, continuity) | Encrypted backups; restore drill in CI; DR runbook; multi-region metadata replication | `deploy/`, `docs/ops/dr.md`, `docs/ops/backup-restore.md` | `backup-restore-drill` / `failover-drill` CI jobs; DR-drill-on-real-infra is the operator action (see `docs/ops/dr.md`) |
| SOC 2 **A1.1**, ISO **A.8.6** (capacity) | Scale gate (L/XL profiles) + fairness/noisy-neighbor enforcement; the full reference-HW run + 72h soak | `internal/perf/`, `internal/fairness/` | `scale-gate-m` (nightly), `make scale-fullstack` (reference HW — see `docs/scale-gate.md`) |

## Confidentiality & privacy (data rights)

| Control | What probectl does | Code | Test / gate |
|---|---|---|---|
| SOC 2 **C1.1 / C1.2**, ISO **A.8.10** (disposal) | Verifiable per-tenant erasure incl. cryptographic offboarding (destroy the tenant's keys → ciphertext permanently unreadable) and backup coverage | `ee/tenantkeys/`, `internal/tenantlife/`, `ee/provider/erase*` | `ee/tenantkeys/tenantkeys_test.go` (`TestCryptoOffboard`), `internal/tenantlife/integration_test.go`, the erasure-covers-backups gate |
| SOC 2 **CC6.8** (no exfiltration / sovereignty) | No phone-home; AI/MCP egress is air-gapped-by-default, per-tenant consent-gated; external feeds read-only + TLS-validated | `internal/ai/egressgate*`, `internal/opendata/` | `internal/ai/egressgate_test.go`, `internal/ai/source_test.go` |

## Gaps / operator-owned controls

These are real controls an F500 auditor will ask about that are **not** evidenced
by code because they live outside it:

- **Penetration test, risk assessment, vendor management, HR controls** —
  organizational programs (out of repo scope).
- **DR drill on real multi-region infrastructure** — the runbook + CI failover
  drill exist; the live cross-region exercise is an operator action
  (`docs/ops/dr.md`), infrastructure-blocked in CI.
- **The `LICENSE` / commercial license texts** — a legal artifact pending
  counsel (placeholder in-tree); not a technical control.
