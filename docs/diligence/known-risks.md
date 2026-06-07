# Known-risks register (DATAROOM-010)

The standing, honest list of residual risks — seeded from the post-triage
review of the blind second audit (`SPRINT-PLAN-TRIAGE.md` §2–§4) and kept
current as sprints close. One row per risk; when a sprint closes one, flip
the status with the commit hash rather than deleting the row.

**Owners:** `eng` = founder + agents (code) · `counsel` = external legal ·
`auditor` = external SOC 2 / pen test · `iron` = needs reference hardware.

## Critical-path risks

| ID(s) | Risk | Status | Owner | Closes via |
|---|---|---|---|---|
| TENANT-101 / WIRE-001 | Bus-published planes trusted the agent-config `tenant_id` — cross-tenant injection on flow/device/eBPF/endpoint | **CLOSED (Sprint 4)** — consumers verify (tenant, agent) against the registry (fail closed, cached); namespaced lanes are the authoritative tenant; injection tests + fuzz in CI. Residual until S11: a forged pair using ANOTHER tenant's registered agent id over pooled bus creds — bounded by the registry check + rejection counters, fully closed by enrollment/SVID | eng | Sprint 11 (residual) |
| WIRE-002 / RED-002 / TENANT-103 / ARCH-004 | No in-repo agent enrollment / SVID issuance — the trust root is operator-manual (deferred as S-EE1) | OPEN — **ADR + threat-model delta reviewed before code** | eng | Sprint 11 |
| LICENSE-001/002 / DATAROOM-001/002 | `LICENSE` is a TBD placeholder; no EE license text; no CLA/DCO; IP chain unproven for non-founder commits | OPEN — counsel decisions kick off now, commits land last | counsel | Phase L (S32–S33) |
| COMPLY-001 / DATAROOM-006 | No SOC 2 attestation (self-declared mapping only) — caps the headline diligence score regardless of code | OPEN — engage auditor now (6–12 mo) | auditor | S29 evidence pack + external attestation |
| SCALE-002 / DOCS-001 / DOCS-006 / OPS-007 | Numeric scale SLOs, agent overhead, and RTO/RPO are PROVISIONAL — harnesses/drills exist, no L/XL or representative run executed | OPEN | iron | Sprint 17 + Sprint 27 (runs, not builds) |

## Security residuals (open until their sprint)

| ID(s) | Risk | Status | Owner | Closes via |
|---|---|---|---|---|
| RED-001 / SEC-001 | Dev auth mode was runtime-selectable in every binary | **CLOSED (Sprint 3, c114a05)** — compiled out of release binaries (-tags devauth only), triple-gated (ack + loopback), no-devauth-in-release CI gate | eng | done |
| WIRE-004 | Bare binary falls back to plaintext HTTP when TLS unconfigured (`server.go:415`); deploys are HTTPS-by-default but the binary fail-opens | OPEN | eng | Sprint 12 |
| SEC-003 | Provider/operator login (`ee/provider/handler.go`) sits outside the tenant-login rate limiter (U-024 covers tenant SSO only) | OPEN | eng | Sprint 9 |
| SEC-004 | OIDC nonce generated and sent but never validated on callback (`internal/control/auth.go:282`) | OPEN | eng | Sprint 9 |
| SEC-006 / OPS-003 | Default `probectl` password fallback in non-dev compose (`probectl.yml:26,79`); hardcoded creds in the backup overlay | OPEN | eng | Sprint 10 |
| SEC-007 | SSRF guard blocks only the exact unspecified address, not 0.0.0.0/8 (`ssrf.go:67`) | OPEN | eng | Sprint 10 |
| RED-003 / EBPF-001/002 | sslsniff TLS capture is host-wide once consented (no per-process allowlist); redaction is post-capture | OPEN — consent gate (C13) limits exposure today | eng | Sprint 18 |
| WIRE-006 | No application-layer replay/freshness protection on ingestion (mTLS limits the attacker to a compromised agent) | OPEN | eng | Sprint 12 |
| ARCH-002 / SEC-005 / TENANT-108 | ClickHouse reached via raw HTTP with string-escaped queries (`chStr`) — injection hardening is manual | OPEN | eng | Sprint 7 (driver + bound params) |
| TENANT-105 / TENANT-107 | Cross-tenant suite predated Sprint 4/5 — no ingest-path injection or query-scoping coverage; siloed-namespace routing untested | **CLOSED (Sprint 6)** — end-to-end ingest injection cases (flow→real CH; device + eBPF/endpoint via the RLS-scoped registry binding on real PG; OTLP token→sink), a predicate-free CH reader proving the row policy (not the app WHERE) scopes reads, and siloed records routing ONLY to namespaced topics + RED-006 fail-closed construction. Runs in the existing required `cross-tenant-isolation` job (no new plumbing) | eng | done |
| TENANT-102 | CH service account was policy-exempt — app compromise = cross-tenant read | **CLOSED (Sprint 5)** — opt-in per-request setting scoping + reader row policy (fail-closed when unset); split reader/writer documented (`docs/security/tenant-isolation.md`). Residual by design: the write/service account stays read-capable for ingest+migrations until the reader split is enabled | eng | done (operator-enabled) |
| CODE-002 | Ignored `json.Unmarshal` errors on ABAC/audit/store reads (`store/abac.go:27,30` is fail-open-ish under deny-override) | OPEN | eng | Sprint 2 (next) |
| CODE-006 | Committed test private key | **CLOSED (Sprint 1, 425143b)** — key deleted, runtime keygen via internal/crypto, gitleaks secret-scan gate | eng | done |
| SCALE-010 | `probectl.otlp.metrics` topic has no consumer — externally-ingested OTLP either drops or the topic is dead code | OPEN | eng | Sprint 16 |
| OPS-002 / COMPLY-002 | Backup artifacts unencrypted; tenant erasure attestation does not cover backups | OPEN | eng | Sprint 27 |
| COMPLY-003 | Residency is a reporting label for pooled tenants (honest per U-042); siloed/hybrid enforcement not yet implemented | OPEN | eng | Sprint 28 (scoped: enforce for siloed/hybrid, disclose for pooled) |

## Accepted risks (deliberate, ADR/decision-backed — re-justify, don't re-litigate)

| Decision | Rationale | Reference |
|---|---|---|
| StreamConfig RPC stays in the schema (explicit deny, no client stub) | Wire compatibility; removal = buf-breaking for zero capability gain; agent has no config-apply path | `docs/adr/config-push.md` (U-044) + Sprint 13 hardening |
| NetworkPolicy default keeps two documented holes; strict profile available | Default-deny `ingressFrom` locks out unknown ingress controllers; holes are loud + documented | U-086 + `values-strict.yaml` (Sprint 26) |
| Topology/detections rebuild on restart (no persistence) | They are caches of durable streams; cold-start tests prove rebuild; only silences/acks (operator inputs) get persisted | `docs/adr/volatile-stores.md` (U-047) + Sprint 16 |
| Isolation tests stay behind tags/skip-harness | They require live PG/CH; the CI job is required — coverage is enforced where it can run | Sprint 6 triage decision |
| cilium/ebpf pre-1.0 on the privileged path | De-facto standard; verifier is the safety boundary; kernel-matrix CI on every bump | `docs/dependency-policy.md` (U-081) |
| MCP stdio trusts the local invoking process (token verified at the binary entry) | Local-process transport; tenant + RBAC still enforced per call | verify + test in Sprint 9 |

## Structural risks (no sprint closes these)

| Risk | Mitigation |
|---|---|
| Solo founder bus factor | Verification net (~30 CI gates), documentation density, ADRs; not eliminated |
| Adoption metrics untested until public launch | PRD v1.0 §8 separates readiness (measurable now) from adoption (clock starts at launch) |
| Open-data/threat-intel AUPs for commercial resale | Tracked per source (`docs/opendata-aup.md`); counsel item before MSP channel opens |
