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
| TENANT-101 / WIRE-001 | Bus-published planes trusted the agent-config `tenant_id` — cross-tenant injection on flow/device/eBPF/endpoint | **CLOSED (Sprint 4)** — consumers verify (tenant, agent) against the registry (fail closed, cached); namespaced lanes are the authoritative tenant; injection tests + fuzz in CI. Residual CLOSED by Sprint 11: agent ids now exist only via cryptographic enrollment (registry rows have issuance provenance), so the forged-pair window requires a stolen live SVID, bounded to 24h + revocable | eng | done |
| WIRE-002 / RED-002 / TENANT-103 / ARCH-004 | No in-repo agent enrollment / SVID issuance — the trust root was operator-manual | **CLOSED (Sprint 11)** — ADR founder-approved (docs/adr/agent-enrollment.md) then implemented: single-use tenant-scoped join tokens (hash-at-rest, atomic consume), repo-managed root→intermediate→leaf CA (root key offline-custody, intermediate sealed via tenantcrypto), 24h CSR-based SVIDs with the SPIFFE tenant claim set by the SERVER from the token, identity-pinned rotation at 2/3 TTL (chain + possession proof + serial provenance), admin API + CLI mint (audited), agent enroll CLI + auto-rotation, every serial recorded (feeds Sprint 12 revocation). Integration tests: happy path, replay, wrong-tenant impossibility, rotation, foreign-CA + bad-proof rejection | eng | done |
| LICENSE-001/002 / DATAROOM-001/002 | `LICENSE` is a TBD placeholder; no EE license text; no CLA/DCO; IP chain unproven for non-founder commits | OPEN — counsel decisions kick off now, commits land last | counsel | Phase L (S32–S33) |
| COMPLY-001 / DATAROOM-006 | No SOC 2 attestation (self-declared mapping only) — caps the headline diligence score regardless of code | OPEN — engage auditor now (6–12 mo) | auditor | S29 evidence pack + external attestation |
| SCALE-002 / DOCS-001 / DOCS-006 / OPS-007 | Numeric scale SLOs, agent overhead, and RTO/RPO are PROVISIONAL — harnesses/drills exist, no L/XL or representative run executed | OPEN | iron | Sprint 17 + Sprint 27 (runs, not builds) |

## Security residuals (open until their sprint)

| ID(s) | Risk | Status | Owner | Closes via |
|---|---|---|---|---|
| RED-001 / SEC-001 | Dev auth mode was runtime-selectable in every binary | **CLOSED (Sprint 3, c114a05)** — compiled out of release binaries (-tags devauth only), triple-gated (ack + loopback), no-devauth-in-release CI gate | eng | done |
| WIRE-003 / WIRE-004 / WIRE-005 / WIRE-007 | Revocation list never fed; plaintext HTTP fail-open; OTLP/MCP bespoke weak TLS; 1.2 floor fleet-wide | **CLOSED (Sprint 12)** — WIRE-003: `revoke-agent` CLI + audited admin API resolve serials/SPIFFE from the S11 registry, persist (migration 0042), push the live deny-list, boot-reload + 30s refresher; SPIFFE-dimension refuses re-issued certs; enrollment/rotation refuse revoked ids. WIRE-004: non-loopback plaintext REFUSES to start without `PROBECTL_ALLOW_PLAINTEXT_HTTP` (Helm sets it behind its TLS ingress). WIRE-005/007: one hardened config (`crypto.ServerTLSConfig`) for API/OTLP/MCP with a **TLS 1.3 floor** on every probectl↔probectl endpoint (outbound probe clients stay 1.2 for third-party interop, allowlisted + documented); `unified-TLS` lint gate bans bespoke `tls.Config` literals | eng | done |
| SEC-003 | Provider/operator login sat outside the tenant-login rate limiter | **CLOSED (Sprint 9)** — per-account + per-IP throttle with exponential lockout on the provider login (reuses the U-024 `auth.Limiter`), 429 + Retry-After, lockouts audited to the provider stream; tests incl. account-rotation-per-IP | eng | done |
| SEC-004 | OIDC nonce generated and sent but never validated on callback | **CLOSED (Sprint 9)** — nonce stored in a transient cookie at login; the ID token's nonce claim must match on callback (missing cookie or mismatch = 401, fail closed); mismatch + missing-cookie + happy-path tests | eng | done |
| SEC-006 / OPS-003 | Default `probectl` password fallback in non-dev compose; hardcoded creds in the DR overlay | **CLOSED (Sprint 10)** — `${POSTGRES_PASSWORD:?}` required-var syntax: the stack REFUSES to start without an operator-set secret; DR drill reuses the same env ref; `.env.example` ships an empty value with generation instructions | eng | done |
| SEC-007 | SSRF guard blocked only the exact unspecified address, not 0.0.0.0/8 | **CLOSED (Sprint 10)** — full 0.0.0.0/8 denied (the Linux this-network→localhost quirk), incl. v4-mapped smuggles; per-range table tests for every blocked class (loopback, RFC1918, ULA, link-local/metadata, CGNAT, multicast, broadcast) | eng | done |
| RED-003 / EBPF-001/002 | sslsniff TLS capture is host-wide once consented (no per-process allowlist); redaction is post-capture | OPEN — consent gate (C13) limits exposure today | eng | Sprint 18 |
| WIRE-006 / RED-008 | No app-layer replay/freshness on ingestion; probe `ca_file` read arbitrary agent paths | **CLOSED (Sprint 12)** — results streams carry a timestamp+nonce envelope inside the mTLS channel: stale (±10m) or replayed (per-agent nonce cache, bounded, no eviction-by-flooding) stream opens are refused fail-closed; store-and-forward intact (the window bounds the ENVELOPE, not result timestamps). `ca_file` is contained to the operator-allowlisted dir (`tls.canary_ca_dir`; symlink+traversal-proof; unset = refused) | eng | done |
| ARCH-002 / SEC-005 / TENANT-108 | ClickHouse reached via raw HTTP with string-escaped queries (`chStr`) — injection hardening was manual | **CLOSED (Sprint 7)** — every CH value is a SERVER-BOUND parameter ({name:Type} + param_*, ClickHouse's native HTTP binding); `chStr`/`chTime`/`sqlStr` deleted; DDL identifiers regex-validated (`chValidUser`), fail closed; injection tests (unit + real-CH) + the `no-stringbuilt-sql` lint gate. FOUNDER DECISION: binding over the existing HTTP transport instead of adopting clickhouse-go/v2 — same security property, no new dependency tree, §4 architecture (breaker/silo-router/TLS) intact | eng | done |
| SEC-002 / COMPLY-004 | Keyless plaintext passthrough was the compose default; bulk-store encryption duty undocumented | **CLOSED (Sprint 8)** — at-rest sealing ON by default (generated-or-required key file on the `controldata` volume + `REQUIRE_AT_REST_ENCRYPTION=true` in compose/Helm, fail-closed); operator duty documented (`docs/hardening.md` §0c) with `probectl-control preflight --strict` detecting unencrypted backing mounts (+ attestation env for cloud volumes) | eng | done |
| SEC-008 / SEC-009 / RED-007 | SCIM errors echoed internals; /openapi.json + /version open; cookie Secure tied to the app listener; MCP stdio auth unverified | **CLOSED (Sprint 9/10)** — SCIM store errors generic (details server-side); /openapi.json auth-gated + /version detail-stripped outside dev; `PROBECTL_PUBLIC_TLS` drives Secure at the deployment edge (Helm sets it); RED-007 VERIFIED: mcp-stdio authenticates before serving, pinned by test, local-trust model in docs/mcp.md | eng | done |
| OPS-010 | CI talked plaintext to Postgres (sslmode=disable fixtures) | **CLOSED (Sprint 10)** — every DB-backed CI job starts Postgres with TLS under a per-run test CA and connects `sslmode=verify-full` (`scripts/ci_pg_tls.sh`); local-dev fallbacks documented in docs/development.md | eng | done |
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
