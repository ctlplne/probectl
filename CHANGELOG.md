# Changelog

All notable changes, grouped from [Conventional
Commits](https://www.conventionalcommits.org/) by
`scripts/release_notes.sh` (U-087). GitHub release bodies are
auto-generated at tag time (`release.yml`); prepend the script's output
here when cutting a release. Diligence-register IDs (U-xxx) in entries
link work to findings.

## Unreleased — second-audit remediation (post-triage plan)

- Sprint 12: transport security (WIRE-003/004/005/006/007, RED-008).
  Revocation is now FED, not just checked: `probectl-control
  revoke-agent` + the audited admin API resolve an agent's issued
  serials + SPIFFE id from the Sprint 11 registry, persist the
  revocation (survives restarts), push the live handshake deny-list,
  and a 30s refresher converges CLI-side revocations; the SPIFFE
  dimension refuses even re-issued certs, and enrollment/rotation
  refuse revoked identities (no resurrection). TLS is mandatory for
  the control API: a non-loopback plaintext listener refuses to start
  without the explicit PROBECTL_ALLOW_PLAINTEXT_HTTP opt-in (the Helm
  chart sets it — plaintext only behind its TLS-terminating ingress).
  One hardened TLS config now serves every probectl listener (API,
  OTLP, MCP — the bespoke weak config in main is gone) with a TLS 1.3
  floor across all probectl↔probectl endpoints (agent mTLS, enrollment
  client included); outbound probe clients (canary HTTP/DNS, gNMI)
  deliberately keep 1.2 for third-party interop, allowlisted in the
  new `unified-TLS` lint gate that fails the build on any bespoke
  tls.Config literal. Ingestion gains app-layer replay/freshness
  protection: results streams carry a timestamp+nonce envelope inside
  the authenticated channel — stale or replayed envelopes are refused
  (bounded per-agent nonce cache that refuses rather than evicts under
  flood), while store-and-forward of buffered results stays intact.
  Probe ca_file parameters are contained to an operator-allowlisted
  directory (traversal- and symlink-escape-proof; refused entirely
  when unconfigured). Also restores the no-stringbuilt-sql gate wiring
  in make lint-go (lost to an external edit after Sprint 7).

- Sprint 11: agent enrollment & SVID issuance — the trust root is now
  repo-managed (WIRE-002, RED-002, TENANT-103, ARCH-004; ADR
  founder-approved before code, docs/adr/agent-enrollment.md). One-time
  tenant-scoped join tokens (hash-at-rest, atomic single-use consume,
  1h expiry, revocable) bootstrap CSR-based issuance of 24h SPIFFE
  SVIDs from a root→intermediate→leaf hierarchy: the root key is shown
  once at `agent-ca init` for offline custody and never persisted; the
  issuing intermediate is sealed at rest via tenantcrypto. The SERVER
  sets the SPIFFE tenant claim from the TOKEN — an agent cannot request
  a tenant. Rotation proves the current identity (chain to our
  hierarchy + key-possession signature over the new CSR + issued-serial
  provenance) and can never change it; the agent runtime auto-rotates
  at 2/3 lifetime with hot-reloaded mTLS material (no restart). Mint
  surfaces: POST /v1/agents/enroll-tokens (admin RBAC, audited) +
  `probectl-control enroll-token`; bootstrap surface mounts OFF /v1
  (`/enroll/agent[/rotate]`), per-IP throttled, with `--ca-pin`
  first-contact server authentication (mismatch refuses, no TOFU). The
  Sprint 4 tenant binding now vouches for repo-issued identities only;
  every serial is recorded for Sprint 12 revocation feeding.
  Integration tests: happy path, replay rejection, wrong-tenant
  impossibility (incl. cross-tenant registry invisibility), rotation,
  foreign-CA + bad-proof rejection; client tests: pin mismatch, 0600
  identity dir, rotation-due policy; docs/agent/enrollment.md.

- Sprint 10: residual hardening (SEC-006/007/008, OPS-003/010). SSRF
  guard denies the full 0.0.0.0/8 "this network" block (Linux routes
  0.x.y.z to localhost) incl. v4-mapped smuggles, with per-range table
  tests across every blocked class. Non-dev compose REQUIRES
  operator-set secrets (`${POSTGRES_PASSWORD:?}` — refuses to start
  unset; DR overlay reuses the env ref; .env.example ships empty).
  SCIM store errors return generic text (details logged server-side);
  /openapi.json is auth-gated and /version strips build detail for
  anonymous callers outside dev mode. CI now talks TLS to Postgres:
  every DB-backed job starts it under a per-run test CA and connects
  sslmode=verify-full (scripts/ci_pg_tls.sh); local-dev fallbacks
  documented.

- Sprint 9: auth/session/transport hardening (SEC-003/004/009,
  RED-007). The provider/operator login — the highest-privilege login
  — gets the U-024 brute-force brake: per-account + per-IP throttle,
  exponential lockout, 429 + Retry-After, lockouts audited to the
  provider stream. OIDC nonce is now ENFORCED on callback: minted at
  login into a transient cookie, compared against the verified ID
  token's nonce claim, fail closed on mismatch or missing cookie.
  Cookie Secure follows the DEPLOYMENT EDGE (PROBECTL_PUBLIC_TLS; the
  Helm chart sets it — cookies were previously not-Secure behind the
  TLS-terminating ingress). RED-007 verified: mcp-stdio authenticates
  PROBECTL_MCP_TOKEN before serving anything (pinned by test); the
  stdio local-trust model is documented in docs/mcp.md.

- Sprint 8: at-rest encryption is the shipped default (SEC-002,
  COMPLY-004). PROBECTL_ENVELOPE_KEY_FILE loads — or GENERATES and
  persists (0600) on first boot — the deployment KEK; compose points it
  at the new controldata volume with REQUIRE_AT_REST_ENCRYPTION=true
  (fail-closed, TENANT-106), Helm already hard-requires a key and now
  sets the require flag too. An explicit PROBECTL_ENVELOPE_KEY
  (KMS/secret-manager injected) always wins. The operator's duty to
  encrypt the BULK telemetry volumes (Postgres/ClickHouse/object store)
  is now a documented contract (docs/hardening.md §0c) enforced by the
  new `probectl-control preflight [--strict]`: it inspects the mounts
  backing the data paths, warns on undetectably-encrypted devices
  (strict = exit 1), and accepts a logged operator attestation for
  cloud-volume encryption invisible from inside a container.

- Sprint 7: ClickHouse queries are parameterized — every VALUE travels
  as a server-bound parameter ({name:Type} placeholder + param_* HTTP
  parameter, ClickHouse's native binding) instead of being escaped into
  the SQL text (ARCH-002, SEC-005, TENANT-108). The hand-rolled
  escaping helpers (chStr/chTime/sqlStr) are deleted across flowstore,
  pathstore, and the chmigrate ledger; tenant scoping is a bound
  parameter everywhere; DDL identifiers (CH users, table names) are
  regex-validated fail-closed since identifiers cannot be bound.
  Injection tests at three depths: SQL-builder unit tests (the raw
  value never appears in SQL), transport tests (param_* carries it),
  and a real-ClickHouse isolation case (a DROP-shaped tenant id selects
  nothing and breaks nothing). New `no-stringbuilt-sql` gate in make
  lint-go (self-testing) fails the build on reintroduced string-built
  CH SQL. FOUNDER DECISION: binding over the existing HTTP transport
  rather than adopting clickhouse-go/v2 — identical security property
  with no new dependency tree and the §4 architecture (breaker,
  silo router, TLS posture) intact.

- Sprint 6: cross-tenant isolation suite extended to the new ingest +
  query guarantees, end to end (TENANT-105 / TENANT-107). Ingest-path
  injection cases for every surface — flow (through real ClickHouse),
  device and eBPF/endpoint results (through the real, RLS-scoped
  registry binding on Postgres), and OTLP (token→tenant, capture sink):
  a client presenting tenant A's identity with payload tenant B is
  re-stamped to A or rejected and never lands in B's partition. The
  registry lookup that vouches for a (tenant, agent) pair is itself
  proven RLS-scoped (it cannot see another tenant's agent). Query-path:
  a non-service ClickHouse reader issuing a PREDICATE-FREE read sees only
  its own tenant's rows (the DB row policy, not the app WHERE, scopes it),
  with the Sprint 5 getSetting reader policy exercised where the server
  allows the custom-settings prefix. Siloed-namespace: a siloed tenant's
  records route ONLY to its namespaced topic — the shared topic never
  carries them — and a malformed namespace refuses construction
  (RED-006). The infra-bound cases run in the existing required
  cross-tenant-isolation CI job (no new plumbing); the silo-routing and
  OTLP cases need no infra and run in the normal suite too.

- Sprint 5: database-level tenant-isolation backstops. (TENANT-104)
  tenancy.AssertIsolationPosture runs at boot and FATALs if the app
  role is super/bypass-RLS or any tenant_id table lacks FORCE ROW
  LEVEL SECURITY — RLS-silently-off can no longer serve traffic;
  isolation suite proves it passes on a migrated DB and rejects an
  unforced table (non-vacuous). (TENANT-102) opt-in ClickHouse
  query-path scoping: tenant-scoped reads attach a per-request
  SQL_probectl_tenant custom setting and EnsureReaderRowPolicy binds a
  dedicated reader user's SELECTs to it (fail-closed when unset), so
  the pooled service account can be removed from the read path; the
  full threat model incl. the residual is in
  docs/security/tenant-isolation.md. (TENANT-106)
  PROBECTL_REQUIRE_AT_REST_ENCRYPTION makes keyless passthrough a fatal
  startup error instead of silent plaintext. All knobs default off
  (keyless dev still boots); enable in the hardened profiles.

- Sprint 4 [CRITICAL]: server-side tenant binding on ingest — the
  payload tenant_id is never authoritative again. Every bus-consumed
  plane (flow, device, eBPF-derived views, endpoint results, cost/
  compliance/topology views) verifies the claimed (tenant, agent) pair
  against the agents registry (RLS-scoped lookup, TTL-cached, FAIL
  CLOSED on mismatch/unknown/outage) and rejects mixed-identity
  batches; tenant-namespaced lanes are the authoritative tenant and
  overwrite payload disagreement (counted, logged). Emitters
  (flow/device/eBPF/endpoint) publish to their tenant's siloed lane
  when configured (PROBECTL_<PLANE>_BUS_NAMESPACE) and REFUSE START on
  a malformed namespace; bus.TopicFor now errors instead of silently
  falling back to the shared lane, and the results/RUM publishers drop
  (loudly) when silo routing is unavailable (TENANT-101, WIRE-001,
  TENANT-107, RED-006). Injection table tests + an end-to-end red-team
  test + FuzzVerifyBatchTenant guard it.

- Sprint 3 [CRITICAL]: the dev-mode auth bypass is COMPILED OUT of
  release binaries — the dev principal exists only behind -tags devauth
  (internal/control/devauth.go); release binaries refuse
  PROBECTL_AUTH_MODE=dev at boot, and even tagged builds require
  PROBECTL_DEV_AUTH_ACK=i-understand plus a loopback-only bind. Active
  dev auth logs at error level and writes an auth.dev_mode_active audit
  event. New required CI gate no-devauth-in-release verifies symbol +
  literal absence on the release binary, self-tests against a tagged
  build, and runs the behavioral boot refusal (RED-001, SEC-001;
  lineage U-001).

- Sprint 1: CI is a proven merge gate — committed branch ruleset
  (.github/rulesets/main.json) + CODEOWNERS + a verify-branch-protection
  job that fails on live-vs-committed drift (TEST-002, SUPPLY-007,
  CODE-007); the committed OIDC test key is gone — the mock IdP
  generates its key at test setup — and a pinned gitleaks secret-scan
  job gates every push/PR (CODE-006); coverage/test/scan outputs are
  retained as 90-day workflow artifacts with a PR coverage comment,
  documented in docs/quality/coverage.md (TEST-008, DATAROOM-005,
  DATAROOM-011); .gitignore asserted + docs/dev/repo-hygiene.md
  (CODE-003, triaged to gitignore-assert only).

- Sprint 0: observe-only denylist hardened — `bpf_probe_write_user` + the
  full state-mutating helper families forbidden (EBPF-006); known-risks
  register + finding-ID reconciliation map committed under
  `docs/diligence/` alongside the triaged sprint plan (DATAROOM-010
  pre-pay; triage verdicts in `docs/diligence/SPRINT-PLAN-TRIAGE.md`).

## [Unreleased]

<!-- generated by scripts/release_notes.sh v0.4.0..HEAD -->
### Features

- feat(ops): timed failover drill — promote-the-standby RTO/RPO measured in CI (U-053)
- feat(ebpf): agent overhead benchmark suite + regression tripwire (U-051)
- feat(agent): staged fleet rollout — waves, registry verification, halt-on-error (U-031)
- feat(deploy): agent DaemonSet chart + VM installer — privileges declared in the artifact (U-016)
- feat(ops): backup/restore tooling, runbook, and a CI-executed drill (U-030)
- feat(perf): full-stack L/XL load gate — harness + S-tier CI smoke (U-005)
- feat(store): versioned ClickHouse migrations with a server-side ledger (U-046)
- feat(deploy): seccomp + capability-drop profile for the eBPF agent (U-052)
- feat(ai): prompt-injection hardening — random evidence ids, structured quoting, fail-closed citations (U-037)
- feat(audit): signed WORM export + chain-verification job for the provider stream (U-041)
- feat(lifecycle): erasure covers pathstore + topology; prometheus series automated (U-027)
- feat(promapi): upstream boundary refuses unscoped queries; deployment restriction documented (U-025)
- feat(store): ClickHouse tenancy enforcement + CH cross-tenant CI gate (U-026)
- feat(tsdb): retention window + byte-wall eviction for the in-memory TSDB (U-018)
- feat(pipeline): per-agent + per-tenant series cardinality caps at ingest (U-017)
- feat(pipeline): bounded retry + dead-letter topic for store write failures (U-019)
- feat(ebpf): TLS-plaintext capture default-OFF, per-tenant consent, boundary redaction (U-003)
- feat(control): gate canary insecure_skip_verify behind admin permission + audit (U-040)
- feat(ebpf): verify BPF object digests before kernel load; tamper refuses (U-014)
- feat(ai): PII redaction pass before remote-model prompts (U-013)
- feat(ai): remote-model egress requires operator ack + per-tenant consent; every call audited (U-013)
- feat(bus): TLS + SASL for the Kafka hop; plaintext refused without explicit dev flag (U-010)
- feat(canary): SSRF denylist for probe targets, dial-time rebind guard, audited override (U-002)
- feat(auth): rate limiting + exponential lockout on auth endpoints (U-024)
- feat(control): strict CSP + X-Frame-Options on every UI/API response (U-023)

### Fixes

- fix(helm): drop duplicate Ingress TLS-redirect annotations (U-016 gate catch)
- fix(perf): full-stack gate provisions its results topic (U-005)
- fix(ops): make the ClickHouse backups volume writable by the server (U-030)
- fix(ebpf): arch_compat.h comment contained */ — the shim never parsed
- fix(ebpf): arm64 uprobe leg needs the UAPI register file (arch_compat.h)
- fix(perf): restore the documented 5ms materiality floor in CI (U-055)
- fix(ebpf): compile sslsniff per-arch — uprobes need a register layout
- fix(build): bpf2go requires -go-package outside go generate (U-021)
- fix(ebpf): route BPF object hashing through internal/crypto (guardrail 3)
- fix(tsdb): hardened TLS client for remote-write; ratchet bans new bare http.Client (U-036)
- fix(crypto): pin the SPIFFE trust domain on every mTLS verify path (U-011)
- fix(supply): bump playwright 1.49.1 -> 1.55.1 (CVE-2025-59288)
- fix(remediation): log the audit-write failure; ban construct-then-discard errors (U-058)
- fix(ebpf): multi-arch libssl discovery; loud WARN + metric when TLS uprobes fail (U-015)
- fix(deploy): Postgres sslmode=require by default; compose PG serves TLS (U-039)
- fix(supply): patch vitest GHSA-5xrq-8626-4rwp; lock browser-worker deps (U-028, U-029)
- fix(auth)!: default PROBECTL_AUTH_MODE to session — fail closed (U-001)

### Performance

- perf(bus): async batched publish with bounded buffer + shed policy (U-004)

### Security & CI

- ci(ebpf): run the in-VM smoke as root (vimto -sudo)
- ci(ebpf): vimto itself must be statically linked
- ci(ebpf): build the kernel-matrix test binary statically (CGO_ENABLED=0)
- ci(ebpf): vimto requires the exec subcommand
- ci(ebpf): call the bpftool binary directly; drop the go-get mutation
- ci(isolation): real ClickHouse credentials + buf-breaking PR baseline
- ci(ebpf): kernel-matrix job loads + attaches BPF programs on 2 LTS kernels (U-021)
- ci(security): scheduled CVE scanning with artifacted evidence (U-069)
- build(supply): digest-pin all third-party images; publish signed SPDX SBOM per release (U-061, U-068)
- ci(release): cosign keyless signatures for all release binaries + checksums (U-006)
- ci(proto): make buf breaking gate blocking; document exception process (U-056)
- ci(release): gate tags on green ci; document branch protection (U-022, U-083)
- ci(supply): SHA-pin every GitHub Action + pin lint + dependabot (U-007)

### Tests

- test(e2e): first real black-box full-stack e2e + nightly job (U-054)
- test(perf): make the full-stack load gate self-diagnosing (U-005)
- test(pathstore): cover the tenancy paths against a fake ClickHouse
- test(coverage): exempt the ebpf/gendigests generator from the floor
- test(chaos): self-test probes adopt the SSRF-guard override (U-002)
- test(ebpf): exercise discoverLibsslDefault — fixes lint 'unused' (U-015)

### Documentation

- docs(security): incident response plan, linked from SECURITY.md (U-066)
- docs(compliance): procurement pack — DPA template, subprocessors, SOC 2 mapping (U-065)
- docs(security): standalone agent security whitepaper (U-034)
- docs(security): threat model — assets, boundaries, STRIDE, evidence-linked (U-033)
- docs(otlp): scope the OTel-native claim to metrics + conventions; roadmap traces/logs (U-020)
- docs: truthfulness pass — FIPS cert cited, AI + eBPF defaults disclosed (U-035, U-070, U-071)
- docs(audit): verify pooled-tenant residency + at-rest encryption claims
- docs(audit): re-verify D-001 with independent eBPF capture-path trace
- docs(audit): adjudicate eBPF capture redaction dispute (D-001)

### Maintenance

- style(pathstore): apply De Morgan in the migration-order assertion
- style(lint): goimports grouping, no builtin shadowing, drop dead test double
- style(pipeline): rename PipelineStats to ConsumerStats (revive no-stutter)
- style(canary): blank unused params in the DialControl chain test (revive)
- style(control): drop redundant apiHandler conversions on throttled auth routes


## [v0.4.0] - 2026-06-06

<!-- generated by scripts/release_notes.sh v0.3.0..v0.4.0 -->
### Features

- feat(remediation): guarded agentic remediation — proposal-only, human-gated [S-EE5, F44]
- feat(support): supportability — secret-stripped bundle + deep health + self-monitoring [S-EE4, F35]
- feat(govern): advanced data governance — classification + redaction + composed view [S-EE3, F34]
- feat(cluster): multi-region / active-active HA with split-brain fencing [S-EE2, F33]
- feat(crypto): FIPS 140-3 build variant + power-on self-test + hardening guides [S-EE1, F32]
- feat(fairness): per-tenant fairness / noisy-neighbor isolation [S-T7, F57]
- feat(tenantkeys): per-tenant key isolation / BYOK with crypto-offboarding [S-T6, F56]
- feat(tenantlife): per-tenant export, retention & verifiable deletion [S-T5, F55]
- feat(whitelabel): per-tenant branding as S8a token overrides [S-T4, F54]
- feat(billing): per-tenant metering, usage export, quotas, showback [S-T3, F53]
- feat(silo): siloed/hybrid isolation — per-tenant schema/CH-db/bus-lane/object-ns [S-T2, F52]
- feat(provider): the provider/management plane — lifecycle, fleet, break-glass [S-T1, F51]
- feat(editions): ee/ boundary, offline Ed25519 license, Admin Editions [S-T0, F-editions]

### Fixes

- fix(perf): make noisy-neighbor inflation gate CI-aware (kill the scale-gate flake)
- fix(fairness): integration-tag build + async-poll race in CI
- fix(audit): scope provider-chain verification in shared-database tests
- fix(tenantlife): per-table erase transactions, provider grants, lint + coverage [S-T5]
- fix(silo): drop the leading blank line in the attachEE body [S-T2]

### Tests

- test(billing): pin the metering fixture clock to avoid a midnight-boundary flake
- test(flow): make TestCollectorEndToEnd robust to UDP worker reordering

### Documentation

- docs(readme): expand with why / what / how for beginners and experts
- docs: apply branded dark mermaid theme across all diagrams; drop banner subline
- docs: refresh README + convert remaining ASCII diagrams to mermaid

### Maintenance

- style(govern): fix misspell lint in S-EE3 (honour/categorised, strat->strategy)
- style(cluster): fix misspell lint (labelled -> labeled)


## [v0.3.0] - 2026-06-05

<!-- generated by scripts/release_notes.sh v0.2.1..v0.3.0 -->
### Features

- feat(scale): chaos self-test, carbon estimates, the L/XL scale gate [S48, F47, F48]
- feat(canary): RTP voice test — MOS (ITU-T E-model), jitter, loss [S47c, F21]
- feat(rum): RUM convergence — privacy-first beacon + synthetic correlation [S47b, F20]
- feat(outage): collective internet-outage view — open-data feeds + vantage correlation [S47a, F19]
- feat(compliance): segmentation validation + audit-grade evidence [S46, F43]
- feat(slo): OpenSLO SLI/SLO engine, error budgets + multi-window burn alerts [S45, F42]
- feat(cost): FinOps egress-cost attribution, chatty-AZ detection, budgets + showback [S44, F41]
- feat(topology): full dependency graph + what-if simulation + indexed engine [S43, F40]
- feat(threat): NDR-lite behavioral detection engine [S42, F37]
- feat(secrets): secret-backend integration + trustctl rotating identities [S41, F31]
- feat(web): frontend-coverage gate — capability→surface registry + CI enforcement [S-FE6]
- feat(web): synthetic result views completeness — per-type detail for ICMP/TCP/UDP/DNS/HTTP [S-FE5]
- feat(web): endpoint & last-mile / WiFi DEM surface — fleet, attribution, privacy-respecting [S-FE4]
- feat(web): threat-intel/IOC triage surface — detections, provenance, incident pivot [S-FE3]
- feat(web): TLS/certificate posture surface — inventory, expiry worklist, certctl handoff [S-FE2]
- feat(web): alerting management surface — active alerts + silence/ack + rule config [S-FE1]
- feat(integrations): Grafana datasource API + Prometheus federation/remote-write + ServiceNow CMDB correlation [S40, F30]

### Fixes

- fix(lint): rename min shadow in outage test helper [S47a]
- fix(control): attach SLO + compliance engines to the API server [S45, S46]
- fix(lint): rename min shadow in slo engine; use struct conversion in compliance validator [S45, S46]
- fix(secrets): route test RSA keygen through internal/crypto [S41, F31]
- fix(secrets): resolve golangci-lint findings [S41, F31]
- fix(lint): endpoint.EndpointView -> endpoint.View; unused ctx params [S-FE4, S-FE5]
- fix(lint): rename device.DeviceConfig -> device.Target; use String() in redaction test [S39, F18]

### Maintenance

- chore: rebrand certctl sibling product to trustctl


## [v0.2.1] - 2026-06-04

<!-- generated by scripts/release_notes.sh v0.2.0..v0.2.1 -->
### Features

- feat(device): SNMP v2c/v3 poller + gNMI/OpenConfig streaming -> DeviceMetric [S39, F18]
- feat(flow): NetFlow v5/v9 + IPFIX + sFlow collectors -> ClickHouse analytics [S38, F17]

### Fixes

- fix(ci): S38 test lint cleanups + crasher-aware fuzz-smoke [S38, F17]

### Maintenance

- chore(proto): regenerate descriptors canonically via buf — fixes CI proto gate
- chore(rebrand): rename netctl -> probectl across the entire repo


## [v0.2.0] - 2026-06-03

<!-- generated by scripts/release_notes.sh v0.1.0..v0.2.0 -->
### Features

- feat(pipeline): consume endpoint DEM results into the TSDB [S37, F16]
- feat(endpoint): cross-OS endpoint agent + last-mile/WiFi DEM [S37, F16, F46]
- feat(browser): browser/transaction synthetic — scripted DEM fleet [S36, F15]
- feat(deploy): IaC + GitOps + Helm hardening [S35, F29]
- feat(lifecycle): zero-downtime upgrades — migration gate, version skew, drain [S34, F28]
- feat(notify): on-call + ITSM integration — page, ticket, bidirectional sync [S33, F27]
- feat(siem): SIEM export — audit + threat signals to the SOC [S32, F26]
- feat(identity): SCIM 2.0 provisioning + ABAC over RBAC + directory integration [S31, F25]
- feat(change): change intelligence + change-to-incident correlation [S29, F39]
- feat(threat): threat-intel enrichment — IOC feeds, scoring, attribution [S28, F38]
- feat(threat): TLS/certificate observability from captured TLS [S27, F36]
- feat(ai): AI test authoring + auto-discovery — propose, don't auto-apply [S26, F45]
- feat(mcp): RBAC-scoped MCP server — read tools over stdio + HTTP [S25, F14]
- feat(web): AI surface PR2 — interactive evidence reading + richer feedback [S24, F13]
- feat(ai): AI RCA + NL query — cited, RBAC-scoped, sovereign-capable [S24, F13]
- feat(ai): unified semantic query layer — tenant-first then RBAC [S23, M9]
- feat(topology): S30 topology graph foundation — versioned, tenant-scoped, traversable [S30, F40]
- feat(otel): S22 OTLP exposure + OBI — TLS-only, authenticated, tenant-scoped receiver + exporter [S22, F12]
- feat(ebpf): S21 eBPF L7 visibility — HTTP/1.1+2, gRPC, DNS, Kafka via TLS uprobes [S21, F11]
- feat(ebpf): S20 eBPF host agent — L3/L4 flows + service map (observe-only) [S20, F11]

### Fixes

- fix(browser-worker): smoke app must send Content-Type: text/html [S36, F15]
- fix(ai): rank reachability verbs over web hints in NL authoring; fix MCP test perms
- fix(compose): bind KRaft controller to a routable address (KAFKA-18281) [S5]

### Security & CI

- build: pin Go toolchain to go1.26.4 for stdlib CVE fixes [govulncheck]

### Tests

- test(config): cover NETCTL_NOTIFY_* parsers [S33, F27]
- test(control): isolate AI/MCP integration tests in fresh tenants [S24, S25]

### Documentation

- docs(ebpf): S19a eBPF feasibility spike — coverage matrix, overhead, go/no-go [S19a, F11]


## [v0.1.0] - 2026-06-01

<!-- generated by scripts/release_notes.sh v0.1..v0.1.0 -->
