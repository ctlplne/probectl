# probectl threat model (U-033)

v1.0 — 2026-06-07. Versioned with the code; review on any change to a trust
boundary (CLAUDE.md §7 guardrails) and at each release. Evidence-linked: every
mitigation cites the code, CI gate, or document that enforces it; every known
gap cites its unified-register ID instead of pretending. Companion docs:
[agent-whitepaper.md](agent-whitepaper.md),
[incident-response.md](incident-response.md), `docs/hardening.md`,
`docs/isolation.md`, CLAUDE.md §7.

## 1. What we protect (assets)

| Asset | Why it matters | Where it lives |
|---|---|---|
| **Tenant telemetry** (flows, probe results, paths, device/BGP/L7 events) | The product's reason to exist; cross-tenant leakage is the declared highest-severity failure (CLAUDE.md §7.1) | Kafka (transit), ClickHouse, Postgres, TSDB, object store |
| **Tenant/config state** (tenants, RBAC, SSO config, SLOs, incidents) | Controls who sees what | Postgres (RLS) |
| **Audit chains** (tenant + provider streams) | The forensic record; targeted by any competent attacker | Postgres hash chains + signed WORM exports to object storage (U-041, `internal/audit/worm.go`) |
| **Secrets** (DB/bus creds, SNMP/API credentials, license keys) | Lateral-movement fuel | envelope encryption via `internal/crypto`; reference-based resolution (`internal/secrets`) |
| **The agent fleet** | Privileged (CAP_BPF) code on customer hosts; the scariest asset to lose | operator-managed hosts; no self-update by design |
| **AI prompts/evidence** | The one place tenant data may deliberately leave the network | air-gapped builtin by default; remote only behind three gates (`docs/ai-egress.md`) |
| **The supply chain** (source → CI → artifacts) | Compromise multiplies into every deployment | GitHub + signed releases (C6/U-006), pinned actions (U-007), digest-pinned images (U-061) |

## 2. Trust boundaries

```
[tenant user] --TLS/session--> [control plane] <--mTLS+SPIFFE--> [agents]
      |                          |       ^  ^                      (CAP_BPF hosts)
 [provider operator]             |       |  +--TLS/auth-- [OTLP/webhook senders]
  (separate domain,              v       |
   break-glass only)        [bus (Kafka, TLS)]--> [stores: PG(RLS)/CH(row policy)/TSDB]
                                 |
                            [AI adapter] --three-gated TLS--> (optional remote LLM)
                            [MCP server] --tenant-then-RBAC--> callers
```

B1 tenant↔tenant (inside every shared component) · B2 agent↔control plane ·
B3 ingest surfaces (bus, OTLP, webhooks) · B4 control plane↔stores ·
B5 operator/provider plane↔tenant data · B6 AI/MCP↔models and callers ·
B7 build/release↔deployments · B8 agent↔monitored host.

## 3. Attacker profiles

1. **External unauthenticated** — internet/intranet reach to exposed listeners.
2. **Malicious tenant** (the defining multi-tenant adversary) — valid
   credentials, hostile intent, aims at B1.
3. **On-path network attacker** — can intercept/inject between components.
4. **Compromised monitored host** — controls traffic the agent observes and
   the local libssl the L7 probe attaches to.
5. **Compromised agent node** — has the agent's identity and CAP_BPF.
6. **Malicious/compelled provider operator** — legitimate provider-plane
   access, wants silent tenant-data reach (B5).
7. **Supply-chain attacker** — targets deps, CI, artifacts (B7).
8. **Prompt-injection attacker** — plants payloads in telemetry that the AI
   layer will read (B6); needs no credentials at all.

## 4. STRIDE by boundary — mitigations (evidence) and gaps (register IDs)

### B1 — Tenant ↔ tenant (the outermost boundary)

| Threat (STRIDE) | Mitigation — evidence |
|---|---|
| Info disclosure: cross-tenant read | RLS at the storage layer (`internal/tenancy`, migrations); **cross-tenant-isolation CI job** runs the suite against real Postgres on every pass; ClickHouse: `tenant_id` partition keys + `ErrNoTenant` pre-flight refusals + DB-level row policies, gated against real CH (U-026, `internal/store/*/isolation_clickhouse_test.go`); TSDB tenant labels enforced at the query proxy — the upstream boundary refuses any unscoped forward (U-025, `internal/promapi/upstream.go`) |
| Tampering: writing into another tenant | tenant resolved at the edge and propagated API→bus→store; bus messages tenant-keyed; consumers stamp/verify (CLAUDE.md §6) |
| DoS: noisy neighbor | per-tenant fairness gate ahead of the pipeline (`internal/fairness`, S-T7); per-agent/per-tenant cardinality caps (U-017, `internal/pipeline/cardinality.go`); bounded async publish with counted shed (U-004, `internal/bus/kafka.go`); the noisy-neighbor SLO gate runs every CI pass at the documented 5ms floor (U-055, `internal/perf/scale.go`) |
| Elevation: tenant → other tenant via AI/MCP | tenant-first-then-RBAC in the AI/MCP query layer (CLAUDE.md §7.5); e2e tenancy assertion over the public API (U-054, `test/e2e`) |
| Repudiation | per-tenant tamper-evident audit chains; erasure produces store-by-store attestations (U-027, `internal/tenantlife`) |

### B2 — Agent ↔ control plane

| Threat | Mitigation — evidence |
|---|---|
| Spoofed agent / spoofed control plane | mTLS with SPIFFE-style tenant-bound identity (guardrail §7.4); **mandatory trust-domain pin** (U-011, C2) |
| Tampering in transit | TLS 1.2+/1.3 via `internal/crypto` hardened configs; no plaintext agent transport |
| Fleet takeover via updates | **No self-update channel exists** (preserved strength ST-04); upgrades are operator-driven waves of **signed artifacts** with registry verification and halt-on-error (U-031, `internal/agent/rollout.go`; C6 cosign) |
| Rogue agent floods | fairness + cardinality caps as B1; per-agent registry identity, skew-gated handshake (`internal/lifecycle/version.go`) |

### B3 — Ingest surfaces (bus, OTLP, webhooks)

| Threat | Mitigation — evidence |
|---|---|
| On-path read/inject | Kafka requires TLS unless explicitly dev-flagged; plaintext is *refused*, in code and at chart render (U-010 `internal/bus/security.go`; the agent chart fail-closes, U-016) |
| Spoofed OTLP/webhook senders | OTLP receiver: TLS-only, bearer-token→tenant auth, cross-tenant payloads rejected, payload treated as untrusted with bounded size (`internal/otel/otlp`, `docs/otlp.md`); webhooks HMAC-verified (guardrail §7.12) |
| Malformed/poison input | fuzz smoke on untrusted parsers every CI pass (`make fuzz-smoke`); malformed results dropped, never panic (CLAUDE.md §6); store-write failures retried then dead-lettered with the original bytes — counted, never silent (U-019) |
| SSRF via probe targets | canary/probe target guard (U-002/C1) |

### B4 — Control plane ↔ stores

| Threat | Mitigation — evidence |
|---|---|
| On-path DB read | `sslmode=require` defaults (U-006/B6); CH/TSDB TLS via https URLs + hardened client (U-036, `crypto.HardenedHTTPClient`) |
| Audit purge by DB owner | provider audit chain exported as Ed25519-**signed WORM segments** to object storage with continuous chain verification (U-041, `internal/audit/worm.go`) |
| Schema drift | sequential idempotent PG migrations + expand/contract CI gate; CH versioned migrations with checksummed ledger — an edited shipped version refuses (U-046, `internal/store/chmigrate`) |
| Crypto misuse | all primitives behind `internal/crypto` (FIPS-swappable); the crypto-import CI guard blocks direct primitive imports (guardrail §7.3) |

### B5 — Provider/operator plane ↔ tenant data

| Threat | Mitigation — evidence |
|---|---|
| Silent operator read of tenant telemetry | **no implicit read access**; break-glass is explicit, time-bounded, tenant-consented, and lands in a *separate* tamper-evident provider audit stream (guardrail §7.1/§7.7; `ee/provider` no-implicit-access suite) |
| Operator-side credential abuse | auth fail-closed by default (U-001); rate-limit + lockout + audit on auth (U-024/C3); `insecure_skip_verify` is admin-permission-gated and audited (U-040/C10) |
| Disgruntled-insider erasure | WORM export survives DB purge (B4); offboarding erasure is attested store-by-store (U-027) |

### B6 — AI / MCP

| Threat | Mitigation — evidence |
|---|---|
| Tenant data exfiltration via model | **air-gapped builtin by default**; remote egress requires three gates: boot-time operator ack env, per-tenant default-deny consent, and a per-call audit event recording the data categories that left (C7, `docs/ai-egress.md`) |
| PII leaving in prompts | C8 redaction pass before any remote prompt (`internal/ai/redact.go`): IPs/secrets masked, hostnames per policy |
| Prompt injection via telemetry | per-session random evidence IDs, structured delimiter framing with defanged escapes, fail-closed citation grounding — a fully injected answer degrades to insufficient-evidence; adversarial suite includes a deliberately compromised model double (U-037/D9, `internal/ai/rca.go`) |
| MCP caller over-reach | tenant-first-then-RBAC on every tool (guardrail §7.5) |
| Model-as-actor | detection is a signal, never an IPS; remediation observe-only/human-gated (guardrails §7.8–7.9) |

### B7 — Supply chain (build → release → deploy)

| Threat | Mitigation — evidence |
|---|---|
| Malicious dependency/action | every workflow action SHA-pinned + CI pin gate (U-007, `scripts/check_action_pins.sh`); scheduled vuln scans (U-069/C12, govulncheck/trivy); base images digest-pinned (U-061) |
| Tampered release artifact | cosign keyless signing of binaries + images, SPDX SBOMs (C6/C11, U-006; `docs/ops/verify-artifacts.md`); releases refuse on red CI (U-083) |
| Tampered BPF object at run time | SHA-256 manifest baked at build; loaders verify embedded bytes before any kernel load and **fail closed** (U-014, `internal/ebpf/integrity.go`) |
| Unsigned bits reaching the fleet | rollout planning *refuses* artifacts without recorded digest+method+verifier (U-031) |

### B8 — Agent ↔ monitored host

| Threat | Mitigation — evidence |
|---|---|
| Agent as enforcement/attack tool | observe-only is **CI-enforced**: the static gate forbids enforcing BPF program types (`internal/ebpf/observeonly_test.go`); programs additionally load+attach-tested on real LTS kernels (U-021, `ebpf-kernel-matrix` job) |
| Privilege escalation from the agent | minimal capability pair CAP_BPF+CAP_PERFMON, default-deny seccomp, read-only root, non-root systemd unit with ambient caps (U-052/U-016; `deploy/agent/`, `deploy/helm/probectl-agent`) |
| Sensitive payload capture | TLS-plaintext (L7) capture is **off by default** and requires explicit enable **plus** per-tenant consent naming the agent's tenant; bodies zeroed at the redaction boundary by default (U-003/C13, `internal/ebpf/l7policy.go`) |
| Host resource exhaustion | chart resource limits; ring-buffer drops are counted, never silent; overhead benchmarked with a CI tripwire (U-051, `docs/agent-overhead.md`) |

## 5. Known gaps (honest list — tracked, not hidden)

| Gap | Register ID / status |
|---|---|
| L/XL full-stack load numbers + SLO sign-off | U-005 — harness + CI smoke landed; reference-hardware run is human-scheduled |
| Multi-region RTO/RPO at representative scale | U-053 — CI drill continuous; representative run + sign-off pending |
| Reference-host agent overhead row (live ring buffer) | U-051 — userspace pipeline measured; live-host row pending |
| `LICENSE` is a TBD placeholder pending counsel | CLAUDE.md §2 — legal artifact, outside the codebase |
| Procurement/legal docs are drafts for counsel | Kept outside the public repo until counsel finalizes them |
| Anything newly filed | the unified diligence register is the single source of truth for open findings |

## 6. Review log

| Version | Date | Change | Reviewer |
|---|---|---|---|
| 1.0 | 2026-06-07 | Initial model; mitigations cross-checked against code/CI at commit time | maintainer (solo); external review welcome via SECURITY.md |
