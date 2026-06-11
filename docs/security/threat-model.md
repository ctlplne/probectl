# probectl threat model

This is the system-wide **threat model** — the security design written from the
attacker's side of the table: what probectl protects, who might attack it, and —
boundary by boundary — what stops them and what honestly does not yet. It is
versioned with the code and should be reviewed on any change to a trust boundary
and at each release. Every mitigation cites the code, CI gate, or document that
enforces it, so you can verify rather than trust.

Companion docs: [agent-whitepaper.md](agent-whitepaper.md) (the agent in depth),
[incident-response.md](incident-response.md) (what happens when something breaks),
[../hardening.md](../hardening.md), [../isolation.md](../isolation.md), and the
project [non-negotiables](../../CONTRIBUTING.md).

## 1. What we protect (assets)

| Asset | Why it matters | Where it lives |
|---|---|---|
| **Tenant telemetry** (flows, probe results, paths, device/BGP/L7 events) | The product's reason to exist; cross-tenant leakage is the declared highest-severity failure | Kafka (transit), ClickHouse, Postgres, TSDB, object store |
| **Tenant / config state** (tenants, RBAC, SSO config, SLOs, incidents) | Controls who sees what | Postgres (RLS) |
| **Audit chains** (tenant + provider streams) | The forensic record; targeted by any competent attacker | Postgres hash chains + signed WORM exports to object storage (`internal/audit/worm.go`) |
| **Secrets** (DB/bus creds, SNMP/API credentials, license keys) | Lateral-movement fuel | envelope encryption via `internal/crypto`; reference-based resolution (`internal/secrets`) |
| **The agent fleet** | Privileged (`CAP_BPF`) code on customer hosts — the scariest asset to lose | operator-managed hosts; no self-update by design |
| **AI prompts / evidence** | The one place tenant data may *deliberately* leave the network | air-gapped built-in model by default (air-gapped — needs no network egress at all); remote only behind three gates ([../ai-egress.md](../ai-egress.md)) |
| **The supply chain** (source → CI → artifacts) | A compromise here multiplies into every deployment | GitHub + cosign-signed releases, SHA-pinned CI actions, digest-pinned base images |

## 2. Trust boundaries

A **trust boundary** is a line in the architecture where the level of trust
changes — whatever crosses it must be authenticated, tenant-scoped, and treated
as possibly hostile, because the thing on the other side may lie. The diagram
is a map of border crossings: B1–B8 name the checkpoints, and §4 inspects each
one.

```text
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

**STRIDE** is the standard checklist of ways a system can be attacked:
**S**poofing (pretending to be someone else), **T**ampering (altering data or
traffic), **R**epudiation (denying an action because no trustworthy record
exists), **I**nformation disclosure (reading what you shouldn't),
**D**enial of service (making it unavailable), and **E**levation of privilege
(gaining power you weren't granted). Each boundary below lists the STRIDE
threats that apply to it and the code or CI gate that answers each one.

### B1 — Tenant ↔ tenant (the outermost boundary)

This is the boundary that matters most: a malicious tenant with valid credentials
trying to reach another tenant's data. The full storage-layer mechanism is in
[tenant-isolation.md](tenant-isolation.md); the summary by threat:

| Threat (STRIDE) | Mitigation — evidence |
|---|---|
| **Info disclosure:** cross-tenant read | RLS (Row-Level Security — Postgres itself filters every row by tenant; [tenant-isolation.md](tenant-isolation.md)) forced at the storage layer (`internal/tenancy`, migrations); the **cross-tenant-isolation** CI job runs the suite against real Postgres on every pass. ClickHouse adds `tenant_id` partition keys, `ErrNoTenant` pre-flight refusals, and DB-level row policies, gated against real ClickHouse (`internal/store/*/isolation_clickhouse_test.go`). For the TSDB (the time-series metric store), the query proxy forces the tenant label and **refuses any unscoped forward** (`internal/promapi/upstream.go`) |
| **Tampering:** writing into another tenant | tenant resolved at the edge and propagated API → bus → store; bus messages are tenant-keyed; consumers stamp and verify |
| **DoS:** noisy neighbor (one tenant's load starving everyone else's) | per-tenant fairness gate ahead of the pipeline (`internal/fairness`); per-agent and per-tenant cardinality caps (`internal/pipeline/cardinality.go`); bounded async publish that sheds load with a counter, never silently (`internal/bus/kafka.go`); a noisy-neighbor SLO gate runs every CI pass at the documented latency floor (`internal/perf/scale.go`) |
| **Elevation:** tenant → other tenant via AI/MCP | the AI/MCP query layer enforces tenant **first**, then RBAC, on every call; an end-to-end tenancy assertion runs over the public API (`test/e2e`) |
| **Repudiation** | per-tenant tamper-evident audit chains; erasure produces store-by-store attestations |

### B2 — Agent ↔ control plane

| Threat | Mitigation — evidence |
|---|---|
| Spoofed agent / spoofed control plane | mTLS (mutual TLS — both ends present certificates, so each proves its identity to the other) with a SPIFFE-style tenant-bound identity (SPIFFE — a standard for naming workloads inside certificates as `spiffe://` URIs; no plaintext agent transport exists) and a **mandatory trust-domain pin** — wrong trust domain, rejected handshake |
| Tampering in transit | TLS 1.2+/1.3 via the hardened configs in `internal/crypto`; no plaintext agent transport |
| Fleet takeover via updates | **No self-update channel exists**; upgrades are operator-driven waves of **cosign-signed artifacts** with registry verification and halt-on-error (`internal/agent/rollout.go`) |
| Rogue agent floods | fairness + cardinality caps as in B1; per-agent registry identity, version-skew-gated handshake (`internal/lifecycle/version.go`) |

### B3 — Ingest surfaces (bus, OTLP, webhooks)

| Threat | Mitigation — evidence |
|---|---|
| On-path read/inject | Kafka requires TLS unless explicitly dev-flagged; plaintext is *refused*, both in code and at chart render (`internal/bus/security.go`; the agent chart fails closed) |
| Spoofed OTLP/webhook senders | the OTLP receiver is TLS-only, authenticates a bearer token to a tenant, rejects cross-tenant payloads, and treats the payload as untrusted with a bounded size (`internal/otel/otlp`, [../otlp.md](../otlp.md)); webhooks are HMAC-verified where the sender signs (HMAC — a keyed hash computed with a shared secret, proving the sender held it; `internal/change`) — a missing required signature fails closed |
| Malformed / poison input | fuzz smoke (feeding the parsers machine-generated malformed input until something breaks) runs on the untrusted parsers every CI pass (`make fuzz-smoke`); malformed results are dropped, never panicked on; store-write failures are retried then dead-lettered with the original bytes — counted, never silently lost |
| SSRF via probe targets (Server-Side Request Forgery — tricking the server into probing addresses only *it* can reach) | a canary/probe target guard blocks probes aimed at internal metadata endpoints and the like (`internal/canary/ssrf.go`) |

### B4 — Control plane ↔ stores

| Threat | Mitigation — evidence |
|---|---|
| On-path DB read | `sslmode=require` by default; ClickHouse/TSDB TLS via `https` URLs and a hardened client (`crypto.HardenedHTTPClient`) |
| Audit purge by DB owner | the provider audit chain is exported as Ed25519-**signed WORM segments** to object storage with continuous chain verification (`internal/audit/worm.go`; see [../hardening.md](../hardening.md) §0b) |
| Schema drift | sequential idempotent Postgres migrations + an expand/contract CI gate (expand/contract — the zero-downtime pattern: add the new shape first, migrate, only then remove the old); ClickHouse migrations are versioned with a checksummed ledger — an edited shipped version is refused (`internal/store/chmigrate`) |
| Crypto misuse | all primitives sit behind `internal/crypto` (FIPS-swappable); a crypto-import CI guard (`scripts/check_crypto_imports.sh`) blocks direct primitive imports anywhere else |

### B5 — Provider/operator plane ↔ tenant data

| Threat | Mitigation — evidence |
|---|---|
| Silent operator read of tenant telemetry | **no implicit read access**; break-glass (emergency access that must be explicitly granted, expires on a clock, and is recorded apart from normal activity) is explicit, time-bounded, tenant-consented, and lands in a *separate* tamper-evident provider audit stream (proven by the `ee/provider` no-implicit-access test suite) |
| Operator-side credential abuse | auth fails closed by default; rate-limit + lockout + audit on auth; any `insecure_skip_verify` is admin-permission-gated and audited |
| Disgruntled-insider erasure | WORM export survives a DB purge (see B4); offboarding erasure is attested store-by-store |

### B6 — AI / MCP

| Threat | Mitigation — evidence |
|---|---|
| Tenant data exfiltration via the model | the built-in model is **air-gapped by default**; remote egress requires three gates — a boot-time operator acknowledgement env var, per-tenant default-deny consent, and a per-call audit event recording exactly which data categories left ([../ai-egress.md](../ai-egress.md)) |
| PII leaving in prompts | a redaction pass runs before any remote prompt (`internal/ai/redact.go`): IPs and secrets masked, hostnames per policy |
| Prompt injection via telemetry | per-session random evidence IDs, structured delimiter framing with defanged escapes, and fail-closed citation grounding — a fully injected answer degrades to "insufficient evidence" rather than obeying the injection; the adversarial test suite includes a deliberately compromised model stand-in (`internal/ai/rca.go`) |
| MCP caller over-reach | tenant **first**, then RBAC, on every tool — enforced at the MCP layer and again at the stores |
| Model-as-actor | detection is a signal, never an IPS; remediation is observe-only / human-gated by default — both hard product guardrails |

### B7 — Supply chain (build → release → deploy)

| Threat | Mitigation — evidence |
|---|---|
| Malicious dependency / action | every workflow action is SHA-pinned (referenced by exact commit hash, so a hijacked tag cannot swap the code) and a CI gate enforces it (`scripts/check_action_pins.sh`); every PR runs the `dependency-scan` and `image-scan` CI jobs, and the weekly `security-scan` workflow re-runs govulncheck / npm audit / trivy on a schedule and archives the raw reports as evidence; base images are digest-pinned (referenced by content hash, not a movable tag) |
| Tampered release artifact | cosign keyless signing of binaries and images (cosign — the artifact-signing tool; *keyless* binds the signature to the CI build's identity in a public transparency log, so there is no long-lived private key to steal), with SPDX SBOMs (software bills of materials — the parts list of each release; [../ops/verify-artifacts.md](../ops/verify-artifacts.md)); releases refuse to cut from a red CI run |
| Tampered eBPF object at run time | a SHA-256 manifest is baked in at build; loaders verify the embedded bytes before any kernel load and **fail closed** (`internal/ebpf/integrity.go`) |
| Unsigned bits reaching the fleet | rollout planning *refuses* any artifact without a recorded digest, verification method, and verifier |

### B8 — Agent ↔ monitored host

| Threat | Mitigation — evidence |
|---|---|
| Agent as an enforcement / attack tool | observe-only is **CI-enforced**: a static gate forbids enforcing eBPF program types (`internal/ebpf/observeonly_test.go`), and programs are additionally load-and-attach tested on real LTS kernels (the `ebpf-kernel-matrix` job). See [agent-whitepaper.md](agent-whitepaper.md) §3 |
| Privilege escalation from the agent | the minimal capability pair `CAP_BPF`+`CAP_PERFMON` (capabilities — fine-grained slices of root's power), a default-deny seccomp profile (a kernel filter that errors any system call not on the allowlist), a read-only root, and a non-root systemd unit with ambient caps (`deploy/agent/`, `deploy/helm/probectl-agent`) |
| Sensitive payload capture | TLS-plaintext (L7) capture is **off by default** and requires explicit enable **plus** per-tenant consent naming the agent's tenant; bodies are zeroed at the redaction boundary by default (`internal/ebpf/l7policy.go`) |
| Host resource exhaustion | chart resource limits; ring-buffer drops are counted, never silent; overhead is benchmarked with a CI tripwire ([../agent-overhead.md](../agent-overhead.md)) |

## 5. Known gaps (the honest list — tracked, not hidden)

A threat model that claims no gaps is not honest. These are the open items as of
this revision:

| Gap | Status |
|---|---|
| Large / extra-large full-stack load numbers + SLO sign-off | the load harness and a CI smoke test have landed; the reference-hardware run is human-scheduled |
| Multi-region RTO/RPO at representative scale | the CI failover drill runs continuously; a representative-scale run and sign-off are pending |
| Reference-host agent overhead (live kernel ring buffer) | the userspace pipeline is measured; the on-host live row is pending |
| `LICENSE` is a placeholder pending counsel | a legal artifact owned outside the codebase |

## 6. Review log

| Version | Date | Change | Reviewer |
|---|---|---|---|
| 1.0 | 2026-06-07 | Initial model; mitigations cross-checked against code and CI at commit time | maintainer (solo); external review welcome via SECURITY.md |
