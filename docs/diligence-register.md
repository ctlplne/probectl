# Diligence evidence crosswalk

**Status:** committed replacement for the finding labels cited by
[`probectl-PRD-v1.0.md`](../probectl-PRD-v1.0.md).

The historical external diligence workspace was not committed to this
repository, so it cannot be treated as followable evidence. This file does not
attempt to recreate unseen finding narratives or claim that an old audit
receipt is current. It preserves the smaller, auditable contract that still
matters: every finding label cited by the v1.0 delivered-state inventory maps
to a real, committed evidence target.

An evidence target shows where the control and its regression proof live. It
is not, by itself, proof that every gate is green. For a reviewable receipt,
pin this file and its targets to an exact Git commit, then use the CI run and
artifacts for that same commit. Remaining or externally validated work stays
qualified in PRD v1.0 §5.

| Finding | Contract carried by PRD v1.0 | Committed evidence target |
|---|---|---|
| U-001 | Authentication refuses to serve without an available configured mode. | [`internal/control/auth_test.go`](../internal/control/auth_test.go) |
| U-003 | Listener and deployment TLS posture is checked fail closed. | [`scripts/check_tls_configs.sh`](../scripts/check_tls_configs.sh) |
| U-005 | Scale claims remain provisional until the named reference-tier runs exist. | [`docs/scale-gate.md`](scale-gate.md) |
| U-007 | Workflow actions must use immutable SHA pins. | [`scripts/check_action_pins.sh`](../scripts/check_action_pins.sh) |
| U-013 | Remote AI use requires tenant consent, redaction, and audit. | [`docs/ai-egress.md`](ai-egress.md) |
| U-014 | Embedded eBPF objects are digest-verified before kernel load. | [`internal/ebpf/integrity_test.go`](../internal/ebpf/integrity_test.go) |
| U-016 | The eBPF agent ships as a hardened, least-capability DaemonSet. | [`deploy/helm/probectl-agent/templates/daemonset.yaml`](../deploy/helm/probectl-agent/templates/daemonset.yaml) |
| U-018 | TLS plaintext capture is off by default and tenant-consent plus workload-scope gated. | [`internal/ebpf/l7policy_test.go`](../internal/ebpf/l7policy_test.go) |
| U-019 | Security and capability wording is guarded against unsupported delivery claims. | [`scripts/check_docs_claims.sh`](../scripts/check_docs_claims.sh) |
| U-021 | Supported eBPF kernels are exercised by the CI kernel matrix. | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| U-022 | Canary destinations are resolved and rejected by the SSRF boundary before probing. | [`internal/canary/ssrf_test.go`](../internal/canary/ssrf_test.go) |
| U-023 | Kafka publishing is bounded, asynchronous, batched, and backpressure-accounted. | [`internal/bus/async_test.go`](../internal/bus/async_test.go) |
| U-024 | Authentication failures are rate-limited with bounded lockout and audit hooks. | [`internal/auth/ratelimit_test.go`](../internal/auth/ratelimit_test.go) |
| U-025 | Cross-tenant isolation has a dedicated real-store CI gate. | [`internal/store/flowstore/isolation_clickhouse_test.go`](../internal/store/flowstore/isolation_clickhouse_test.go) |
| U-026 | Active metric identities are capped per agent and per tenant. | [`internal/pipeline/cardinality_test.go`](../internal/pipeline/cardinality_test.go) |
| U-027 | Tenant offboarding erases and verifies every attached store while preserving the neighbor tenant. | [`internal/tenantlife/offboard_test.go`](../internal/tenantlife/offboard_test.go) |
| U-029 | Lightweight in-memory telemetry storage has retention and oldest-first byte bounds. | [`internal/store/tsdb/retention_test.go`](../internal/store/tsdb/retention_test.go) |
| U-030 | Backup and restore drills round-trip PostgreSQL, ClickHouse, and signed object evidence. | [`scripts/backup_restore_drill.sh`](../scripts/backup_restore_drill.sh) |
| U-031 | Fleet rollout is staged, health-gated, reversible, and human-controlled. | [`internal/agent/rollout_test.go`](../internal/agent/rollout_test.go) |
| U-033 | Compliance mappings point to testable controls and qualify external assurance. | [`docs/compliance/control-evidence.md`](compliance/control-evidence.md) |
| U-037 | Model-visible evidence uses opaque IDs and rejects prompt-injection attempts. | [`internal/ai/injection_test.go`](../internal/ai/injection_test.go) |
| U-038 | Tenant-bound agent identities are rejected after registry-driven revocation. | [`internal/agenttransport/revocation_test.go`](../internal/agenttransport/revocation_test.go) |
| U-041 | Audit streams support signed WORM export and chain verification. | [`internal/audit/worm_test.go`](../internal/audit/worm_test.go) |
| U-042 | Pooled, siloed, hybrid, and residency semantics are stated without overstating pooled residency. | [`docs/isolation.md`](isolation.md) |
| U-047 | Volatile topology is rebuildable while alert operations and forensic evidence use durable stores. | [`docs/adr/volatile-stores.md`](adr/volatile-stores.md) |
| U-048 | AI analysis has a process-wide bounded concurrency backstop. | [`internal/ai/rca.go`](../internal/ai/rca.go) |
| U-049 | RCA quality uses labeled scenarios and blocking accuracy and citation floors. | [`internal/ai/eval/eval_test.go`](../internal/ai/eval/eval_test.go) |
| U-050 | L4 and L7 eBPF ring-buffer sizes follow bounded runtime configuration. | [`internal/ebpf/ringbuf_config_test.go`](../internal/ebpf/ringbuf_config_test.go) |
| U-051 | Agent overhead has a reproducible benchmark harness and keeps reference-host numbers provisional. | [`docs/agent-overhead.md`](agent-overhead.md) |
| U-053 | The failover path is executable while representative RTO and RPO sign-off remains provisional. | [`scripts/failover_drill.sh`](../scripts/failover_drill.sh) |
| U-054 | Nightly black-box coverage boots the stack and follows the API-to-agent result path. | [`test/e2e/e2e_test.go`](../test/e2e/e2e_test.go) |
| U-055 | Scale and noisy-neighbor floors are encoded as executable regression tests. | [`internal/perf/scale_test.go`](../internal/perf/scale_test.go) |
| U-057 | Stateful store integration coverage is measured by a dedicated floor test and CI job. | [`internal/store/store_coverage_integration_test.go`](../internal/store/store_coverage_integration_test.go) |
| U-059 | Protobuf generators and plugins are pinned and generated-code drift fails CI. | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| U-061 | Frontend dependencies are locked and audited; deployment images use immutable digests. | [`web/package-lock.json`](../web/package-lock.json), [`scripts/check_npm_audit_policy.mjs`](../scripts/check_npm_audit_policy.mjs), [`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml) |
| U-065 | Procurement artifacts are drafts and unfinished legal review is disclosed. | [`docs/compliance/control-evidence.md`](compliance/control-evidence.md) |
| U-068 | Release images and artifacts carry SBOMs, signatures, and self-verification. | [`.github/workflows/release.yml`](../.github/workflows/release.yml) |
| U-073 | eBPF L4 capture handles IPv4 and IPv6 and counts unsupported address families. | [`internal/ebpf/filtered_test.go`](../internal/ebpf/filtered_test.go) |
| U-074 | Go `crypto/tls` plaintext capture is explicitly outside the GA scope. | [`docs/ebpf-agent.md`](ebpf-agent.md) |
| U-075 | Kernel capability and lockdown checks degrade explicitly instead of silently failing. | [`internal/ebpf/capability_linux_test.go`](../internal/ebpf/capability_linux_test.go) |
| U-078 | Remote store and model clients use bounded circuit breakers. | [`internal/breaker/breaker_test.go`](../internal/breaker/breaker_test.go) |
| U-080 | Pre-1.0 and other dependency risks are recorded with upgrade policy. | [`docs/dependency-policy.md`](dependency-policy.md) |
| U-082 | Every externally fed parser class is covered by the dynamic fuzz policy. | [`scripts/check_fuzz_policy.sh`](../scripts/check_fuzz_policy.sh) |
| U-086 | The control-plane Helm chart defaults to NetworkPolicy and fails closed on missing ingress scope. | [`scripts/check_helm_hardening.sh`](../scripts/check_helm_hardening.sh) |
| U-090 | The silo registry router has a bounded stale window and then fails closed. | [`ee/silo/router_stale_test.go`](../ee/silo/router_stale_test.go) |
| U-091 | MCP tokens are hashed, tenant-scoped, and backed by row-level security. | [`internal/store/mcptokens.go`](../internal/store/mcptokens.go) |
| U-092 | AI evidence is reduced through per-domain field allowlists before serialization. | [`internal/ai/hygiene_test.go`](../internal/ai/hygiene_test.go) |
| U-093 | Optional persisted AI answers include provenance and tenant-scoped retention. | [`internal/store/aianswers.go`](../internal/store/aianswers.go) |
| U-094 | The Python analyzer enforces its stated coverage floor. | [`analyzer/pyproject.toml`](../analyzer/pyproject.toml) |
