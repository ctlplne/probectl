#!/usr/bin/env bash
# check_strength_controls.sh - PROTECT strength regression guard.
#
# The audit's PROTECT phase records confirmed positive controls. This gate keeps
# those controls from becoming invisible tribal knowledge: each assertion points
# at a durable test, script, workflow, or implementation seam that must keep
# existing. It is intentionally static and dependency-light so CI can run it
# before heavier service tests.
set -euo pipefail
cd "$(dirname "$0")/.."

ids=(
  AIRCA-004 AIRCA-005 AIRCA-006 AIRCA-007
  ARCH-005 ARCH-006 ARCH-007 CODE-007 CODE-008 CODE-014
  CORRECT-004 CORRECT-005 CORRECT-006 CORRECT-007
  DOCS-005 DOCS-006 DOCS-007 DOCS-008
  EBPF-005 EBPF-006 FUZZ-005
  KEYS-005 KEYS-006 KEYS-007
  OPS-007 OPS-008 OPS-009 OPS-010
  RED-006 RED-007 RED-008
  RESIL-008 RESIL-009 RESIL-010 RESIL-011 RESIL-012 RESIL-013
  SCALE-007 SCALE-008 SCALE-009
  SCHEMA-I01 SCHEMA-I02 SCHEMA-I03 SCHEMA-I04
  SUPPLY-004 SUPPLY-005 SUPPLY-006 SUPPLY-007
  TENANT-004 TENANT-005 TENANT-006 TENANT-007 TENANT-008
  TEST-006 TEST-007 TEST-008 UX-006 VERIFY-005 VERIFY-006
  WIRE-005 WIRE-006 WIRE-007
)

fail=0
err() { echo "::error::strength-controls: $*" >&2; fail=1; }

need_file() {
  local id="$1" path="$2"
  [ -e "$path" ] || err "$id: missing $path"
}

need_pattern() {
  local id="$1" path="$2" pattern="$3"
  if [ -d "$path" ]; then
    if grep -RIEq "$pattern" "$path" 2>/dev/null; then
      return
    fi
  elif grep -Eq "$pattern" "$path" 2>/dev/null; then
    return
  fi
  err "$id: $path lacks pattern /$pattern/"
}

need_absent() {
  local id="$1" path="$2" pattern="$3"
  if grep -RInE "$pattern" "$path" 2>/dev/null | grep -vE '_test\.go|node_modules|dist' | grep -q .; then
    err "$id: forbidden pattern /$pattern/ found under $path"
  fi
}

if [ "${#ids[@]}" -ne 62 ]; then
  err "internal guard bug: expected 62 PROTECT IDs, got ${#ids[@]}"
fi

# AIRCA: air-gapped default, tenant/RBAC evidence gathering, citation hygiene,
# consent-gated remote egress, and RCA eval floors.
need_pattern AIRCA-004 internal/control/ai.go 'NewBuiltinModel'
need_pattern AIRCA-004 internal/ai/eval/eval_test.go 'minMean(AnswerAccuracy|CitationPrecision)'
need_pattern AIRCA-005 internal/ai/engine_test.go 'source queried for tenant'
need_pattern AIRCA-005 internal/ai/mcp/server.go 'auth\.Authorize'
need_pattern AIRCA-006 internal/ai/injection_test.go 'uncited|injected|EvidenceIDsAreSessionRandom'
need_pattern AIRCA-006 internal/ai/rca.go 'ground(Citations|Findings)'
need_pattern AIRCA-007 internal/ai/eval/eval_test.go '0\.85'
need_pattern AIRCA-007 internal/ai/model_resilient.go 'circuit|cache|fallback|remap'

# Architecture / wire boundaries.
need_pattern ARCH-005 internal/agent/client.go 'mTLS|ServerMTLS|InternalClientTLSConfig|ClientTLS'
need_pattern ARCH-005 internal/agenttransport/service.go 'TenantID|AgentID|SPIFFE|peer'
need_pattern ARCH-006 internal/otel/otlp/receiver.go 'Register.*(Metrics|Trace|Logs)ServiceServer'
need_pattern ARCH-006 internal/otel/otlp/server.go '/v1/(metrics|traces|logs)'
need_pattern ARCH-007 internal/ai/engine.go 'Principal|TenantID|Authorize'
need_pattern ARCH-007 internal/control/mcp.go 'mcp\.tool_call|TenantAppend'
need_pattern WIRE-005 scripts/check_tls_configs.sh 'unified-TLS gate'
need_pattern WIRE-006 internal/otel/otlp/receiver.go 'Authenticate|tenant'
need_pattern WIRE-006 internal/otel/otlp/receiver_test.go 'out-of-tenant|tenant.*mismatch|mismatch.*tenant|spoof'
need_pattern WIRE-007 internal/control/enrollapi.go 'invalid enrollment token|MintToken'
need_pattern WIRE-007 internal/enroll/enroll_integration_test.go 'one-time|replay|hash'

# Code quality, schema, and executed-verification gates.
need_pattern CODE-007 Makefile 'verify-all|lint-go|test-isolation'
need_pattern CODE-007 .github/workflows/ci.yml 'verify-all'
need_pattern CODE-008 scripts/check_repo_hygiene.sh 'SELFTEST'
need_pattern CODE-008 scripts/check_swallowed_errors.sh 'constructed-then-discarded'
need_pattern CODE-008 scripts/check_stringbuilt_sql.sh 'no-stringbuilt-sql'
need_pattern CODE-014 Makefile 'lint-go:'
need_pattern CODE-014 Makefile 'gofmt -l'
need_pattern CODE-014 Makefile 'vet ./\.\.\.'
need_pattern CODE-014 Makefile 'golangci-lint run'
need_pattern CODE-014 Makefile 'check_swallowed_errors\.sh'
need_pattern CODE-014 Makefile 'check_repo_hygiene\.sh SELFTEST'
need_pattern CODE-014 scripts/check_swallowed_errors.sh 'fmt\.Errorf|errors\.New'
need_pattern CODE-014 scripts/check_repo_hygiene.sh 'SELFTEST'
need_pattern DOCS-005 scripts/check_docs_claims.sh 'SELFTEST'
need_pattern DOCS-006 docs/otlp.md 'metrics|traces|logs'
need_pattern DOCS-006 internal/otel/otlp/signals.go 'Metrics|TraceSink|LogSink'
need_pattern DOCS-007 docs/agent-overhead.md 'illustrative|reference hardware|smoke'
need_pattern DOCS-007 docs/scale-gate.md 'UNVERIFIED|reference hardware|72'
need_pattern DOCS-008 web/src/surfaces.ts 'native|federated|placeholder'
need_pattern DOCS-008 web/src/test/surface-coverage.test.tsx 'axe|placeholder|federated'
need_pattern SCHEMA-I01 Makefile 'proto'
need_pattern SCHEMA-I02 internal/otel/conventions.go 'semconv|SchemaURL|OTel'
need_pattern SCHEMA-I03 scripts/check_openapi.sh 'OpenAPI completeness gate'
need_pattern SCHEMA-I04 Makefile 'migration-gate'
need_pattern TEST-006 scripts/verify_all.sh 'ALL GREEN|run_step'
need_pattern TEST-007 Makefile 'test-isolation'
need_pattern TEST-007 .github/workflows/ci.yml 'cross-plane|correlated incident|test-isolation'
need_pattern TEST-008 internal/ai/eval/eval_test.go 'RCAEval|citation_precision'
need_pattern UX-006 web/src/api/client.ts 'apiURL|drop the /v1 prefix'
need_pattern UX-006 web/src/test/surface-coverage.test.tsx 'axe'

# Correctness / resilience / scale controls.
need_pattern CORRECT-004 internal/agent/agent.go 'Ack|Publish|durab|stored|ResultID'
need_pattern CORRECT-004 internal/agenttransport/service.go 'TenantId|AgentId|tenant.*agent'
need_pattern CORRECT-005 internal/agent/resultid_test.go 'ResultIDSurvivesBufferRoundTrip|dedup'
need_pattern CORRECT-005 internal/agenttransport/service.go 'Flush|durability barrier|SendAndClose'
need_pattern CORRECT-005 internal/agenttransport/streamresults_resilience_test.go 'RefusesAckWhenFlushFails|ack sent before the bus durability barrier'
need_pattern CORRECT-005 internal/store/flowstore/clickhouse.go 'FINAL'
need_pattern CORRECT-005 internal/store/otelstore/clickhouse.go 'ReplacingMergeTree|dedup|FINAL'
need_pattern CORRECT-005 internal/store/ebpfstore/clickhouse.go 'ReplacingMergeTree|dedup|FINAL'
need_pattern CORRECT-006 internal/pipeline/clockskew.go 'clampFuture|MaxFutureSkew|FutureClamped'
need_pattern CORRECT-006 internal/pipeline/clockskew_ingest_test.go 'Clamp|future'
need_pattern CORRECT-007 internal/flow/model.go 'SamplingRate|BytesScaled|PacketsScaled'
need_pattern CORRECT-007 internal/pipeline/otlp_histogram_test.go 'histogram'
need_pattern RESIL-008 internal/backup/backup_test.go 'Tamper|Truncation|NoPlaintext'
need_pattern RESIL-009 internal/agent/buffer.go 'disk|frame|ack|replay'
need_pattern RESIL-009 internal/agent/coordination.go 'jitter|backoff|retry'
need_pattern RESIL-010 internal/pipeline/otlpdlq.go 'DLQ|dead'
need_pattern RESIL-010 internal/pipeline/consumer.go 'retry|commit|context'
need_pattern RESIL-011 internal/breaker/breaker.go 'Circuit|Breaker|Open|Half'
need_pattern RESIL-011 internal/breaker/breaker_test.go 'opens|half'
need_pattern RESIL-012 scripts/backup_restore_drill.sh 'restore|verify'
need_pattern RESIL-012 .github/workflows/ci.yml 'backup|restore|failover'
need_pattern RESIL-013 internal/opendata 'stale|degrad|cache|fallback'
need_pattern SCALE-007 internal/pipeline/cardinality_test.go 'tenant.*unaffected|TenantDropped'
need_pattern SCALE-007 internal/fairness 'tenant|quota|limit'
need_pattern SCALE-008 internal/bus/kafka.go 'Commit|Batch|TenantKey|key'
need_pattern SCALE-009 internal/store/flowstore/clickhouse.go 'PARTITION BY \(tenant_id|TTL|retention'
need_pattern SCALE-009 internal/store/otelstore/clickhouse.go 'PARTITION BY \(tenant_id|TTL|retention'

# eBPF, fuzzing, keys, supply chain, and ops controls.
need_pattern EBPF-005 internal/ebpf/observeonly_test.go 'observe|block|drop|iptables'
need_pattern EBPF-006 internal/ebpf/integrity.go 'SHA|digest|Verify'
need_pattern EBPF-006 internal/ebpf/trustboundary_test.go 'digest|tamper'
need_pattern FUZZ-005 scripts/fuzz_smoke.sh 'go test.*-fuzz|fuzz-smoke'
need_pattern FUZZ-005 scripts/list_fuzz_targets.sh 'Fuzz'
need_pattern KEYS-005 scripts/check_crypto_imports.sh 'internal/crypto'
need_pattern KEYS-005 internal/crypto/crypto.go 'Provider|Zeroize|Encrypt|Decrypt'
need_pattern KEYS-006 .github/workflows/release.yml 'cosign|verify-blob|id-token'
need_absent KEYS-006 cmd 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 internal 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 ee 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 pkg 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_pattern KEYS-007 internal/tenantcrypto 'fail|zero|cache|ttl|BYOK|KEK'
need_pattern KEYS-007 internal/control/enrollapi.go 'agent-ca|revoke|SVID|SPIFFE'
need_pattern OPS-007 scripts/check_helm_hardening.sh 'TLS|fail|secret|Secure'
need_pattern OPS-007 deploy/compose/probectl.yml 'PROBECTL_SESSION_HMAC_KEY|TLS|443|8443'
need_pattern OPS-008 internal/agent/rollout.go 'wave|rollback|budget|pause'
need_pattern OPS-008 scripts/check_version_consistency.sh 'compose|Helm|VERSION'
need_pattern OPS-009 Makefile 'backup-restore-drill|migration-gate|helm-gate'
need_pattern OPS-010 internal/control/handlers.go 'ready|live|drain|shutdown'
need_pattern OPS-010 internal/control/server.go 'Shutdown|draining|ShutdownTimeout'
need_pattern RED-006 internal/ai/injection_test.go 'prompt|injection|uncited'
need_pattern RED-007 internal/otel/otlp/receiver_test.go 'out-of-tenant|tenant.*mismatch|spoof'
need_pattern RED-008 scripts/check_cosign_wiring.sh 'cosign|verify'
need_pattern RED-008 scripts/check_supply_pins.sh 'supply-pins'
need_pattern SUPPLY-004 .github/workflows/release.yml 'cosign verify|verify-blob'
need_pattern SUPPLY-005 web/package-lock.json 'integrity'
need_pattern SUPPLY-005 docs/third-party-licenses.md 'Third-party|License|Module'
need_pattern SUPPLY-006 scripts/check_action_pins.sh 'SHA-pinned|floating action'
need_pattern SUPPLY-007 internal/ebpf/integrity.go 'digest'

# Tenant isolation controls.
need_pattern TENANT-004 internal/tenancy/tenancy.go 'set_config.*probectl\.tenant_id|InTenant'
need_pattern TENANT-005 internal/otel/otlp/receiver.go 'resourceTenant|authenticated|tenant'
need_pattern TENANT-006 internal/store/flowstore/scoping_test.go 'tenantSettingName|tenant_id'
need_pattern TENANT-007 internal/control/prometheus.go 'tenant_id'
need_pattern TENANT-007 internal/control/resultview.go 'GetTenantId|TenantID|tenant'
need_pattern TENANT-008 internal/ai/engine_test.go 'denied query must not reach the source'
need_pattern TENANT-008 internal/ai/mcp/server.go 'auth\.Authorize|ResourceTenantKey'

# Verification meta-controls are backed by the remediation harness artifacts,
# but the product must keep the export hook that turns gate results into review
# receipts.
need_pattern VERIFY-005 scripts/export-receipts.sh 'verify-all-summary'
need_pattern VERIFY-006 scripts/export-receipts.sh 'coverage|verify-all'

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "strength-controls gate: OK (${#ids[@]} PROTECT strengths checked)"
