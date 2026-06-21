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
  CORRECT-004 CORRECT-005 CORRECT-006 CORRECT-007 CORRECT-008 CORRECT-009
  COVER-008 COVER-009
  DOCS-004 DOCS-005 DOCS-006 DOCS-007 DOCS-008
  EBPF-004 EBPF-005 EBPF-006 EBPF-007 FUZZ-005 FUZZ-007 FUZZ-008
  KEYS-004 KEYS-005 KEYS-006 KEYS-007
  OPS-005 OPS-006 OPS-007 OPS-008 OPS-009 OPS-010
  PERF-008 PERF-009 PERF-010
  PRIVACY-008 PRIVACY-009 PRIVACY-010 PRIVACY-011
  PRODUCT-011 PRODUCT-012 PRODUCT-013 PRODUCT-014
  RED-005 RED-006 RED-007 RED-008
  RESIL-008 RESIL-009 RESIL-010 RESIL-011 RESIL-012 RESIL-013
  RESIL-S01 RESIL-S02 RESIL-S03
  SCALE-006 SCALE-007 SCALE-008 SCALE-009
  SCHEMA-002 SCHEMA-003 SCHEMA-004
  SEC-003 SEC-004
  SCHEMA-I01 SCHEMA-I02 SCHEMA-I03 SCHEMA-I04
  SUPPLY-003 SUPPLY-004 SUPPLY-005 SUPPLY-006 SUPPLY-007
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

if [ "${#ids[@]}" -ne 96 ]; then
  err "internal guard bug: expected 96 PROTECT IDs, got ${#ids[@]}"
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
need_pattern COVER-008 scripts/check_openapi.sh 'TestOpenAPIGateCatchesPlantedRouteAndSpecDrift|TestProviderOpenAPIMatchesRoutes'
need_pattern COVER-008 internal/control/openapi_test.go 'TestOpenAPIMatchesRoutes|TestOpenAPIGateCatchesPlantedRouteAndSpecDrift|documented but has no registered route'
need_pattern COVER-008 ee/provider/openapi_test.go 'TestProviderOpenAPIMatchesRoutes|TestProviderOpenAPIGateCatchesPlantedDrift|documented phantom route'
need_pattern COVER-008 docs/development.md 'provider .*/provider/v1'
need_pattern COVER-009 web/package.json 'coverage-gate'
need_pattern COVER-009 web/src/featureCatalog.ts 'REQUIRED_FEATURES|PLANE_ACTIVE_SYNTHETIC|F57|future'
need_pattern COVER-009 web/src/surfaces.ts 'featureIds|native|federated|none-by-design|offNav'
need_pattern COVER-009 web/src/test/surface-coverage.test.tsx 'featureCoverageViolations|futureFeatureViolations|missing surface declaration'
need_pattern COVER-009 web/src/test/surface-coverage.test.tsx 'every native surface renders a real screen|PLACEHOLDER_MARKER|every federated surface has its declared evidence'
need_pattern COVER-009 web/src/test/surface-coverage.test.tsx 'axe|toHaveNoViolations'
need_pattern DOCS-004 README.md 'cited evidence'
need_pattern DOCS-004 README.md 'caller is allowed to see'
need_pattern DOCS-004 docs/ai-rca.md 'no network call, no phone-home'
need_pattern DOCS-004 internal/control/ai.go 'AIModelEnabled'
need_pattern DOCS-004 internal/control/ai.go 'NewBuiltinModel'
need_pattern DOCS-004 internal/ai/egressgate.go 'ErrEgressDenied|fail closed'
need_pattern DOCS-004 internal/ai/model_builtin.go 'network, no phone-home'
need_pattern DOCS-004 internal/ai/eval/eval.go 'NewBuiltinModel'
need_pattern DOCS-004 scripts/check_docs_claims.sh 'DOCS-S03|DOCS-004'
need_pattern DOCS-005 scripts/check_docs_claims.sh 'SELFTEST|bad fixture correctly rejected'
need_pattern DOCS-005 Makefile 'check_docs_claims\.sh SELFTEST && .*check_docs_claims\.sh'
need_pattern DOCS-005 .github/workflows/ci.yml 'check_docs_claims\.sh SELFTEST && .*check_docs_claims\.sh'
need_pattern DOCS-005 web/package.json 'coverage-gate'
need_pattern DOCS-005 .github/workflows/ci.yml 'npm run coverage-gate'
need_pattern DOCS-005 web/src/test/surface-coverage.test.tsx 'the gate itself fails on a capability with no surface'
need_pattern DOCS-005 web/src/test/surface-coverage.test.tsx 'required PRD feature disappears or has no surface kind'
need_pattern DOCS-005 web/src/test/surface-coverage.test.tsx 'PLACEHOLDER_MARKER|toHaveNoViolations'
need_pattern DOCS-005 web/src/surfaces.ts 'native|federated|none-by-design'
need_pattern DOCS-006 docs/otlp.md 'metrics|traces|logs'
need_pattern DOCS-006 internal/otel/otlp/signals.go 'Metrics|TraceSink|LogSink'
need_pattern DOCS-007 docs/agent-overhead.md 'illustrative|reference hardware|smoke'
need_pattern DOCS-007 docs/scale-gate.md 'UNVERIFIED|reference hardware|72'
need_pattern DOCS-008 web/src/surfaces.ts 'native|federated|placeholder'
need_pattern DOCS-008 web/src/test/surface-coverage.test.tsx 'axe|placeholder|federated'
need_pattern SCHEMA-002 proto/probectl/agent/v1/agent.proto 'protocol_version|accepted_capabilities|server_capabilities|additive-only'
need_pattern SCHEMA-002 internal/agenttransport/service.go 'agentProtocolVersion|serverCapabilities|AcceptedCapabilities|ServerCapabilities'
need_pattern SCHEMA-002 internal/agenttransport/negotiation_test.go 'TestAcceptedCapabilitiesIntersectsRequestedAndKnown|TestServerCapabilitiesReturnsCopy|TestServerCapabilitiesAdvertiseVersionedBehaviors'
need_pattern SCHEMA-002 internal/agenttransport/skew_integration_test.go 'TestRegisterEnforcesVersionSkew|TestRegisterEnforcesMinVersionFloor'
need_pattern SCHEMA-003 Makefile 'migration-gate'
need_pattern SCHEMA-003 internal/store/migrate/compat.go 'drop table|drop column|Locking-DDL|lock-ok'
need_pattern SCHEMA-003 internal/store/migrate/compat_test.go 'TestCheckSQLRejectsDestructive|TestCheckSQLRejectsLockingDDL|TestCheckSQLRequiresNoTxForConcurrentIndex|TestCheckSQLLockOKAnnotation|TestMigrationsExpandContractCompat'
need_pattern SCHEMA-003 internal/store/chmigrate/gate.go 'DROP TABLE|RENAME TABLE|Destructive|Justification'
need_pattern SCHEMA-003 internal/store/chmigrate/gate_test.go 'TestCheckMigrationsFlagsDestructive|TestCheckMigrationsAllowsAnnotated|TestCheckMigrationsAllowsAdditive'
need_pattern SCHEMA-003 internal/store/chgate_test.go 'TestClickHouseMigrationGate|TestClickHouseMigrationGateCatchesInjectedDestructive'
need_pattern SCHEMA-003 migrations/README.md 'CREATE INDEX CONCURRENTLY|lock-ok|Destructive: true|Justification'
need_pattern SCHEMA-004 scripts/check_openapi.sh 'OpenAPI 3\.1|TestOpenAPIMatchesRoutes|TestProviderOpenAPIMatchesRoutes|TestDeprecatedOperationsDeclareLifecycle'
need_pattern SCHEMA-004 internal/control/apilifecycle.go 'Deprecation|Sunset|X-Probectl-API-Replacement|LTS|openapi.json'
need_pattern SCHEMA-004 internal/control/openapi_test.go 'TestOpenAPIMatchesRoutes|TestOpenAPIGateCatchesPlantedRouteAndSpecDrift|TestDeprecatedOperationsDeclareLifecycle'
need_pattern SCHEMA-004 internal/otel/conventions.go 'SemConvVersion|SchemaURL|ScopeVersion|KnownAttributes'
need_pattern SCHEMA-004 internal/otel/otlp/convert.go 'SchemaUrl: schemaURL|Version: scopeVersion'
need_pattern SCHEMA-004 internal/otel/otlp/schemaurl_test.go 'TestExportedOTLPCarriesSchemaURL|TestSchemaURLPinnedToSemConvVersion'
need_pattern SEC-003 internal/control/v1.go 'type apiRoute|Permission string|tenant boundary'
need_pattern SEC-003 internal/control/server.go 'apiRoutes|requirePermission|apiLifecycleFor'
need_pattern SEC-003 internal/control/auth.go 'requirePermission|Tenant lifecycle|ABAC over RBAC|principal.*tenant'
need_pattern SEC-003 internal/control/auth_test.go 'TestRequirePermission|missing principal|missing permission|authn-only'
need_pattern SEC-003 internal/control/route_coverage_test.go 'TestEveryV1RouteIsDocumented|TestAPIRouteTableEntriesAreUniqueAndPermissioned|/v1/me|TestNonV1SurfacesDocumentedOrExcluded'
need_pattern SEC-004 internal/control/middleware.go 'contentSecurityPolicy|frame-ancestors|object-src|securityHeaders|Strict-Transport-Security|Permissions-Policy'
need_pattern SEC-004 internal/control/middleware_test.go 'TestSecurityHeadersCSPAndFraming|unsafe-inline|X-Frame-Options|Permissions-Policy'
need_pattern SEC-004 internal/control/server.go '/ingest/changes|handleChangeWebhook|/ingest/itsm|handleITSMWebhook|/ingest/rum|/scim/v2'
need_pattern SEC-004 internal/control/change_integration_test.go 'TestChangeWebhookRejectsUnsignedAndForged|TestChangeWebhookTenantIsolation'
need_pattern SEC-004 internal/control/notify_integration_test.go 'forged inbound should be 401|X-Probectl-Signature'
need_pattern SEC-004 internal/control/rumapi_test.go 'TestBuildRUMGatingAndFailClosed|TestRUMBeaconIngestPublishesUnderVerifiedTenant|TestRUMEndpointNotWiredAndUnavailableIngest'
need_pattern SEC-004 internal/control/scim_integration_test.go 'TestSCIMAuthAndTenantIsolation|invalid bearer'
need_pattern SEC-004 ee/provider/handler.go 'auth/login|asOperator|asTenantAdmin|auth.NewLimiter|provider auth lockout'
need_pattern SEC-004 ee/provider/openapi_test.go 'TestProviderOpenAPIMatchesRoutes|TestProviderOpenAPIGateCatchesPlantedDrift'
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
need_pattern CORRECT-006 internal/pipeline/integrity_ledger.go 'IntegrityStats|Malformed|TenantRejected|DeadLettered|Dropped'
need_pattern CORRECT-006 internal/pipeline/integrity_ledger_test.go 'ExposesEveryLossCounter|MalformedPayloads|DeadLettered|TenantRejected|Dropped'
need_pattern CORRECT-006 internal/control/topology_integrity.go 'TopologyPlaneIntegrityStats|PersistFailed|malformed_total|rejected_total|stored_total'
need_pattern CORRECT-006 internal/control/topology_integrity_test.go 'CountsMalformedInputs|CountsRejectedInputs|CountsUnscopedPersistFailedAndStored'
need_pattern CORRECT-007 internal/store/flowstore/clickhouse.go 'ReplacingMergeTree|row_id|FINAL'
need_pattern CORRECT-007 internal/store/flowstore/final_dedup_test.go 'AggregationsReadFinal|FlowDedupDDLUsesReplacingMergeTreeRowID|FINAL'
need_pattern CORRECT-007 internal/store/flowstore/final_dedup_integration_test.go 'FlowFinalDedupRealRoundTrip|redelivered|double-counted'
need_pattern CORRECT-007 internal/store/flowstore/rowid_test.go 'FlowRowIDDedupKey|identical rows'
need_pattern CORRECT-008 internal/pipeline/otlp.go 'histogramSeries|_bucket|_count|_sum|otel_temporality'
need_pattern CORRECT-008 internal/pipeline/otlp_histogram_test.go 'TestHistogramConversionDeltaTemporality'
need_pattern CORRECT-008 internal/pipeline/otlp_histogram_test.go 'probectl_otlp_request_latency_bucket'
need_pattern CORRECT-009 internal/pipeline/clockskew.go 'NormalizeEventTimeUnixNano|ResultEventTime|MaxFutureSkew|FutureClamped'
need_pattern CORRECT-009 internal/pipeline/clockskew_test.go 'ResultEventTimeUsesSharedNormalizer|NormalizeEventTimeUnixNano'
need_pattern CORRECT-009 internal/pipeline/clockskew_ingest_test.go 'FutureClampAcrossIngestPaths|otlp_histogram|flow'
need_pattern CORRECT-009 internal/pipeline/flow.go 'clampFutureTime|FutureClamped'
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
need_pattern RESIL-S01 scripts/backup_postgres.sh 'refusing to write plaintext tenant backup|allow-plaintext-tenant-backup|backup-seal'
need_pattern RESIL-S01 scripts/backup_restore_drill.sh 'sealed \.dump\.pbk|left a plaintext \.dump|backup-open|verify marker survival|BACKUP_RESTORE_RESULT'
need_pattern RESIL-S01 deploy/helm/probectl/templates/restore-job.yaml 'backoffLimit: 0|backup-open|pg_restore|restore\.clickhouse\.serverBackupPath|RESTORE DATABASE'
need_pattern RESIL-S01 .github/workflows/ci.yml 'backup-restore-drill'
need_pattern RESIL-S01 cmd/probectl-control/backup_cli_contract_test.go 'TestBackupDrillExercisesSealedPBKPath|TestStandalonePostgresBackupsAreSealedOrBreakGlass|TestRestoreJobInvokesBackupOpenAsRealCLI'
need_pattern RESIL-S01 cmd/probectl-control/clickhouse_restore_job_test.go 'ClickHouse restore Job|restore\.clickhouse\.enabled'
need_pattern RESIL-S02 internal/agenttransport/service.go 'Flush|durability barrier|SendAndClose|publish not durable'
need_pattern RESIL-S02 internal/agenttransport/streamresults_resilience_test.go 'TestStreamResultsRefusesAckWhenFlushFails|ack sent before the bus durability barrier'
need_pattern RESIL-S02 internal/pipeline/consumer.go 'durably stored OR dead-lettered|offset UNCOMMITTED|DeadLettered|Dropped'
need_pattern RESIL-S02 internal/pipeline/durability_barrier_test.go 'TestDecoupledHandlerWaitsForDurableWrite|TestDecoupledTrueLossDoesNotCommit'
need_pattern RESIL-S02 internal/pipeline/retry_dlq_test.go 'TestStoreWriteRetriesTransientFailure|TestStoreWriteExhaustionDeadLetters|TestDLQPublishFailureIsCountedLoss'
need_pattern RESIL-S02 internal/pipeline/replay_test.go 'TestDeadLetterReplayReingests'
need_pattern RESIL-S02 internal/agent/buffer.go 'bounded, FIFO store-and-forward queue|maxRecords|maxBytes|ErrBufferFull'
need_pattern RESIL-S02 internal/agent/buffer_test.go 'TestBufferDrainAfterDisconnect|TestBufferPartialDrainKeepsRemainder|TestBufferByteBoundRejectsAndCounts'
need_pattern RESIL-S02 internal/bus/memory_overflow_test.go 'TestMemoryFlushWaitsForHandlers|TestMemoryDropPolicyReportsLossToPublisher'
need_pattern RESIL-S03 internal/chaos/selftest_integration_test.go 'TestChaosRunDetectedBySLO|TestChaosLatencyVisibleInProbeMetrics'
need_pattern RESIL-S03 internal/chaos/dependency_matrix.go 'DependencyChaosMatrix|Retry-After|medium replicaCount and PDB|TestDependencyDrillPrintsCounters'
need_pattern RESIL-S03 internal/chaos/dependency_matrix_test.go 'TestDependencyChaosMatrixCoversRequiredFaults|TestDependencyChaosMatrixHasRunnableEvidence'
need_pattern RESIL-S03 internal/chaos/dependency_drill_test.go 'TestDependencyDrillPrintsCounters|CHAOS_DEPENDENCY_RESULT'
need_pattern RESIL-S03 docs/chaos.md 'TestChaosRunDetectedBySLO|TestChaosLatencyVisibleInProbeMetrics|make chaos-dependency-drill'
need_pattern RESIL-S03 deploy/helm/probectl/values-multitenant.yaml 'replicaCount: 3|minAvailable: 2'
need_pattern RESIL-S03 internal/control/clusterapi.go 'Retry-After|writer_unavailable'
need_pattern RESIL-S03 internal/control/cluster_test.go 'TestWriteFenceDuringFailover|Retry-After|writer_unavailable'
need_pattern RESIL-S03 cmd/probectl-control/ha_reference_coherence_test.go 'TestMediumReferenceShipsCoherentTopology|replicaCount: 3|PodDisruptionBudget'
need_pattern SCALE-006 internal/pipeline/cardinality.go 'DefaultMaxSeriesPerAgent|DefaultMaxSeriesPerTenant|TenantActiveSeries|TenantDropped'
need_pattern SCALE-006 internal/pipeline/cardinality_test.go 'TestCardinalityStatsExposeTenantActiveSeries|tenant.*unaffected|TenantDropped'
need_pattern SCALE-006 internal/pipeline/otlp_fairness_test.go 'OTLPCardinalityCapAndFairness|fairness gate shed nothing'
need_pattern SCALE-006 internal/fairness 'tenant|quota|limit'
need_pattern SCALE-006 cmd/probectl-control/builders.go 'WithFairness|WithCardinalityCaps|WithWriteWorkers'
need_pattern SCALE-007 internal/bus/kafka.go 'BOUNDED in-flight|ErrPublishShed|Stats\(\)|Flush blocks until every record'
need_pattern SCALE-007 internal/pipeline/consumer.go 'BOUNDED channel|WriteQueueSaturated|writeWithRetry|dead-letter publish failed'
need_pattern SCALE-007 internal/pipeline/durability_barrier_test.go 'TestDecoupledHandlerWaitsForDurableWrite|TestDecoupledTrueLossDoesNotCommit'
need_pattern SCALE-007 internal/pipeline/retry_dlq_test.go 'TestStoreWriteRetriesTransientFailure|TestStoreWriteExhaustionDeadLetters|TestDLQPublishFailureIsCountedLoss'
need_pattern SCALE-007 internal/agenttransport/service.go 'Flush|durability barrier|publish not durable'
need_pattern SCALE-007 internal/agenttransport/streamresults_resilience_test.go 'TestStreamResultsRefusesAckWhenFlushFails|ack sent before the bus durability barrier'
need_pattern SCALE-008 internal/bus/kafka.go 'Commit|Batch|TenantKey|key'
need_pattern SCALE-009 internal/store/flowstore/clickhouse.go 'PARTITION BY \(tenant_id|TTL|retention'
need_pattern SCALE-009 internal/store/otelstore/clickhouse.go 'PARTITION BY \(tenant_id|TTL|retention'
need_pattern PERF-008 Makefile 'perf-smoke|TestIngestBaseline|TestPooledMultiTenant'
need_pattern PERF-008 .github/workflows/ci.yml 'perf-smoke|Load/perf smoke'
need_pattern PERF-008 docs/perf-baseline.md 'smoke detector|not a full scale validation|Pooled isolation'
need_pattern PERF-008 internal/perf/hotpaths.go 'MeasurementLoadGate|make perf-smoke'
need_pattern PERF-009 Makefile 'scale-gate-m|TestScaleGate'
need_pattern PERF-009 .github/workflows/nightly.yml 'scale-gate-m|M-tier FULL-STACK regression'
need_pattern PERF-009 docs/scale-gate.md 'TestScaleGateFlowPlaneCI|M-tier full-stack gates|reference hardware'
need_pattern PERF-009 internal/perf/scale_test.go 'TestScaleGateFlowPlaneCI|DriveFlowPlane'
need_pattern PERF-009 internal/perf/fullstack_integration_test.go 'TestFullStackFlowGate|ClickHouse'
need_pattern PERF-010 internal/ebpf/bench_test.go 'TestAgentOverheadReport|20k floor|AGENT OVERHEAD'
need_pattern PERF-010 scripts/bench/agent_overhead.sh 'TestAgentOverheadReport|REFERENCE'
need_pattern PERF-010 docs/agent-overhead.md 'TestAgentOverheadReport|live ring-buffer|reference-host row|n/a'
need_pattern PRIVACY-008 internal/rum/beacon.go 'DisallowUnknownFields|RejectNoConsent|RedactPath|client IP and user agent are never stored'
need_pattern PRIVACY-008 internal/rum/beacon_test.go 'TestParseBeaconPrivacyFailClosed|unknown field user_id|query string leaked|TestRedactPath'
need_pattern PRIVACY-008 web/public/probectl-rum.js 'consent|doNotTrack|globalPrivacyControl|sendBeacon|PATH ONLY'
need_pattern PRIVACY-009 internal/ebpf/l7policy.go 'OFF by default|L7CaptureConsentTenant|L7CaptureScope|RedactPayload'
need_pattern PRIVACY-009 internal/ebpf/l7policy_test.go 'TestL7CaptureConsentGate|enabled without consent|consent for another tenant|TestAgentWithoutConsentHasNoL7Capture|TestRedactPayloadZeroesSensitiveHeaderValues|TestRedactPayloadZeroesNonStandardSecretHeaders'
need_pattern PRIVACY-009 internal/ebpf/bpf/sslsniff.bpf.c 'scope_tgids|scope_cgroups|capture_cfg|window bounds|length-only'
need_pattern PRIVACY-010 internal/ai/egress.go 'ErrEgressDenied|egressPolicy == nil|tenant_governance\.ai_remote_egress'
need_pattern PRIVACY-010 internal/ai/redact.go 'reBearer|reKV|reAKIA|reIPv4|reEmail|rePhone|reMAC|tenant-scoped'
need_pattern PRIVACY-010 internal/ai/egress_test.go 'TestRemoteModelEgressDeniedWithoutConsent|remote model was called|TestBuiltinModelNeverConsultsEgress|TestHTTPModelRemoteEgressFlag'
need_pattern PRIVACY-010 internal/ai/redact_test.go 'TestRedactionTokenDictionaryAttackRequiresTenantKey|TestRemotePromptRedactedLocalUntouched|same value under another tenant must not match'
need_pattern PRIVACY-011 internal/tenantlife/tenantlife.go 'flows|objects|tsdb|paths|topology|otel|ebpf|tenant_keys|ReportSHA256|lifecycle.erase'
need_pattern PRIVACY-011 internal/tenantlife/tenantlife_test.go 'TestEraseGoneFromEveryStore|VerifiedZero|provider audit stream|report hash'
need_pattern PRIVACY-011 internal/tenantlife/offboard_test.go 'unwired plane|Erase|attestation|Complete'
need_pattern PRODUCT-011 web/src/test/surface-coverage.test.tsx 'uniqueRoutes|every native surface passes the WCAG 2\.2 AA bar|axe|toHaveNoViolations'
need_pattern PRODUCT-011 web/src/test/surface-coverage.test.tsx 'provider console|offNav|every native surface renders a real screen'
need_pattern PRODUCT-011 web/src/surfaces.ts 'provider|offNav|native'
need_pattern PRODUCT-012 web/src/test/a11y-primitives.test.tsx 'SkipLink|Field|StatusDot|modal focus trap wraps|restores focus'
need_pattern PRODUCT-012 web/src/shell/AppShell.tsx 'SkipLink|main-content|CommandPalette'
need_pattern PRODUCT-012 web/src/shell/CommandPalette.tsx 'role="combobox"|aria-activedescendant|aria-selected|Escape'
need_pattern PRODUCT-012 web/src/components/Modal.tsx 'focus trap|Escape|aria-modal|aria-labelledby|previouslyFocused'
need_pattern PRODUCT-012 web/src/components/Input.tsx 'htmlFor|aria-invalid|aria-describedby'
need_pattern PRODUCT-012 web/src/components/Badge.tsx 'StatusDot|aria-hidden'
need_pattern PRODUCT-012 web/src/styles/tokens.css 'prefers-reduced-motion'
need_pattern PRODUCT-012 web/src/components/States.module.css 'prefers-reduced-motion'
need_pattern PRODUCT-012 web/src/viz/PathGraph.module.css 'prefers-reduced-motion'
need_pattern PRODUCT-013 internal/control/errors.go 'errorBody|errorDetail|writeError|RequestIDFromContext'
need_pattern PRODUCT-013 internal/control/errors_test.go 'TestAPIHandlerMapsErrors|plain error leaked detail'
need_pattern PRODUCT-013 internal/control/health_test.go 'error envelope should include request_id'
need_pattern PRODUCT-013 internal/control/openapi.json 'ErrorResponse|ErrorCode|request_id joins client output to server logs'
need_pattern PRODUCT-013 internal/apierror/apierror_test.go 'TestWithCodeStringLiteralsAreRegistered|public registry'
need_pattern PRODUCT-013 internal/cli/cli.go 'request_id=%s'
need_pattern PRODUCT-013 internal/cli/cli_test.go 'TestCLIAPIErrorIncludesRequestID|formatted error missing code/request_id'
need_pattern PRODUCT-014 docs/getting-started.md 'The fastest way to first data: the evaluation stack|deploy/compose/eval\.yml'
need_pattern PRODUCT-014 docs/getting-started.md 'See first data|--profile tools run --rm viewer|/v1/topology'
need_pattern PRODUCT-014 docs/getting-started.md 'Add synthetic probes|PROBECTL_JOIN_TOKEN|/v1/results/latest'
need_pattern PRODUCT-014 docs/getting-started.md 'HTTPS on loopback|gRPC/mTLS listener|PROBECTL_AUTH_MODE=dev'
need_pattern PRODUCT-014 docs/getting-started.md 'curl --cacert ./certs/ca\.crt https://127\.0\.0\.1:8443/v1/(results/latest|topology)'
need_pattern PRODUCT-014 docs/getting-started.md 'evaluation-only|bind loopback only|never published to your network'

# eBPF, fuzzing, keys, supply chain, and ops controls.
need_pattern EBPF-004 internal/ebpf/observeonly_test.go 'TestBPFProgramsAreObserveOnly'
need_pattern EBPF-004 internal/ebpf/observeonly_test.go 'tracepoint/|kprobe/|uprobe/|raw_tracepoint/|fentry/|fexit/'
need_pattern EBPF-004 internal/ebpf/observeonly_test.go 'bpf_redirect|bpf_override_return|bpf_probe_write_user|bpf_setsockopt|bpf_skb_store_bytes|bpf_xdp_adjust_head'
need_pattern EBPF-004 Makefile 'test:.*Run unit tests across all workspace modules'
need_pattern EBPF-004 .github/workflows/ci.yml 'make test'
need_pattern EBPF-004 .github/workflows/ci.yml 'observe-only static gate runs in'
need_pattern EBPF-004 .github/workflows/ci.yml 'test-go'
need_pattern EBPF-005 internal/ebpf/integrity.go 'crypto\.Hash|VerifyObjectDigest|refusing kernel load'
need_pattern EBPF-005 internal/ebpf/integrity_test.go 'TestVerifyObjectDigestTamper|MissingManifestFailsClosed|make ebpf-agent'
need_pattern EBPF-005 internal/ebpf/source_live_linux.go 'VerifyObjectDigest\("l4flow"'
need_pattern EBPF-005 internal/ebpf/source_live_l7_linux.go 'VerifyObjectDigest\(objName'
need_pattern EBPF-005 internal/ebpf/trustboundary_test.go 'TestObjectDigestVerificationWiredIntoEveryLoader|verify must come first'
need_pattern EBPF-005 internal/ebpf/gendigests/main.go 'ObjectDigest|bpf_digests_ebpf.go|\*_bpfel\.o'
need_pattern EBPF-006 internal/ebpf/config.go 'MaxServiceEdges|MaxL7Conns|L7ConnIdleTTL|50_000|8192'
need_pattern EBPF-006 internal/ebpf/runtime.go 'SetBounds\(cfg\.MaxServiceEdges|SetBounds\(cfg\.MaxL7Conns|l7Evicted|syncDrops'
need_pattern EBPF-006 internal/ebpf/servicemap.go 'maxEdges|idleTTL|Evicted|evictOldest'
need_pattern EBPF-006 internal/ebpf/l7/tracker.go 'maxConns|idleTTL|Evicted|SetBounds'
need_pattern EBPF-006 internal/ebpf/l7/bounds.go 'l7MaxBufBytes|l7MaxPending|drop\+reset|evict'
need_pattern EBPF-006 internal/ebpf/aggregate.go 'DropStats|Dropped|RecordDropStats|Stats'
need_pattern EBPF-006 internal/ebpf/l7bounds_test.go 'MaxL7Conns|MaxServiceEdges|L7Evicted|Evicted'
need_pattern EBPF-006 internal/ebpf/runtime_test.go 'TestAgentRunReportsDrops|TestAgentRunReportsDetailedKernelDrops|syncDrops'
need_pattern EBPF-006 internal/ebpf/l7/manager_bounds_test.go 'Evicted|SetBounds|N>>cap'
need_pattern EBPF-006 internal/ebpf/bench_test.go 'TestAgentOverheadReport'
need_pattern EBPF-007 deploy/helm/probectl-agent/values.yaml 'capabilityPosture:|probectl-agent-capability-posture|validationFailureAction: Audit|background: true'
need_pattern EBPF-007 deploy/helm/probectl-agent/templates/capability-posture-policy.yaml 'probectl.dev/finding: EBPF-007|AnyNotIn|SYS_ADMIN is legacy break-glass|BPF|PERFMON'
need_pattern EBPF-007 scripts/check_helm_hardening.sh 'capability posture ClusterPolicy missing|acknowledged legacy mode lost capability posture audit policy|SYS_ADMIN is legacy break-glass'
need_pattern EBPF-007 internal/ebpf/deploy_contract_test.go 'TestAgentCapabilityPostureAdmissionAuditsLegacyAndExtraCaps|policy reports|probectl-agent-capability-posture'
need_pattern EBPF-007 docs/ebpf-agent.md 'probectl-agent-capability-posture|policy reports|EBPF-007'
need_pattern EBPF-007 deploy/helm/README.md 'probectl-agent-capability-posture|policy reports|EBPF-007'
need_pattern FUZZ-005 scripts/fuzz_smoke.sh 'go test.*-fuzz|fuzz-smoke'
need_pattern FUZZ-005 scripts/list_fuzz_targets.sh 'Fuzz'
need_pattern FUZZ-007 scripts/check_fuzz_policy.sh 'list_fuzz_targets.sh|FuzzVerifyBatchTenant|FuzzDecodeRemoteWrite|FuzzProviderDecode|fromJSON\(needs.discover-fuzz-targets.outputs.matrix\)'
need_pattern FUZZ-007 scripts/fuzz_smoke.sh 'Failing input written to|context deadline with ZERO executions|list_fuzz_targets.sh|fuzz-smoke: all targets clean'
need_pattern FUZZ-007 scripts/list_fuzz_targets.sh 'roots=\(internal\)|roots\+=\(ee\)|--github-output|sort -u'
need_pattern FUZZ-007 .github/workflows/ci.yml 'make fuzz-policy|make fuzz-smoke|Fuzz smoke \(untrusted-input parsers must not crash\)'
need_pattern FUZZ-007 .github/workflows/nightly.yml 'discover-fuzz-targets|fromJSON\(needs.discover-fuzz-targets.outputs.matrix\)|FUZZ_NIGHTLY_FUZZTIME: "10m"|fuzz-crashers'
need_pattern FUZZ-007 docs/development.md 'internal/` and, when present, `ee/`|PR smoke and the nightly matrix|never panic'
need_pattern FUZZ-008 internal/otel/otlp/receiver.go 'grpc.MaxRecvMsgSize\(maxRecvBytes\)|http.MaxBytesReader|httpbody.ReadLimited|Content-Encoding.*gzip'
need_pattern FUZZ-008 internal/otel/otlp/receiver_gzip_test.go 'TestReadOTLPBodyRejectsOversizedGzipOutput|ErrTooLarge|Content-Encoding'
need_pattern FUZZ-008 internal/promapi/remotewrite.go 'MaxDecodedBytes|snappy.DecodedLen|MaxSeries|MaxSamples|MaxLabels|MaxLabelBytes'
need_pattern FUZZ-008 internal/promapi/remotewrite_fuzz_test.go 'FuzzDecodeRemoteWrite|MaxDecodedBytes|MaxSamples|tenant-a'
need_pattern FUZZ-008 internal/httpbody/body.go 'ReadLimited|LimitReader\(r, maxBytes\+1\)|ErrTooLarge|DecodeHTTPJSONStrict'
need_pattern FUZZ-008 internal/httpbody/body_test.go 'TestReadLimitedRejectsOversizeWithoutTruncation|TestDecodeHTTPJSONStrictUsesMaxBytesReader|ErrTooLarge'
need_pattern FUZZ-008 internal/ebpf/source_live_linux.go 'defer func\(\)|recover\(\)|DecodeFailures|DropStats'
need_pattern FUZZ-008 internal/ebpf/runtime_test.go 'TestAgentRunReportsDetailedKernelDrops|DecodeFailures|L4RingBufferFull'
need_pattern KEYS-004 scripts/check_crypto_imports.sh 'crypto-import guard|internal/crypto'
need_pattern KEYS-004 internal/crypto/crypto.go 'Provider|Random|Encrypt|Decrypt|ConstantTimeEqual|Zeroize'
need_pattern KEYS-004 internal/crypto/crypto.go 'rand.Reader|aes.NewCipher|cipher.NewGCM|hmac.Equal'
need_pattern KEYS-004 internal/crypto/password.go 'PBKDF2-HMAC-SHA256|pbkdf2Key|ConstantTimeEqual'
need_pattern KEYS-004 internal/crypto/selftest.go 'PowerOnSelfTest|SHA-256 KAT|HMAC-SHA-256 KAT|PBKDF2-SHA-256 KAT|AES-GCM'
need_pattern KEYS-005 internal/enroll/enroll.go 'DefaultLeafTTL|DefaultTokenTTL|sealCAKey|tenantcrypto.Seal|tenantcrypto.HasScheme|ErrRevoked'
need_pattern KEYS-005 internal/enroll/enroll.go 'MintToken'
need_pattern KEYS-005 internal/enroll/enroll.go 'Consume\(ctx, crypto.Hash'
need_pattern KEYS-005 internal/enroll/enroll.go 'Rotate verifies the current identity|KnownSerial'
need_pattern KEYS-005 internal/enroll/enroll.go 'ListRevoked'
need_pattern KEYS-005 internal/store/enrollment.go 'token_hash|used_at IS NULL|expires_at > now'
need_pattern KEYS-005 internal/store/enrollment.go 'ConsumeForTenant|RevokeAgent|ListRevoked'
need_pattern KEYS-005 internal/control/enrollapi.go 'SetAgentRevocationPush|handleRevokeAgent|revokePush|agent.enroll_token_minted|RegisterCollectorForTenant'
need_pattern KEYS-005 internal/enroll/seal_test.go 'refuse to persist a plaintext CA key|sealed CA key must not be the plaintext'
need_pattern KEYS-005 internal/enroll/enroll_integration_test.go 'TestEnrollTokenReplayRejected|TestEnrollTokenRevokeBlocksRedeem|TestRevokeAgentPersistsAndBlocksReissuance'
need_pattern KEYS-006 .github/workflows/release.yml 'id-token: write|cosign sign --yes|cosign verify|release\.yml@refs/tags'
need_pattern KEYS-006 scripts/check_cosign_wiring.sh 'cosign-wiring gate|cosign verify-blob|release workflow tag identity pin'
need_pattern KEYS-006 internal/audit/worm.go 'requires a persisted Ed25519 signing key|NewWormExporterEphemeralForTest|ResolveWormSigningKey|refusing to mint an ephemeral'
need_pattern KEYS-006 internal/audit/worm_test.go 'TestWormExporterRefusesEmptyKey|TestResolveWormSigningKeyStableAndFailClosed|ephemeral key must NOT verify'
need_pattern KEYS-006 internal/license/license.go 'VerifyEd25519|trustedPubPEMs|signature verification failed'
need_pattern KEYS-006 cmd/probectl-license/main.go 'KEEP OFFLINE|GenerateEd25519KeyPEM|SignEd25519|Verify'
need_absent KEYS-006 cmd 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 internal 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 ee 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_absent KEYS-006 pkg 'self.?update.*(download|install|apply|exec|binary|package)|auto.?update.*(download|install|apply|exec|binary|package)'
need_pattern KEYS-007 internal/tenantcrypto 'fail|zero|cache|ttl|BYOK|KEK'
need_pattern KEYS-007 internal/control/enrollapi.go 'agent-ca|revoke|SVID|SPIFFE'
need_pattern OPS-005 docs/ops/fleet-rollout.md 'no agent self-update channel|agent never fetches or executes'
need_pattern OPS-005 docs/ops/fleet-rollout.md 'deterministic waves|Verify the artifact|Resume'
need_pattern OPS-005 internal/agent/rollout.go 'VerifiedArtifact|PlanRollout|Advance|Verify|Resume'
need_pattern OPS-005 internal/agent/rollout.go 'unattested artifact|version-skew|waves never overlap|VerifyWindow|HeartbeatSLO'
need_pattern OPS-005 internal/agent/rollout_test.go 'TestPlanRolloutRefusesUnattestedArtifacts|TestRolloutWavesNeverOverlapOrSkip|TestRolloutHaltsOnStragglerAfterWindow|TestRolloutResumeIsExplicitAndRecovers'
need_pattern OPS-006 Makefile 'backup-restore-drill'
need_pattern OPS-006 scripts/backup_postgres.sh 'backup-seal|refusing to write plaintext|PROBECTL_PLAINTEXT_BACKUP_ACK|\\.dump\\.pbk'
need_pattern OPS-006 scripts/restore_postgres.sh 'sha256sum -c|DROP DATABASE|pg_restore'
need_pattern OPS-006 scripts/backup_restore_drill.sh 'backup_postgres did not produce a sealed \\.dump\\.pbk|left a plaintext \\.dump|backup-open|verify marker survival'
need_pattern OPS-007 internal/control/handlers.go 'handleReadyz|draining|apierror.Unavailable\("draining"\)|handleHealthz'
need_pattern OPS-007 internal/control/server.go 'draining.Store\(true\)|ShutdownTimeout|http.Shutdown|context.WithTimeout'
need_pattern OPS-007 internal/control/drain_test.go 'TestReadyzDrains|http.StatusServiceUnavailable|healthz should stay 200'
need_pattern OPS-008 internal/agent/rollout.go 'wave|rollback|budget|pause'
need_pattern OPS-008 scripts/check_version_consistency.sh 'compose|Helm|VERSION'
need_pattern OPS-009 Makefile 'backup-restore-drill|migration-gate|helm-gate'
need_pattern OPS-010 internal/control/handlers.go 'ready|live|drain|shutdown'
need_pattern OPS-010 internal/control/server.go 'Shutdown|draining|ShutdownTimeout'
need_pattern RED-005 internal/agenttransport/streamresults_resilience_test.go 'TestStreamResultsRestampsPayloadIdentityFromMTLS|TenantId:.*tenant-b|evil-agent|authoritative tenant/agent key'
need_pattern RED-005 internal/agenttransport/service.go 'Authoritative identity comes from the mTLS certificate|TenantId = id\.TenantID|AgentId = id\.AgentID'
need_pattern RED-005 internal/agenttransport/freshness.go 'FreshnessSentAtKey|FreshnessNonceKey|stale|replayed'
need_pattern RED-005 internal/agenttransport/freshness_test.go 'TestFreshnessReplayWindow|same nonce inside the window is refused|missing freshness metadata must refuse|TestFreshnessNonceCacheBounded'
need_pattern RED-005 internal/enroll/enroll_integration_test.go 'TestEnrollTokenReplayRejected|wrong-tenant rejection|TestRevokeAgentPersistsAndBlocksReissuance'
need_pattern RED-006 internal/control/rolloutapi_test.go 'TestFleetRCERoutesDoNotAcceptAgentExecutablePayload|image_tag|executable|download_url'
need_pattern RED-006 internal/control/rolloutapi.go 'version, digest, and verify_method are required|VerifiedArtifact'
need_pattern RED-006 internal/agent/rollout.go 'NO agent self-update channel|fetch and exec new code is a fleet-wide RCE primitive|VerifiedArtifact'
need_pattern RED-006 docs/ops/fleet-rollout.md 'no agent self-update channel|agent never fetches or executes|Verified artifacts only'
need_pattern RED-006 deploy/helm/probectl-agent/templates/daemonset.yaml 'privileged eBPF agent image must be digest-pinned|image.allowTagOnly'
need_pattern RED-006 scripts/check_helm_hardening.sh 'RED-003|tag-only|image-integrity|validationFailureAction'
need_pattern RED-007 internal/otel/otlp/receiver_test.go 'out-of-tenant|tenant.*mismatch|spoof'
need_pattern RED-008 scripts/check_cosign_wiring.sh 'cosign|verify'
need_pattern RED-008 scripts/check_supply_pins.sh 'supply-pins'
need_pattern SUPPLY-003 .github/workflows/release.yml 'cosign sign --yes|steps\.build\.outputs\.digest|cosign verify'
need_pattern SUPPLY-003 .github/workflows/release.yml 'cosign sign-blob --yes|all artifacts verify|all packages verify'
need_pattern SUPPLY-003 docs/ops/verify-artifacts.md 'cosign verify-blob|certificate-identity-regexp|release\.yml@refs/tags'
need_pattern SUPPLY-004 scripts/check_cosign_wiring.sh 'install\.sh, airgap bundle, Ansible package_url/airgap, image signing, and admission policy are fail-closed'
need_pattern SUPPLY-004 deploy/agent/install.sh 'PROBECTL_VERIFY_COSIGN:-1|PROBECTL_UNVERIFIED_INSTALL_ACK|cosign verify-blob'
need_pattern SUPPLY-004 deploy/ansible/roles/probectl_agents/tasks/main.yml 'probectl_verify_cosign|cosign verify-blob for the local air-gap package|probectl_airgap_pkg_path'
need_pattern SUPPLY-004 scripts/airgap-bundle.sh 'PROBECTL_AIRGAP_VERIFY_COSIGN:-1|PROBECTL_AIRGAP_UNVERIFIED_ACK|IMAGE-VERIFICATION.txt'
need_pattern SUPPLY-005 internal/ebpf/integrity.go 'VerifyObjectDigest|ObjectDigest|internal/crypto|refusing kernel load'
need_pattern SUPPLY-005 internal/ebpf/trustboundary_test.go 'TestObjectDigestVerificationWiredIntoEveryLoader|TestNoOperatorSuppliedBPFObjectPath|VerifyObjectDigest before the kernel'
need_pattern SUPPLY-005 internal/ebpf/integrity_test.go 'TestVerifyObjectDigest|tampered|missing'
need_pattern SUPPLY-006 scripts/check_supply_pins.sh 'supply-pins SELFTEST|UNPINNED npm manifest dependency|UNPINNED Python manifest dependency|TAG-ONLY container'
need_pattern SUPPLY-006 scripts/check_action_pins.sh 'every workflow action is SHA-pinned|floating action refs'
need_pattern SUPPLY-006 docs/dependency-policy.md 'exact versions|supply-pins gate|semver ranges|digest pin'
need_pattern SUPPLY-007 Makefile 'GOVULNCHECK_VERSION|govulncheck'
need_pattern SUPPLY-007 .github/workflows/security-scan.yml 'govulncheck|npm audit|Gate on High and Critical|severity: CRITICAL,HIGH'
need_pattern SUPPLY-007 .github/workflows/ci.yml 'govulncheck|Trivy filesystem scan|npm audit'
need_pattern SUPPLY-007 scripts/check_npm_audit_policy.mjs 'critical advisory|high advisory|npm audit policy: OK'
need_pattern SUPPLY-007 scripts/verify_all.sh 'govulncheck|trivy fs --scanners vuln --severity CRITICAL,HIGH'

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
