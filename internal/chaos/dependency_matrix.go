// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chaos

// DependencyScenario is one required dependency-chaos proof.
//
// The UDP proxy proves probe efficacy against a known network fault. This
// matrix covers the other half: when probectl's own dependencies fail, the
// blast radius, counters, retry/DLQ behavior, and recovery path are explicit
// and backed by named tests.
type DependencyScenario struct {
	ID                string
	Dependency        string
	Fault             string
	BlastRadius       string
	ExpectedSignals   []string
	RetryDLQBehavior  string
	RecoveryAssertion string
	Evidence          []ScenarioEvidence
}

// ScenarioEvidence points at a concrete test or runbook gate that proves part
// of a scenario. TestPattern is the -run regular expression used by the make
// gate when the evidence is a Go test.
type ScenarioEvidence struct {
	Package     string
	TestPattern string
}

// DependencyChaosMatrix returns the release-gated dependency-chaos contract.
func DependencyChaosMatrix() []DependencyScenario {
	out := make([]DependencyScenario, len(dependencyChaosMatrix))
	for i, s := range dependencyChaosMatrix {
		out[i] = s
		out[i].ExpectedSignals = append([]string(nil), s.ExpectedSignals...)
		out[i].Evidence = append([]ScenarioEvidence(nil), s.Evidence...)
	}
	return out
}

var dependencyChaosMatrix = []DependencyScenario{
	{
		ID:          "bus-kafka-producer",
		Dependency:  "Kafka / bus producer",
		Fault:       "broker unreachable or produce latency spikes",
		BlastRadius: "Only the publish hot path for accepted bus records is affected; the bounded async buffer returns a counted shed instead of blocking agents or API handlers.",
		ExpectedSignals: []string{
			"bus.Stats().Shed",
			"bus.Stats().Produced",
			"bus.Stats().Failed",
			"bus.ErrPublishShed",
		},
		RetryDLQBehavior:  "A record that never reaches the broker is returned to the caller as an error so the upstream ACK path can retry; no DLQ is used before broker acceptance.",
		RecoveryAssertion: "A slow broker still completes asynchronous produces when it responds, and a dead broker cannot deadlock Close.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/bus", TestPattern: "TestAsyncPublishShedsOnUnreachableBroker"},
			{Package: "./internal/bus", TestPattern: "TestAsyncPublishLatencyIsolatedFromSlowBroker"},
		},
	},
	{
		ID:          "bus-memory-handler",
		Dependency:  "lightweight in-memory bus",
		Fault:       "subscriber handler errors or subscriber buffer saturation",
		BlastRadius: "Only the failing subscriber lane is retried or shed; draining subscribers continue and publishers receive an explicit loss signal under the opt-in drop policy.",
		ExpectedSignals: []string{
			"bus.Memory.HandlerErrors",
			"bus.Memory.HandlerLost",
			"bus.Memory.Dropped",
			"bus.ErrMemoryDropped",
		},
		RetryDLQBehavior:  "Handler errors redeliver up to a bounded retry budget; permanent failure is counted lost, and drop-policy overflow returns ErrMemoryDropped to prevent silent ACK.",
		RecoveryAssertion: "Transient handler errors redeliver until success; the default block policy keeps every message when a subscriber can drain.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/bus", TestPattern: "TestMemoryRedeliversOnHandlerError"},
			{Package: "./internal/bus", TestPattern: "TestMemoryDropOverflowDoesNotBlock"},
			{Package: "./internal/bus", TestPattern: "TestMemoryBlockPolicyLosesNothing"},
			{Package: "./internal/bus", TestPattern: "TestMemoryDropPolicyReportsLossToPublisher"},
		},
	},
	{
		ID:          "result-tsdb-store",
		Dependency:  "Prometheus remote-write / TSDB writer",
		Fault:       "transient writer error, persistent writer outage, or batching flush failure",
		BlastRadius: "Only the affected tenant-keyed telemetry writes retry or dead-letter; the consumer does not advance the offset before durable write or replayable DLQ outcome.",
		ExpectedSignals: []string{
			"pipeline.Consumer.Stats().Retried",
			"pipeline.Consumer.Stats().DeadLettered",
			"pipeline.Consumer.Stats().Dropped",
			"tsdb.BatchingWriter error",
		},
		RetryDLQBehavior:  "Transient writer errors retry and then store; exhausted writes publish the original bytes to the DLQ, and store+DLQ double failure returns an error so the bus redelivers.",
		RecoveryAssertion: "DLQ payloads keep the original tenant key and replay can reingest them after the writer recovers.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/pipeline", TestPattern: "TestStoreWriteRetriesTransientFailure"},
			{Package: "./internal/pipeline", TestPattern: "TestStoreWriteExhaustionDeadLetters"},
			{Package: "./internal/pipeline", TestPattern: "TestDLQPublishFailureIsCountedLoss"},
			{Package: "./internal/pipeline", TestPattern: "TestDecoupledTrueLossDoesNotCommit"},
			{Package: "./internal/pipeline", TestPattern: "TestDeadLetterReplayReingests"},
			{Package: "./internal/store/tsdb", TestPattern: "TestBatchingWriterPropagatesError"},
		},
	},
	{
		ID:          "flow-device-otlp-stores",
		Dependency:  "flow, device, and OTLP storage/export paths",
		Fault:       "store failure, exporter failure, or tenant registry outage",
		BlastRadius: "The failed signal path retries or redelivers within its own tenant-scoped stream; tenant verification fails closed before any cross-tenant write.",
		ExpectedSignals: []string{
			"pipeline.FlowConsumer dead-letter count",
			"pipeline.DeviceConsumer dead-letter count",
			"pipeline.OTLPMetrics dead-letter count",
			"pipeline.OTLPExportConsumer.Failed",
		},
		RetryDLQBehavior:  "Store failures follow the same retry/DLQ contract as result telemetry; export failures return an error to preserve at-least-once redelivery.",
		RecoveryAssertion: "A recovered store/exporter can drain replayed records without changing the bus tenant authority.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/pipeline", TestPattern: "TestFlowWriteRetryDLQParity"},
			{Package: "./internal/pipeline", TestPattern: "TestDeviceWriteRetryDLQOnTransientFailure"},
			{Package: "./internal/pipeline", TestPattern: "TestOTLPMetricsDeadLettersOnStoreFailure"},
			{Package: "./internal/pipeline", TestPattern: "TestOTLPMetricsDropWhenDLQAlsoFails"},
			{Package: "./internal/pipeline", TestPattern: "TestOTLPExportConsumer"},
			{Package: "./internal/pipeline", TestPattern: "TestOTLPTraceLogExportConsumers"},
			{Package: "./internal/pipeline", TestPattern: "TestVerifyBatchTenant"},
		},
	},
	{
		ID:          "clickhouse-telemetry",
		Dependency:  "ClickHouse telemetry stores",
		Fault:       "HTTP 5xx/429 storm, oversized response, or migration statement failure",
		BlastRadius: "The shared ClickHouse transport opens its circuit breaker and bounded reader before a telemetry fault can become an all-tenant control-plane memory or availability failure.",
		ExpectedSignals: []string{
			"chclient.Conn.BreakerStats().State",
			"chclient.ErrResponseTooLarge",
			"chmigrate version+statement error",
		},
		RetryDLQBehavior:  "Write-path callers see the ClickHouse error and enter their owning retry/DLQ path; failed migrations stop before recording the failed version as applied.",
		RecoveryAssertion: "Healthy 2xx responses keep the breaker closed, and a failed migration can be retried from the last recorded version.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/store/chclient", TestPattern: "TestDo_5xxTripsBreaker"},
			{Package: "./internal/store/chclient", TestPattern: "TestDo_429TripsBreaker"},
			{Package: "./internal/store/chclient", TestPattern: "TestReadResponseBodyBounded"},
			{Package: "./internal/store/chmigrate", TestPattern: "TestStatementFailureStopsAndDoesNotRecord"},
		},
	},
	{
		ID:          "postgres-control-plane",
		Dependency:  "Postgres metadata writer",
		Fault:       "writer failover, writer unavailable, or tenant-lifecycle status source failure",
		BlastRadius: "Mutating requests fail closed with a writer fence while reads and login remain available; lifecycle status degrades open instead of blocking telemetry pipelines.",
		ExpectedSignals: []string{
			"HTTP 503 writer_unavailable",
			"Retry-After",
			"/readyz writes_usable=false",
			"tenant lifecycle degraded status",
		},
		RetryDLQBehavior:  "HTTP writes are rejected before partial mutation; bus consumers rely on uncommitted offsets or DLQ rather than committing uncertain writes.",
		RecoveryAssertion: "After promotion, writes resume; failover-drill records RTO/RPO for the live Postgres topology.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/control", TestPattern: "TestWriteFenceDuringFailover"},
			{Package: "./internal/control", TestPattern: "TestTenantLifecycleDegradesOpen"},
		},
	},
	{
		ID:          "edge-disk-buffer",
		Dependency:  "agent disk-backed store-and-forward buffer",
		Fault:       "control-plane outage, partial reconnect failure, disk byte cap, or corrupt frame tail",
		BlastRadius: "Only the tenant-bound agent buffer fills; byte and record caps reject new frames before disk exhaustion or unbounded allocation.",
		ExpectedSignals: []string{
			"agent.Buffer.Dropped",
			"agent.Buffer.Bytes",
			"agent.ErrBufferFull",
			"torn-tail frame rejection",
		},
		RetryDLQBehavior:  "The agent keeps undrained records on send failure and drains them FIFO after reconnect; over-cap frames are counted and rejected instead of corrupting the queue.",
		RecoveryAssertion: "Buffered records persist across disconnect/reopen and drain in order after the control plane recovers.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/agent", TestPattern: "TestBufferDrainAfterDisconnect"},
			{Package: "./internal/agent", TestPattern: "TestBufferPartialDrainKeepsRemainder"},
			{Package: "./internal/agent", TestPattern: "TestBufferByteBoundRejectsAndCounts"},
			{Package: "./internal/agent", TestPattern: "TestReadFrame_CorruptLengthIsTornTail"},
			{Package: "./internal/agent", TestPattern: "TestReadFrame_JustOverCapRejected"},
		},
	},
	{
		ID:          "memory-pressure",
		Dependency:  "bounded in-process memory surfaces",
		Fault:       "cardinality flood, oversized label set, or oversized ClickHouse response",
		BlastRadius: "A noisy agent/tenant or huge upstream response is rejected or truncated at the owning surface rather than growing shared process memory without bound.",
		ExpectedSignals: []string{
			"pipeline.CardinalityLimiter.Stats().Dropped",
			"pipeline.CardinalityLimiter.Stats().TenantDropped",
			"chclient.ErrResponseTooLarge",
		},
		RetryDLQBehavior:  "Accepted known series keep flowing; rejected new identities and oversized responses are counted and fail closed rather than retried indefinitely.",
		RecoveryAssertion: "Quiet tenants and known identities continue after the flood; small ClickHouse responses still decode normally.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/pipeline", TestPattern: "TestCardinalityLabelCaps"},
			{Package: "./internal/pipeline", TestPattern: "TestCardinalityCapFloodIsolatesTenants"},
			{Package: "./internal/store/chclient", TestPattern: "TestReadResponseBodyBounded"},
		},
	},
	{
		ID:          "control-plane-replica",
		Dependency:  "control-plane replica / pod",
		Fault:       "one replica restarts or is killed during result-derived view updates",
		BlastRadius: "Shared side effects stay single-consumer, while per-replica read views rebuild from their own group; a pod loss cannot split the write-side fanout contract.",
		ExpectedSignals: []string{
			"result fan shared group",
			"result fan per-replica view group",
			"medium replicaCount and PDB",
		},
		RetryDLQBehavior:  "Kafka redelivers uncommitted work to the surviving group member; pure read-model consumers can rebuild without taking ownership of side effects.",
		RecoveryAssertion: "The medium reference topology ships at least three replicas with a PDB and uses separate groups for shared effects versus replica-local read views.",
		Evidence: []ScenarioEvidence{
			{Package: "./internal/control", TestPattern: "TestResultFanUsesPerReplicaViewGroup"},
			{Package: "./internal/control", TestPattern: "TestResultFanDefaultGroupStaysShared"},
			{Package: "./cmd/probectl-control", TestPattern: "TestMediumReferenceShipsCoherentTopology"},
		},
	},
}
