// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import "time"

// HotPathSurfaceKind names the served surface a hot-path SLO applies to.
type HotPathSurfaceKind string

const (
	SurfaceControlAPI HotPathSurfaceKind = "control-api"
	SurfaceOTLPHTTP   HotPathSurfaceKind = "otlp-http"
	SurfaceMCPJSONRPC HotPathSurfaceKind = "mcp-json-rpc"
	SurfaceAgent      HotPathSurfaceKind = "agent-transport"
)

// MeasurementKind names how a row is measured. Trace-derived rows use
// production timing telemetry; benchmark rows point at runnable Go benchmarks.
type MeasurementKind string

const (
	MeasurementTrace     MeasurementKind = "trace"
	MeasurementBenchmark MeasurementKind = "benchmark"
	MeasurementLoadGate  MeasurementKind = "load-gate"
)

// HotPathSurface identifies one concrete served API/transport surface.
type HotPathSurface struct {
	Kind    HotPathSurfaceKind
	Method  string // HTTP method for HTTP surfaces; JSON-RPC method for MCP.
	Pattern string // Route pattern, OTLP path, or transport entry point.
}

// HotPathTargets are the operator-visible "fast enough" numbers for one path.
// Percentiles are ceilings; MinThroughputPerSecond is a floor at the path's
// normal payload shape.
type HotPathTargets struct {
	P50                    time.Duration
	P95                    time.Duration
	P99                    time.Duration
	MinThroughputPerSecond float64
}

// HotPathMeasurement is the receipt a reviewer can run or derive to prove a
// row. Benchmark receipts are exact commands; trace receipts name the emitted
// timing field and source.
type HotPathMeasurement struct {
	Kind    MeasurementKind
	Command string
	Receipt string
	Source  string
}

// HotPathSLO is one user-visible hot path with percentile and throughput
// targets plus a measurement receipt. IDs are stable so audit reports, docs, and
// future benchmark output can grep the same handle.
type HotPathSLO struct {
	ID           string
	Name         string
	Owner        string
	Surfaces     []HotPathSurface
	Targets      HotPathTargets
	Measurements []HotPathMeasurement
	Notes        string
}

// HotPathCatalog returns the GA hot-path SLO denominator. These are deliberately
// conservative GA service objectives, not reference-hardware proof rows: PERF-001
// owns L/XL/XXL validation, while this catalog makes every served path's target and
// receipt explicit enough for CI/review to guard.
func HotPathCatalog() []HotPathSLO {
	controlTrace := HotPathMeasurement{
		Kind:    MeasurementTrace,
		Command: `journalctl -u probectl-control | grep 'duration_ms'`,
		Receipt: "control access log duration_ms, grouped by method+path",
		Source:  "internal/control/middleware.go:accessLog",
	}
	return []HotPathSLO{
		{
			ID:    "hp-agent-control-checkin",
			Name:  "Agent control-plane check-in/read model",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/agents/{id}/ci"},
			},
			Targets: HotPathTargets{P50: 50 * time.Millisecond, P95: 250 * time.Millisecond, P99: 750 * time.Millisecond, MinThroughputPerSecond: 50},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementLoadGate, Command: "make perf-smoke", Receipt: "pooled tenant query latency + isolation smoke", Source: "internal/perf/pooled_integration_test.go:TestPooledMultiTenant"},
			},
			Notes: "The row covers the tenant-scoped agent/CI read path operators hit during rollout and enrollment checks.",
		},
		{
			ID:    "hp-agent-result-push",
			Name:  "Agent result-push ingest",
			Owner: "agenttransport",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceAgent, Method: "StreamResults", Pattern: "probectl.agent.v1.AgentService/StreamResults"},
			},
			Targets: HotPathTargets{P50: 100 * time.Millisecond, P95: 500 * time.Millisecond, P99: 2 * time.Second, MinThroughputPerSecond: 50},
			Measurements: []HotPathMeasurement{
				{
					Kind:    MeasurementBenchmark,
					Command: "go test ./internal/perf -run '^TestAgentResultPushLatency$' -count=1 -v",
					Receipt: "mTLS StreamResults ack latency through agent gRPC, bus flush, and result TSDB write",
					Source:  "internal/perf/agent_result_push_latency_test.go:TestAgentResultPushLatency",
				},
			},
			Notes: "Covers native agent gRPC/mTLS result streams through the bus durability barrier and result pipeline store; downstream incident correlation remains hp-probe-result-to-incident.",
		},
		{
			ID:    "hp-results-latest",
			Name:  "Latest synthetic result read model",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/results/latest"},
			},
			Targets:      HotPathTargets{P50: 75 * time.Millisecond, P95: 300 * time.Millisecond, P99: time.Second, MinThroughputPerSecond: 40},
			Measurements: []HotPathMeasurement{controlTrace},
			Notes:        "Backs the target/result detail views, including waterfall and latency/loss cards.",
		},
		{
			ID:    "hp-incident-feed",
			Name:  "Incident feed and detail",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/incidents"},
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/incidents/{id}"},
			},
			Targets:      HotPathTargets{P50: 100 * time.Millisecond, P95: 500 * time.Millisecond, P99: 1500 * time.Millisecond, MinThroughputPerSecond: 25},
			Measurements: []HotPathMeasurement{controlTrace},
			Notes:        "Covers the hot incident pages before expensive cross-plane expansion.",
		},
		{
			ID:    "hp-incident-correlation",
			Name:  "Incident cross-plane correlation",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/incidents/{id}/cis"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/call", Pattern: "correlate_incident"},
			},
			Targets: HotPathTargets{P50: 250 * time.Millisecond, P95: 1500 * time.Millisecond, P99: 3 * time.Second, MinThroughputPerSecond: 5},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem", Receipt: "MCP tool-call JSON-RPC benchmark", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandleToolCallListTests"},
			},
			Notes: "The control route and MCP tool both enforce tenant first, then RBAC; this row covers their served response budget.",
		},
		{
			ID:    "hp-probe-result-to-incident",
			Name:  "Probe result to incident write",
			Owner: "incident",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceAgent, Method: "publish", Pattern: "probectl.network.results -> incident"},
			},
			Targets: HotPathTargets{P50: 250 * time.Millisecond, P95: 2 * time.Second, P99: 5 * time.Second, MinThroughputPerSecond: 20},
			Measurements: []HotPathMeasurement{
				{
					Kind:    MeasurementLoadGate,
					Command: "go test ./internal/perf -run '^TestProbeResultToIncidentLatency$' -count=1 -v",
					Receipt: "ingest_e2e plus correlation_read and incident_write phase timings",
					Source:  "internal/perf/probe_incident_latency_test.go:TestProbeResultToIncidentLatency",
				},
			},
			Notes: "Measures the write-side user promise: a tenant-bound probe result that raises a signal is correlated and visible as an incident quickly.",
		},
		{
			ID:    "hp-flow-query",
			Name:  "Flow analytics query",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/flows/top"},
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/flows/capacity"},
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/flows/anomalies"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/call", Pattern: "query_flows"},
			},
			Targets: HotPathTargets{P50: 200 * time.Millisecond, P95: time.Second, P99: 2500 * time.Millisecond, MinThroughputPerSecond: 10},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem", Receipt: "MCP JSON-RPC dispatch benchmark", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandleToolCallListTests"},
			},
			Notes: "Applies to tenant-scoped flow summaries used by the flows workspace and RCA evidence.",
		},
		{
			ID:    "hp-topology-read",
			Name:  "Topology graph read",
			Owner: "topology",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/topology"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/call", Pattern: "get_path"},
			},
			Targets: HotPathTargets{P50: 250 * time.Millisecond, P95: 1500 * time.Millisecond, P99: 3 * time.Second, MinThroughputPerSecond: 8},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem", Receipt: "MCP path/tool dispatch benchmark", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandleToolCallListTests"},
			},
			Notes: "Covers graph load for topology/path views; topology rebuild cold-start is a separate resilience row.",
		},
		{
			ID:    "hp-topology-whatif",
			Name:  "Topology what-if simulation",
			Owner: "topology",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "POST", Pattern: "/v1/topology/whatif"},
			},
			Targets:      HotPathTargets{P50: 300 * time.Millisecond, P95: 2 * time.Second, P99: 5 * time.Second, MinThroughputPerSecond: 3},
			Measurements: []HotPathMeasurement{controlTrace},
			Notes:        "The simulation should stay interactive; very large graphs graduate to the scale-gate dataset.",
		},
		{
			ID:    "hp-ai-ask",
			Name:  "AI RCA answer request",
			Owner: "ai",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "POST", Pattern: "/v1/ai/ask"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/call", Pattern: "explain_degradation"},
			},
			Targets: HotPathTargets{P50: 1500 * time.Millisecond, P95: 8 * time.Second, P99: 20 * time.Second, MinThroughputPerSecond: 0.2},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem", Receipt: "MCP tool-call dispatch benchmark; model-adapter latency is measured by deployment traces", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandleToolCallListTests"},
			},
			Notes: "Targets the product response budget around scoped evidence collection plus adapter call; remote model provider latency is deployment-specific.",
		},
		{
			ID:    "hp-mcp-jsonrpc",
			Name:  "MCP JSON-RPC dispatch",
			Owner: "ai",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceMCPJSONRPC, Method: "initialize", Pattern: "initialize"},
				{Kind: SurfaceMCPJSONRPC, Method: "ping", Pattern: "ping"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/list", Pattern: "tools/list"},
				{Kind: SurfaceMCPJSONRPC, Method: "tools/call", Pattern: "tools/call"},
			},
			Targets: HotPathTargets{P50: 50 * time.Millisecond, P95: 250 * time.Millisecond, P99: time.Second, MinThroughputPerSecond: 100},
			Measurements: []HotPathMeasurement{
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandlePing -run '^$' -benchmem", Receipt: "MCP JSON-RPC ping dispatch benchmark", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandlePing"},
				{Kind: MeasurementBenchmark, Command: "go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem", Receipt: "MCP JSON-RPC tool-call benchmark", Source: "internal/ai/mcp/mcp_bench_test.go:BenchmarkHandleToolCallListTests"},
			},
			Notes: "Measures protocol overhead separately from backend tool cost.",
		},
		{
			ID:    "hp-otlp-http-ingest",
			Name:  "OTLP HTTP metrics/traces/logs ingest",
			Owner: "otel",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceOTLPHTTP, Method: "POST", Pattern: "/v1/metrics"},
				{Kind: SurfaceOTLPHTTP, Method: "POST", Pattern: "/v1/traces"},
				{Kind: SurfaceOTLPHTTP, Method: "POST", Pattern: "/v1/logs"},
			},
			Targets: HotPathTargets{P50: 20 * time.Millisecond, P95: 100 * time.Millisecond, P99: 250 * time.Millisecond, MinThroughputPerSecond: 200},
			Measurements: []HotPathMeasurement{
				{Kind: MeasurementBenchmark, Command: "go test ./internal/otel/otlp -bench BenchmarkOTLPHTTP -run '^$' -benchmem", Receipt: "OTLP HTTP signal handler benchmarks", Source: "internal/otel/otlp/receiver_bench_test.go"},
				{Kind: MeasurementLoadGate, Command: "make load-test-smoke", Receipt: "full-stack Kafka+Prometheus ingest/query smoke", Source: "internal/perf/fullstack_integration_test.go:TestFullStackLoadGate"},
			},
			Notes: "Targets handler overhead after TLS termination/auth; payload-size and backend-write scale are covered by the full-stack load gate.",
		},
		{
			ID:    "hp-prom-query",
			Name:  "Prometheus-compatible query/federation",
			Owner: "control",
			Surfaces: []HotPathSurface{
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/grafana/api/v1/query"},
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/grafana/api/v1/query_range"},
				{Kind: SurfaceControlAPI, Method: "GET", Pattern: "/v1/prometheus/federate"},
			},
			Targets: HotPathTargets{P50: 150 * time.Millisecond, P95: 750 * time.Millisecond, P99: 2 * time.Second, MinThroughputPerSecond: 15},
			Measurements: []HotPathMeasurement{
				controlTrace,
				{Kind: MeasurementLoadGate, Command: "make load-test-smoke", Receipt: "tenant-scoped PromQL count query leg", Source: "internal/perf/fullstack_integration_test.go:TestFullStackLoadGate"},
			},
			Notes: "Covers Grafana datasource and federated scrape reads; long range-query fanout belongs to full-stack/reference runs.",
		},
	}
}

// HotPathByID returns one catalog row by stable ID.
func HotPathByID(id string) (HotPathSLO, bool) {
	for _, hp := range HotPathCatalog() {
		if hp.ID == id {
			return hp, true
		}
	}
	return HotPathSLO{}, false
}
