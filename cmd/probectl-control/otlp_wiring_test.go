// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"strings"
	"testing"
)

func TestOTLPSubsystemsWireAllThreeSignals(t *testing.T) {
	src := buildersSource(t)
	for name, needle := range map[string]string{
		"metrics bus topic":          "bus.OTLPMetricsTopic",
		"traces bus topic":           "bus.OTLPTracesTopic",
		"logs bus topic":             "bus.OTLPLogsTopic",
		"metrics bus sink":           "otlp.NewBusSink",
		"traces bus sink":            "otlp.NewBusTraceSink",
		"logs bus sink":              "otlp.NewBusLogSink",
		"metrics ingest consumer":    "pipeline.NewOTLPConsumer",
		"traces ingest consumer":     "pipeline.NewOTLPTraceConsumer",
		"logs ingest consumer":       "pipeline.NewOTLPLogConsumer",
		"metrics export consumer":    "pipeline.NewOTLPExportConsumer",
		"traces export consumer":     "pipeline.NewOTLPTraceExportConsumer",
		"logs export consumer":       "pipeline.NewOTLPLogExportConsumer",
		"three-signal export log":    "otlp export enabled (metrics+traces+logs)",
		"three-signal receiver sink": "otlp.Sinks{",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("startOTLPSubsystems is missing %s marker %q", name, needle)
		}
	}
}

func TestOTLPSubsystemsSuperviseHotIngestionPaths(t *testing.T) {
	src := buildersSource(t)
	for name, needle := range map[string]string{
		"receiver":                `superviseRestart(ctx, "otlp-receiver"`,
		"metrics ingest consumer": `superviseBusLaneRestart(ctx, "otlp-metrics-consumer"`,
		"traces ingest consumer":  `superviseBusLaneRestart(ctx, "otlp-traces-consumer"`,
		"logs ingest consumer":    `superviseBusLaneRestart(ctx, "otlp-logs-consumer"`,
		"metrics export consumer": `superviseBusLaneRestart(ctx, "otlp-export"`,
		"traces export consumer":  `superviseBusLaneRestart(ctx, "otlp-trace-export"`,
		"logs export consumer":    `superviseBusLaneRestart(ctx, "otlp-log-export"`,
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("startOTLPSubsystems must supervise %s with marker %q", name, needle)
		}
	}
	if got := strings.Count(src, "WithNamespaceTenants(snap.tenants)"); got < 6 {
		t.Fatalf("all six OTLP consumers/exporters must subscribe namespaced lanes; got %d WithNamespaceTenants markers", got)
	}
}

func TestOTLPSubsystemsUseTenantBucketKeys(t *testing.T) {
	src := buildersSource(t)
	for name, rawKey := range map[string]string{
		"metrics": "bus.OTLPMetricsTopic, []byte(tenant)",
		"traces":  "bus.OTLPTracesTopic, []byte(tenant)",
		"logs":    "bus.OTLPLogsTopic, []byte(tenant)",
	} {
		if strings.Contains(src, rawKey) {
			t.Fatalf("OTLP %s publish path uses a raw tenant key; use bus.TenantKey(tenant, entropy)", name)
		}
	}
	if got := strings.Count(src, "bus.TenantKey(tenant, entropy)"); got < 3 {
		if got != 1 || strings.Count(src, "publishOTLPBus(ctx, resultBus") < 3 {
			t.Fatalf("OTLP publish paths must route all three signals through publishOTLPBus and bucket with bus.TenantKey; TenantKey uses=%d", got)
		}
	}
}

func buildersSource(t *testing.T) string {
	t.Helper()
	srcBytes, err := os.ReadFile("builders.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(srcBytes)
}
