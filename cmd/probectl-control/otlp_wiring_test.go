// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
		"metrics ingest consumer": `superviseRestart(ctx, "otlp-metrics-consumer"`,
		"traces ingest consumer":  `superviseRestart(ctx, "otlp-traces-consumer"`,
		"logs ingest consumer":    `superviseRestart(ctx, "otlp-logs-consumer"`,
		"metrics export consumer": `superviseRestart(ctx, "otlp-export"`,
		"traces export consumer":  `superviseRestart(ctx, "otlp-trace-export"`,
		"logs export consumer":    `superviseRestart(ctx, "otlp-log-export"`,
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("startOTLPSubsystems must supervise %s with marker %q", name, needle)
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
