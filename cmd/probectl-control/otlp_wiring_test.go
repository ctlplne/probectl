// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"os"
	"strings"
	"testing"
)

func TestOTLPSubsystemsWireAllThreeSignals(t *testing.T) {
	srcBytes, err := os.ReadFile("builders.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(srcBytes)
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
