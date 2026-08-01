// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pipeline

import (
	"context"
	"errors"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
)

type fakeExporter struct {
	calls int
	fail  bool
}

func (f *fakeExporter) ExportMetrics(_ context.Context, _ *colmetricspb.ExportMetricsServiceRequest) error {
	f.calls++
	if f.fail {
		return errors.New("collector down")
	}
	return nil
}

// ARCH-007: a successful export is counted; an export failure returns an error
// (so the at-least-once consumer redelivers) and is counted as failed — never a
// silent drop. A malformed payload is dropped without erroring the stream.
func TestOTLPExportConsumer(t *testing.T) {
	payload, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{}},
	})

	// Success path.
	exp := &fakeExporter{}
	c := NewOTLPExportConsumer(bus.NewMemory(), exp, testLogger())
	if err := c.handle(context.Background(), bus.Message{Value: payload}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if c.Exported() != 1 || c.Failed() != 0 {
		t.Fatalf("success counters: exported=%d failed=%d", c.Exported(), c.Failed())
	}

	// Failure path → error returned (redelivery) + counted.
	expF := &fakeExporter{fail: true}
	cf := NewOTLPExportConsumer(bus.NewMemory(), expF, testLogger())
	if err := cf.handle(context.Background(), bus.Message{Value: payload}); err == nil {
		t.Fatal("export failure must return an error so the record redelivers")
	}
	if cf.Failed() != 1 {
		t.Fatalf("failure not counted: %d", cf.Failed())
	}

	// Malformed payload is dropped, not errored.
	if err := c.handle(context.Background(), bus.Message{Value: []byte("garbage")}); err != nil {
		t.Fatalf("malformed payload must not error the stream: %v", err)
	}
}

type fakeSignalExporter struct {
	traces int
	logs   int
}

func (f *fakeSignalExporter) ExportTraces(_ context.Context, _ *coltracepb.ExportTraceServiceRequest) error {
	f.traces++
	return nil
}

func (f *fakeSignalExporter) ExportLogs(_ context.Context, _ *collogspb.ExportLogsServiceRequest) error {
	f.logs++
	return nil
}

// TestOTLPTraceExportConsumer / Logs: ARCH-003 — ingested traces/logs published
// to their bus topics are drained by the export consumers and forwarded to the
// external collector (the wired re-export path). A failed forward redelivers.
func TestOTLPTraceLogExportConsumers(t *testing.T) {
	tracePayload, _ := proto.Marshal(&coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{}},
	})
	logPayload, _ := proto.Marshal(&collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{}},
	})

	exp := &fakeSignalExporter{}
	tc := NewOTLPTraceExportConsumer(bus.NewMemory(), exp, testLogger())
	if err := tc.handle(context.Background(), bus.Message{Value: tracePayload}); err != nil {
		t.Fatalf("trace export: %v", err)
	}
	lc := NewOTLPLogExportConsumer(bus.NewMemory(), exp, testLogger())
	if err := lc.handle(context.Background(), bus.Message{Value: logPayload}); err != nil {
		t.Fatalf("log export: %v", err)
	}
	if exp.traces != 1 || exp.logs != 1 {
		t.Fatalf("forwards: traces=%d logs=%d, want 1/1", exp.traces, exp.logs)
	}
	if tc.Exported() != 1 || lc.Exported() != 1 {
		t.Fatalf("exported counters: traces=%d logs=%d", tc.Exported(), lc.Exported())
	}

	// Malformed payloads are dropped, not errored.
	if err := tc.handle(context.Background(), bus.Message{Value: []byte("x")}); err != nil {
		t.Fatalf("malformed trace payload must not error: %v", err)
	}
	if err := lc.handle(context.Background(), bus.Message{Value: []byte("x")}); err != nil {
		t.Fatalf("malformed log payload must not error: %v", err)
	}
}
