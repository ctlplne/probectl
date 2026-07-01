// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"log/slog"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
)

// ResultFan is the decode-once fan-out for the control plane's sidecar result
// consumers (Sprint 14, SCALE-013). Before it, six subscribers (result views,
// threat-intel IOC, TLS posture, NDR DNS, outage vantage, RUM synthetic) each
// held their own consumer group and independently unmarshaled EVERY result —
// a 6× read + decode multiplier on the hottest topic. The fan subscribes
// ONCE, unmarshals ONCE, and hands the SAME decoded record to every sink.
//
// Contract: sinks treat the record as IMMUTABLE — it is shared across all of
// them. A sink error is logged and counted, never fails the stream and never
// blocks the other sinks (these are derived caches/signals; the durable
// pipeline is the separate tsdb consumer with retry+DLQ).
type ResultFan struct {
	bus       bus.Bus
	log       *slog.Logger
	group     string
	sinks     []ResultSink
	nsTenants map[string]string

	decoded   atomic.Uint64
	sinkFails atomic.Uint64
}

// ResultSink is one downstream consumer of decoded results.
type ResultSink struct {
	Name string
	Fn   func(ctx context.Context, r *resultv1.Result) error
}

// NewResultFan builds the fan over the shared result topic.
func NewResultFan(b bus.Bus, log *slog.Logger, sinks ...ResultSink) *ResultFan {
	if log == nil {
		log = slog.Default()
	}
	return &ResultFan{bus: b, log: log, group: "result-fan", sinks: sinks}
}

// WithGroup overrides the consumer group. Shared side-effect fans keep the
// default "result-fan"; pure read-model fans can use a per-replica view group.
func (f *ResultFan) WithGroup(group string) *ResultFan {
	if group != "" {
		f.group = group
	}
	return f
}

// WithViewGroup makes this fan a pure read-model consumer: every control-plane
// replica gets its own group and therefore fans in the complete result stream.
func (f *ResultFan) WithViewGroup(base string) *ResultFan {
	return f.WithGroup(viewGroup(base))
}

// WithNamespaceTenants subscribes the fan to each siloed tenant's result lane.
func (f *ResultFan) WithNamespaceTenants(ns map[string]string) *ResultFan {
	f.nsTenants = ns
	return f
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (f *ResultFan) LaneFanoutEnabled() bool { return true }

// Run subscribes (one group per lane, one decode per message) until ctx is canceled.
func (f *ResultFan) Run(ctx context.Context) error {
	names := make([]string, len(f.sinks))
	for i, s := range f.sinks {
		names[i] = s.Name
	}
	f.log.Info("result fan starting (decode once, fan out)", "group", f.group, "sinks", names)
	return pipeline.RunLanes(ctx, f.bus, bus.NetworkResultsTopic, f.group, f.nsTenants, f.handleLane)
}

func (f *ResultFan) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		f.log.Warn("result fan: skipping malformed result", "error", err)
		return nil
	}
	stampResultLaneTenant(&r, laneTenant)
	f.decoded.Add(1)
	for _, s := range f.sinks {
		if err := s.Fn(ctx, &r); err != nil {
			f.sinkFails.Add(1)
			f.log.Warn("result sink failed (continuing)", "sink", s.Name, "error", err.Error())
		}
	}
	return nil
}

// Decoded reports messages decoded (each exactly once).
func (f *ResultFan) Decoded() uint64 { return f.decoded.Load() }

// runResultSink is the standalone-mode helper the individual consumers' Run
// methods use (tests / non-fan deployments): one subscription, one decode,
// one typed sink — the same code path the fan exercises.
func runResultSinkLanes(ctx context.Context, b bus.Bus, group string, log *slog.Logger, nsTenants map[string]string, sink func(context.Context, *resultv1.Result) error) error {
	return pipeline.RunLanes(ctx, b, bus.NetworkResultsTopic, group, nsTenants, func(ctx context.Context, msg bus.Message, laneTenant string) error {
		var r resultv1.Result
		if err := proto.Unmarshal(msg.Value, &r); err != nil {
			log.Warn("skipping malformed result", "error", err)
			return nil
		}
		stampResultLaneTenant(&r, laneTenant)
		return sink(ctx, &r)
	})
}
