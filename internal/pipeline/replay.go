// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// Dead-letter replay (ARCH-001).
//
// Records that exhausted their store-write retry budget are dead-lettered to
// probectl.deadletter.* topics with the ORIGINAL marshaled payload, tenant-keyed
// (consumer.go / flow.go / device.go / otlpdlq.go). Before this there was no way
// for the product itself to reprocess them — the only "recovery" was ad-hoc
// operator tooling. DeadLetterReplayer drains a DLQ topic and re-publishes each
// record to its SOURCE topic, so the normal ingest consumers pick it up again
// (an at-least-once round trip — dedup downstream collapses any double-apply).
//
// It is a one-shot drain, not a daemon: it stops after IdleTimeout with no new
// record (so a CLI invocation terminates) or when MaxRecords is reached. The
// key (tenant) and value (original payload) are preserved verbatim, so a
// replayed record lands with its original tenant/series — never reattributed.

// dlqSource maps each dead-letter topic to the source topic its records replay
// into. A DLQ topic with no mapping is a programming error (fail closed).
var dlqSource = map[string]string{
	bus.DeadLetterBGPTopic:         bus.BGPEventsTopic,
	bus.DeadLetterResultsTopic:     bus.NetworkResultsTopic,
	bus.DeadLetterDeviceTopic:      bus.DeviceMetricsTopic,
	bus.DeadLetterFlowTopic:        bus.FlowEventsTopic,
	bus.DeadLetterOTLPMetricsTopic: bus.OTLPMetricsTopic,
	bus.DeadLetterOTLPTracesTopic:  bus.OTLPTracesTopic,
	bus.DeadLetterOTLPLogsTopic:    bus.OTLPLogsTopic,
}

// ReplayableTopics returns the dead-letter topics the replayer understands.
func ReplayableTopics() []string {
	out := make([]string, 0, len(dlqSource))
	for t := range dlqSource {
		out = append(out, t)
	}
	return out
}

// SourceTopicFor returns the source topic a dead-letter topic replays into.
func SourceTopicFor(dlqTopic string) (string, bool) {
	src, ok := dlqSource[dlqTopic]
	return src, ok
}

// ReplayConfig configures one DLQ drain.
type ReplayConfig struct {
	DLQTopic    string        // the probectl.deadletter.* topic to drain
	Group       string        // consumer group (default: a dedicated replay group)
	MaxRecords  int           // stop after N records (0 = unbounded until idle)
	MaxPerSec   float64       // throttle re-publish rate (0 = unthrottled)
	IdleTimeout time.Duration // stop after this long with no new record (default 5s)
}

// ReplayResult reports a drain's outcome.
type ReplayResult struct {
	DLQTopic    string
	SourceTopic string
	Replayed    int
}

// DeadLetterReplayer re-ingests dead-lettered records.
type DeadLetterReplayer struct {
	bus bus.Bus
	log *slog.Logger
}

// NewDeadLetterReplayer builds a replayer over the same bus the control plane
// uses (so it publishes to the live source topics).
func NewDeadLetterReplayer(b bus.Bus, log *slog.Logger) *DeadLetterReplayer {
	if log == nil {
		log = slog.Default()
	}
	return &DeadLetterReplayer{bus: b, log: log}
}

// Replay drains cfg.DLQTopic and re-publishes each record to its source topic.
// It blocks until idle, MaxRecords, or ctx cancellation, then returns counts.
func (r *DeadLetterReplayer) Replay(ctx context.Context, cfg ReplayConfig) (ReplayResult, error) {
	src, ok := dlqSource[cfg.DLQTopic]
	if !ok {
		return ReplayResult{}, fmt.Errorf("replay: %q is not a known dead-letter topic (want one of %v)", cfg.DLQTopic, ReplayableTopics())
	}
	group := cfg.Group
	if group == "" {
		group = DefaultGroup + "-dlq-replay"
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = 5 * time.Second
	}

	var replayed atomic.Int64
	// minInterval throttles re-publish to MaxPerSec.
	var minInterval time.Duration
	if cfg.MaxPerSec > 0 {
		minInterval = time.Duration(float64(time.Second) / cfg.MaxPerSec)
	}
	var last time.Time

	// A child context we cancel on idle/MaxRecords so Subscribe returns.
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Idle watchdog: cancel if no record arrives within idle.
	gotOne := make(chan struct{}, 1)
	go func() {
		timer := time.NewTimer(idle)
		defer timer.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case <-gotOne:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idle)
			case <-timer.C:
				cancel() // idle: nothing left to drain
				return
			}
		}
	}()

	r.log.Info("dead-letter replay starting", "dlq_topic", cfg.DLQTopic, "source_topic", src,
		"max_records", cfg.MaxRecords, "max_per_sec", cfg.MaxPerSec, "idle_timeout", idle.String())

	handle := func(hctx context.Context, msg bus.Message) error {
		select {
		case gotOne <- struct{}{}:
		default:
		}
		if minInterval > 0 {
			if d := minInterval - time.Since(last); d > 0 {
				select {
				case <-time.After(d):
				case <-hctx.Done():
					return hctx.Err()
				}
			}
			last = time.Now()
		}
		// Re-publish to the SOURCE topic, preserving the tenant key + original
		// payload verbatim — the record re-enters the normal ingest path.
		if err := r.bus.Publish(hctx, src, msg.Key, msg.Value); err != nil {
			// Leave uncommitted → redelivered; never silently lose a record.
			return fmt.Errorf("replay: re-publish to %s: %w", src, err)
		}
		n := replayed.Add(1)
		if cfg.MaxRecords > 0 && int(n) >= cfg.MaxRecords {
			cancel() // reached the cap
		}
		return nil
	}

	err := r.bus.Subscribe(subCtx, cfg.DLQTopic, group, handle)
	// A canceled subCtx (idle / cap / parent cancel) is the normal stop, not an error.
	if err != nil && subCtx.Err() == nil && ctx.Err() == nil {
		return ReplayResult{}, err
	}
	res := ReplayResult{DLQTopic: cfg.DLQTopic, SourceTopic: src, Replayed: int(replayed.Load())}
	r.log.Info("dead-letter replay finished", "dlq_topic", cfg.DLQTopic, "source_topic", src, "replayed", res.Replayed)
	return res, nil
}
