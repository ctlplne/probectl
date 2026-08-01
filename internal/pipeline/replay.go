// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
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

// The DLQ→source mapping is bus.SourceTopicForDeadLetter (S-f02d4e59): each
// lane's dead letters replay into the SAME lane they left — the endpoint lane
// re-verifies agent bindings, namespaced (siloed) lanes re-apply their lane
// tenant — so replay re-enters through a path that re-applies exactly the
// authority the record was originally admitted under. A DLQ topic with no
// mapping is a programming error (fail closed).

// ReplayableTopics returns the base dead-letter topics the replayer
// understands (namespaced variants of each replay too).
func ReplayableTopics() []string {
	return []string{
		bus.DeadLetterResultsTopic,
		bus.DeadLetterResultsTopic + ".endpoint",
		bus.DeadLetterResultsTopic + ".rum",
		bus.DeadLetterDeviceTopic,
		bus.DeadLetterFlowTopic,
		bus.DeadLetterOTLPMetricsTopic,
		bus.DeadLetterOTLPTracesTopic,
		bus.DeadLetterOTLPLogsTopic,
	}
}

// SourceTopicFor returns the source topic a dead-letter topic replays into.
func SourceTopicFor(dlqTopic string) (string, bool) {
	return bus.SourceTopicForDeadLetter(dlqTopic)
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
	// Refused counts legacy records that failed tenant re-verification and
	// were NOT replayed (fail closed).
	Refused int
}

// DeadLetterReplayer re-ingests dead-lettered records.
type DeadLetterReplayer struct {
	bus     bus.Bus
	log     *slog.Logger
	binding TenantBinding
}

// WithBinding attaches the agents registry so replay of the LEGACY shared
// results DLQ can re-verify records before handing them to the trusted
// network lane. Pre-S-f02d4e59 deployments parked endpoint- and RUM-lane
// records on that shared topic; replaying that residue verbatim would launder
// an unverified payload tenant through the trusted lane. With a binding, each
// legacy record's (tenant, agent) is re-checked and a failure is REFUSED
// (counted, logged) — the same fail-closed posture as first ingest. New dead
// letters land on per-lane topics whose replay re-enters verifying lanes, so
// they need no replayer-side check.
func (r *DeadLetterReplayer) WithBinding(b TenantBinding) *DeadLetterReplayer {
	r.binding = b
	return r
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
	src, ok := bus.SourceTopicForDeadLetter(cfg.DLQTopic)
	if !ok {
		return ReplayResult{}, fmt.Errorf("replay: %q is not a known dead-letter topic (want one of %v)", cfg.DLQTopic, ReplayableTopics())
	}
	// The legacy shared results DLQ replays into the TRUSTED network lane; its
	// records may predate per-lane dead-lettering. Refuse to replay it without
	// a binding to re-verify against (fail closed), and re-verify each record.
	verifyLegacy := cfg.DLQTopic == bus.DeadLetterResultsTopic
	if verifyLegacy && r.binding == nil {
		return ReplayResult{}, fmt.Errorf("replay: %s re-enters the trusted network lane; a tenant binding is required to re-verify parked records (fail closed)", bus.DeadLetterResultsTopic)
	}
	group := cfg.Group
	if group == "" {
		group = DefaultGroup + "-dlq-replay"
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = 5 * time.Second
	}

	var replayed, refused atomic.Int64
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
		if verifyLegacy {
			if err := r.verifyLegacyResult(hctx, msg); err != nil {
				refused.Add(1)
				r.log.Error("REFUSED dead-letter replay: legacy record failed tenant re-verification (fail closed)",
					"dlq_topic", cfg.DLQTopic, "error", err.Error(), "refused_total", refused.Load())
				return nil // consumed (never replayed); operators triage from the log + count
			}
		}
		// Re-publish to the SOURCE topic, preserving the tenant key + original
		// payload verbatim — the record re-enters the normal ingest path.
		if err := r.bus.Publish(hctx, src, msg.Key, msg.Value); err != nil {
			// Leave uncommitted → redelivered; never silently lose a record.
			return fmt.Errorf("replay: re-publish to %s: %w", src, err)
		}
		if _, inProcess := r.bus.(*bus.Memory); !inProcess {
			if flusher, ok := r.bus.(bus.Flusher); ok {
				if err := flusher.Flush(hctx); err != nil {
					// Leave the DLQ offset uncommitted until the replayed source
					// record is broker-durable/processed. Kafka Publish is async.
					return fmt.Errorf("replay: flush re-published record to %s: %w", src, err)
				}
			}
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
	res := ReplayResult{DLQTopic: cfg.DLQTopic, SourceTopic: src, Replayed: int(replayed.Load()), Refused: int(refused.Load())}
	r.log.Info("dead-letter replay finished", "dlq_topic", cfg.DLQTopic, "source_topic", src,
		"replayed", res.Replayed, "refused", res.Refused)
	return res, nil
}

// verifyLegacyResult re-verifies one legacy shared-DLQ record: the payload's
// claimed (tenant, agent) must still be bound in the agents registry, and the
// bus key must agree with the payload tenant. Anything unverifiable is
// refused — including RUM records (no agent id), which cannot prove a binding
// and predate per-lane dead-lettering.
func (r *DeadLetterReplayer) verifyLegacyResult(ctx context.Context, msg bus.Message) error {
	var rec resultv1.Result
	if err := proto.Unmarshal(msg.Value, &rec); err != nil {
		return fmt.Errorf("undecodable result payload: %w", err)
	}
	tenant, agent := rec.GetTenantId(), rec.GetAgentId()
	if tenant == "" || agent == "" {
		return fmt.Errorf("record carries no verifiable identity (tenant %q, agent %q)", tenant, agent)
	}
	if keyTenant := string(tenantFromKey(msg.Key)); keyTenant != "" && keyTenant != tenant {
		return fmt.Errorf("bus key tenant %q disagrees with payload tenant %q", keyTenant, tenant)
	}
	if err := r.binding.Verify(ctx, tenant, agent); err != nil {
		return fmt.Errorf("agent %q is not bound to tenant %q: %w", agent, tenant, err)
	}
	return nil
}
