// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// DefaultGroup is the consumer-group name for the control-plane result pipeline.
const DefaultGroup = "probectl-control"

// permanentWrite reports whether a store-write error is one the upstream will
// never accept on retry (a 4xx remote-write reject — out-of-order/too-old
// sample). The result, device, and flow retry loops all short-circuit on it
// and dead-letter immediately rather than burning the backoff budget on a
// write that cannot succeed (CORRECT-003).
func permanentWrite(err error) bool { return errors.Is(err, tsdb.ErrPermanentReject) }

// Consumer drains result messages from the bus and writes them to the TSDB.
type Consumer struct {
	bus        bus.Bus
	tsdb       tsdb.Writer
	group      string
	log        *slog.Logger
	namespaces []string          // siloed bus lanes (S-T2), known at startup
	nsTenants  map[string]string // namespace -> tenant id (lane authority, TENANT-101)
	binding    TenantBinding     // registry-backed verification; nil = unit tests
	gate       *fairness.Gate    // per-tenant ingest bounds (S-T7); nil = unbounded

	rejectedTenant atomic.Uint64 // results dropped by tenant verification

	// Store-write resilience (U-019): bounded retry with jittered backoff,
	// then the dead-letter topic — telemetry loss is never silent.
	maxRetries int
	retryBase  time.Duration
	sleep      func(context.Context, time.Duration) // injectable for tests

	retried      atomic.Uint64 // write attempts beyond the first
	deadLettered atomic.Uint64 // records routed to the DLQ after exhaustion
	dropped      atomic.Uint64 // records lost entirely (DLQ publish ALSO failed)

	// Write-stage decoupling (SCALE-001): decode/verify enqueue onto a
	// BOUNDED channel drained by writeWorkers goroutines doing the remote
	// write (+ retry/DLQ). Enqueue blocks when full — backpressure reaches
	// the bus consumer instead of an unbounded buffer. nil = synchronous
	// (unit tests calling handleLane directly keep the old behavior).
	writeCh      chan writeItem
	writeWorkers int

	// card caps per-agent/per-tenant series identities (U-017); always set.
	card *CardinalityLimiter
}

// ConsumerStats are the consumer's loss-accounting counters (U-019).
type ConsumerStats struct {
	Retried      uint64
	DeadLettered uint64
	Dropped      uint64
}

// Stats reports the cumulative retry/DLQ counters.
func (c *Consumer) Stats() ConsumerStats {
	return ConsumerStats{Retried: c.retried.Load(), DeadLettered: c.deadLettered.Load(), Dropped: c.dropped.Load()}
}

// NewConsumer builds the result-pipeline consumer.
func NewConsumer(b bus.Bus, w tsdb.Writer, group string, log *slog.Logger) *Consumer {
	if group == "" {
		group = DefaultGroup
	}
	return &Consumer{
		bus: b, tsdb: w, group: group, log: log,
		maxRetries: 3,
		retryBase:  50 * time.Millisecond,
		sleep:      sleepCtx,
		card:       NewCardinalityLimiter(0, 0),
	}
}

// WithCardinalityCaps overrides the per-agent / per-tenant series caps
// (U-017); non-positive values keep the defaults.
func (c *Consumer) WithCardinalityCaps(perAgent, perTenant int) *Consumer {
	c.card = NewCardinalityLimiter(perAgent, perTenant)
	return c
}

// CardinalityStats exposes the series-cap rejection counters.
func (c *Consumer) CardinalityStats() CardinalityStats { return c.card.Stats() }

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// WithNamespaces adds siloed tenants' namespaced result lanes (S-T2). The set
// is resolved at startup; a tenant siloed after boot publishes to its lane as
// soon as it exists, and the consumer attaches on the next restart (the
// shared lane remains subscribed throughout, so nothing is ever unconsumed
// for pooled tenants).
func (c *Consumer) WithNamespaces(ns []string) *Consumer {
	c.namespaces = append(c.namespaces, ns...)
	return c
}

// WithNamespaceTenants supplies the namespace -> tenant map so namespaced
// lanes can be the AUTHORITATIVE tenant source for their records (TENANT-101).
func (c *Consumer) WithNamespaceTenants(m map[string]string) *Consumer {
	c.nsTenants = m
	return c
}

// WithTenantBinding installs registry-backed verification of agent-published
// results (the endpoint lanes) — the payload tenant is never authoritative
// (TENANT-101). nil keeps legacy behavior for DB-less unit tests.
func (c *Consumer) WithTenantBinding(b TenantBinding) *Consumer {
	c.binding = b
	return c
}

// RejectedTenant reports results dropped fail-closed by tenant verification.
func (c *Consumer) RejectedTenant() uint64 { return c.rejectedTenant.Load() }

// resultTopics are the bus topics carrying resultv1.Result that the pipeline
// drains into the TSDB. Network-plane probe results (S6), endpoint/DEM results
// (S37) and real-user page views (S47b) share the canonical result schema, so
// one handler serves all three. Each topic gets its own consumer group so
// their offsets are independent. Siloed namespaces (S-T2) add one lane per
// (namespace × topic), each with its own group.
func (c *Consumer) resultTopics() []topicGroup {
	base := []topicGroup{
		// network results are published by the CONTROL PLANE after the mTLS
		// identity re-stamp (agenttransport.ingest) — the publisher is trusted.
		{topic: bus.NetworkResultsTopic, group: c.group},
		// endpoint results are published DIRECTLY by endpoint agents — the
		// payload tenant must be verified against the registry (TENANT-101).
		{topic: bus.EndpointResultsTopic, group: c.group + "-endpoint", verify: true},
		// RUM is published by the control plane's beacon ingest (server-side
		// tenant from the app key); records carry no agent id.
		{topic: bus.RUMEventsTopic, group: c.group + "-rum"},
	}
	out := base
	for _, ns := range c.namespaces {
		if !bus.ValidNamespace(ns) || ns == "" {
			continue
		}
		laneTenant := ""
		if c.nsTenants != nil {
			laneTenant = c.nsTenants[ns]
		}
		for _, b := range base {
			t, err := bus.TopicFor(ns, b.topic)
			if err != nil {
				continue // unreachable: ValidNamespace guarded above
			}
			out = append(out, topicGroup{
				topic:      t,
				group:      b.group + "-" + ns,
				verify:     b.verify,
				laneTenant: laneTenant, // the lane is authoritative (TENANT-101)
			})
		}
	}
	return out
}

type topicGroup struct {
	topic, group string
	verify       bool   // registry-verify the payload (agent-published lanes)
	laneTenant   string // non-empty: namespaced lane bound to one tenant
}

// Run subscribes to every result topic and writes each result to the TSDB until
// ctx is canceled. It blocks. The subscriptions run concurrently; a fatal error
// on any one cancels the rest and is returned.
func (c *Consumer) Run(ctx context.Context) error {
	subs := c.resultTopics()
	topics := make([]string, len(subs))
	for i, s := range subs {
		topics[i] = s.topic
	}
	c.log.Info("result pipeline consumer starting", "topics", topics, "group", c.group)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SCALE-001: the write stage. Decode/verify (the subscription handlers)
	// and the remote write run in separate stages joined by a bounded queue.
	workers := c.writeWorkers
	if workers <= 0 {
		workers = 4
	}
	c.writeCh = make(chan writeItem, workers*16)
	var writeWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		writeWG.Add(1)
		go func() {
			defer writeWG.Done()
			for it := range c.writeCh {
				if err := c.writeWithRetry(ctx, it.series); err != nil {
					c.deadLetter(ctx, it.msg, it.r, err)
				}
			}
		}()
	}
	defer func() {
		close(c.writeCh)
		writeWG.Wait()
		c.writeCh = nil
	}()

	var wg sync.WaitGroup
	errs := make(chan error, len(subs))
	for _, s := range subs {
		wg.Add(1)
		go func(s topicGroup) {
			defer wg.Done()
			h := func(hctx context.Context, msg bus.Message) error { return c.handleLane(hctx, msg, s) }
			if err := c.bus.Subscribe(ctx, s.topic, s.group, h); err != nil && ctx.Err() == nil {
				c.log.Error("result subscription failed", "topic", s.topic, "error", err.Error())
				errs <- err
				cancel() // one topic's fatal error stops the others
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err // a clean ctx cancel pushes nothing → returns nil
		}
	}
	return nil
}

// WithFairness bounds per-tenant admission (S-T7): over-rate tenants are
// shed with accounting BEFORE the expensive section, so one tenant's burst
// cannot stall the shared pipeline. Wrapping the consumer makes the bound
// identical under Kafka and the lightweight bus modes.
func (c *Consumer) WithFairness(g *fairness.Gate) *Consumer {
	c.gate = g
	return c
}

// writeItem carries one decoded record's series to the write stage, plus the
// ORIGINAL message + decoded result for the DLQ path.
type writeItem struct {
	series []tsdb.Series
	msg    bus.Message
	r      *resultv1.Result
}

// WithWriteWorkers sets the write-stage parallelism (default 4 in Run).
func (c *Consumer) WithWriteWorkers(n int) *Consumer {
	if n > 0 {
		c.writeWorkers = n
	}
	return c
}

// handle decodes one result and writes its series. Malformed messages are
// dropped (they can never succeed); transient store-write failures are
// retried with jittered backoff and, after exhaustion, dead-lettered with
// the ORIGINAL bytes (U-019) — never silently lost.
func (c *Consumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, topicGroup{})
}

// handleLane is handle with the lane's tenant-authority context (TENANT-101):
// agent-published lanes (endpoint) verify the payload (tenant, agent) against
// the registry; namespaced lanes overwrite the tenant with the lane's.
func (c *Consumer) handleLane(ctx context.Context, msg bus.Message, lane topicGroup) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		c.log.Error("dropping malformed result", "error", err.Error())
		return nil
	}
	if lane.verify || lane.laneTenant != "" {
		binding := c.binding
		if !lane.verify {
			binding = nil // control-published lane: re-stamp only, no agent check
		}
		tenant, overwritten, verr := VerifyBatchTenant(ctx, binding, lane.laneTenant,
			[]Identity{{Tenant: r.GetTenantId(), Agent: r.GetAgentId()}})
		if verr != nil {
			c.rejectedTenant.Add(1)
			c.log.Error("REJECTED result: tenant verification failed (TENANT-101, fail closed)",
				"claimed_tenant", r.GetTenantId(), "agent_id", r.GetAgentId(),
				"lane_tenant", lane.laneTenant, "topic", lane.topic,
				"rejected_total", c.rejectedTenant.Load(), "error", verr.Error())
			return nil
		}
		if overwritten {
			c.log.Warn("result tenant overwritten by lane (payload disagreed)",
				"claimed_tenant", r.GetTenantId(), "lane_tenant", tenant, "topic", lane.topic)
		}
		r.TenantId = tenant
	}
	// Fairness (S-T7): per-tenant ingest bounds. Shed work is counted on the
	// gate (surfaced via /v1/fairness, the provider console, and TSDB series)
	// — never silent, never another tenant's problem. Shed messages are not
	// metered: billing reflects stored work.
	if c.gate != nil {
		okResults := c.gate.AdmitN(ctx, r.GetTenantId(), fairness.MeterResults, 1)
		okBytes := c.gate.AdmitN(ctx, r.GetTenantId(), fairness.MeterBytes, int64(len(msg.Value)))
		if !okResults || !okBytes {
			c.log.Debug("result shed by fairness bounds", "tenant_id", r.GetTenantId())
			return nil
		}
	}
	// Metering (S-T3): derived from the stream already flowing — a no-op
	// unless the ee/billing recorder is installed at the attach seam.
	usage.Record(r.GetTenantId(), usage.MeterResultsIngested, 1)
	usage.Record(r.GetTenantId(), usage.MeterIngestBytes, int64(len(msg.Value)))
	// Cardinality caps (U-017): NEW series identities past the per-agent /
	// per-tenant caps are rejected per-series and counted; known identities
	// keep flowing, other tenants are untouched.
	series, droppedSeries := c.card.Filter(r.GetTenantId(), r.GetAgentId(), ResultToSeries(&r))
	if droppedSeries > 0 {
		c.log.Warn("series rejected by cardinality cap",
			"tenant_id", r.GetTenantId(), "agent_id", r.GetAgentId(),
			"rejected", droppedSeries, "rejected_total", c.card.Stats().Dropped)
	}
	if len(series) == 0 {
		return nil
	}
	if ch := c.writeCh; ch != nil {
		// Decoupled: block on the BOUNDED queue (backpressure), the write
		// stage owns retry + DLQ. The decode stage moves on to the next
		// message — no per-record synchronous remote-write on this path.
		ch <- writeItem{series: series, msg: msg, r: &r}
		return nil
	}
	if err := c.writeWithRetry(ctx, series); err != nil {
		c.deadLetter(ctx, msg, &r, err)
	}
	return nil
}

// writeWithRetry attempts the store write up to 1+maxRetries times with
// exponential backoff + jitter (50ms, ~100ms, ~200ms by default). A canceled
// context stops retrying immediately.
func (c *Consumer) writeWithRetry(ctx context.Context, series []tsdb.Series) error {
	var err error
	for attempt := 0; ; attempt++ {
		if err = c.tsdb.Write(ctx, series); err == nil {
			return nil
		}
		if attempt >= c.maxRetries || ctx.Err() != nil || permanentWrite(err) {
			return err
		}
		c.retried.Add(1)
		backoff := c.retryBase << attempt
		c.sleep(ctx, backoff+time.Duration(rand.Int64N(int64(backoff)/2+1)))
	}
}

// deadLetter routes the ORIGINAL message bytes to the dead-letter topic
// (tenant-keyed, replayable) and accounts the outcome. A DLQ publish failure
// is the only true loss — it is counted and logged at ERROR.
func (c *Consumer) deadLetter(ctx context.Context, msg bus.Message, r *resultv1.Result, writeErr error) {
	if err := c.bus.Publish(ctx, bus.DeadLetterResultsTopic, msg.Key, msg.Value); err != nil {
		c.dropped.Add(1)
		c.log.Error("RESULT LOST: store write exhausted retries and dead-letter publish failed",
			"tenant_id", r.GetTenantId(), "agent_id", r.GetAgentId(),
			"write_error", writeErr.Error(), "dlq_error", err.Error(),
			"dropped_total", c.dropped.Load())
		return
	}
	c.deadLettered.Add(1)
	c.log.Error("store write exhausted retries — result dead-lettered (replayable)",
		"tenant_id", r.GetTenantId(), "agent_id", r.GetAgentId(),
		"topic", bus.DeadLetterResultsTopic, "error", writeErr.Error(),
		"dead_lettered_total", c.deadLettered.Load())
}
