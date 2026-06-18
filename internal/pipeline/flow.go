// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// FlowGroup is the consumer-group name for the flow pipeline (its offsets are
// independent of the result pipeline's).
const FlowGroup = DefaultGroup + "-flow"

// FlowEnricher fills ASN/geo for an IP (the S15 opendata enricher). nil
// disables enrichment — sovereignty first: external lookups are opt-in, and
// device-asserted AS numbers (NetFlow v5/v9/IPFIX export them) still flow
// through untouched.
type FlowEnricher interface {
	Enrich(ctx context.Context, ip string) (opendata.Enrichment, error)
}

// FlowConsumer drains probectl.flow.events into the flow store, enriching
// records on the way in (once, at ingest — not at query time).
type FlowConsumer struct {
	bus    bus.Bus
	store  flowstore.Store
	enrich FlowEnricher
	group  string
	log    *slog.Logger
	gate   *fairness.Gate // per-tenant ingest bounds (S-T7); nil = unbounded

	// Server-side tenant binding (TENANT-101): payload tenants are verified
	// against the agents registry (shared lane) or overwritten by the lane
	// tenant (namespaced lanes). nil binding = unit tests only.
	binding    TenantBinding
	nsTenants  map[string]string // bus namespace -> tenant id (siloed lanes)
	strictLane bool              // WIRE-001: refuse the shared pooled lane

	rejected    atomic.Uint64 // batches dropped fail-closed (TENANT-101)
	overwritten atomic.Uint64 // payload tenant corrected to the lane tenant

	// Store-write resilience (CORRECT-010 / SCALE-005): the flow plane now
	// rides the SAME retry+DLQ contract as the result + device pipelines —
	// transient store failures retry with jittered backoff, exhaustion
	// dead-letters the ORIGINAL bytes, and loss is never silent. Previously the
	// handler merely logged the insert error and dropped the batch while the
	// comment claimed parity with the result pipeline; it lied.
	maxRetries   int
	retryBase    time.Duration
	sleep        func(context.Context, time.Duration)
	retried      atomic.Uint64
	deadLettered atomic.Uint64
	dropped      atomic.Uint64
	ledger       *integrityLedger
}

// DeadLettered reports flow batches routed to the DLQ after store exhaustion.
func (c *FlowConsumer) DeadLettered() uint64 { return c.deadLettered.Load() }

// Dropped reports flow batches lost entirely (the DLQ publish ALSO failed).
func (c *FlowConsumer) Dropped() uint64 { return c.dropped.Load() }

// IntegrityStats returns the aggregate receipt ledger for this consumer.
func (c *FlowConsumer) IntegrityStats() IntegrityStats { return c.ledger.stats() }

// WithMetrics exports the aggregate receipt ledger at /metrics.
func (c *FlowConsumer) WithMetrics(reg *metrics.Registry) *FlowConsumer {
	c.ledger.withMetrics(reg)
	return c
}

// NewFlowConsumer builds the consumer; enrich may be nil.
func NewFlowConsumer(b bus.Bus, st flowstore.Store, enrich FlowEnricher, log *slog.Logger) *FlowConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &FlowConsumer{
		bus: b, store: st, enrich: enrich, group: FlowGroup, log: log,
		maxRetries: 3, retryBase: 50 * time.Millisecond, sleep: sleepCtx,
		ledger: newIntegrityLedger("flow"),
	}
}

// lanes returns every subscription: the shared topic plus one namespaced
// lane per siloed tenant (TENANT-107).
func (c *FlowConsumer) lanes() ([]laneSub, error) {
	subs := []laneSub{{topic: bus.FlowEventsTopic, group: c.group}}
	for ns, tid := range c.nsTenants {
		t, err := bus.TopicFor(ns, bus.FlowEventsTopic)
		if err != nil {
			return nil, err // RED-006: a malformed namespace is fatal, never shared-lane
		}
		subs = append(subs, laneSub{topic: t, group: c.group + "-" + ns, laneTenant: tid})
	}
	return subs, nil
}

// Run subscribes until ctx is canceled. It blocks.
func (c *FlowConsumer) Run(ctx context.Context) error {
	subs, lerr := c.lanes()
	if lerr != nil {
		return lerr
	}
	if len(subs) > 1 {
		ctx2, cancel := context.WithCancel(ctx)
		defer cancel()
		errs := make(chan error, len(subs))
		var wg sync.WaitGroup
		for _, s := range subs {
			wg.Add(1)
			go func(s laneSub) {
				defer wg.Done()
				h := func(hctx context.Context, msg bus.Message) error { return c.handleLane(hctx, msg, s.laneTenant) }
				if err := c.bus.Subscribe(ctx2, s.topic, s.group, h); err != nil && ctx2.Err() == nil {
					errs <- err
					cancel()
				}
			}(s)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return err
			}
		}
		return nil
	}
	c.log.Info("flow pipeline consumer starting", "topic", bus.FlowEventsTopic, "group", c.group,
		"enrichment", c.enrich != nil)
	if err := c.bus.Subscribe(ctx, bus.FlowEventsTopic, c.group, c.handle); err != nil && ctx.Err() == nil {
		c.log.Error("flow subscription failed", "error", err.Error())
		return err
	}
	return nil
}

// WithFairness bounds per-tenant flow admission (S-T7, see Consumer.WithFairness).
func (c *FlowConsumer) WithFairness(g *fairness.Gate) *FlowConsumer {
	c.gate = g
	return c
}

// WithTenantBinding installs the registry-backed tenant verification
// (TENANT-101). Production always sets it; nil keeps legacy behavior for
// DB-less unit tests.
func (c *FlowConsumer) WithTenantBinding(b TenantBinding) *FlowConsumer {
	c.binding = b
	return c
}

// WithStrictTenantLanes enables WIRE-001 strict-lane mode: flow batches are
// refused on the shared pooled lane and must arrive on a tenant-namespaced
// lane. Off by default; on in the multi-tenant/regulated profile.
func (c *FlowConsumer) WithStrictTenantLanes(strict bool) *FlowConsumer {
	c.strictLane = strict
	return c
}

// WithNamespaceTenants subscribes the consumer to each siloed tenant's
// namespaced flow lane (TENANT-107) and makes the lane the authoritative
// tenant for records arriving on it.
func (c *FlowConsumer) WithNamespaceTenants(ns map[string]string) *FlowConsumer {
	c.nsTenants = ns
	return c
}

// RejectedBatches reports batches dropped by tenant verification.
func (c *FlowConsumer) RejectedBatches() uint64 { return c.rejected.Load() }

// handle serves the shared lane.
func (c *FlowConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

// handleLane decodes one FlowBatch, VERIFIES its tenant (TENANT-101: the
// payload is never authoritative — the lane tenant or the agents registry
// is), re-stamps, enriches, and inserts. Malformed/unverifiable messages are
// dropped fail-closed and counted; transient store failures retry with
// jittered backoff and, on exhaustion, dead-letter the ORIGINAL bytes — real
// parity with the result + device pipelines (CORRECT-010).
func (c *FlowConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	c.ledger.addReceived(1)
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.ledger.addMalformed(1)
		c.log.Error("dropping malformed flow batch", "error", err.Error())
		return nil
	}
	if len(batch.Flows) == 0 {
		return nil
	}
	ids := make([]Identity, len(batch.Flows))
	for i, f := range batch.Flows {
		ids[i] = Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
	}
	tenant, overwritten, verr := VerifyBatchTenantStrict(ctx, c.binding, laneTenant, c.strictLane, ids)
	if verr != nil {
		c.rejected.Add(1)
		c.ledger.addTenantRejected(1)
		noteTenantRejection()
		c.log.Error("REJECTED flow batch: tenant verification failed (TENANT-101, fail closed)",
			"claimed_tenant", ids[0].Tenant, "agent_id", ids[0].Agent,
			"lane_tenant", laneTenant, "rows", len(batch.Flows),
			"rejected_total", c.rejected.Load(), "error", verr.Error())
		return nil
	}
	if overwritten {
		c.overwritten.Add(1)
		c.log.Warn("flow batch tenant overwritten by lane (payload disagreed)",
			"claimed_tenant", ids[0].Tenant, "lane_tenant", tenant, "agent_id", ids[0].Agent)
	}
	for _, f := range batch.Flows {
		f.TenantId = tenant // authoritative re-stamp before anything persists
	}
	// Fairness (S-T7): batch-level admission by the VERIFIED tenant —
	// shedding happens BEFORE enrichment + insert (the expensive section).
	if c.gate != nil && !c.gate.AdmitN(ctx, tenant, fairness.MeterFlowEvents, int64(len(batch.Flows))) {
		c.ledger.addFairnessShed(1)
		c.log.Debug("flow batch shed by fairness bounds", "tenant_id", tenant, "rows", len(batch.Flows))
		return nil
	}
	rows := make([]flowstore.Row, 0, len(batch.Flows))
	for _, f := range batch.Flows {
		c.enrichRecord(ctx, f)
		rows = append(rows, rowFromProto(f))
	}
	// CORRECT-010: retry with jittered backoff; exhaustion routes the ORIGINAL
	// bytes to the flow DLQ — never a silent drop. Meter only what actually
	// lands, so a dead-lettered batch is not counted as stored.
	if err := c.insertWithRetry(ctx, rows); err != nil {
		if unknownWriteOutcome(ctx, err) {
			return err
		}
		c.deadLetter(ctx, msg, tenant, err)
		return nil
	}
	c.ledger.addStored(1)
	// Metering (S-T3): stored flow events, tagged by the VERIFIED tenant.
	usage.Record(tenant, usage.MeterFlowEvents, int64(len(rows)))
	return nil
}

// insertWithRetry mirrors the result + device pipelines' policy (U-019).
func (c *FlowConsumer) insertWithRetry(ctx context.Context, rows []flowstore.Row) error {
	var err error
	for attempt := 0; ; attempt++ {
		if err = c.store.Insert(ctx, rows); err == nil {
			return nil
		}
		if attempt >= c.maxRetries || ctx.Err() != nil {
			return err
		}
		c.retried.Add(1)
		backoff := c.retryBase << attempt
		c.sleep(ctx, backoff+time.Duration(rand.Int64N(int64(backoff)/2+1)))
	}
}

// deadLetter publishes the ORIGINAL message bytes to the flow DLQ (tenant-keyed,
// replayable). A DLQ publish failure is the only true loss.
func (c *FlowConsumer) deadLetter(ctx context.Context, msg bus.Message, tenant string, insertErr error) {
	if c.bus == nil {
		c.dropped.Add(1)
		c.ledger.addDropped(1)
		c.log.Error("FLOW BATCH LOST: insert exhausted retries and no bus for the DLQ",
			"tenant_id", tenant, "insert_error", insertErr.Error(), "dropped_total", c.dropped.Load())
		return
	}
	if err := c.bus.Publish(ctx, bus.DeadLetterFlowTopic, msg.Key, msg.Value); err != nil {
		c.dropped.Add(1)
		c.ledger.addDropped(1)
		c.log.Error("FLOW BATCH LOST: insert exhausted retries and dead-letter publish failed",
			"tenant_id", tenant, "insert_error", insertErr.Error(), "dlq_error", err.Error(),
			"dropped_total", c.dropped.Load())
		return
	}
	c.deadLettered.Add(1)
	c.ledger.addDeadLettered(1)
	c.log.Warn("flow batch dead-lettered after insert retries",
		"tenant_id", tenant, "topic", bus.DeadLetterFlowTopic, "insert_error", insertErr.Error())
}

// enrichRecord fills missing ASN/geo via opendata (S15). Device-asserted AS
// numbers win (only zero/empty fields are filled); enrichment failures degrade
// gracefully — a down source never blocks ingest (CLAUDE.md §7 guardrail 10).
func (c *FlowConsumer) enrichRecord(ctx context.Context, f *flowv1.FlowRecord) {
	if c.enrich == nil {
		return
	}
	fill := func(addr string, asn *uint32, asName, country *string) {
		if addr == "" || (*asn != 0 && *country != "") {
			return
		}
		e, err := c.enrich.Enrich(ctx, addr)
		if err != nil {
			return
		}
		if *asn == 0 && e.ASN != 0 {
			*asn = e.ASN
			if *asName == "" {
				*asName = e.ASName
			}
		}
		if *country == "" {
			*country = e.CountryCode
		}
	}
	fill(f.GetSourceAddress(), &f.SourceAsn, &f.SourceAsName, &f.SourceCountry)
	fill(f.GetDestinationAddress(), &f.DestinationAsn, &f.DestinationAsName, &f.DestinationCountry)
}

// rowFromProto flattens the bus record into the storage row.
func rowFromProto(f *flowv1.FlowRecord) flowstore.Row {
	ts := time.Unix(0, f.GetEndUnixNano()).UTC()
	if f.GetEndUnixNano() == 0 {
		ts = time.Unix(0, f.GetObservedAtUnixNano()).UTC()
	}
	// CORRECT-015: sFlow v5 carries no flow-start time, so StartUnixNano is 0 —
	// time.Unix(0,0) would store 1970-01-01, poisoning duration math and any
	// time-window query. Fall back to the flow's own timestamp so a start-less
	// record is stamped "started when we observed it", not at the epoch.
	startTS := ts
	if f.GetStartUnixNano() != 0 {
		startTS = time.Unix(0, f.GetStartUnixNano()).UTC()
	}
	// CORRECT-006: clamp far-future exporter clocks so a drifting NetFlow/sFlow
	// exporter cannot land rows in the future and poison capacity/top-talker
	// windows. The clamp is the shared one (FutureClamped counter); benign sub-
	// window skew passes through. startTS is never left after ts.
	now := time.Now()
	ts = clampFutureTime(ts, now)
	startTS = clampFutureTime(startTS, now)
	if startTS.After(ts) {
		startTS = ts
	}
	return flowstore.Row{
		TenantID:      f.GetTenantId(),
		AgentID:       f.GetAgentId(),
		Exporter:      f.GetExporterAddress(),
		ObsDomain:     f.GetObservationDomain(),
		Protocol:      f.GetFlowProtocol(),
		TS:            ts,
		StartTS:       startTS,
		SrcAddr:       f.GetSourceAddress(),
		DstAddr:       f.GetDestinationAddress(),
		SrcPort:       uint16(f.GetSourcePort()),
		DstPort:       uint16(f.GetDestinationPort()),
		Transport:     f.GetNetworkTransport(),
		NetType:       f.GetNetworkType(),
		InIf:          f.GetInputInterface(),
		OutIf:         f.GetOutputInterface(),
		VLAN:          uint16(f.GetVlan()),
		ToS:           uint8(f.GetTos()),
		TCPFlags:      uint8(f.GetTcpFlags()),
		NextHop:       f.GetNextHop(),
		Bytes:         f.GetBytes(),
		Packets:       f.GetPackets(),
		Sampling:      f.GetSamplingRate(),
		BytesScaled:   f.GetBytesScaled(),
		PacketsScaled: f.GetPacketsScaled(),
		SrcASN:        f.GetSourceAsn(),
		SrcASName:     f.GetSourceAsName(),
		SrcCountry:    f.GetSourceCountry(),
		DstASN:        f.GetDestinationAsn(),
		DstASName:     f.GetDestinationAsName(),
		DstCountry:    f.GetDestinationCountry(),
	}
}
