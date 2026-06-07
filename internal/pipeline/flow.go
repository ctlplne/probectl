package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
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
	binding   TenantBinding
	nsTenants map[string]string // bus namespace -> tenant id (siloed lanes)

	rejected    atomic.Uint64 // batches dropped fail-closed (TENANT-101)
	overwritten atomic.Uint64 // payload tenant corrected to the lane tenant
}

// NewFlowConsumer builds the consumer; enrich may be nil.
func NewFlowConsumer(b bus.Bus, st flowstore.Store, enrich FlowEnricher, log *slog.Logger) *FlowConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &FlowConsumer{bus: b, store: st, enrich: enrich, group: FlowGroup, log: log}
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
// dropped fail-closed and counted; transient store failures are logged and
// dropped (best-effort, matching the result pipeline).
func (c *FlowConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
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
	tenant, overwritten, verr := VerifyBatchTenant(ctx, c.binding, laneTenant, ids)
	if verr != nil {
		c.rejected.Add(1)
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
		c.log.Debug("flow batch shed by fairness bounds", "tenant_id", tenant, "rows", len(batch.Flows))
		return nil
	}
	rows := make([]flowstore.Row, 0, len(batch.Flows))
	for _, f := range batch.Flows {
		c.enrichRecord(ctx, f)
		rows = append(rows, rowFromProto(f))
	}
	// Metering (S-T3): stored flow events, tagged by the VERIFIED tenant.
	usage.Record(tenant, usage.MeterFlowEvents, int64(len(rows)))
	if err := c.store.Insert(ctx, rows); err != nil {
		c.log.Error("flow store insert failed", "rows", len(rows),
			"tenant_id", batch.Flows[0].GetTenantId(), "error", err.Error())
	}
	return nil
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
	return flowstore.Row{
		TenantID:      f.GetTenantId(),
		AgentID:       f.GetAgentId(),
		Exporter:      f.GetExporterAddress(),
		ObsDomain:     f.GetObservationDomain(),
		Protocol:      f.GetFlowProtocol(),
		TS:            ts,
		StartTS:       time.Unix(0, f.GetStartUnixNano()).UTC(),
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
