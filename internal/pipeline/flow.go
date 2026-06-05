package pipeline

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
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
}

// NewFlowConsumer builds the consumer; enrich may be nil.
func NewFlowConsumer(b bus.Bus, st flowstore.Store, enrich FlowEnricher, log *slog.Logger) *FlowConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &FlowConsumer{bus: b, store: st, enrich: enrich, group: FlowGroup, log: log}
}

// Run subscribes until ctx is canceled. It blocks.
func (c *FlowConsumer) Run(ctx context.Context) error {
	c.log.Info("flow pipeline consumer starting", "topic", bus.FlowEventsTopic, "group", c.group,
		"enrichment", c.enrich != nil)
	if err := c.bus.Subscribe(ctx, bus.FlowEventsTopic, c.group, c.handle); err != nil && ctx.Err() == nil {
		c.log.Error("flow subscription failed", "error", err.Error())
		return err
	}
	return nil
}

// handle decodes one FlowBatch, enriches, and inserts. Malformed messages and
// transient store failures are logged and dropped (best-effort, matching the
// result pipeline) rather than blocking the stream.
func (c *FlowConsumer) handle(ctx context.Context, msg bus.Message) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.log.Error("dropping malformed flow batch", "error", err.Error())
		return nil
	}
	if len(batch.Flows) == 0 {
		return nil
	}
	rows := make([]flowstore.Row, 0, len(batch.Flows))
	for _, f := range batch.Flows {
		c.enrichRecord(ctx, f)
		rows = append(rows, rowFromProto(f))
	}
	// Metering (S-T3): stored flow events, tagged by the batch's tenant key.
	usage.Record(string(msg.Key), usage.MeterFlowEvents, int64(len(rows)))
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
