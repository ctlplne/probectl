package bus

import (
	"context"
	"errors"
	"fmt"
)

// NetworkResultsTopic is the topic for network-plane probe results (S6). The
// convention is probectl.<type>.results / probectl.<type>.events.
const NetworkResultsTopic = "probectl.network.results"

// BGPEventsTopic carries routing-security signals from the BGP analyzer bridge
// (S14), tenant-tagged via the message key.
const BGPEventsTopic = "probectl.bgp.events"

// EBPFFlowsTopic carries L3/L4 flow + service-edge batches from the eBPF host
// agent (S20), tenant-tagged via the message key. Payload: ebpfv1.FlowBatch.
const EBPFFlowsTopic = "probectl.ebpf.flows"

// OTLPMetricsTopic carries OTLP metrics ingested by the OTLP receiver (S22),
// tenant-tagged via the message key. Payload: a marshaled OTLP
// ExportMetricsServiceRequest.
const OTLPMetricsTopic = "probectl.otlp.metrics"

// FlowEventsTopic carries normalized device-flow batches (NetFlow v5/v9, IPFIX,
// sFlow v5) from the flow collector (S38), tenant-tagged via the message key.
// Payload: flowv1.FlowBatch. The control plane consumes it, enriches ASN/geo
// (S15), and persists to ClickHouse (internal/store/flowstore).
const FlowEventsTopic = "probectl.flow.events"

// DeviceMetricsTopic carries normalized device-telemetry batches (SNMP polls +
// gNMI/OpenConfig subscriptions, S39) from the device collector, tenant-tagged
// via the message key. Payload: devicev1.DeviceMetricBatch. The control plane
// consumes it and lands the samples in the TSDB.
const DeviceMetricsTopic = "probectl.device.metrics"

// EndpointResultsTopic carries DEM results from the endpoint agent (S37) — WiFi /
// gateway / last-mile / session signals and the slowdown attribution — tenant-
// tagged via the message key. Payload: resultv1.Result (the canonical canary
// result schema), so it flows through the same pipeline → TSDB path.
const EndpointResultsTopic = "probectl.endpoint.results"

// RUMEventsTopic carries real-user page views from the RUM beacon ingest
// (S47b) — validated, consent-gated, PII-redacted at the edge — tenant-tagged
// via the message key. Payload: resultv1.Result (canary_type "rum"; the
// canonical schema), so RUM flows through the same pipeline → TSDB path.
const RUMEventsTopic = "probectl.rum.events"

// Message is one bus record. Key partitions the record (the tenant id, so a
// tenant's results stay ordered and co-located — pooled tenant-tagging).
type Message struct {
	Topic string
	Key   []byte
	Value []byte
}

// Handler processes a consumed message.
type Handler func(ctx context.Context, msg Message) error

// Bus is the result/event transport. Payloads are Protobuf.
type Bus interface {
	// Publish sends value to topic, partitioned by key.
	Publish(ctx context.Context, topic string, key, value []byte) error
	// Subscribe consumes topic in the given consumer group, invoking handler for
	// each message until ctx is canceled. It blocks.
	Subscribe(ctx context.Context, topic, group string, handler Handler) error
	// Close releases resources.
	Close() error
}

// New builds a Bus for the given mode. "memory" (or empty) is the lightweight
// in-process bus; "kafka" requires brokers.
func New(mode string, brokers []string) (Bus, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "kafka":
		if len(brokers) == 0 {
			return nil, errors.New("bus: kafka mode requires PROBECTL_BUS_BROKERS")
		}
		return NewKafka(brokers)
	default:
		return nil, fmt.Errorf("bus: unknown mode %q (want memory|kafka)", mode)
	}
}
