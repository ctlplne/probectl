package bus

import (
	"context"
	"errors"
	"fmt"
)

// NetworkResultsTopic is the topic for network-plane probe results (S6). The
// convention is netctl.<type>.results / netctl.<type>.events.
const NetworkResultsTopic = "netctl.network.results"

// BGPEventsTopic carries routing-security signals from the BGP analyzer bridge
// (S14), tenant-tagged via the message key.
const BGPEventsTopic = "netctl.bgp.events"

// EBPFFlowsTopic carries L3/L4 flow + service-edge batches from the eBPF host
// agent (S20), tenant-tagged via the message key. Payload: ebpfv1.FlowBatch.
const EBPFFlowsTopic = "netctl.ebpf.flows"

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
			return nil, errors.New("bus: kafka mode requires NETCTL_BUS_BROKERS")
		}
		return NewKafka(brokers)
	default:
		return nil, fmt.Errorf("bus: unknown mode %q (want memory|kafka)", mode)
	}
}
