package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// Source is a stream of observed flows. The live source is a CO-RE eBPF program
// (built only under -tags ebpf); the FixtureSource replays recorded flows for
// CI / macOS / unprivileged hosts. Drops reports cumulative source-side drops
// (ring-buffer backpressure for the live source; always 0 for fixtures).
type Source interface {
	// Flows returns a channel of observed flows, closed when ctx is canceled or
	// the source is exhausted.
	Flows(ctx context.Context) (<-chan Flow, error)
	// Drops returns the cumulative dropped-record count.
	Drops() uint64
	// Close releases source resources.
	Close() error
}

// FixtureSource replays flows from a recorded JSON file (an array of records).
// It needs no privileges and runs anywhere — the no-kernel path the S20 sprint
// requires for CI, and the default for macOS / unprivileged containers.
type FixtureSource struct {
	flows []Flow
}

// fixtureFlow is the flat, human-editable JSON shape of a recorded flow.
type fixtureFlow struct {
	TenantID    string `json:"tenant_id"`
	AgentID     string `json:"agent_id"`
	Host        string `json:"host"`
	SrcAddress  string `json:"source_address"`
	SrcPort     uint32 `json:"source_port"`
	SrcPID      uint32 `json:"source_pid"`
	DstAddress  string `json:"destination_address"`
	DstPort     uint32 `json:"destination_port"`
	Transport   string `json:"network_transport"`
	NetworkType string `json:"network_type"`
	Bytes       uint64 `json:"bytes"`
	Packets     uint64 `json:"packets"`
	Direction   string `json:"direction"`
	State       string `json:"state"`
}

// NewFixtureSource loads recorded flows from path.
func NewFixtureSource(path string) (*FixtureSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ebpf: read fixture: %w", err)
	}
	var recs []fixtureFlow
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("ebpf: parse fixture: %w", err)
	}
	flows := make([]Flow, 0, len(recs))
	for _, r := range recs {
		flows = append(flows, Flow{
			TenantID:    r.TenantID,
			AgentID:     r.AgentID,
			Host:        r.Host,
			Source:      Endpoint{Address: r.SrcAddress, Port: r.SrcPort, PID: r.SrcPID},
			Destination: Endpoint{Address: r.DstAddress, Port: r.DstPort},
			Transport:   r.Transport,
			NetworkType: r.NetworkType,
			Bytes:       r.Bytes,
			Packets:     r.Packets,
			Direction:   r.Direction,
			State:       r.State,
		})
	}
	return &FixtureSource{flows: flows}, nil
}

// Flows emits the recorded flows once, then closes the channel.
func (s *FixtureSource) Flows(ctx context.Context) (<-chan Flow, error) {
	ch := make(chan Flow)
	go func() {
		defer close(ch)
		for _, f := range s.flows {
			select {
			case <-ctx.Done():
				return
			case ch <- f:
			}
		}
	}()
	return ch, nil
}

// Drops is always 0 for a fixture source.
func (s *FixtureSource) Drops() uint64 { return 0 }

// Close is a no-op for a fixture source.
func (s *FixtureSource) Close() error { return nil }
