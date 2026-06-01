package ebpf

import "time"

// Network/transport/direction string constants. These are the on-the-wire
// values (OTel network.transport / network.type / network.io.direction), kept
// as strings to match result.proto and stay OTel-shaped.
const (
	TransportTCP = "tcp"
	TransportUDP = "udp"

	NetworkIPv4 = "ipv4"
	NetworkIPv6 = "ipv6"

	DirectionIngress = "ingress"
	DirectionEgress  = "egress"

	StateEstablished = "established"
	StateClose       = "close"
)

// Endpoint identifies one side of a connection. Workload is the resolved
// service/workload name (container / pod / process); when enrichment is
// unavailable it is empty and ID falls back to the address, so a service map is
// still produced on a bare host.
type Endpoint struct {
	Address   string
	Port      uint32
	PID       uint32
	Process   string
	Container string
	Workload  string
}

// ID is the stable identity used to key service-map edges: the workload when
// known, otherwise the address.
func (e Endpoint) ID() string {
	if e.Workload != "" {
		return e.Workload
	}
	return e.Address
}

// Flow is one observed L3/L4 connection event (one direction). It is the
// userspace-side representation of a ring-buffer record; the live eBPF source
// produces these, and so does the FixtureSource used in CI.
type Flow struct {
	TenantID string
	AgentID  string
	Host     string
	Observed time.Time

	Source      Endpoint
	Destination Endpoint
	Transport   string // tcp | udp
	NetworkType string // ipv4 | ipv6

	Bytes     uint64
	Packets   uint64
	Direction string // ingress | egress
	State     string // established | close
}

// ServiceEdge is a directed aggregate of flows between two endpoints — the unit
// of the service map.
type ServiceEdge struct {
	TenantID    string
	Source      string // source endpoint id
	Destination string // destination endpoint id
	DestPort    uint32
	Transport   string
	Connections uint64
	Bytes       uint64
	Packets     uint64
	FirstSeen   time.Time
	LastSeen    time.Time
}
