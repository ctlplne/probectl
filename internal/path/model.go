// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"fmt"
	"time"
)

// MPLSLabel is one entry of an MPLS label stack carried on an ICMP Time Exceeded
// response (RFC 4950).
type MPLSLabel struct {
	Label uint32 `json:"label"`
	TC    uint8  `json:"tc"`
	S     bool   `json:"s"` // bottom-of-stack
	TTL   uint8  `json:"ttl"`
}

// HopNode is one distinct responder observed at a TTL position. Two or more nodes
// at the same TTL are ECMP branches.
type HopNode struct {
	IP        string      `json:"ip"`
	Sent      int         `json:"sent"`
	Received  int         `json:"received"`
	LossRatio float64     `json:"loss_ratio"`
	RTTMinMs  float64     `json:"rtt_min_ms"`
	RTTAvgMs  float64     `json:"rtt_avg_ms"`
	RTTMaxMs  float64     `json:"rtt_max_ms"`
	MPLS      []MPLSLabel `json:"mpls,omitempty"`
	// Geo is present only when the deployment enriched the responder from an
	// operator-supplied location table (see geo.go). Never fetched externally.
	Geo *HopGeo `json:"geo,omitempty"`
}

// HopGeo is an approximate location for a responder, sourced exclusively from
// operator-supplied data — the product never phones a geolocation service.
type HopGeo struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"country,omitempty"`
	Source  string  `json:"source,omitempty"`
}

// Hop is everything observed at one TTL distance from the source.
type Hop struct {
	TTL   int       `json:"ttl"`
	Nodes []HopNode `json:"nodes"`
}

// Link is an observed adjacency: a responder at TTL was followed by To at TTL+1
// within the same (stable) flow.
type Link struct {
	TTL  int    `json:"ttl"`
	From string `json:"from"`
	To   string `json:"to"`
}

// MeasurementFidelity is a closed, versioned receipt describing how a path's
// latency and hop evidence was acquired. It prevents precise-looking RTTs from
// implying kernel or NIC timestamping that the current engine does not use.
// Zero-value/absent receipts are legacy snapshots and must stay unknown rather
// than being reconstructed from mode alone.
type MeasurementFidelity struct {
	Version              int    `json:"version"`
	ProbeTransport       string `json:"probe_transport"`       // icmp | tcp | mixed
	AcquisitionMode      string `json:"acquisition_mode"`      // raw_icmp | icmp_datagram | tcp_connect_raw_icmp | tcp_connect | mixed
	TimingSource         string `json:"timing_source"`         // application_monotonic
	HopVisibility        string `json:"hop_visibility"`        // full | destination_only | mixed
	KernelTimestamping   bool   `json:"kernel_timestamping"`   // true only when actually enabled
	HardwareTimestamping bool   `json:"hardware_timestamping"` // true only when actually enabled
}

// Path is the merged, multi-path result of a discovery.
type Path struct {
	Target              string               `json:"target"`
	TargetIP            string               `json:"target_ip"`
	Mode                string               `json:"mode"`
	MaxHops             int                  `json:"max_hops"`
	TraceCount          int                  `json:"trace_count"`
	DestinationReached  bool                 `json:"destination_reached"`
	MeasurementFidelity *MeasurementFidelity `json:"measurement_fidelity,omitempty"`
	Hops                []Hop                `json:"hops"`
	Links               []Link               `json:"links"`
}

// Config is a path-test definition.
type Config struct {
	Target        string
	Mode          string // "icmp" | "tcp"
	Port          int    // TCP mode target port
	TraceCount    int    // number of distinct flows (3–10)
	MaxHops       int    // TTL ceiling
	ProbesPerHop  int    // probes per (flow, TTL)
	PerHopTimeout time.Duration
	Privileged    bool // prefer raw sockets (full traceroute)
}

// normalize fills defaults and validates the config.
func (c *Config) normalize() error {
	if c.Target == "" {
		return fmt.Errorf("path: target is required")
	}
	switch c.Mode {
	case "":
		c.Mode = "icmp"
	case "icmp", "tcp":
	default:
		return fmt.Errorf("path: unknown mode %q (want icmp|tcp)", c.Mode)
	}
	if c.Mode == "tcp" && (c.Port < 1 || c.Port > 65535) {
		return fmt.Errorf("path: tcp mode requires a valid port")
	}
	if c.TraceCount == 0 {
		c.TraceCount = 3
	}
	if c.TraceCount < 1 || c.TraceCount > 16 {
		return fmt.Errorf("path: trace_count must be between 1 and 16")
	}
	if c.MaxHops == 0 {
		c.MaxHops = 30
	}
	if c.MaxHops < 1 || c.MaxHops > 64 {
		return fmt.Errorf("path: max_hops must be between 1 and 64")
	}
	if c.ProbesPerHop == 0 {
		c.ProbesPerHop = 1
	}
	if c.ProbesPerHop < 1 || c.ProbesPerHop > 10 {
		return fmt.Errorf("path: probes_per_hop must be between 1 and 10")
	}
	if c.PerHopTimeout == 0 {
		c.PerHopTimeout = time.Second
	}
	return nil
}

// hopObservation is what one flow saw at one TTL. Because a flow follows a single
// stable path, all of that flow's probes at a TTL reach the same responder, so
// loss is attributable to that responder.
type hopObservation struct {
	ttl      int
	ip       string // responder; "" when no probe got a response
	sent     int
	received int
	rtts     []time.Duration
	mpls     []MPLSLabel
	final    bool // the destination responded (echo reply / TCP SYN-ACK or RST)
}

// flowTrace is one single-flow traceroute: observations by ascending TTL, ending
// at the destination or MaxHops.
type flowTrace struct {
	flowID   uint16
	hops     []hopObservation
	fidelity MeasurementFidelity
}
