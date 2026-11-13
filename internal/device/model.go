// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"net/netip"
	"time"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

// Metric names (DeviceMetric.name). No established OTel semantic convention
// covers network-device telemetry, so these live in the probectl.device.*
// namespace (the S6 discipline: standard names where they exist, one probectl
// namespace where they don't). SNMP and gNMI emit the SAME names.
const (
	MetricUptimeSeconds = "probectl.device.uptime.seconds"

	MetricIfOperStatus  = "probectl.device.if.oper.status" // 1 = up, 0 = not up
	MetricIfSpeedMbps   = "probectl.device.if.speed.mbps"
	MetricIfInOctets    = "probectl.device.if.in.octets"  // cumulative counter
	MetricIfOutOctets   = "probectl.device.if.out.octets" // cumulative counter
	MetricIfInErrors    = "probectl.device.if.in.errors"
	MetricIfOutErrors   = "probectl.device.if.out.errors"
	MetricIfInDiscards  = "probectl.device.if.in.discards"
	MetricIfOutDiscards = "probectl.device.if.out.discards"

	MetricCPUUtilization = "probectl.device.cpu.utilization"    // percent, averaged
	MetricMemoryUsed     = "probectl.device.memory.used.bytes"  // bytes
	MetricMemoryTotal    = "probectl.device.memory.total.bytes" // bytes

	MetricSensorCelsius = "probectl.device.sensor.temperature.celsius"
)

// Transport sources (DeviceMetric.source).
const (
	SourceSNMP = "snmp"
	SourceGNMI = "gnmi"
)

// Metric is one normalized device sample (the Go-native mirror of
// devicev1.DeviceMetric).
type Metric struct {
	TenantID string
	AgentID  string

	Device     string // management address polled / dialed
	DeviceName string // sysName (SNMP) or target name (gNMI)
	Source     string // snmp | gnmi

	IfIndex uint32 // 0 when device-wide
	IfName  string
	// InterfaceAddresses are the normalized addresses assigned to IfIndex.
	// They travel with the interface sample so the control plane can rebuild
	// correlation and conflict state by replaying the tenant-tagged bus.
	InterfaceAddresses []string

	Name  string
	Value float64
	Unit  string
	At    time.Time
	// ExactCounter retains the original typed integer before the legacy TSDB
	// float conversion. Absence is not zero. It proves neither continuity nor
	// current source authority; the capacity reader must establish both.
	ExactCounter *CounterValue
}

// CounterValue is the original SNMP counter domain, not a rounded TSDB value.
// Width is 32 or 64 only when the matching ASN.1 counter type was observed.
type CounterValue struct {
	Value uint64
	Width uint32
	// Presence is independent of the numeric value: zero ticks are valid.
	UptimeTicks, DiscontinuityTicks uint32
	UptimeKnown, DiscontinuityKnown bool
	PollStartedAt, PollCompletedAt  time.Time
}

// ToProto maps onto the bus/storage schema.
func (m Metric) ToProto() *devicev1.DeviceMetric {
	out := &devicev1.DeviceMetric{
		TenantId:      m.TenantID,
		AgentId:       m.AgentID,
		DeviceAddress: m.Device,
		DeviceName:    m.DeviceName,
		Source:        m.Source,
		IfIndex:       m.IfIndex,
		IfName:        m.IfName,
		Name:          m.Name,
		Value:         m.Value,
		Unit:          m.Unit,
		TimeUnixNano:  m.At.UnixNano(),
		InterfaceAddresses: append(
			[]string(nil),
			m.InterfaceAddresses...,
		),
	}
	if m.ExactCounter != nil {
		out.ExactCounter = &devicev1.DeviceCounter{Value: m.ExactCounter.Value, Width: m.ExactCounter.Width}
		if m.ExactCounter.UptimeKnown {
			ticks := m.ExactCounter.UptimeTicks
			out.ExactCounter.UptimeTicks = &ticks
		}
		if m.ExactCounter.DiscontinuityKnown {
			ticks := m.ExactCounter.DiscontinuityTicks
			out.ExactCounter.DiscontinuityTicks = &ticks
		}
		if !m.ExactCounter.PollStartedAt.IsZero() {
			out.ExactCounter.PollStartedAtUnixNano = m.ExactCounter.PollStartedAt.UnixNano()
		}
		if !m.ExactCounter.PollCompletedAt.IsZero() {
			out.ExactCounter.PollCompletedAtUnixNano = m.ExactCounter.PollCompletedAt.UnixNano()
		}
	}
	return out
}

// Interface is one device interface as discovered by the SNMP poll — the
// correlation unit shared with the path (hop IP) and flow (ifIndex) planes.
type Interface struct {
	Index     uint32
	Name      string // ifName (falls back to ifDescr)
	Descr     string
	SpeedMbps uint64
	OperUp    bool
	// OperStatus preserves an actually returned IF-MIB ifOperStatus value
	// (1..7). Zero means unavailable; OperUp's zero value is not a down sample.
	OperStatus uint32
	// AdminStatus is the observed IF-MIB administrative state (1..3), not
	// configured intent inferred by the control plane. Zero is unavailable.
	AdminStatus uint32
	Addrs       []netip.Addr // complete IP-MIB table; legacy IPv4 if unsupported
	// Scoped addresses retain device-local zone IDs in raw metrics. They are
	// never promoted to globally scoped canonical address aliases.
	ScopedAddrs []string
}

// Inventory is one device's discovered identity + interfaces, fed to the
// Correlator after every poll.
type Inventory struct {
	Device     string // management address (the config key)
	SysName    string
	SysDescr   string
	Interfaces map[uint32]Interface
	// The connected SNMP peer, retained only inside this collector. A DNS
	// target can report its actual observed IP without a query-time lookup.
	peerAddress netip.Addr
	// Complete-poll prefix availability/content participate in identity
	// change detection. Never reuse another poll's prefix table on failure.
	prefixAttempted      bool
	interfacePrefixes    []snmpInterfacePrefix
	addressesUnavailable bool
}
