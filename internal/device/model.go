// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"net/netip"
	"time"

	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
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

	Name  string
	Value float64
	Unit  string
	At    time.Time
}

// ToProto maps onto the bus/storage schema.
func (m Metric) ToProto() *devicev1.DeviceMetric {
	return &devicev1.DeviceMetric{
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
	}
}

// Interface is one device interface as discovered by the SNMP poll — the
// correlation unit shared with the path (hop IP) and flow (ifIndex) planes.
type Interface struct {
	Index     uint32
	Name      string // ifName (falls back to ifDescr)
	Descr     string
	SpeedMbps uint64
	OperUp    bool
	Addrs     []netip.Addr // from ipAddrTable
}

// Inventory is one device's discovered identity + interfaces, fed to the
// Correlator after every poll.
type Inventory struct {
	Device     string // management address (the config key)
	SysName    string
	SysDescr   string
	Interfaces map[uint32]Interface
}
