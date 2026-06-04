package otel

import (
	"strconv"

	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
)

// Device-telemetry attribute keys (S39). No OTel semantic convention covers
// network-device telemetry, so the detail lives under probectl.device.* (the
// S6 rule: standard names where they exist, one probectl namespace where they
// don't). tenant/agent reuse the probectl identity keys.
const (
	AttrDeviceAddress = "probectl.device.address"
	AttrDeviceName    = "probectl.device.name"
	AttrDeviceSource  = "probectl.device.source"
	AttrDeviceIfIndex = "probectl.device.interface.index"
	AttrDeviceIfName  = "probectl.device.interface.name"
)

// Register the device keys into the shared conformance set.
func init() {
	for _, k := range []string{
		AttrDeviceAddress, AttrDeviceName, AttrDeviceSource, AttrDeviceIfIndex, AttrDeviceIfName,
	} {
		KnownAttributes[k] = true
	}
}

// DeviceMetricAttributes maps a DeviceMetric to its OTel resource attributes —
// the tenant is the outermost scope; zero/empty optionals are omitted.
func DeviceMetricAttributes(m *devicev1.DeviceMetric) map[string]string {
	attrs := map[string]string{
		AttrTenantID: m.GetTenantId(),
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	put(AttrAgentID, m.GetAgentId())
	put(AttrDeviceAddress, m.GetDeviceAddress())
	put(AttrDeviceName, m.GetDeviceName())
	put(AttrDeviceSource, m.GetSource())
	if m.GetIfIndex() != 0 {
		attrs[AttrDeviceIfIndex] = strconv.FormatUint(uint64(m.GetIfIndex()), 10)
	}
	put(AttrDeviceIfName, m.GetIfName())
	return attrs
}
