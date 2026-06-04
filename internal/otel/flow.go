package otel

import (
	"strconv"

	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
)

// eBPF flow / service-map attribute keys (S20), following the OpenTelemetry
// source.* / destination.* / network.* / process.* / container.* / host.*
// conventions. tenant_id / agent_id reuse the probectl.* identity keys above.
const (
	AttrHostName           = "host.name"
	AttrSourceAddress      = "source.address"
	AttrSourcePort         = "source.port"
	AttrDestinationAddress = "destination.address"
	AttrDestinationPort    = "destination.port"
	AttrNetworkType        = "network.type"
	AttrNetworkIODirection = "network.io.direction"
	AttrProcessName        = "process.executable.name"
	AttrContainerID        = "container.id"
)

// Register the eBPF keys into the shared conformance set so FlowAttributes is
// held to the same "no invented names" bar as ResultAttributes (S6).
func init() {
	for _, k := range []string{
		AttrHostName, AttrSourceAddress, AttrSourcePort,
		AttrDestinationAddress, AttrDestinationPort, AttrNetworkType,
		AttrNetworkIODirection, AttrProcessName, AttrContainerID,
	} {
		KnownAttributes[k] = true
	}
}

// FlowAttributes maps an eBPF Flow to its OTel resource + network attributes —
// the mapping the OTLP layer (S22) exposes rather than remapping. The tenant is
// the outermost scope (probectl.tenant.id); empty optionals are omitted.
func FlowAttributes(f *ebpfv1.Flow) map[string]string {
	attrs := map[string]string{
		AttrTenantID: f.GetTenantId(),
		AttrAgentID:  f.GetAgentId(),
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	putPort := func(k string, p uint32) {
		if p != 0 {
			attrs[k] = strconv.FormatUint(uint64(p), 10)
		}
	}
	put(AttrHostName, f.GetHost())
	put(AttrSourceAddress, f.GetSourceAddress())
	putPort(AttrSourcePort, f.GetSourcePort())
	put(AttrDestinationAddress, f.GetDestinationAddress())
	putPort(AttrDestinationPort, f.GetDestinationPort())
	put(AttrNetworkTransport, f.GetNetworkTransport())
	put(AttrNetworkType, f.GetNetworkType())
	put(AttrNetworkIODirection, f.GetDirection())
	put(AttrProcessName, f.GetProcessName())
	put(AttrContainerID, f.GetContainerId())
	return attrs
}
