// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flow

import (
	"net/netip"
	"strconv"
	"time"

	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
)

// Wire protocols a Record can be decoded from (FlowRecord.flow_protocol).
const (
	ProtoNetFlow5         = "netflow5"
	ProtoNetFlow9         = "netflow9"
	ProtoIPFIX            = "ipfix"
	ProtoSFlow5           = "sflow5"
	ProtoAWSVPCFlowLogs   = "aws_vpc_flow_logs"
	ProtoAzureNSGFlowLogs = "azure_nsg_flow_logs"
	ProtoGCPVPCFlowLogs   = "gcp_vpc_flow_logs"
)

// Record is one normalized flow observation, decoded from any of the four wire
// protocols. Addresses use netip so v4/v6 handling stays allocation-free in the
// hot path; ToProto maps onto the OTel-named flowv1.FlowRecord.
type Record struct {
	TenantID string
	AgentID  string

	// Exporter is the device that emitted the datagram (the UDP source);
	// ObservationDomain is the v9 source ID / IPFIX observation domain /
	// sFlow sub-agent ID — together they scope template state.
	Exporter          string
	ObservationDomain uint32
	Protocol          string

	ObservedAt time.Time // collector receive time
	Start, End time.Time // flow start/end (exporter clock mapped to unix)

	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16
	Transport        uint8 // IP protocol number (6 tcp, 17 udp, 1 icmp, ...)

	InIf, OutIf uint32
	VLAN        uint16
	ToS         uint8
	TCPFlags    uint8
	NextHop     netip.Addr

	Bytes, Packets uint64
	SamplingRate   uint64 // 1 = unsampled

	// Device-asserted AS numbers (NetFlow v5/v9/IPFIX can export these); the
	// control-plane enricher (S15) fills them only when zero.
	SrcAS, DstAS uint32
}

// transportName maps an IP protocol number onto the OTel network.transport
// values where one exists; other protocols carry their number as a string
// (no invented names — CLAUDE.md §6 telemetry conventions).
func transportName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	default:
		return strconv.FormatUint(uint64(p), 10)
	}
}

// networkType returns the OTel network.type value for the record's addresses.
func networkType(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return ""
	case a.Is4() || a.Is4In6():
		return "ipv4"
	default:
		return "ipv6"
	}
}

// rate returns the effective sampling rate (1 = unsampled) so scaling never
// multiplies by zero.
func (r Record) rate() uint64 {
	if r.SamplingRate == 0 {
		return 1
	}
	return r.SamplingRate
}

// ToProto maps the record onto the bus/storage schema, applying sampling
// correction (bytes_scaled / packets_scaled = raw x rate).
func (r Record) ToProto() *flowv1.FlowRecord {
	pr := &flowv1.FlowRecord{
		TenantId:           r.TenantID,
		AgentId:            r.AgentID,
		ExporterAddress:    r.Exporter,
		ObservationDomain:  r.ObservationDomain,
		FlowProtocol:       r.Protocol,
		ObservedAtUnixNano: unixNano(r.ObservedAt),
		StartUnixNano:      unixNano(r.Start),
		EndUnixNano:        unixNano(r.End),
		SourcePort:         uint32(r.SrcPort),
		DestinationPort:    uint32(r.DstPort),
		NetworkTransport:   transportName(r.Transport),
		NetworkType:        networkType(r.SrcAddr),
		InputInterface:     r.InIf,
		OutputInterface:    r.OutIf,
		Vlan:               uint32(r.VLAN),
		Tos:                uint32(r.ToS),
		TcpFlags:           uint32(r.TCPFlags),
		Bytes:              r.Bytes,
		Packets:            r.Packets,
		SamplingRate:       r.rate(),
		BytesScaled:        r.Bytes * r.rate(),
		PacketsScaled:      r.Packets * r.rate(),
		SourceAsn:          r.SrcAS,
		DestinationAsn:     r.DstAS,
	}
	if r.SrcAddr.IsValid() {
		pr.SourceAddress = r.SrcAddr.Unmap().String()
	}
	if r.DstAddr.IsValid() {
		pr.DestinationAddress = r.DstAddr.Unmap().String()
	}
	if r.NextHop.IsValid() && !r.NextHop.IsUnspecified() {
		pr.NextHop = r.NextHop.Unmap().String()
	}
	return pr
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
