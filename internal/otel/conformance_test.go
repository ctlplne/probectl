// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otel

import (
	"testing"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// TestAllSignalMappingsConform is the S22 cross-signal conformance check: every
// signal type's attribute mapping may emit ONLY OTel-standard or probectl.* names
// (the S6 ResultAttributes discipline, now enforced across all planes), and each
// carries the tenant as the outermost scope (F50).
//
// ARCH-001: the "result" case now populates Attributes with the full set of
// canary passthrough keys (one per canary type) so the gate actually catches any
// unregistered key a plugin might add. Previously the map was empty and the
// passthrough loop never exercised.
func TestAllSignalMappingsConform(t *testing.T) {
	// icmpAttrs represents the attribute set the ICMP canary writes after a probe.
	icmpAttrs := map[string]string{
		"probectl.icmp.mode":                 "privileged",
		"network.peer.address":               "93.184.216.34",
		"probectl.icmp.dropped_seqs":         "1,2",
		"probectl.icmp.drop_send_offsets_ms": "10,20",
	}
	// dnsAttrs represents the attribute set the DNS canary writes after a query.
	dnsAttrs := map[string]string{
		"probectl.dns.qtype":     "A",
		"probectl.dns.transport": "udp",
		"probectl.dns.mode":      "resolver",
		"probectl.dns.server":    "8.8.8.8:53",
		"probectl.dns.rcode":     "NOERROR",
		"probectl.dns.answer":    "A 93.184.216.34",
		"probectl.dns.dnssec":    "secure",
		"probectl.dns.trace":     "ns1 > ns2",
	}
	// tlsAttrs represents the attribute set the HTTP canary writes for a TLS probe.
	tlsAttrs := map[string]string{
		"http.response.status_code":          "200",
		"network.protocol.version":           "HTTP/1.1",
		"network.peer.address":               "93.184.216.34",
		"network.peer.port":                  "443",
		"tls.protocol.version":               "1.3",
		"tls.cipher.suite":                   "TLS_AES_128_GCM_SHA256",
		"probectl.tls.resumed":               "false",
		"probectl.tls.verification_disabled": "false",
		"probectl.tls.server.verified":       "true",
		"probectl.tls.server.subject":        "CN=example.com",
		"probectl.tls.server.issuer":         "CN=DigiCert",
		"probectl.tls.server.not_before":     "2024-01-01T00:00:00Z",
		"probectl.tls.server.not_after":      "2025-01-01T00:00:00Z",
		"probectl.tls.server.san":            "example.com,www.example.com",
		"probectl.tls.server.chain":          "example.com > DigiCert",
		"probectl.tls.server.cert":           "base64==",
	}
	// voiceAttrs represents the attribute set the voice/RTP canary writes.
	voiceAttrs := map[string]string{
		"probectl.voice.jitter_buffer_ms": "20",
	}
	mappings := map[string]map[string]string{
		// Canary passthrough: exercise each plugin's attribute set so the gate
		// catches any unregistered key (ARCH-001 fix — was empty attrs map).
		"result/icmp": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "icmp",
			ServerAddress: "x", ServerPort: 443, NetworkTransport: "icmp",
			Attributes: icmpAttrs,
		}),
		"result/dns": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "dns",
			ServerAddress: "8.8.8.8", ServerPort: 53, NetworkTransport: "udp",
			Attributes: dnsAttrs,
		}),
		"result/http+tls": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "http",
			ServerAddress: "example.com", ServerPort: 443, NetworkTransport: "tcp", NetworkProtocolName: "https",
			Attributes: tlsAttrs,
		}),
		"result/voice": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "voice",
			ServerAddress: "203.0.113.1", ServerPort: 5004, NetworkTransport: "udp",
			Attributes: voiceAttrs,
		}),
		// Original minimal case (no passthrough — still must pass).
		"result": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "icmp",
			ServerAddress: "x", ServerPort: 443, NetworkTransport: "tcp", NetworkProtocolName: "http",
		}),
		"flow": FlowAttributes(&ebpfv1.Flow{
			TenantId: "t", AgentId: "a", Host: "h",
			SourceAddress: "1.1.1.1", SourcePort: 5, DestinationAddress: "2.2.2.2", DestinationPort: 443,
			NetworkTransport: "tcp", NetworkType: "ipv4", Direction: "egress", ProcessName: "p", ContainerId: "c",
		}),
		"l7": L7CallAttributes(&ebpfv1.L7Call{
			TenantId: "t", AgentId: "a", Protocol: "grpc", Method: "svc/M", Status: "0", Encrypted: true,
		}),
		"bgp": BGPEventAttributes(&bgpv1.BGPEvent{
			TenantId: "t", EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
			Severity: bgpv1.Severity_SEVERITY_CRITICAL, Confidence: 0.9, Prefix: "192.0.2.0/24",
			NewOriginAsn: 64500, PeerAsn: 65000, RpkiStatus: bgpv1.RpkiStatus_RPKI_STATUS_INVALID,
			Collector: "rrc00", PeerAddress: "203.0.113.1",
		}),
		"path": PathAttributes(PathSummary{
			TenantID: "t", Target: "example.com", TargetIP: "93.184.216.34", Mode: "icmp",
			HopCount: 12, DestinationReached: true,
		}),
		"device": DeviceMetricAttributes(&devicev1.DeviceMetric{
			TenantId: "t", AgentId: "a", DeviceAddress: "192.0.2.1", DeviceName: "core-sw1",
			Source: "snmp", IfIndex: 3, IfName: "eth0",
			Name: "probectl.device.if.in.octets", Value: 1, Unit: "octets",
		}),
		"netflow": NetFlowAttributes(&flowv1.FlowRecord{
			TenantId: "t", AgentId: "a", ExporterAddress: "203.0.113.10", FlowProtocol: "netflow9",
			SourceAddress: "10.0.0.1", SourcePort: 53, DestinationAddress: "10.0.0.2", DestinationPort: 443,
			NetworkTransport: "udp", NetworkType: "ipv4", InputInterface: 3, OutputInterface: 4,
			SamplingRate: 64, SourceAsn: 64500, SourceAsName: "ACME", SourceCountry: "DE",
			DestinationAsn: 64501, DestinationAsName: "OTHER", DestinationCountry: "NL",
		}),
	}

	for signal, attrs := range mappings {
		if len(attrs) == 0 {
			t.Errorf("%s: empty attribute map", signal)
		}
		for k := range attrs {
			if !KnownAttributes[k] {
				t.Errorf("%s: attribute %q is not an OTel/probectl convention name (invented attribute)", signal, k)
			}
		}
		if attrs[AttrTenantID] != "t" {
			t.Errorf("%s: missing tenant scope (%s)", signal, AttrTenantID)
		}
	}
}
