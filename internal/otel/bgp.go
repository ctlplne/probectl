package otel

import (
	"strconv"
	"strings"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
)

// BGP routing-signal attribute keys (S14 / finalized S22). BGP has no OTel
// standard, so these use the probectl.bgp.* namespace; the collector peer's
// address uses the OTel network.peer.address convention.
const (
	AttrBGPEventType  = "probectl.bgp.event_type"
	AttrBGPSeverity   = "probectl.bgp.severity"
	AttrBGPConfidence = "probectl.bgp.confidence"
	AttrBGPPrefix     = "probectl.bgp.prefix"
	AttrBGPOriginASN  = "probectl.bgp.origin_asn"
	AttrBGPPeerASN    = "probectl.bgp.peer_asn"
	AttrBGPRPKIStatus = "probectl.bgp.rpki_status"
	AttrBGPCollector  = "probectl.bgp.collector"
	AttrPeerAddress   = "network.peer.address"
)

func init() {
	for _, k := range []string{
		AttrBGPEventType, AttrBGPSeverity, AttrBGPConfidence, AttrBGPPrefix,
		AttrBGPOriginASN, AttrBGPPeerASN, AttrBGPRPKIStatus, AttrBGPCollector, AttrPeerAddress,
	} {
		KnownAttributes[k] = true
	}
}

// BGPEventAttributes maps a BGP routing-security event to its OTel/probectl
// attributes. The tenant is the outermost scope; empty optionals are omitted.
func BGPEventAttributes(e *bgpv1.BGPEvent) map[string]string {
	attrs := map[string]string{AttrTenantID: e.GetTenantId()}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	put(AttrBGPEventType, enumShort(e.GetEventType().String(), "EVENT_TYPE_"))
	put(AttrBGPSeverity, enumShort(e.GetSeverity().String(), "SEVERITY_"))
	attrs[AttrBGPConfidence] = strconv.FormatFloat(e.GetConfidence(), 'f', -1, 64)
	put(AttrBGPPrefix, e.GetPrefix())
	if e.GetNewOriginAsn() != 0 {
		attrs[AttrBGPOriginASN] = strconv.FormatUint(uint64(e.GetNewOriginAsn()), 10)
	}
	if e.GetPeerAsn() != 0 {
		attrs[AttrBGPPeerASN] = strconv.FormatUint(uint64(e.GetPeerAsn()), 10)
	}
	put(AttrBGPRPKIStatus, enumShort(e.GetRpkiStatus().String(), "RPKI_STATUS_"))
	put(AttrBGPCollector, e.GetCollector())
	put(AttrPeerAddress, e.GetPeerAddress())
	return attrs
}

// enumShort trims a proto enum's prefix and lowercases it; UNSPECIFIED -> "".
func enumShort(s, prefix string) string {
	s = strings.TrimPrefix(s, prefix)
	if s == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(s)
}
