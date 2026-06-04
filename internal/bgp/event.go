package bgp

import (
	"errors"
	"fmt"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
)

// Event is the analyzer's JSON event shape (the analyzer↔control-plane contract).
// The Python analyzer writes these as JSON Lines; the bridge parses them and
// republishes the canonical probectl.bgp.v1.BGPEvent protobuf onto the bus. The
// JSON keys and lowercase enum strings match analyzer/probectl_analyzer/events.py.
type Event struct {
	TenantID           string   `json:"tenant_id"`
	EventType          string   `json:"event_type"`
	Severity           string   `json:"severity"`
	Confidence         float64  `json:"confidence"`
	Prefix             string   `json:"prefix"`
	NewOriginASN       uint32   `json:"new_origin_asn"`
	OldOriginASN       uint32   `json:"old_origin_asn"`
	NewASPath          []uint32 `json:"new_as_path"`
	OldASPath          []uint32 `json:"old_as_path"`
	ExpectedOrigins    []uint32 `json:"expected_origins"`
	RPKIStatus         string   `json:"rpki_status"`
	Collector          string   `json:"collector"`
	PeerASN            uint32   `json:"peer_asn"`
	PeerAddress        string   `json:"peer_address"`
	Message            string   `json:"message"`
	DetectedAtUnixNano int64    `json:"detected_at_unix_nano"`
}

// validate enforces the invariants the bus message must satisfy. Tenant is the
// outermost scope (F50): an event without one is rejected, never published — the
// bridge fails closed rather than risk an unattributed/cross-tenant record.
func (e Event) validate() error {
	if e.TenantID == "" {
		return errors.New("event has no tenant_id")
	}
	if e.Prefix == "" {
		return errors.New("event has no prefix")
	}
	if eventTypeProto(e.EventType) == bgpv1.EventType_EVENT_TYPE_UNSPECIFIED {
		return fmt.Errorf("unknown event_type %q", e.EventType)
	}
	return nil
}

func (e Event) toProto() *bgpv1.BGPEvent {
	return &bgpv1.BGPEvent{
		TenantId:           e.TenantID,
		EventType:          eventTypeProto(e.EventType),
		Severity:           severityProto(e.Severity),
		Confidence:         e.Confidence,
		Prefix:             e.Prefix,
		NewOriginAsn:       e.NewOriginASN,
		OldOriginAsn:       e.OldOriginASN,
		NewAsPath:          e.NewASPath,
		OldAsPath:          e.OldASPath,
		ExpectedOrigins:    e.ExpectedOrigins,
		RpkiStatus:         rpkiStatusProto(e.RPKIStatus),
		Collector:          e.Collector,
		PeerAsn:            e.PeerASN,
		PeerAddress:        e.PeerAddress,
		Message:            e.Message,
		DetectedAtUnixNano: e.DetectedAtUnixNano,
	}
}

func eventTypeProto(s string) bgpv1.EventType {
	switch s {
	case "origin_change":
		return bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE
	case "possible_hijack":
		return bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK
	case "possible_leak":
		return bgpv1.EventType_EVENT_TYPE_POSSIBLE_LEAK
	case "rpki_invalid":
		return bgpv1.EventType_EVENT_TYPE_RPKI_INVALID
	default:
		return bgpv1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}

func severityProto(s string) bgpv1.Severity {
	switch s {
	case "info":
		return bgpv1.Severity_SEVERITY_INFO
	case "warning":
		return bgpv1.Severity_SEVERITY_WARNING
	case "critical":
		return bgpv1.Severity_SEVERITY_CRITICAL
	default:
		return bgpv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func rpkiStatusProto(s string) bgpv1.RpkiStatus {
	switch s {
	case "valid":
		return bgpv1.RpkiStatus_RPKI_STATUS_VALID
	case "invalid":
		return bgpv1.RpkiStatus_RPKI_STATUS_INVALID
	case "not_found":
		return bgpv1.RpkiStatus_RPKI_STATUS_NOT_FOUND
	case "unknown":
		return bgpv1.RpkiStatus_RPKI_STATUS_UNKNOWN
	default:
		return bgpv1.RpkiStatus_RPKI_STATUS_UNSPECIFIED
	}
}
