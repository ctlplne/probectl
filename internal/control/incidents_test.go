package control

import (
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/alert"
	bgpv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/bgp/v1"
	"github.com/imfeelingtheagi/netctl/internal/incident"
)

func TestSignalFromAlert(t *testing.T) {
	a := alert.Alert{
		TenantID: "t1", RuleName: "loss-high", RuleID: "r1", State: alert.StateFiring,
		Severity: alert.SeverityCritical, Metric: "netctl_probe_loss_ratio",
		Labels: map[string]string{"server_address": "192.0.2.10"}, Value: 0.9, At: time.Unix(100, 0),
	}
	s := signalFromAlert(a)
	if s.TenantID != "t1" || s.Plane != "network" || s.Kind != "alert.firing" {
		t.Errorf("signal = %+v", s)
	}
	if s.Severity != incident.SeverityCritical || s.Target != "192.0.2.10" {
		t.Errorf("severity/target = %q/%q", s.Severity, s.Target)
	}
	if s.Attributes["metric"] != "netctl_probe_loss_ratio" || s.Attributes["rule_id"] != "r1" {
		t.Errorf("attributes = %+v", s.Attributes)
	}
}

func TestSignalFromBGPEvent(t *testing.T) {
	e := &bgpv1.BGPEvent{
		TenantId: "t1", EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity: bgpv1.Severity_SEVERITY_CRITICAL, Prefix: "192.0.2.0/24",
		Message: "possible hijack", DetectedAtUnixNano: 100 * 1_000_000_000,
		Collector: "rrc00", NewOriginAsn: 64500,
	}
	s := signalFromBGPEvent(e)
	if s.TenantID != "t1" || s.Plane != "bgp" || s.Kind != "bgp.possible_hijack" {
		t.Errorf("signal = %+v", s)
	}
	if s.Severity != incident.SeverityCritical || s.Target != "192.0.2.0/24" || s.Prefix != "192.0.2.0/24" {
		t.Errorf("severity/target/prefix = %q/%q/%q", s.Severity, s.Target, s.Prefix)
	}
	if s.Attributes["collector"] != "rrc00" || s.Attributes["new_origin_asn"] != "64500" {
		t.Errorf("attributes = %+v", s.Attributes)
	}
	if !s.OccurredAt.Equal(time.Unix(100, 0)) {
		t.Errorf("occurred_at = %v", s.OccurredAt)
	}
}

func TestBGPKindAndSeverity(t *testing.T) {
	kinds := map[bgpv1.EventType]string{
		bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE:   "origin_change",
		bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK: "possible_hijack",
		bgpv1.EventType_EVENT_TYPE_POSSIBLE_LEAK:   "possible_leak",
		bgpv1.EventType_EVENT_TYPE_RPKI_INVALID:    "rpki_invalid",
	}
	for et, want := range kinds {
		if got := bgpKind(et); got != want {
			t.Errorf("bgpKind(%v) = %q, want %q", et, got, want)
		}
	}
	if bgpSeverity(bgpv1.Severity_SEVERITY_CRITICAL) != incident.SeverityCritical {
		t.Error("critical severity")
	}
	if bgpSeverity(bgpv1.Severity_SEVERITY_UNSPECIFIED) != incident.SeverityInfo {
		t.Error("unspecified should map to info")
	}
}
