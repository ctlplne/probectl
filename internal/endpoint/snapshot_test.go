package endpoint

import (
	"fmt"
	"testing"
	"time"
)

func rv(typ, target string, at time.Time, metrics map[string]float64, attrs map[string]string) ResultView {
	return ResultView{Type: typ, Target: target, Success: true, Metrics: metrics, Attributes: attrs, ObservedAt: at}
}

func TestSnapshotStoreAssemblesViews(t *testing.T) {
	s := NewSnapshotStore(0)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	s.Record("t-a", "laptop-1", rv(TypeAttribution, "app.acme.example", at,
		map[string]float64{"confidence": 0.8, "slow": 1, "wifi_score": 0.9, "isp_score": 0.1},
		map[string]string{"endpoint.cause": "wifi", "endpoint.summary": "weak RSSI (-82 dBm)"}))
	s.Record("t-a", "laptop-1", rv(TypeWiFi, "HomeNet", at,
		map[string]float64{"rssi_dbm": -82, "associated": 1},
		map[string]string{"wifi.ssid": "HomeNet", "wifi.band": "2.4GHz"}))
	s.Record("t-a", "laptop-1", rv(TypeGateway, "192.168.1.1", at,
		map[string]float64{"rtt_ms": 3.2, "loss_pct": 0, "reachable": 1},
		map[string]string{"gateway.ip": "192.168.1.1"}))
	s.Record("t-a", "laptop-1", rv(TypeSession, "app.acme.example", at,
		map[string]float64{"total_ms": 900}, nil))
	// Healthy endpoint, later observation.
	s.Record("t-a", "laptop-2", rv(TypeAttribution, "app.acme.example", at.Add(time.Minute),
		map[string]float64{"confidence": 0.9, "slow": 0},
		map[string]string{"endpoint.cause": "none"}))
	// Another tenant.
	s.Record("t-b", "secret-laptop", rv(TypeAttribution, "x", at, nil, map[string]string{"endpoint.cause": "isp"}))
	// Unscoped / non-DEM dropped.
	s.Record("", "ghost", rv(TypeAttribution, "x", at, nil, nil))
	s.Record("t-a", "", rv(TypeAttribution, "x", at, nil, nil))
	s.Record("t-a", "laptop-1", rv("icmp", "x", at, nil, nil))

	views := s.List("t-a")
	if len(views) != 2 {
		t.Fatalf("views = %d", len(views))
	}
	// Impaired endpoints sort first.
	v := views[0]
	if v.AgentID != "laptop-1" || !v.Slow || v.Cause != "wifi" || v.Confidence != 0.8 {
		t.Fatalf("headline = %+v", v)
	}
	if v.WiFi == nil || v.WiFi.Metrics["rssi_dbm"] != -82 || v.WiFi.Attributes["wifi.ssid"] != "HomeNet" {
		t.Fatalf("wifi = %+v", v.WiFi)
	}
	if v.Gateway == nil || v.Gateway.Metrics["rtt_ms"] != 3.2 {
		t.Fatalf("gateway = %+v", v.Gateway)
	}
	if len(v.Sessions) != 1 || v.Sessions[0].Metrics["total_ms"] != 900 {
		t.Fatalf("sessions = %+v", v.Sessions)
	}
	for _, view := range views {
		if view.AgentID == "secret-laptop" {
			t.Fatal("CROSS-TENANT LEAK in List")
		}
	}

	// Privacy: a withheld identifier is ABSENT, never back-filled.
	s.Record("t-a", "laptop-1", rv(TypeWiFi, "", at.Add(2*time.Minute),
		map[string]float64{"rssi_dbm": -60, "associated": 1}, map[string]string{"wifi.band": "5GHz"}))
	v = s.List("t-a")[0]
	if _, has := v.WiFi.Attributes["wifi.ssid"]; has {
		t.Fatalf("privacy-withheld SSID resurfaced: %+v", v.WiFi.Attributes)
	}

	// Out-of-order older result never regresses the view.
	s.Record("t-a", "laptop-1", rv(TypeWiFi, "Old", at.Add(-time.Hour),
		map[string]float64{"rssi_dbm": -30}, map[string]string{"wifi.ssid": "Old"}))
	if got := s.List("t-a")[0].WiFi.Metrics["rssi_dbm"]; got != -60 {
		t.Fatalf("older observation overwrote newer: rssi=%v", got)
	}
}

func TestSnapshotStoreBounds(t *testing.T) {
	s := NewSnapshotStore(3)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		s.Record("t", fmt.Sprintf("ep-%d", i), rv(TypeAttribution, "x", at.Add(time.Duration(i)*time.Minute),
			map[string]float64{"slow": 0}, map[string]string{"endpoint.cause": "none"}))
	}
	if s.Len("t") != 3 {
		t.Fatalf("len = %d, want cap 3", s.Len("t"))
	}
	for _, v := range s.List("t") {
		if v.AgentID == "ep-0" || v.AgentID == "ep-1" || v.AgentID == "ep-2" {
			t.Fatalf("stalest endpoint not evicted: %s", v.AgentID)
		}
	}

	// Session-target cap per agent.
	for i := 0; i < 15; i++ {
		s.Record("t", "ep-5", rv(TypeSession, fmt.Sprintf("svc-%02d", i), at.Add(time.Duration(i)*time.Second),
			map[string]float64{"total_ms": 100}, nil))
	}
	var ep5 View
	for _, v := range s.List("t") {
		if v.AgentID == "ep-5" {
			ep5 = v
		}
	}
	if len(ep5.Sessions) != 10 {
		t.Fatalf("session targets = %d, want cap 10", len(ep5.Sessions))
	}
}
