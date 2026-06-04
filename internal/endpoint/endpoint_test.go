package endpoint

import (
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

func TestIsPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.1": true,
		"10.0.0.1":    true,
		"172.16.5.4":  true,
		"100.64.0.1":  true, // CGNAT
		"169.254.1.1": true, // link-local
		"127.0.0.1":   true,
		"1.1.1.1":     false,
		"8.8.8.8":     false,
		"100.128.0.1": false, // just outside CGNAT
		"":            false,
		"not-an-ip":   false,
	}
	for ip, want := range cases {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestClassifyAndGateway(t *testing.T) {
	lm := LastMile{
		Target: "1.1.1.1",
		Hops: []LastMileHop{
			{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 2},
			{Index: 2, IP: "100.64.0.1", Private: true, RTTMs: 9}, // CPE/CGNAT, still local
			{Index: 3, IP: "203.0.113.1", Private: false, RTTMs: 14, LossPct: 5},
			{Index: 4, IP: "", RTTMs: 0, LossPct: 100}, // unresponsive
			{Index: 5, IP: "1.1.1.1", Private: false, RTTMs: 20},
		},
	}
	lm.classify()
	if lm.LocalRTTMs != 9 { // last private hop
		t.Errorf("LocalRTTMs = %v, want 9", lm.LocalRTTMs)
	}
	if lm.ISPRTTMs != 14 || lm.ISPLossPct != 5 { // first public hop
		t.Errorf("ISP = %v/%v, want 14/5", lm.ISPRTTMs, lm.ISPLossPct)
	}
	if lm.BeyondRTTMs != 20 { // last hop
		t.Errorf("BeyondRTTMs = %v, want 20", lm.BeyondRTTMs)
	}
	g := gatewayFromLastMile(lm)
	if g.IP != "192.168.1.1" || !g.Reachable || g.RTTMs != 2 {
		t.Errorf("gateway = %+v, want first private hop", g)
	}
}

func TestGatewayUnreachableFromFullLoss(t *testing.T) {
	lm := LastMile{Hops: []LastMileHop{{Index: 1, IP: "192.168.0.1", Private: true, RTTMs: 3, LossPct: 100}}}
	if g := gatewayFromLastMile(lm); g.Reachable {
		t.Errorf("100%% loss first hop should be unreachable, got %+v", g)
	}
}

func TestToResults(t *testing.T) {
	s := Sample{
		TenantID: "t1", AgentID: "laptop-1", Timestamp: time.Unix(1700000000, 0),
		WiFi:    WiFi{Present: true, Associated: true, SSID: "office", Band: "5GHz", RSSIDBm: -55, Channel: 36, Have: WiFiHave{RSSI: true}},
		Gateway: Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 3},
		LastMile: LastMile{Target: "1.1.1.1", Reached: true, ISPRTTMs: 18, Hops: []LastMileHop{
			{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 3},
		}},
		Sessions: []Session{{Target: "https://app", Success: true, TotalMs: 320, TTFBms: 90}},
	}
	s.Attribution = Attribute(s, DefaultThresholds())

	results := s.ToResults()
	byType := map[string]bool{}
	for _, r := range results {
		byType[r.Type] = true
		if r.StartedAt.IsZero() {
			t.Errorf("result %q missing StartedAt", r.Type)
		}
	}
	for _, want := range []string{TypeAttribution, TypeWiFi, TypeGateway, TypeLastMile, TypeSession} {
		if !byType[want] {
			t.Errorf("missing result type %q", want)
		}
	}

	// The attribution result carries the cause as an attribute and is the headline.
	att := findResult(t, results, TypeAttribution)
	if att.Attributes["endpoint.cause"] != string(CauseNone) {
		t.Errorf("attribution cause attr = %q, want none", att.Attributes["endpoint.cause"])
	}
	wifi := findResult(t, results, TypeWiFi)
	if wifi.Metrics["rssi_dbm"] != -55 || wifi.Attributes["wifi.ssid"] != "office" {
		t.Errorf("wifi result = %+v", wifi)
	}
	sess := findResult(t, results, TypeSession)
	if sess.Metrics["total_ms"] != 320 {
		t.Errorf("session total_ms = %v, want 320", sess.Metrics["total_ms"])
	}
}

func findResult(t *testing.T, rs []canary.Result, typ string) canary.Result {
	t.Helper()
	for _, r := range rs {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no result of type %q", typ)
	return canary.Result{}
}
