package author

import (
	"fmt"
	"strings"
	"testing"
)

func targetTypes(ps []DiscoveryProposal) map[string]string {
	m := map[string]string{}
	for _, p := range ps {
		m[p.Spec.Target] = p.Spec.Type
	}
	return m
}

func TestDiscoverFromServiceMap(t *testing.T) {
	obs := []Observation{
		{Target: "payments.svc", Port: 443, Kind: "service", Count: 50},
		{Target: "db.svc", Port: 5432, Protocol: "tcp", Kind: "service", Count: 30},
		{Target: "ns.svc", Port: 53, Protocol: "udp", Kind: "service", Count: 20},
		{Target: "8.8.8.8", Kind: "flow", Count: 10},
		{Target: "noisy.svc", Port: 9999, Kind: "flow", Count: 1},      // below threshold → dropped
		{Target: "203.0.113.0/24", Kind: "prefix", Count: 40},          // a prefix → not a synthetic target
		{Target: "already.svc", Port: 443, Kind: "service", Count: 99}, // already monitored → deduped
	}
	existing := []string{"https://already.svc"}
	props := Discover(obs, existing, DiscoverOptions{})

	got := targetTypes(props)
	if got["https://payments.svc"] != "http" {
		t.Errorf("payments:443 → http https://payments.svc, got %v", got)
	}
	if got["db.svc:5432"] != "tcp" {
		t.Errorf("db:5432 → tcp, got %v", got)
	}
	if got["ns.svc"] != "dns" {
		t.Errorf("ns:53 → dns, got %v", got)
	}
	if got["8.8.8.8"] != "icmp" {
		t.Errorf("bare IP → icmp, got %v", got)
	}
	for tgt := range got {
		if strings.Contains(tgt, "noisy") {
			t.Error("a below-threshold observation must be dropped (noise)")
		}
		if strings.Contains(tgt, "already") {
			t.Error("an already-monitored target must be deduped")
		}
		if strings.Contains(tgt, "/24") {
			t.Error("a prefix must not become a synthetic-test proposal")
		}
	}

	// Ranked by score: payments (highest count + well-known-port bonus) is first.
	if len(props) == 0 || props[0].Spec.Target != "https://payments.svc" {
		t.Errorf("highest-score proposal should be payments, got %+v", props)
	}
}

func TestDiscoverThresholdAndCap(t *testing.T) {
	var obs []Observation
	for i := 0; i < 30; i++ {
		obs = append(obs, Observation{Target: fmt.Sprintf("svc-%02d.local", i), Port: 443, Kind: "service", Count: 5})
	}
	if props := Discover(obs, nil, DiscoverOptions{Max: 10}); len(props) != 10 {
		t.Errorf("cap not applied: got %d proposals, want 10", len(props))
	}
}
