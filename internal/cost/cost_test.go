package cost

import (
	"math"
	"strings"
	"testing"
	"time"
)

var costT = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

// fixtureEngine: two AZs in us-east-1 + one zone in eu-west-1; checkout
// (payments team) in 1a, inventory (logistics) in 1b, analytics in eu-west-1a.
func fixtureEngine(t *testing.T, prices *PriceTable, budgets []Budget) *Engine {
	t.Helper()
	zones, err := ParseZoneRules("10.0.1.0/24=us-east-1a, 10.0.2.0/24=us-east-1b, 10.9.0.0/16=eu-west-1a")
	if err != nil {
		t.Fatal(err)
	}
	owners, err := ParseOwnerRules("10.0.1.0/24=checkout:payments, 10.0.2.0/24=inventory:logistics, 10.9.0.0/16=analytics:data")
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(NewMapper(zones, owners), prices, budgets)
}

// The sprint's named test: fixture flows + pricing → expected dollars per
// service (and team showback).
func TestCostAttribution(t *testing.T) {
	e := fixtureEngine(t, DefaultPriceTable(), nil)

	// checkout → inventory: 10 GiB inter-AZ @ $0.01/GiB = $0.10
	e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: costT})
	// checkout → analytics (eu): 5 GiB inter-region @ $0.02/GiB = $0.10
	e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.9.0.9", Bytes: 5 << 30, At: costT})
	// checkout → internet: 2 GiB @ $0.09/GiB = $0.18
	e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "203.0.113.50", Bytes: 2 << 30, At: costT})
	// inventory same-zone: free.
	e.Observe("t1", FlowSample{Src: "10.0.2.7", Dst: "10.0.2.8", Bytes: 100 << 30, At: costT})

	s := e.Summary("t1")
	if !s.Priced || !s.ZonesMapped {
		t.Fatalf("honesty flags: %+v", s)
	}
	wantCheckout := 0.10 + 0.10 + 0.18
	if got := s.ByService["checkout"].USD; math.Abs(got-wantCheckout) > 1e-9 {
		t.Fatalf("checkout USD = %.4f, want %.4f", got, wantCheckout)
	}
	if got := s.ByService["inventory"].USD; got != 0 {
		t.Fatalf("same-zone traffic priced: $%.4f", got)
	}
	// Team showback mirrors the service attribution.
	if got := s.ByTeam["payments"].USD; math.Abs(got-wantCheckout) > 1e-9 {
		t.Fatalf("payments team USD = %.4f, want %.4f", got, wantCheckout)
	}
	if s.ByClass[ClassInterAZ].Bytes != 10<<30 || s.ByClass[ClassInternet].USD == 0 {
		t.Fatalf("class breakdown = %+v", s.ByClass)
	}
	// Trend bucket carries the volume + dollars.
	if len(s.Trend) != 1 || s.Trend[0].Bytes == 0 || s.Trend[0].USD == 0 {
		t.Fatalf("trend = %+v", s.Trend)
	}

	// Tenant isolation: another tenant sees nothing.
	if other := e.Summary("t2"); other.TotalBytes != 0 || len(other.ByService) != 0 {
		t.Fatalf("cross-tenant cost data: %+v", other)
	}
}

// The sprint's named test: a cross-AZ "chatty service" is detected.
func TestChattyCrossAZDetection(t *testing.T) {
	e := fixtureEngine(t, DefaultPriceTable(), nil)

	// 600 MiB ×2 inter-AZ from checkout: crosses the 1 GiB chatty threshold.
	for i := 0; i < 2; i++ {
		e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 600 << 20,
			At: costT.Add(time.Duration(i) * time.Minute)})
	}
	// A quiet inter-AZ pair stays under it.
	e.Observe("t1", FlowSample{Src: "10.0.2.7", Dst: "10.0.1.5", Bytes: 1 << 20, At: costT})

	s := e.Summary("t1")
	if len(s.ChattyPairs) < 2 {
		t.Fatalf("pairs = %+v", s.ChattyPairs)
	}
	top := s.ChattyPairs[0]
	if !top.Chatty || top.Service != "checkout" || top.SrcZone != "us-east-1a" || top.DstZone != "us-east-1b" {
		t.Fatalf("top pair = %+v", top)
	}
	for _, p := range s.ChattyPairs[1:] {
		if p.Chatty {
			t.Fatalf("quiet pair flagged chatty: %+v", p)
		}
	}
}

// The sprint's named test: no pricing → volume-only, honestly flagged.
func TestDegradationWithoutPricing(t *testing.T) {
	e := fixtureEngine(t, nil, nil) // nil price table = volume-only

	e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: costT})
	s := e.Summary("t1")
	if s.Priced {
		t.Fatal("priced=true without a price table")
	}
	if s.TotalUSD != 0 {
		t.Fatalf("dollars invented without pricing: $%.2f", s.TotalUSD)
	}
	if s.TotalBytes != 10<<30 || s.ByService["checkout"].Bytes != 10<<30 {
		t.Fatalf("volume accounting must survive: %+v", s)
	}
	// Without zone rules everything is unknown-class volume — still counted.
	bare := NewEngine(NewMapper(nil, nil), nil, nil)
	bare.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 1 << 20, At: costT})
	bs := bare.Summary("t1")
	if bs.ZonesMapped || bs.ByClass[ClassUnknown].Bytes != 1<<20 {
		t.Fatalf("bare summary = %+v", bs)
	}
}

// The sprint's "Done when": a budget trend/alert fires — once per month.
func TestBudgetAlertFiresOncePerMonth(t *testing.T) {
	budgets, err := ParseBudgets("team:payments=0.15, service:analytics=100")
	if err != nil {
		t.Fatal(err)
	}
	e := fixtureEngine(t, DefaultPriceTable(), budgets)

	// 10 GiB inter-AZ = $0.10: under budget, no signal.
	if sigs := e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: costT}); len(sigs) != 0 {
		t.Fatalf("premature alert: %+v", sigs)
	}
	// Another 10 GiB → $0.20 ≥ $0.15: the breach signal fires.
	sigs := e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: costT.Add(time.Hour)})
	if len(sigs) != 1 {
		t.Fatalf("want 1 budget signal, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Plane != "cost" || sig.Kind != "cost.budget_exceeded" || sig.TenantID != "t1" ||
		sig.Attributes["cost.budget_name"] != "payments" {
		t.Fatalf("signal = %+v", sig)
	}
	if !strings.Contains(sig.Summary, "$0.20") || !strings.Contains(sig.Summary, "$0.15") {
		t.Fatalf("summary = %s", sig.Summary)
	}
	// Continued spend in the SAME month stays quiet (alert fatigue control)…
	if sigs := e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: costT.Add(2 * time.Hour)}); len(sigs) != 0 {
		t.Fatalf("re-alerted within the month: %+v", sigs)
	}
	// …and the budget status shows the breach.
	s := e.Summary("t1")
	var payments *BudgetStatus
	for i := range s.Budgets {
		if s.Budgets[i].Name == "payments" {
			payments = &s.Budgets[i]
		}
	}
	if payments == nil || !payments.Exceeded || payments.SpentUSD < 0.15 {
		t.Fatalf("budget status = %+v", s.Budgets)
	}
	// A NEW month resets the accumulator and may alert again.
	nextMonth := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if sigs := e.Observe("t1", FlowSample{Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 30 << 30, At: nextMonth}); len(sigs) != 1 {
		t.Fatalf("new month did not re-arm the budget: %+v", sigs)
	}
}

func TestParsersFailClosed(t *testing.T) {
	if _, err := ParseZoneRules("not-a-rule"); err == nil {
		t.Error("bad zone rule accepted")
	}
	if _, err := ParseZoneRules("10.0.0.0/8"); err == nil {
		t.Error("zone rule without zone accepted")
	}
	if _, err := ParseOwnerRules("10.0.0.0/8=:team"); err == nil {
		t.Error("owner rule without service accepted")
	}
	if _, err := ParseBudgets("payments=500"); err == nil {
		t.Error("budget without kind accepted")
	}
	if _, err := ParseBudgets("team:payments=-5"); err == nil {
		t.Error("negative budget accepted")
	}
	if _, err := LoadPriceTable("/does/not/exist.json"); err == nil {
		t.Error("missing price file accepted")
	}
	// Region derivation convention.
	if r := regionOfZone("us-east-1a"); r != "us-east-1" {
		t.Errorf("regionOfZone = %s", r)
	}
}
