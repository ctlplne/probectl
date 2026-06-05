package carbon

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/cost"
)

func testMapper(t *testing.T) *cost.Mapper {
	t.Helper()
	zones, err := cost.ParseZoneRules("10.1.0.0/16=us-east-1a/us-east-1,10.2.0.0/16=us-east-1b/us-east-1,10.9.0.0/16=eu-west-1a/eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	owners, err := cost.ParseOwnerRules("10.1.0.0/16=checkout:payments")
	if err != nil {
		t.Fatal(err)
	}
	return cost.NewMapper(zones, owners)
}

func at(h int) time.Time {
	return time.Date(2026, 6, 5, h, 30, 0, 0, time.UTC)
}

func TestObserveEstimatesByClassAndAttribution(t *testing.T) {
	e := NewEngine(testMapper(t), DefaultCoefficients(400))
	gb := uint64(1 << 30)

	// 10 GB cross-AZ from the checkout service.
	for i := 0; i < 10; i++ {
		e.Observe("t1", cost.FlowSample{Src: "10.1.0.5", Dst: "10.2.0.9", Bytes: gb, At: at(12)})
	}
	// 2 GB internet egress, unattributed source.
	for i := 0; i < 2; i++ {
		e.Observe("t1", cost.FlowSample{Src: "10.9.0.7", Dst: "203.0.113.9", Bytes: gb, At: at(13)})
	}

	s := e.Summary("t1")
	// inter_az: 10 GB × 0.01 kWh/GB = 0.1 kWh × 400 g = 40 g.
	ia := s.ByClass[cost.ClassInterAZ]
	if math.Abs(ia.KWh-0.1) > 1e-9 || math.Abs(ia.GCO2e-40) > 1e-6 {
		t.Fatalf("inter_az estimate wrong: %+v", ia)
	}
	// internet: 2 GB × 0.06 = 0.12 kWh × 400 = 48 g.
	eg := s.ByClass[cost.ClassInternet]
	if math.Abs(eg.KWh-0.12) > 1e-9 || math.Abs(eg.GCO2e-48) > 1e-6 {
		t.Fatalf("internet estimate wrong: %+v", eg)
	}
	if math.Abs(s.TotalGCO2e-88) > 1e-6 || s.TotalBytes != 12*gb {
		t.Fatalf("totals wrong: %+v", s)
	}
	// Attribution rides the cost mapper: checkout/payments own the AZ traffic.
	if s.ByService["checkout"].Bytes != 10*gb || s.ByTeam["payments"].Bytes != 10*gb {
		t.Fatalf("attribution wrong: %+v / %+v", s.ByService, s.ByTeam)
	}
	if s.ByService["(unattributed)"].Bytes != 2*gb {
		t.Fatalf("unattributed bucket wrong: %+v", s.ByService)
	}
	// Trend buckets by hour.
	if len(s.Trend) != 2 || !s.Trend[0].Hour.Before(s.Trend[1].Hour) {
		t.Fatalf("trend wrong: %+v", s.Trend)
	}
}

// The honesty contract: estimates SAY they are estimates, with methodology.
func TestMethodologyHonesty(t *testing.T) {
	e := NewEngine(testMapper(t), DefaultCoefficients(0))
	s := e.Summary("t1")
	m := s.Methodology
	if m.Measured {
		t.Fatal("measured must be false — these are coefficient estimates, structurally")
	}
	if m.Source == "" || m.GridGCO2ePerKWh != 436 {
		t.Fatalf("methodology incomplete: %+v", m)
	}
	if m.Note == "" {
		t.Fatal("the estimate note must ride every response")
	}
}

func TestTenantIsolationAndUnscopedDrops(t *testing.T) {
	e := NewEngine(testMapper(t), DefaultCoefficients(400))
	gb := uint64(1 << 30)
	e.Observe("tenant-a", cost.FlowSample{Src: "10.1.0.5", Dst: "10.2.0.9", Bytes: gb, At: at(12)})
	e.Observe("tenant-b", cost.FlowSample{Src: "10.9.0.7", Dst: "203.0.113.9", Bytes: gb, At: at(12)})
	// Unscoped/empty records are dropped (guardrail 1).
	e.Observe("", cost.FlowSample{Src: "10.1.0.5", Dst: "10.2.0.9", Bytes: gb, At: at(12)})
	e.Observe("tenant-a", cost.FlowSample{Bytes: gb, At: at(12)})

	a, b := e.Summary("tenant-a"), e.Summary("tenant-b")
	if a.TotalBytes != gb || b.TotalBytes != gb {
		t.Fatalf("totals wrong: a=%d b=%d", a.TotalBytes, b.TotalBytes)
	}
	if _, leak := a.ByClass[cost.ClassInternet]; leak {
		t.Fatal("tenant-a must not see tenant-b's internet traffic")
	}
	if _, leak := b.ByClass[cost.ClassInterAZ]; leak {
		t.Fatal("tenant-b must not see tenant-a's AZ traffic")
	}
}

func TestBoundsAttributionKeys(t *testing.T) {
	// No owner rules → every distinct src lands in service buckets… which
	// must stay bounded via the "(other)" overflow.
	e := NewEngine(cost.NewMapper(nil, nil), DefaultCoefficients(400))
	for i := 0; i < maxKeys+100; i++ {
		e.Observe("t1", cost.FlowSample{
			Src: fmt.Sprintf("10.1.%d.%d", i/250, i%250), Dst: "203.0.113.9",
			Bytes: 1024, At: at(12),
		})
	}
	s := e.Summary("t1")
	if len(s.ByService) > maxKeys+1 {
		t.Fatalf("service buckets must stay bounded, got %d", len(s.ByService))
	}
}

func TestZeroGridDefaultsAndCustomCoefficients(t *testing.T) {
	c := DefaultCoefficients(50) // a clean grid
	e := NewEngine(testMapper(t), c)
	e.Observe("t1", cost.FlowSample{Src: "10.1.0.5", Dst: "203.0.113.9", Bytes: 1 << 30, At: at(12)})
	s := e.Summary("t1")
	if math.Abs(s.TotalGCO2e-0.06*50) > 1e-9 {
		t.Fatalf("custom grid intensity must apply: %v", s.TotalGCO2e)
	}
}
