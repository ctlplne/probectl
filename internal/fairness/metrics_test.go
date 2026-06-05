package fairness

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// TestWriteSeries: fairness accounting lands in the TSDB as per-tenant,
// per-meter series — the Grafana-federable observability leg.
func TestWriteSeries(t *testing.T) {
	g := NewGate(Policy{ResultsPerSec: 1, BurstSeconds: 1}, nil)
	ctx := context.Background()
	// One admit, then sheds (capacity 1) + one query.
	for range 5 {
		g.AdmitN(ctx, "tnA", MeterResults, 1)
	}
	rel, err := g.BeginQuery(ctx, "tnA")
	if err != nil {
		t.Fatal(err)
	}

	w := tsdb.NewMemory()
	if err := WriteSeries(ctx, w, g); err != nil {
		t.Fatal(err)
	}
	shed := w.Query("probectl_fairness_shed_units_total", map[string]string{"tenant_id": "tnA", "meter": MeterResults})
	if len(shed) == 0 || shed[0].Value < 3 {
		t.Fatalf("shed series: %+v", shed)
	}
	adm := w.Query("probectl_fairness_admitted_units_total", map[string]string{"tenant_id": "tnA", "meter": MeterResults})
	if len(adm) == 0 || adm[0].Value < 1 {
		t.Fatalf("admitted series: %+v", adm)
	}
	inflight := w.Query("probectl_fairness_queries_in_flight", map[string]string{"tenant_id": "tnA"})
	if len(inflight) == 0 || inflight[0].Value != 1 {
		t.Fatalf("in-flight gauge: %+v", inflight)
	}
	rel()

	// nil writer / nil gate / empty gate are all no-ops.
	if err := WriteSeries(ctx, nil, g); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeries(ctx, w, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteSeries(ctx, w, NewGate(Policy{}, nil)); err != nil {
		t.Fatal(err)
	}
}

// TestRunMetricsLoop: the loop writes on its ticker and stops with ctx.
func TestRunMetricsLoop(t *testing.T) {
	g := NewGate(Policy{}, nil)
	g.AdmitN(context.Background(), "tnA", MeterResults, 1)
	w := tsdb.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunMetrics(ctx, w, g, 5*time.Millisecond, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_fairness_admitted_units_total", map[string]string{"tenant_id": "tnA"})) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if len(w.Query("probectl_fairness_admitted_units_total", map[string]string{"tenant_id": "tnA"})) == 0 {
		t.Fatal("the metrics loop must write fairness series")
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]float64{"": 0, "x": 0, "-5": 0, "250": 250, "0.5": 0.5} {
		if got := ParseRate(in); got != want {
			t.Fatalf("ParseRate(%q) = %v, want %v", in, got, want)
		}
	}
}
