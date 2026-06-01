package incident

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var t0 = time.Unix(1_700_000_000, 0)

func TestSeverityMax(t *testing.T) {
	if Max(SeverityInfo, SeverityCritical) != SeverityCritical {
		t.Error("info vs critical")
	}
	if Max(SeverityCritical, SeverityWarning) != SeverityCritical {
		t.Error("critical vs warning")
	}
	if Max(SeverityWarning, SeverityWarning) != SeverityWarning {
		t.Error("warning vs warning")
	}
}

func TestTargetsRelated(t *testing.T) {
	cases := []struct {
		name                   string
		incT, incP, sigT, sigP string
		want                   bool
	}{
		{"exact target", "192.0.2.10", "", "192.0.2.10", "", true},
		{"ip in incident prefix", "", "192.0.2.0/24", "192.0.2.10", "", true},
		{"incident ip in signal prefix", "192.0.2.10", "", "", "192.0.2.0/24", true},
		{"overlapping prefixes", "", "192.0.2.0/24", "", "192.0.2.128/25", true},
		{"host:port target in prefix", "", "192.0.2.0/24", "192.0.2.10:443", "", true},
		{"unrelated ips", "192.0.2.10", "", "203.0.113.5", "", false},
		{"dns name no match", "api.example.com", "", "192.0.2.10", "", false},
		{"dns name exact", "api.example.com", "", "api.example.com", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := targetsRelated(c.incT, c.incP, c.sigT, c.sigP); got != c.want {
				t.Errorf("targetsRelated(%q,%q,%q,%q) = %v, want %v", c.incT, c.incP, c.sigT, c.sigP, got, c.want)
			}
		})
	}
}

func TestWithinWindow(t *testing.T) {
	w := 5 * time.Minute
	if !withinWindow(t0.Add(time.Minute), t0, t0, w) {
		t.Error("1 min after should be within a 5-min window")
	}
	if withinWindow(t0.Add(10*time.Minute), t0, t0, w) {
		t.Error("10 min after should be outside a 5-min window")
	}
	if withinWindow(t0.Add(-10*time.Minute), t0, t0, w) {
		t.Error("10 min before should be outside a 5-min window")
	}
}

// TestCorrelatorGroupsNetworkAndBGP is the S17 Done-when: a network alert on an
// IP and a BGP event on the prefix that contains it group into one incident with
// a coherent timeline.
func TestCorrelatorGroupsNetworkAndBGP(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 5*time.Minute, discard())
	ctx := context.Background()

	i1, err := c.Ingest(ctx, Signal{
		TenantID: "t1", Plane: "network", Kind: "alert.firing", Severity: SeverityWarning,
		Title: "high loss to 192.0.2.10", Target: "192.0.2.10", OccurredAt: t0,
	})
	if err != nil {
		t.Fatal(err)
	}

	i2, err := c.Ingest(ctx, Signal{
		TenantID: "t1", Plane: "bgp", Kind: "bgp.possible_hijack", Severity: SeverityCritical,
		Title: "possible hijack of 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24",
		OccurredAt: t0.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	if i1.ID != i2.ID {
		t.Fatalf("network + BGP signals should be one incident, got %s and %s", i1.ID, i2.ID)
	}
	if store.Len() != 1 {
		t.Errorf("expected exactly 1 incident, got %d", store.Len())
	}
	if i2.SignalCount != 2 || len(i2.Signals) != 2 {
		t.Errorf("incident should have a 2-signal timeline, got count=%d signals=%d", i2.SignalCount, len(i2.Signals))
	}
	if i2.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical (max of the signals)", i2.Severity)
	}
	// Timeline is time-ordered network → BGP.
	if i2.Signals[0].Plane != "network" || i2.Signals[1].Plane != "bgp" {
		t.Errorf("timeline order = %s,%s", i2.Signals[0].Plane, i2.Signals[1].Plane)
	}
}

func TestCorrelatorUnrelatedTargetsAreSeparate(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 5*time.Minute, discard())
	ctx := context.Background()
	_, _ = c.Ingest(ctx, Signal{TenantID: "t1", Plane: "network", Target: "192.0.2.10", OccurredAt: t0})
	_, _ = c.Ingest(ctx, Signal{TenantID: "t1", Plane: "network", Target: "203.0.113.5", OccurredAt: t0.Add(time.Minute)})
	if store.Len() != 2 {
		t.Errorf("unrelated targets should be 2 incidents, got %d", store.Len())
	}
}

func TestCorrelatorOutsideWindowOpensNewIncident(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 5*time.Minute, discard())
	ctx := context.Background()
	_, _ = c.Ingest(ctx, Signal{TenantID: "t1", Plane: "network", Target: "192.0.2.10", OccurredAt: t0})
	_, _ = c.Ingest(ctx, Signal{TenantID: "t1", Plane: "network", Target: "192.0.2.10", OccurredAt: t0.Add(time.Hour)})
	if store.Len() != 2 {
		t.Errorf("same target an hour apart should open a new incident, got %d", store.Len())
	}
}

func TestCorrelatorTenantIsolation(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 5*time.Minute, discard())
	ctx := context.Background()
	// Same target, same time, different tenants → never correlated.
	_, _ = c.Ingest(ctx, Signal{TenantID: "t1", Plane: "network", Target: "192.0.2.10", OccurredAt: t0})
	_, _ = c.Ingest(ctx, Signal{TenantID: "t2", Plane: "network", Target: "192.0.2.10", OccurredAt: t0})
	if store.Len() != 2 {
		t.Errorf("cross-tenant signals must not group, got %d incidents", store.Len())
	}
}

func TestCorrelatorFailsClosedWithoutTenant(t *testing.T) {
	c := NewCorrelator(NewMemoryStore(), 5*time.Minute, discard())
	if _, err := c.Ingest(context.Background(), Signal{Plane: "network", Target: "192.0.2.10"}); err == nil {
		t.Fatal("a signal without a tenant must be rejected (fail closed)")
	}
}
