// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestIncidentCorrelationAndAPI proves the S17 Done-when end to end against
// Postgres: a network alert signal and a BGP signal for the prefix that contains
// its target group into ONE incident, which the timeline API returns with both
// signals, and which PATCH resolves.
func TestIncidentCorrelationAndAPI(t *testing.T) {
	h, db := setupAPI(t)
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	ctx := context.Background()
	tenant := tenancy.DefaultTenantID.String()
	now := time.Now().UTC().Truncate(time.Second)

	i1, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "network", Kind: "alert.firing", Severity: incident.SeverityWarning,
		Title: "high loss to 192.0.2.10", Target: "192.0.2.10", OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	i2, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "possible hijack 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24",
		OccurredAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if i1.ID != i2.ID {
		t.Fatalf("network + BGP signals should be one incident, got %s and %s", i1.ID, i2.ID)
	}

	// List shows the incident with the correlated aggregates.
	rec := apiReq(t, h, http.MethodGet, "/v1/incidents", "", nil)
	var listed struct{ Items []incident.Incident }
	mustJSON(t, rec, &listed)
	var found *incident.Incident
	for i := range listed.Items {
		if listed.Items[i].ID == i1.ID {
			found = &listed.Items[i]
		}
	}
	if found == nil {
		t.Fatal("correlated incident not in the list")
	}
	if found.SignalCount != 2 || found.Severity != incident.SeverityCritical {
		t.Errorf("incident = count %d / severity %q, want 2 / critical", found.SignalCount, found.Severity)
	}

	// Get returns the unified, time-ordered timeline overlaying both planes.
	rec = apiReq(t, h, http.MethodGet, "/v1/incidents/"+i1.ID, "", nil)
	var got incident.Incident
	mustJSON(t, rec, &got)
	if len(got.Signals) != 2 || got.Signals[0].Plane != "network" || got.Signals[1].Plane != "bgp" {
		t.Fatalf("timeline = %+v", got.Signals)
	}

	// Resolve.
	rec = apiReq(t, h, http.MethodPatch, "/v1/incidents/"+i1.ID, "", map[string]any{"status": "resolved"})
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve = %d: %s", rec.Code, rec.Body)
	}
	var resolved incident.Incident
	mustJSON(t, rec, &resolved)
	if resolved.Status != incident.StatusResolved || resolved.ResolvedAt == nil {
		t.Errorf("resolved = %+v", resolved)
	}

	// A bad PATCH status → 422.
	if rec = apiReq(t, h, http.MethodPatch, "/v1/incidents/"+i1.ID, "", map[string]any{"status": "open"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid status = %d, want 422", rec.Code)
	}
}

func TestIncidentCorrelationSerializesAcrossPostgresCorrelators(t *testing.T) {
	_, db := setupAPI(t)
	ctx := context.Background()
	tn, err := store.NewTenants(db.Pool()).Create(ctx,
		fmt.Sprintf("incha-%d", time.Now().UnixNano()), "Incident HA")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	c1 := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	c2 := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	now := time.Now().UTC().Truncate(time.Second)
	const n = 32
	start := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		c := c1
		plane, kind := "network", "alert.firing"
		if i%2 == 1 {
			c = c2
			plane, kind = "bgp", "bgp.possible_hijack"
		}
		wg.Add(1)
		go func(i int, c *incident.Correlator, plane, kind string) {
			defer wg.Done()
			<-start
			_, err := c.Ingest(ctx, incident.Signal{
				TenantID: tn.ID, Plane: plane, Kind: kind, Severity: incident.SeverityWarning,
				Title: fmt.Sprintf("%s signal %02d", plane, i), Target: "203.0.113.10",
				OccurredAt: now.Add(time.Duration(i%3) * time.Second),
			})
			errs <- err
		}(i, c, plane, kind)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ingest: %v", err)
		}
	}

	var open []incident.Incident
	var full *incident.Incident
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			var e error
			open, e = store.Incidents{}.OpenIncidents(ctx, sc)
			if e != nil || len(open) != 1 {
				return e
			}
			full, e = store.Incidents{}.Get(ctx, sc, open[0].ID)
			return e
		}); err != nil {
		t.Fatalf("read incidents: %v", err)
	}
	if len(open) != 1 {
		t.Fatalf("two Postgres correlators opened %d incidents, want exactly 1", len(open))
	}
	if full.SignalCount != n || len(full.Signals) != n {
		t.Fatalf("incident has count=%d signals=%d, want all %d signals in one incident", full.SignalCount, len(full.Signals), n)
	}
	planes := map[string]bool{}
	for _, sig := range full.Signals {
		planes[sig.Plane] = true
	}
	if len(planes) != 2 {
		t.Fatalf("incident planes = %v, want both network and bgp evidence", planes)
	}
}

// TestIncidentsAPITenantIsolation proves an incident in tenant B is invisible to
// the default tenant (RLS, end to end).
func TestIncidentsAPITenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		fmt.Sprintf("inciso-%d", time.Now().UnixNano()), "Incident Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())

	inc, err := c.Ingest(context.Background(), incident.Signal{
		TenantID: tn.ID, Plane: "network", Title: "tenant B incident",
		Target: "192.0.2.10", Severity: incident.SeverityWarning, OccurredAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Default tenant cannot fetch tenant B's incident (404).
	if rec := apiReq(t, h, http.MethodGet, "/v1/incidents/"+inc.ID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant get = %d, want 404", rec.Code)
	}
	// Tenant B can.
	if rec := apiReq(t, h, http.MethodGet, "/v1/incidents/"+inc.ID, tn.ID, nil); rec.Code != http.StatusOK {
		t.Errorf("tenant B get = %d, want 200", rec.Code)
	}
}

func TestThreatDetectionsAPIReadsDurableIncidentSignals(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	tn, err := store.NewTenants(db.Pool()).Create(ctx,
		fmt.Sprintf("detiso-%d", time.Now().UnixNano()), "Detection Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	inc, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenancy.DefaultTenantID.String(),
		Plane:    "threat", Kind: "ioc.botnet_c2", Severity: incident.SeverityCritical,
		Title: "203.0.113.66 matches threat-intel indicator", Target: "203.0.113.66",
		OccurredAt: now,
		Attributes: map[string]string{
			"intel.source": "feodo", "intel.confidence": "90",
			"intel.category": "botnet", "intel.indicator": "203.0.113.66",
			"intel.license": "CC0",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ingest(ctx, incident.Signal{
		TenantID: tn.ID,
		Plane:    "threat", Kind: "ioc.botnet_c2", Severity: incident.SeverityCritical,
		Title: "secret.other matches threat-intel indicator", Target: "secret.other",
		OccurredAt: now,
		Attributes: map[string]string{
			"intel.source": "feodo", "intel.confidence": "90", "intel.indicator": "secret.other",
		},
	}); err != nil {
		t.Fatal(err)
	}

	rec := apiReq(t, h, http.MethodGet, "/v1/threat/detections", "", nil)
	var resp struct {
		DetectionsRunning bool               `json:"detections_running"`
		Items             []threat.Detection `json:"items"`
	}
	mustJSON(t, rec, &resp)
	if !resp.DetectionsRunning || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if got := resp.Items[0]; got.IncidentID != inc.ID || got.Source != "feodo" || got.Indicator != "203.0.113.66" {
		t.Fatalf("detection = %+v, want incident %s / default tenant IOC", got, inc.ID)
	}
	if strings.Contains(rec.Body.String(), "secret.other") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}

	rec = apiReq(t, h, http.MethodGet, "/v1/threat/detections", tn.ID, nil)
	if !strings.Contains(rec.Body.String(), "secret.other") || strings.Contains(rec.Body.String(), "203.0.113.66") {
		t.Fatalf("tenant B detection view wrong: %s", rec.Body.String())
	}
}
