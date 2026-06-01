//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/path"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/internal/store/pathstore"
	"github.com/imfeelingtheagi/netctl/migrations"
)

type fakeDiscoverer struct {
	calls      int
	lastTarget string
}

func (f *fakeDiscoverer) run(_ context.Context, cfg path.Config) (*path.Path, error) {
	f.calls++
	f.lastTarget = cfg.Target
	return samplePath(cfg.Target), nil
}

func samplePath(target string) *path.Path {
	return &path.Path{
		Target: target, TargetIP: target, Mode: "icmp", MaxHops: 30, TraceCount: 3, DestinationReached: true,
		Hops: []path.Hop{
			{TTL: 1, Nodes: []path.HopNode{{IP: "10.0.0.1", Sent: 3, Received: 3, RTTAvgMs: 1.0}}},
			{TTL: 2, Nodes: []path.HopNode{
				{IP: "10.0.0.2", Sent: 2, Received: 1, LossRatio: 0.5, RTTAvgMs: 12.0},
				{IP: "10.0.0.3", Sent: 1, Received: 1, RTTAvgMs: 13.0},
			}},
			{TTL: 3, Nodes: []path.HopNode{{IP: target, Sent: 3, Received: 3, RTTAvgMs: 20.0}}},
		},
		Links: []path.Link{
			{TTL: 1, From: "10.0.0.1", To: "10.0.0.2"}, {TTL: 1, From: "10.0.0.1", To: "10.0.0.3"},
			{TTL: 2, From: "10.0.0.2", To: target}, {TTL: 2, From: "10.0.0.3", To: target},
		},
	}
}

func setupPathAPI(t *testing.T) (http.Handler, *store.DB, *fakeDiscoverer) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	disc := &fakeDiscoverer{}
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), pathstore.NewMemory(), disc.run)
	return srv.Handler(), db, disc
}

func TestPathAPI(t *testing.T) {
	h, _, disc := setupPathAPI(t)

	rec := apiReq(t, h, http.MethodPost, "/v1/tests", "",
		map[string]any{"name": fmt.Sprintf("p-%d", time.Now().UnixNano()), "type": "icmp", "target": "9.9.9.9"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create test = %d: %s", rec.Code, rec.Body)
	}
	var created store.Test
	mustJSON(t, rec, &created)

	// No path yet → 404.
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID+"/path", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get path before discovery = %d, want 404", rec.Code)
	}

	// Discover → 200 + the merged multi-path; the discoverer ran for the host.
	rec = apiReq(t, h, http.MethodPost, "/v1/tests/"+created.ID+"/path", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover = %d: %s", rec.Code, rec.Body)
	}
	var p path.Path
	mustJSON(t, rec, &p)
	if p.Target != "9.9.9.9" || len(p.Hops) != 3 || !p.DestinationReached {
		t.Errorf("discovered path = %+v", p)
	}
	if len(p.Hops[1].Nodes) != 2 {
		t.Errorf("ttl 2 should expose 2 ECMP nodes, got %d", len(p.Hops[1].Nodes))
	}
	if disc.calls != 1 || disc.lastTarget != "9.9.9.9" {
		t.Errorf("discoverer calls=%d target=%q", disc.calls, disc.lastTarget)
	}

	// Now it is stored and served.
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID+"/path", "", nil); rec.Code != http.StatusOK {
		t.Errorf("get path after discovery = %d, want 200", rec.Code)
	}
}

// TestPathAPITenantIsolation proves the path-viz API is tenant-scoped: a path
// discovered for a test in tenant B is invisible to the default tenant (the test
// itself isn't visible, so the path endpoint 404s).
func TestPathAPITenantIsolation(t *testing.T) {
	h, db, _ := setupPathAPI(t)
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		fmt.Sprintf("pathiso-%d", time.Now().UnixNano()), "Path Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	rec := apiReq(t, h, http.MethodPost, "/v1/tests", tn.ID,
		map[string]any{"name": fmt.Sprintf("p-%d", time.Now().UnixNano()), "type": "icmp", "target": "9.9.9.9"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create in tenant B = %d: %s", rec.Code, rec.Body)
	}
	var created store.Test
	mustJSON(t, rec, &created)

	if rec = apiReq(t, h, http.MethodPost, "/v1/tests/"+created.ID+"/path", tn.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("discover in tenant B = %d", rec.Code)
	}
	// Tenant B can read it...
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID+"/path", tn.ID, nil); rec.Code != http.StatusOK {
		t.Errorf("tenant B get path = %d, want 200", rec.Code)
	}
	// ...the default tenant cannot even see the test (404).
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID+"/path", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant path get = %d, want 404", rec.Code)
	}
}
