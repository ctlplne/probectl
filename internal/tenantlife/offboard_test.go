package tenantlife

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// U-027 e2e offboard: erasure covers flows, objects, tsdb, PATHS and
// TOPOLOGY; the attestation enumerates every store with verified-zero
// results; the neighbor tenant is untouched.
func TestEraseCoversEveryStoreEndToEnd(t *testing.T) {
	ctx := context.Background()
	flows := flowstore.NewMemory()
	objects := objectstore.NewMemory()
	tsdbW := tsdb.NewMemory()
	paths := pathstore.NewMemory()
	topo := topology.NewMemoryStore()

	seed := func(tenant string) {
		_ = flows.Insert(ctx, []flowstore.Row{{TenantID: tenant, AgentID: "a", Exporter: "e",
			TS: time.Now(), SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", Bytes: 10, Packets: 1}})
		_ = objects.Put(ctx, "tenant/"+tenant+"/browser/x.png", "image/png", []byte("img"))
		_ = tsdbW.Write(ctx, []tsdb.Series{{Metric: "m", Labels: map[string]string{"tenant_id": tenant}, Value: 1}})
		_ = paths.Save(ctx, tenant, &path.Path{Target: "t.example", TargetIP: "198.51.100.9", Mode: "icmp",
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "198.51.100.9"}}}}})
		topo.ObserveServiceEdge(tenant, topology.ServiceEdgeInput{Source: "svc-a", Destination: "svc-b"}, time.Now())
	}
	seed("victim")
	seed("neighbor")

	e := New(nil, flows, objects, tsdbW, nil, "test backup note", nil).
		WithPaths(paths).WithTopology(topo)

	att, err := e.Erase(ctx, "victim", "victim-slug", "test")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if !att.Complete {
		t.Fatalf("attestation incomplete: %+v", att.Stores)
	}

	// The attestation enumerates every store, including paths + topology.
	want := map[string]bool{"flows": false, "objects": false, "tsdb": false, "paths": false, "topology": false}
	for _, sr := range att.Stores {
		if _, ok := want[sr.Store]; ok {
			want[sr.Store] = true
			if !sr.VerifiedZero {
				t.Errorf("store %s not verified zero: %+v", sr.Store, sr)
			}
		}
	}
	for store, seen := range want {
		if !seen {
			t.Errorf("attestation missing store %q", store)
		}
	}

	// Zero residual rows for the victim, neighbor intact, per store.
	if _, ok, _ := paths.Latest(ctx, "victim", "t.example"); ok {
		t.Fatal("victim path survived erasure")
	}
	if _, ok, _ := paths.Latest(ctx, "neighbor", "t.example"); !ok {
		t.Fatal("neighbor path damaged")
	}
	if n := len(tsdbW.Query("m", map[string]string{"tenant_id": "victim"})); n != 0 {
		t.Fatalf("victim tsdb series remain: %d", n)
	}
	if n := len(tsdbW.Query("m", map[string]string{"tenant_id": "neighbor"})); n != 1 {
		t.Fatalf("neighbor tsdb series damaged: %d", n)
	}
	if topo.DeleteTenant("victim") != 0 {
		t.Fatal("victim topology graph survived erasure")
	}
	if topo.DeleteTenant("neighbor") != 1 {
		t.Fatal("neighbor topology graph damaged")
	}
	if left, _ := objects.List(ctx, "tenant/victim/"); len(left) != 0 {
		t.Fatalf("victim objects remain: %v", left)
	}
	if left, _ := objects.List(ctx, "tenant/neighbor/"); len(left) != 1 {
		t.Fatalf("neighbor objects damaged: %v", left)
	}
}

// U-027: prometheus-mode series deletion is AUTOMATED via the admin API when
// enabled — delete_series is invoked with the tenant matcher and the
// post-delete verification query must return empty.
func TestPrometheusAdminDeleteAutomated(t *testing.T) {
	var deleteMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/admin/tsdb/delete_series"):
			deleteMatch = r.URL.Query().Get("match[]")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/v1/admin/tsdb/clean_tombstones"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/v1/query"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success", "data": map[string]any{"resultType": "vector", "result": []any{}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	e := New(nil, nil, nil, tsdb.NewPrometheus(srv.URL), nil, "", nil)
	att, err := e.Erase(context.Background(), "t-prom", "slug", "test")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if !strings.Contains(deleteMatch, `tenant_id="t-prom"`) {
		t.Fatalf("delete_series matcher = %q", deleteMatch)
	}
	for _, sr := range att.Stores {
		if sr.Store == "tsdb" && !sr.VerifiedZero {
			t.Fatalf("automated prom deletion not verified: %+v", sr)
		}
	}
}

// When the admin API is disabled, the attestation records the documented
// manual step honestly (Complete=false) — never a silent skip.
func TestPrometheusAdminDisabledRecordsManualStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // admin API off
	}))
	defer srv.Close()

	e := New(nil, nil, nil, tsdb.NewPrometheus(srv.URL), nil, "", nil)
	att, err := e.Erase(context.Background(), "t-prom", "slug", "test")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if att.Complete {
		t.Fatal("attestation must be incomplete when the manual step remains")
	}
	found := false
	for _, sr := range att.Stores {
		if sr.Store == "tsdb" && strings.Contains(sr.Notes, "MANUAL STEP REQUIRED") {
			found = true
		}
	}
	if !found {
		t.Fatalf("manual step not recorded: %+v", att.Stores)
	}
}
