// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TENANT-001: a siloed tenant's eBPF edges must route to its per-tenant
// database (and residency data plane), not the shared pooled table.
func TestEBPFInsertRoutesPerTarget(t *testing.T) {
	type hit struct{ host, query string }
	var mu sync.Mutex
	var hits []hit
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.Query().Get("query"))
		hits = append(hits, hit{r.Host, q})
		mu.Unlock()
		w.WriteHeader(200)
	}
	shared := httptest.NewServer(http.HandlerFunc(h))
	defer shared.Close()
	plane := httptest.NewServer(http.HandlerFunc(h))
	defer plane.Close()

	c, err := NewClickHouse(shared.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		switch tenant {
		case "siloed":
			return Target{Database: "probectl_t_abc"}, nil
		case "residency":
			return Target{BaseURL: plane.URL, Database: "probectl_t_eu"}, nil
		case "broken":
			return Target{}, errors.New("registry down")
		default:
			return Target{}, nil
		}
	})

	now := time.Now()
	edges := []Edge{
		{TenantID: "pooled", WindowStart: now, SrcWorkload: "a", DstWorkload: "b"},
		{TenantID: "siloed", WindowStart: now, SrcWorkload: "a", DstWorkload: "b"},
		{TenantID: "residency", WindowStart: now, SrcWorkload: "a", DstWorkload: "b"},
	}
	if err := c.Insert(context.Background(), edges); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	inserts := map[string]string{}
	for _, x := range hits {
		if strings.HasPrefix(x.query, "INSERT INTO ") {
			inserts[strings.Fields(strings.TrimPrefix(x.query, "INSERT INTO "))[0]] = x.host
		}
	}
	mu.Unlock()
	sharedHost := strings.TrimPrefix(shared.URL, "http://")
	planeHost := strings.TrimPrefix(plane.URL, "http://")
	if inserts["probectl_ebpf_edges"] != sharedHost {
		t.Fatalf("pooled edges must land in the shared table: %+v", inserts)
	}
	if inserts["probectl_t_abc.probectl_ebpf_edges"] != sharedHost {
		t.Fatalf("siloed edges must land in the tenant database: %+v", inserts)
	}
	if inserts["probectl_t_eu.probectl_ebpf_edges"] != planeHost {
		t.Fatalf("residency edges must land on the pinned data plane: %+v", inserts)
	}

	// A routing error fails the whole batch (fail closed).
	if err := c.Insert(context.Background(), []Edge{{TenantID: "broken", WindowStart: now}}); err == nil {
		t.Fatal("a routing error must fail the insert (fail closed)")
	}
}

// TENANT-001: reads route to the tenant's store too, with the tenant bound.
func TestEBPFQueryRoutesToTenantStore(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		queries = append(queries, q)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		if tenant == "siloed" {
			return Target{Database: "probectl_t_x"}, nil
		}
		return Target{}, nil
	})
	if _, err := c.TopEdges(context.Background(), "siloed", EdgeQuery{Limit: 5}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	var siloedSeen bool
	for _, qs := range queries {
		if strings.Contains(qs, "FROM+probectl_t_x.probectl_ebpf_edges") || strings.Contains(qs, "FROM probectl_t_x.probectl_ebpf_edges") {
			siloedSeen = true
		}
		if strings.Contains(qs, "tenant_id='siloed'") {
			t.Fatalf("raw tenant literal in SQL (must be bound): %s", qs)
		}
	}
	if !siloedSeen {
		t.Fatalf("siloed read did not route to the tenant database: %v", queries)
	}
}

// TENANT-001: provisioning + teardown DDL shapes for a siloed eBPF database.
func TestEBPFEnsureAndDropTenantDatabase(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.Query().Get("query"))
		queries = append(queries, q)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}, 30); err != nil {
		t.Fatal(err)
	}
	if err := c.DropTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DropTenantDatabase(context.Background(), Target{Database: "bad name"}); err == nil {
		t.Fatal("malformed drop must be refused")
	}
	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS probectl_t_y",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_ebpf_edges",
		"DROP DATABASE IF EXISTS probectl_t_y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DDL missing %q in:\n%s", want, joined)
		}
	}
}
