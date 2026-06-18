// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pathstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

func mkPath() *path.Path {
	return &path.Path{Target: "t.example", TargetIP: "198.51.100.9", Mode: "icmp",
		Hops:  []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "198.51.100.9"}}}},
		Links: []path.Link{{TTL: 1, From: "a", To: "b"}}}
}

// TENANT-001: a siloed tenant's path hops/links must route to its per-tenant
// database (and residency data plane), not the shared pooled tables.
func TestPathSaveRoutesPerTarget(t *testing.T) {
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

	c, err := NewClickHouse(shared.URL)
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

	for _, tn := range []string{"pooled", "siloed", "residency"} {
		if err := c.Save(context.Background(), tn, mkPath()); err != nil {
			t.Fatalf("save %s: %v", tn, err)
		}
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
	if inserts["probectl_path_hops2"] != sharedHost {
		t.Fatalf("pooled hops must land in the shared table: %+v", inserts)
	}
	if inserts["probectl_t_abc.probectl_path_hops2"] != sharedHost {
		t.Fatalf("siloed hops must land in the tenant database: %+v", inserts)
	}
	if inserts["probectl_t_eu.probectl_path_hops2"] != planeHost {
		t.Fatalf("residency hops must land on the pinned data plane: %+v", inserts)
	}

	if err := c.Save(context.Background(), "broken", mkPath()); err == nil {
		t.Fatal("a routing error must fail the save (fail closed)")
	}
}

// TENANT-001: Latest reads route to the tenant's database too.
func TestPathQueryRoutesToTenantStore(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		queries = append(queries, q)
		mu.Unlock()
		w.WriteHeader(200) // empty body => no rows
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		if tenant == "siloed" {
			return Target{Database: "probectl_t_x"}, nil
		}
		return Target{}, nil
	})
	if _, _, err := c.Latest(context.Background(), "siloed", "t.example"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	var seen bool
	for _, qs := range queries {
		if strings.Contains(qs, "probectl_t_x.probectl_path_hops2") {
			seen = true
		}
		if strings.Contains(qs, "tenant_id='siloed'") {
			t.Fatalf("raw tenant literal in SQL (must be bound): %s", qs)
		}
	}
	if !seen {
		t.Fatalf("siloed read did not route to the tenant database: %v", queries)
	}
}

// TENANT-001: provisioning + teardown DDL shapes for a siloed path database.
func TestPathEnsureAndDropTenantDatabase(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	var raws []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.Query().Get("query"))
		queries = append(queries, q)
		raws = append(raws, r.URL.RawQuery)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}, 30); err != nil {
		t.Fatal(err)
	}
	if err := c.DropTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	joined := strings.Join(queries, "\n")
	joinedRaw := strings.Join(raws, "\n")
	mu.Unlock()
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS probectl_t_y",
		"CREATE TABLE IF NOT EXISTS probectl_ch_migrations",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_path_hops2",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_path_links2",
		"INSERT INTO probectl_ch_migrations",
		"DROP DATABASE IF EXISTS probectl_t_y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DDL missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joinedRaw, "param_component=pathstore%3Aprobectl_t_y") {
		t.Fatalf("tenant path migrations were not recorded with a tenant-specific component key:\n%s", joinedRaw)
	}
}

func TestPathEnsureTenantDatabaseUpgradesOldTenantLedger(t *testing.T) {
	target := Target{Database: "probectl_t_old"}
	hopsV1, err := qualify(target, "probectl_path_hops")
	if err != nil {
		t.Fatal(err)
	}
	linksV1, err := qualify(target, "probectl_path_links")
	if err != nil {
		t.Fatal(err)
	}
	hopsV2, err := qualify(target, hopsTable)
	if err != nil {
		t.Fatal(err)
	}
	linksV2, err := qualify(target, linksTable)
	if err != nil {
		t.Fatal(err)
	}
	migs := chMigrationsFor(hopsV1, linksV1, hopsV2, linksV2)
	v1Checksum := chmigrate.Checksum(migs[0])

	type hit struct {
		query     string
		component string
		version   string
	}
	var mu sync.Mutex
	var hits []hit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qv := r.URL.Query()
		query := qv.Get("query")
		component := qv.Get("param_component")
		mu.Lock()
		hits = append(hits, hit{query: query, component: component, version: qv.Get("param_version")})
		mu.Unlock()
		if strings.Contains(query, "SELECT version, checksum FROM probectl_ch_migrations") &&
			component == "pathstore:probectl_t_old" {
			_, _ = w.Write([]byte(`{"version":1,"checksum":"` + v1Checksum + `"}` + "\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureTenantDatabase(context.Background(), target, 0); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	var joined []string
	var sawTenantV2Record bool
	for _, h := range hits {
		joined = append(joined, h.query)
		if strings.Contains(h.query, "INSERT INTO probectl_ch_migrations") &&
			h.component == "pathstore:probectl_t_old" && h.version == "2" {
			sawTenantV2Record = true
		}
	}
	body := strings.Join(joined, "\n")
	for _, forbidden := range []string{
		"CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_path_hops (",
		"CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_path_links (",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("tenant v1 was rerun even though the tenant ledger already recorded it:\n%s", body)
		}
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_path_hops2",
		"CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_path_links2",
		"DROP TABLE IF EXISTS probectl_t_old.probectl_path_hops",
		"DROP TABLE IF EXISTS probectl_t_old.probectl_path_links",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("old tenant ledger did not apply pending v2 %q in:\n%s", want, body)
		}
	}
	if !sawTenantV2Record {
		t.Fatalf("pending tenant v2 was not recorded under the tenant component key: %+v", hits)
	}
}
