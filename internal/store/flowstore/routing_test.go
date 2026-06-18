// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

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

	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

func TestTableForRouting(t *testing.T) {
	if tab, err := tableFor(Target{}); err != nil || tab != "probectl_flows" {
		t.Fatalf("pooled table: %q %v", tab, err)
	}
	if tab, err := tableFor(Target{Database: "probectl_t_3fa2"}); err != nil || tab != "probectl_t_3fa2.probectl_flows" {
		t.Fatalf("siloed table: %q %v", tab, err)
	}
	if _, err := tableFor(Target{Database: `x; DROP DATABASE`}); err == nil {
		t.Fatal("malformed database must be refused")
	}
}

// TestInsertRoutesPerTarget proves the S-T2 separation property at the store:
// one mixed batch splits into per-target INSERTs — a siloed tenant's rows go
// to its database (on its data plane), pooled rows to the shared table, and a
// routing error fails the batch (fail closed) rather than misfiling rows.
func TestInsertRoutesPerTarget(t *testing.T) {
	type hit struct{ host, query string }
	var mu sync.Mutex
	var hits []hit
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, hit{r.Host, r.URL.Query().Get("query")})
		mu.Unlock()
		w.WriteHeader(200)
	}
	shared := httptest.NewServer(http.HandlerFunc(handler))
	defer shared.Close()
	plane := httptest.NewServer(http.HandlerFunc(handler))
	defer plane.Close()

	c, err := NewClickHouse(shared.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		switch tenant {
		case "siloed-tenant":
			return Target{Database: "probectl_t_abc"}, nil
		case "residency-tenant":
			return Target{BaseURL: plane.URL, Database: "probectl_t_eu"}, nil
		case "broken":
			return Target{}, errors.New("registry down")
		default:
			return Target{}, nil
		}
	})

	now := time.Now()
	rows := []Row{
		{TenantID: "pooled-tenant", TS: now, StartTS: now, Bytes: 1},
		{TenantID: "siloed-tenant", TS: now, StartTS: now, Bytes: 2},
		{TenantID: "residency-tenant", TS: now, StartTS: now, Bytes: 3},
	}
	if err := c.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	inserts := map[string]string{} // table -> host
	for _, h := range hits {
		if strings.HasPrefix(h.query, "INSERT INTO ") {
			table := strings.Fields(strings.TrimPrefix(h.query, "INSERT INTO "))[0]
			inserts[table] = h.host
		}
	}
	mu.Unlock()
	sharedHost := strings.TrimPrefix(shared.URL, "http://")
	planeHost := strings.TrimPrefix(plane.URL, "http://")
	if inserts["probectl_flows"] != sharedHost {
		t.Fatalf("pooled rows must land in the shared table on the shared plane: %+v", inserts)
	}
	if inserts["probectl_t_abc.probectl_flows"] != sharedHost {
		t.Fatalf("siloed rows must land in the tenant database: %+v", inserts)
	}
	if inserts["probectl_t_eu.probectl_flows"] != planeHost {
		t.Fatalf("residency rows must land on the pinned data plane: %+v", inserts)
	}

	// A routing failure fails the WHOLE batch — nothing is misfiled.
	if err := c.Insert(context.Background(), []Row{{TenantID: "broken", TS: now, StartTS: now}}); err == nil {
		t.Fatal("a routing error must fail the insert (fail closed)")
	}
}

// TestInsertChunksLargeBatch: SCALE-008. The FlowBatch size is agent-controlled,
// so a large batch must be split into bounded sub-batch POSTs rather than one
// giant request body. A batch of maxInsertChunk+1 rows must produce exactly 2
// INSERTs.
func TestInsertChunksLargeBatch(t *testing.T) {
	var mu sync.Mutex
	var insertPosts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		// Count only the flow-DATA inserts (JSONEachRow), not migration-ledger
		// or dedup-migration INSERTs that the first-use schema bootstrap emits.
		if strings.HasPrefix(q, "INSERT INTO probectl_flows ") && strings.Contains(q, "FORMAT JSONEachRow") {
			mu.Lock()
			insertPosts++
			mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	n := maxInsertChunk + 1
	rows := make([]Row, n)
	for i := range rows {
		rows[i] = Row{TenantID: "pooled", TS: now, StartTS: now, Bytes: uint64(i)}
	}
	if err := c.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := insertPosts
	mu.Unlock()
	if got != 2 {
		t.Fatalf("%d rows produced %d INSERT POSTs, want 2 (chunked at %d, not one giant body)", n, got, maxInsertChunk)
	}
}

// TestQueryRoutesToTenantStore proves reads route the same way: a siloed
// tenant's TopTalkers hits its database; pooled hits the shared table.
func TestQueryRoutesToTenantStore(t *testing.T) {
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
	q := TopQuery{TenantID: "siloed", By: BySrc, Window: time.Hour, Limit: 5, Now: time.Now()}
	if _, err := c.TopTalkers(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	q.TenantID = "pooled"
	if _, err := c.TopTalkers(context.Background(), q); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	var siloedSeen, pooledSeen bool
	for _, qs := range queries {
		// The tenant travels as a BOUND parameter (param_tenant), never inside
		// the SQL text (SEC-005/TENANT-108).
		if strings.Contains(qs, "FROM probectl_t_x.probectl_flows") &&
			strings.Contains(qs, "tenant_id={tenant:String}") && strings.Contains(qs, "param_tenant=siloed") {
			siloedSeen = true
		}
		// CORRECT-003: aggregations read the ReplacingMergeTree with FINAL.
		if strings.Contains(qs, "FROM probectl_flows FINAL WHERE tenant_id={tenant:String}") &&
			strings.Contains(qs, "param_tenant=pooled") {
			pooledSeen = true
		}
		if strings.Contains(qs, "tenant_id='siloed'") || strings.Contains(qs, "tenant_id='pooled'") {
			t.Fatalf("raw tenant literal in SQL (must be bound): %s", qs)
		}
	}
	if !siloedSeen || !pooledSeen {
		t.Fatalf("routed queries wrong: %v", queries)
	}
}

// TestEnsureAndDropTenantDatabase pins the provisioning DDL shapes.
func TestEnsureAndDropTenantDatabase(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	var raws []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		queries = append(queries, q)
		raws = append(raws, r.URL.RawQuery)
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
	joinedRaw := strings.Join(raws, "\n")
	mu.Unlock()
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS probectl_t_y",
		"CREATE TABLE IF NOT EXISTS probectl_ch_migrations",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_flows",
		"INSERT INTO probectl_ch_migrations",
		"ALTER TABLE probectl_t_y.probectl_flows MODIFY TTL",
		"DROP DATABASE IF EXISTS probectl_t_y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DDL missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joinedRaw, "param_component=flowstore%3Aprobectl_t_y") {
		t.Fatalf("tenant flow migrations were not recorded with a tenant-specific component key:\n%s", joinedRaw)
	}
}

func TestEnsureTenantDatabaseUpgradesOldTenantLedger(t *testing.T) {
	target := Target{Database: "probectl_t_old"}
	table, err := tableFor(target)
	if err != nil {
		t.Fatal(err)
	}
	migs := chMigrationsFor(table)
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
			component == "flowstore:probectl_t_old" {
			_, _ = w.Write([]byte(`{"version":1,"checksum":"` + v1Checksum + `"}` + "\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL, 0)
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
			h.component == "flowstore:probectl_t_old" && h.version == "2" {
			sawTenantV2Record = true
		}
	}
	body := strings.Join(joined, "\n")
	if strings.Contains(body, "CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_flows (\n") {
		t.Fatalf("tenant v1 was rerun even though the tenant ledger already recorded it:\n%s", body)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS probectl_t_old.probectl_flows_dedup",
		"RENAME TABLE probectl_t_old.probectl_flows TO probectl_t_old.probectl_flows_pre_dedup",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("old tenant ledger did not apply pending v2 %q in:\n%s", want, body)
		}
	}
	if !sawTenantV2Record {
		t.Fatalf("pending tenant v2 was not recorded under the tenant component key: %+v", hits)
	}
}
