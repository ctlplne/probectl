// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pathstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCH speaks just enough of the ClickHouse HTTP protocol for the tenancy
// paths (U-026/U-027) to run without a server: DDL/INSERT/DELETE are 200s,
// count() returns 3 before a tenant's DELETE and 0 after, and the Latest
// queries return one reconstructed path.
type fakeCH struct {
	mu      sync.Mutex
	queries []string
	deleted map[string]bool // table -> tenant rows deleted
}

func (f *fakeCH) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		qv := r.URL.Query()
		q := qv.Get("query")
		// Record the SQL plus any bound params (param_*) so tests can assert
		// values travel as parameters, never inside the SQL text (SEC-005).
		rec := q
		for k, vs := range qv {
			if strings.HasPrefix(k, "param_") && len(vs) > 0 {
				rec += " /*" + k + "=" + vs[0] + "*/"
			}
		}
		f.mu.Lock()
		f.queries = append(f.queries, rec)
		f.mu.Unlock()
		switch {
		case strings.Contains(q, "count() AS n"):
			table := "probectl_path_hops"
			if strings.Contains(q, "probectl_path_links") {
				table = "probectl_path_links"
			}
			f.mu.Lock()
			gone := f.deleted[table]
			f.mu.Unlock()
			if gone {
				_, _ = w.Write([]byte(`{"n":"0"}` + "\n"))
			} else {
				_, _ = w.Write([]byte(`{"n":"3"}` + "\n"))
			}
		case strings.HasPrefix(q, "DELETE FROM"):
			table := "probectl_path_hops"
			if strings.Contains(q, "probectl_path_links") {
				table = "probectl_path_links"
			}
			f.mu.Lock()
			f.deleted[table] = true
			f.mu.Unlock()
		case strings.Contains(q, "SELECT path_id"):
			if strings.Contains(q, "'missing.example'") || qv.Get("param_target") == "missing.example" {
				return // no rows -> not found
			}
			_, _ = w.Write([]byte(`{"path_id":"p1","target_ip":"8.8.8.8","mode":"icmp"}` + "\n"))
		case strings.Contains(q, "FROM probectl_path_hops") && strings.Contains(q, "path_id="):
			_, _ = w.Write([]byte(
				`{"ttl":1,"responder":"10.0.0.1","sent":3,"received":3,"loss_ratio":0,"rtt_min_ms":"1.1","rtt_avg_ms":1.5,"rtt_max_ms":2.0,"mpls_labels":[16001]}` + "\n" +
					`{"ttl":2,"responder":"8.8.8.8","sent":3,"received":2,"loss_ratio":0.33,"rtt_min_ms":4.0,"rtt_avg_ms":4.5,"rtt_max_ms":5.0,"mpls_labels":[]}` + "\n"))
		case strings.Contains(q, "FROM probectl_path_links") && strings.Contains(q, "path_id="):
			_, _ = w.Write([]byte(`{"ttl":1,"from_ip":"10.0.0.1","to_ip":"8.8.8.8"}` + "\n"))
		}
	}
}

func (f *fakeCH) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

func newFakeCH(t *testing.T) (*fakeCH, *ClickHouse) {
	t.Helper()
	f := &fakeCH{deleted: map[string]bool{}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	ch, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatalf("NewClickHouse: %v", err)
	}
	return f, ch
}

// U-026: every tenant-keyed operation refuses an empty tenant BEFORE anything
// reaches the wire.
func TestClickHouseRefusesUnscopedOperations(t *testing.T) {
	f, ch := newFakeCH(t)
	ctx := context.Background()
	before := f.count() // the connect-time migration traffic (U-046)

	if err := ch.Save(ctx, "", samplePath()); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("Save without tenant = %v, want ErrNoTenant", err)
	}
	if _, _, err := ch.Latest(ctx, "", "x"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("Latest without tenant = %v, want ErrNoTenant", err)
	}
	if _, _, err := ch.DeleteTenant(ctx, ""); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("DeleteTenant without tenant = %v, want ErrNoTenant", err)
	}
	if f.count() != before {
		t.Fatalf("an unscoped operation reached ClickHouse: %v", f.queries[before:])
	}
}

// U-026: the row-policy DDL covers raw + rollup tables, exempts exactly the
// service user, and defaults that user to `default`.
func TestClickHouseRowPolicyDDL(t *testing.T) {
	f, ch := newFakeCH(t)
	if err := ch.EnsureRowPolicies(context.Background(), ""); err != nil {
		t.Fatalf("EnsureRowPolicies: %v", err)
	}
	var policies []string
	f.mu.Lock()
	for _, q := range f.queries {
		if strings.HasPrefix(q, "CREATE ROW POLICY") {
			policies = append(policies, q)
		}
	}
	f.mu.Unlock()
	if len(policies) != 8 {
		t.Fatalf("want 8 row policies (2 per table), got %d: %v", len(policies), policies)
	}
	joined := strings.Join(policies, "\n")
	for _, want := range []string{
		"ON probectl_path_hops2", "ON probectl_path_links2",
		"ON probectl_path_hops_rollups_hour", "ON probectl_path_links_rollups_hour",
		"tenant_id = currentUser() TO ALL EXCEPT default", "USING 1 TO default",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("row policies missing %q:\n%s", want, joined)
		}
	}
}

// U-027: erasure counts, deletes with mutations_sync, and verifies both
// tables — the returned counts are the attestation's evidence.
func TestClickHouseDeleteTenantVerifies(t *testing.T) {
	f, ch := newFakeCH(t)
	deleted, remaining, err := ch.DeleteTenant(context.Background(), "t-gone")
	if err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if deleted != 6 || remaining != 0 {
		t.Fatalf("deleted=%d remaining=%d, want 6/0 (3 rows per table, verified gone)", deleted, remaining)
	}
	var sawSync, sawScope bool
	f.mu.Lock()
	for _, q := range f.queries {
		if strings.HasPrefix(q, "DELETE FROM") {
			sawSync = sawSync || strings.Contains(q, "mutations_sync=2")
			// Tenant must be a BOUND parameter (SEC-005/TENANT-108): the SQL
			// carries the placeholder; the value travels as param_tenant.
			sawScope = sawScope || (strings.Contains(q, "tenant_id={tenant:String}") && strings.Contains(q, "/*param_tenant=t-gone*/"))
			if strings.Contains(q, "tenant_id='t-gone'") {
				t.Fatalf("raw tenant literal in DELETE SQL (must be bound): %s", q)
			}
		}
	}
	f.mu.Unlock()
	if !sawSync || !sawScope {
		t.Fatalf("DELETE must be tenant-scoped (bound) and mutations_sync: sync=%v scope=%v", sawSync, sawScope)
	}
}

// Latest reconstructs hops (TTL-ordered, MPLS, destination detection) and
// links from the row shape ClickHouse actually returns (numbers and strings).
func TestClickHouseLatestReconstructsPath(t *testing.T) {
	_, ch := newFakeCH(t)
	p, ok, err := ch.Latest(context.Background(), "t1", "dns.example")
	if err != nil || !ok {
		t.Fatalf("Latest: ok=%v err=%v", ok, err)
	}
	if p.TargetIP != "8.8.8.8" || p.Mode != "icmp" || !p.DestinationReached || p.MaxHops != 2 {
		t.Fatalf("path meta = %+v", p)
	}
	if len(p.Hops) != 2 || p.Hops[0].TTL != 1 || p.Hops[1].TTL != 2 {
		t.Fatalf("hops = %+v", p.Hops)
	}
	n := p.Hops[0].Nodes[0]
	if n.IP != "10.0.0.1" || n.RTTMinMs != 1.1 || len(n.MPLS) != 1 || n.MPLS[0].Label != 16001 {
		t.Fatalf("hop node = %+v", n)
	}
	if len(p.Links) != 1 || p.Links[0].From != "10.0.0.1" || p.Links[0].To != "8.8.8.8" {
		t.Fatalf("links = %+v", p.Links)
	}

	// And the not-found branch stays a clean miss, not an error.
	if _, ok, err := ch.Latest(context.Background(), "t1", "missing.example"); ok || err != nil {
		t.Fatalf("missing target: ok=%v err=%v, want clean miss", ok, err)
	}
}
