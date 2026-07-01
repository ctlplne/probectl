// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func seriesFor(metric string) []tsdb.Series {
	return []tsdb.Series{{Metric: metric, Labels: map[string]string{"tenant_id": "x"}, Value: 1}}
}

// SCALE-007: a series with thousands of labels / megabyte label values must be
// rejected or truncated + counted — the series-count cap alone doesn't stop a
// single admitted identity from carrying an unbounded label set/value.
func TestCardinalityLabelCaps(t *testing.T) {
	l := NewCardinalityLimiter(1000, 50000)

	// 10k labels on one series → dropped (counted), not admitted.
	bigLabels := make(map[string]string, 10000)
	for i := 0; i < 10000; i++ {
		bigLabels[fmt.Sprintf("k%d", i)] = "v"
	}
	adm, dropped := l.Filter("t", "a", []tsdb.Series{{Metric: "m", Labels: bigLabels, Value: 1}})
	if len(adm) != 0 || dropped != 1 {
		t.Fatalf("over-label series: admitted=%d dropped=%d, want 0/1", len(adm), dropped)
	}

	// A 1 MiB label value is replaced by a bounded hash marker, then admitted.
	huge := make([]byte, 1<<20)
	for i := range huge {
		huge[i] = 'a'
	}
	s := []tsdb.Series{{Metric: "m2", Labels: map[string]string{"tenant_id": "x", "big": string(huge)}, Value: 1}}
	adm, dropped = l.Filter("t", "a", s)
	if len(adm) != 1 || dropped != 0 {
		t.Fatalf("over-value series: admitted=%d dropped=%d, want 1/0", len(adm), dropped)
	}
	if got := adm[0].Labels["big"]; len(got) > maxLabelValueLen || !strings.HasPrefix(got, "truncated:sha256:") {
		t.Errorf("label value marker = %q (len=%d)", got, len(got))
	}
	if st := l.Stats(); st.LabelTruncated != 1 || st.TenantTruncated["t"] != 1 {
		t.Fatalf("truncation stats = %+v, want 1", st)
	}

	// Two different overlong values sharing the same first 256 bytes must NOT
	// collapse into one identity.
	prefix := strings.Repeat("p", maxLabelValueLen)
	twin := []tsdb.Series{
		{Metric: "m3", Labels: map[string]string{"tenant_id": "x", "identity": prefix + "-left"}, Value: 1},
		{Metric: "m3", Labels: map[string]string{"tenant_id": "x", "identity": prefix + "-right"}, Value: 1},
	}
	adm, dropped = l.Filter("t", "a", twin)
	if len(adm) != 2 || dropped != 0 {
		t.Fatalf("same-prefix overlong values: admitted=%d dropped=%d, want 2/0", len(adm), dropped)
	}
	if adm[0].Labels["identity"] == adm[1].Labels["identity"] {
		t.Fatalf("overlong values conflated into %q", adm[0].Labels["identity"])
	}
	if st := l.Stats(); st.LabelTruncated != 3 || st.TenantTruncated["t"] != 3 {
		t.Fatalf("truncation stats after twins = %+v, want 3", st)
	}
}

// U-017: one agent flooding unique series hits its cap (rejected + counted);
// a DIFFERENT tenant is completely unaffected.
func TestCardinalityCapFloodIsolatesTenants(t *testing.T) {
	l := NewCardinalityLimiter(10, 100)

	totalAdmitted, totalDropped := 0, 0
	for i := 0; i < 50; i++ {
		adm, dropped := l.Filter("tenant-flood", "agent-1", seriesFor(fmt.Sprintf("m_%d", i)))
		totalAdmitted += len(adm)
		totalDropped += dropped
	}
	if totalAdmitted != 10 {
		t.Fatalf("admitted = %d, want exactly the per-agent cap (10)", totalAdmitted)
	}
	if totalDropped != 40 {
		t.Fatalf("dropped = %d, want 40", totalDropped)
	}
	st := l.Stats()
	if st.Dropped != 40 || st.TenantDropped["tenant-flood"] != 40 {
		t.Fatalf("stats = %+v, want the drops attributed to the flooder", st)
	}

	// The quiet tenant admits freely — the flood is not its problem.
	adm, dropped := l.Filter("tenant-quiet", "agent-9", seriesFor("steady_metric"))
	if len(adm) != 1 || dropped != 0 {
		t.Fatalf("quiet tenant impacted: admitted=%d dropped=%d", len(adm), dropped)
	}
	if st := l.Stats(); st.TenantDropped["tenant-quiet"] != 0 {
		t.Fatalf("quiet tenant has drops: %+v", st)
	}
}

// Known identities keep flowing at the cap — steady-state telemetry is never
// starved; only NEW identities are gated.
func TestCardinalityKnownSeriesKeepFlowing(t *testing.T) {
	l := NewCardinalityLimiter(1, 10)
	if adm, d := l.Filter("t", "a", seriesFor("known")); len(adm) != 1 || d != 0 {
		t.Fatalf("first series rejected: %d/%d", len(adm), d)
	}
	if _, d := l.Filter("t", "a", seriesFor("overflow")); d != 1 {
		t.Fatal("cap did not reject the new identity")
	}
	for i := 0; i < 5; i++ {
		if adm, d := l.Filter("t", "a", seriesFor("known")); len(adm) != 1 || d != 0 {
			t.Fatalf("known identity starved at the cap (iteration %d)", i)
		}
	}
}

func TestCardinalityStatsExposeTenantActiveSeries(t *testing.T) {
	l := NewCardinalityLimiter(100, 100)
	l.Filter("tenant-a", "agent-1", seriesFor("a1"))
	l.Filter("tenant-a", "agent-1", seriesFor("a2"))
	l.Filter("tenant-a", "agent-2", seriesFor("a1"))
	l.Filter("tenant-b", "agent-1", seriesFor("b1"))

	st := l.Stats()
	if st.ActiveSeries != 3 {
		t.Fatalf("active series = %d, want 3", st.ActiveSeries)
	}
	if got := st.TenantActiveSeries["tenant-a"]; got != 2 {
		t.Fatalf("tenant-a active series = %d, want 2", got)
	}
	if got := st.TenantActiveSeries["tenant-b"]; got != 1 {
		t.Fatalf("tenant-b active series = %d, want 1", got)
	}

	st.TenantActiveSeries["tenant-a"] = 999
	if got := l.Stats().TenantActiveSeries["tenant-a"]; got != 2 {
		t.Fatalf("tenant active-series map must be a snapshot copy, got %d", got)
	}
}

// The per-tenant wall holds across many agents.
func TestCardinalityPerTenantWall(t *testing.T) {
	l := NewCardinalityLimiter(1000, 5)
	dropped := 0
	for agent := 0; agent < 10; agent++ {
		_, d := l.Filter("t", fmt.Sprintf("a%d", agent), seriesFor(fmt.Sprintf("m%d", agent)))
		dropped += d
	}
	if dropped != 5 {
		t.Fatalf("dropped = %d, want 5 (the tenant wall)", dropped)
	}
}

// Distinct label VALUES are distinct identities (the explosion vector).
func TestCardinalityIdentityIncludesLabels(t *testing.T) {
	l := NewCardinalityLimiter(2, 10)
	a := []tsdb.Series{{Metric: "m", Labels: map[string]string{"server_address": "a"}}}
	b := []tsdb.Series{{Metric: "m", Labels: map[string]string{"server_address": "b"}}}
	c := []tsdb.Series{{Metric: "m", Labels: map[string]string{"server_address": "c"}}}
	l.Filter("t", "ag", a)
	l.Filter("t", "ag", b)
	if _, d := l.Filter("t", "ag", c); d != 1 {
		t.Fatal("label-value explosion not capped")
	}
}

func TestCardinalityLimiterConcurrentTenantShards(t *testing.T) {
	const tenants = 64
	const perTenant = 8
	l := NewCardinalityLimiter(100, 1000)

	var wg sync.WaitGroup
	var failures atomic.Int64
	for tenantN := 0; tenantN < tenants; tenantN++ {
		for seriesN := 0; seriesN < perTenant; seriesN++ {
			wg.Add(1)
			go func(tenantN, seriesN int) {
				defer wg.Done()
				tenant := fmt.Sprintf("tenant-%02d", tenantN)
				agent := fmt.Sprintf("agent-%02d", seriesN%4)
				admitted, dropped := l.Filter(tenant, agent, seriesFor(fmt.Sprintf("metric_%02d", seriesN)))
				if len(admitted) != 1 || dropped != 0 {
					failures.Add(1)
				}
			}(tenantN, seriesN)
		}
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent sharded filter had %d failed admissions", failures.Load())
	}

	st := l.Stats()
	if st.ActiveSeries != tenants*perTenant {
		t.Fatalf("active series = %d, want %d", st.ActiveSeries, tenants*perTenant)
	}
	for tenantN := 0; tenantN < tenants; tenantN++ {
		tenant := fmt.Sprintf("tenant-%02d", tenantN)
		if got := st.TenantActiveSeries[tenant]; got != perTenant {
			t.Fatalf("%s active series = %d, want %d", tenant, got, perTenant)
		}
	}
}

// BenchmarkCardinalityLimiterConcurrentTenants is the SPINE-006 contention
// receipt. Before sharding, both sub-benchmarks serialized on one global mutex;
// after sharding, the many-tenant case exercises cross-tenant parallelism while
// the single-tenant case remains intentionally serialized to preserve one
// tenant's per-agent/per-tenant cap semantics.
func BenchmarkCardinalityLimiterConcurrentTenants(b *testing.B) {
	const (
		agentCount  = 8
		seriesCount = 256
	)
	seriesPool := make([]tsdb.Series, seriesCount)
	for i := range seriesPool {
		seriesPool[i] = tsdb.Series{
			Metric: fmt.Sprintf("bench_metric_%03d", i),
			Labels: map[string]string{"host": fmt.Sprintf("host-%03d", i)},
			Value:  float64(i),
		}
	}
	agents := make([]string, agentCount)
	for i := range agents {
		agents[i] = fmt.Sprintf("agent-%02d", i)
	}

	for _, tc := range []struct {
		name    string
		tenants int
	}{
		{name: "single_tenant_contention_control", tenants: 1},
		{name: "many_tenants_sharded", tenants: 128},
	} {
		b.Run(tc.name, func(b *testing.B) {
			l := NewCardinalityLimiter(seriesCount+1, seriesCount+1)
			tenants := make([]string, tc.tenants)
			for i := range tenants {
				tenants[i] = fmt.Sprintf("tenant-%03d", i)
			}
			var seq atomic.Uint64
			b.ReportAllocs()
			b.SetParallelism(8)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					n := int(seq.Add(1))
					s := []tsdb.Series{seriesPool[n%len(seriesPool)]}
					l.Filter(tenants[n%len(tenants)], agents[n%len(agents)], s)
				}
			})
		})
	}
}
