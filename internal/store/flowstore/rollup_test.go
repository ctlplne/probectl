// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFlowRollupDDLAndBackfillAreTenantScoped(t *testing.T) {
	ddl := createFlowRollupsDDL(sharedFlowRollupsTable)
	for _, want := range []string{
		"PARTITION BY (tenant_id, toYYYYMMDD(bucket))",
		"ORDER BY (tenant_id, bucket, protocol, exporter, src_addr, dst_addr, transport, row_id)",
		"ENGINE = ReplacingMergeTree",
	} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("rollup DDL missing %q:\n%s", want, ddl)
		}
	}
	mv := createFlowRollupsMVDDL(sharedFlowRollupsMV, sharedFlowsTable, sharedFlowRollupsTable)
	for _, want := range []string{
		"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_flow_rollups_hour_mv",
		"TO probectl_flow_rollups_hour",
		"FROM probectl_flows",
		"WHERE row_id != ''",
	} {
		if !strings.Contains(mv, want) {
			t.Fatalf("rollup MV missing %q:\n%s", want, mv)
		}
	}
	backfill := flowRollupBackfillSQL(sharedFlowsTable, sharedFlowRollupsTable)
	for _, want := range []string{
		"INSERT INTO probectl_flow_rollups_hour",
		"FROM probectl_flows FINAL",
		"WHERE tenant_id={tenant:String}",
		"AND row_id != ''",
	} {
		if !strings.Contains(backfill, want) {
			t.Fatalf("rollup backfill SQL missing %q:\n%s", want, backfill)
		}
	}
}

func TestFlowRawRetentionLeavesHourlyRollupsQueryableTenantScoped(t *testing.T) {
	now := time.Date(2026, 6, 30, 14, 0, 0, 0, time.UTC)
	from := now.Add(-2 * time.Hour)
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		mu.Lock()
		queries = append(queries, q)
		mu.Unlock()
		if strings.Contains(q, "FROM probectl_flow_rollups_hour") && strings.Contains(r.URL.RawQuery, "param_tenant=tenant-a") {
			_, _ = w.Write([]byte(`{"bucket":"2026-06-30 13:00:00","protocol":"aws_vpc_flow_logs","exporter":"aws:eni-1","transport":"tcp","bytes_scaled":42,"packets_scaled":2,"flow_count":1}` + "\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTenantBefore(context.Background(), "tenant-a", from); err != nil {
		t.Fatal(err)
	}
	rollups, err := c.HourlyRollups(context.Background(), "tenant-a", from, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollups) != 1 || rollups[0].Bytes != 42 || rollups[0].Flows != 1 {
		t.Fatalf("tenant-a rollups = %+v", rollups)
	}
	other, err := c.HourlyRollups(context.Background(), "tenant-b", from, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("tenant-b should not see tenant-a rollups: %+v", other)
	}

	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "DELETE FROM probectl_flows WHERE tenant_id={tenant:String} AND ts <") {
		t.Fatalf("raw retention delete was not issued:\n%s", joined)
	}
	if strings.Contains(joined, "DELETE FROM probectl_flow_rollups_hour WHERE") {
		t.Fatalf("raw retention must not delete long-retention rollups:\n%s", joined)
	}
	if strings.Contains(joined, "tenant_id='tenant-a'") || strings.Contains(joined, "tenant_id='tenant-b'") {
		t.Fatalf("tenant was rendered as a literal instead of a bound parameter:\n%s", joined)
	}
}

func TestFlowRollupBackfillControlIsRoutedAndBound(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		mu.Lock()
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
			return Target{Database: "probectl_t_roll"}, nil
		}
		return Target{}, nil
	})
	from := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	if err := c.BackfillRollups(context.Background(), "siloed", from, to); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	for _, want := range []string{
		"DELETE FROM probectl_t_roll.probectl_flow_rollups_hour WHERE tenant_id={tenant:String}",
		"INSERT INTO probectl_t_roll.probectl_flow_rollups_hour",
		"FROM probectl_t_roll.probectl_flows FINAL",
		"WHERE tenant_id={tenant:String}",
		"param_tenant=siloed",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("backfill SQL missing %q:\n%s", want, joined)
		}
	}
}
