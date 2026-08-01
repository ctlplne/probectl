// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flowstore

import (
	"context"
	"encoding/json"
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
		"exporter String",
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
		"exporter,",
		"FROM probectl_flows",
		"WHERE row_id != ''",
	} {
		if !strings.Contains(mv, want) {
			t.Fatalf("rollup MV missing %q:\n%s", want, mv)
		}
	}
	legacyMV := createFlowRollupsMVWithLegacyDDL(sharedFlowRollupsMV, sharedFlowsTable, sharedFlowRollupsTable)
	for _, want := range []string{
		"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_flow_rollups_hour_mv",
		"TO probectl_flow_rollups_hour",
		"FROM probectl_flows",
		"if(row_id != '', row_id,",
		"concat('legacy:', toString(cityHash64(",
	} {
		if !strings.Contains(legacyMV, want) {
			t.Fatalf("legacy rollup MV missing %q:\n%s", want, legacyMV)
		}
	}
	if strings.Contains(legacyMV, "WHERE row_id") {
		t.Fatalf("legacy rollup MV must not skip migrated empty-row_id rows:\n%s", legacyMV)
	}
	subjectMV := createFlowRollupsSubjectMVDDL(sharedFlowRollupsMV, sharedFlowsTable, sharedFlowRollupsTable)
	for _, want := range []string{
		"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_flow_rollups_hour_mv",
		"TO probectl_flow_rollups_hour",
		"FROM probectl_flows",
		"[agent_id, exporter, src_addr, dst_addr, next_hop,",
		"toString(src_asn), toString(dst_asn)] AS subject_keys",
	} {
		if !strings.Contains(subjectMV, want) {
			t.Fatalf("subject-aware rollup MV missing %q:\n%s", want, subjectMV)
		}
	}
	backfill := flowRollupBackfillSQL(sharedFlowsTable, sharedFlowRollupsTable)
	for _, want := range []string{
		"INSERT INTO probectl_flow_rollups_hour",
		"flow_count, subject_keys",
		"FROM probectl_flows",
		"WHERE tenant_id={tenant:String}",
		"if(row_id != '', row_id,",
		"concat('legacy:', toString(cityHash64(",
		"toString(src_asn), toString(dst_asn)] AS subject_keys",
	} {
		if !strings.Contains(backfill, want) {
			t.Fatalf("rollup backfill SQL missing %q:\n%s", want, backfill)
		}
	}
	if strings.Contains(backfill, "FROM probectl_flows FINAL") ||
		strings.Contains(backfill, "WHERE row_id") ||
		strings.Contains(backfill, "AND row_id") {
		t.Fatalf("rollup backfill must preserve legacy rows before destination dedup:\n%s", backfill)
	}
	foundV4 := false
	foundV5 := false
	for _, m := range CHMigrations() {
		switch m.Version {
		case 4:
			foundV4 = true
			if !m.Destructive || !strings.Contains(m.Justification, "materialized view") {
				t.Fatalf("v4 legacy MV migration must annotate its MV drop/recreate: %+v", m)
			}
			if len(m.Statements) != 2 ||
				!strings.Contains(m.Statements[0], "DROP TABLE IF EXISTS probectl_flow_rollups_hour_mv") ||
				!strings.Contains(m.Statements[1], "concat('legacy:', toString(cityHash64(") {
				t.Fatalf("v4 legacy MV migration statements are incomplete: %+v", m.Statements)
			}
		case 5:
			foundV5 = true
			joined := strings.Join(m.Statements, "\n")
			for _, want := range []string{
				"DROP TABLE IF EXISTS probectl_flow_rollups_hour_mv",
				"ADD COLUMN IF NOT EXISTS subject_keys Array(String) DEFAULT []",
				"DELETE FROM probectl_flow_rollups_hour",
				"SELECT tenant_id, if(row_id != ''",
				"INSERT INTO probectl_flow_rollups_hour",
				"AS subject_keys",
				"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_flow_rollups_hour_mv",
			} {
				if !strings.Contains(joined, want) {
					t.Fatalf("v5 subject-key migration missing %q:\n%s", want, joined)
				}
			}
			if len(m.Statements) != 5 || !m.Destructive || !strings.Contains(m.Justification, "preserving aged-out history") {
				t.Fatalf("v5 subject-key migration must document its exact replacement safety: %+v", m)
			}
		}
	}
	if !foundV4 {
		t.Fatal("missing flowstore v4 migration for legacy flow rollup row ids")
	}
	if !foundV5 {
		t.Fatal("missing flowstore v5 migration for subject-aware long-retention rollups")
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
	rollups, err := c.hourlyRollups(context.Background(), "tenant-a", from, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollups) != 1 || rollups[0].Bytes != 42 || rollups[0].Flows != 1 {
		t.Fatalf("tenant-a rollups = %+v", rollups)
	}
	other, err := c.hourlyRollups(context.Background(), "tenant-b", from, now)
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
	c.WithRouter(func(_ context.Context, tenant string) (Target, error) {
		if tenant == "siloed" {
			return Target{Database: "probectl_t_roll"}, nil
		}
		return Target{}, nil
	})
	from := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	if err := c.backfillRollups(context.Background(), "siloed", from, to); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	for _, want := range []string{
		"DELETE FROM probectl_t_roll.probectl_flow_rollups_hour WHERE tenant_id={tenant:String}",
		"INSERT INTO probectl_t_roll.probectl_flow_rollups_hour",
		"FROM probectl_t_roll.probectl_flows",
		"WHERE tenant_id={tenant:String}",
		"param_tenant=siloed",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("backfill SQL missing %q:\n%s", want, joined)
		}
	}
}

func TestFlowClickHouseCountersPreserveUInt64Precision(t *testing.T) {
	now := time.Date(2026, 6, 30, 14, 0, 0, 0, time.UTC)
	const (
		bytes   = uint64(9007199254740993)
		packets = uint64(9007199254740995)
		flows   = uint64(9007199254740997)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		switch {
		case strings.Contains(q, "FROM probectl_flow_rollups_hour") && strings.Contains(q, "sum(bytes_scaled) AS bytes_scaled"):
			_, _ = w.Write([]byte(`{"bucket":"2026-06-30 13:00:00","protocol":"netflow9","exporter":"r1","transport":"tcp","bytes_scaled":9007199254740993,"packets_scaled":"9007199254740995","flow_count":9007199254740997}` + "\n"))
		case strings.Contains(q, "sum(bytes_scaled) AS b,"):
			_, _ = w.Write([]byte(`{"k":"10.0.0.1","d":"","b":9007199254740993,"p":"9007199254740995","f":9007199254740997,"e":2}` + "\n"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	top, err := c.TopTalkers(context.Background(), TopQuery{
		TenantID: "tenant-a",
		By:       BySrc,
		Window:   time.Hour,
		Limit:    1,
		Now:      now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 1 || top[0].Bytes != bytes || top[0].Packets != packets || top[0].Flows != flows {
		t.Fatalf("top-talkers counters lost precision: %+v", top)
	}
	if top[0].ExporterCount != 2 {
		t.Fatalf("top-talkers exporter count = %d, want 2", top[0].ExporterCount)
	}
	encoded, err := json.Marshal(top[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"bytes_str":"9007199254740993"`,
		`"packets_str":"9007199254740995"`,
		`"flows_str":"9007199254740997"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("top-talkers JSON missing exact string counter %s: %s", want, encoded)
		}
	}

	rollups, err := c.hourlyRollups(context.Background(), "tenant-a", now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollups) != 1 || rollups[0].Bytes != bytes || rollups[0].Packets != packets || rollups[0].Flows != flows {
		t.Fatalf("hourly rollup counters lost precision: %+v", rollups)
	}
}
