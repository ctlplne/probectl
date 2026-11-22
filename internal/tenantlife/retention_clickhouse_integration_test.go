// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestRetentionSweepPrunesBackdatedClickHouseRowsAndAuditsPG(t *testing.T) {
	url := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for the retention sweep proof")
	}
	flows, err := flowstore.NewClickHouseWithClient(url, 0, nil)
	if err != nil {
		testsupport.SkipOrFatal(t, "flow ClickHouse unavailable: %v", err)
	}
	endpoints, err := endpointstore.NewClickHouseWithClient(url, 0, nil)
	if err != nil {
		t.Fatalf("endpoint ClickHouse schema: %v", err)
	}
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	providerHead, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	engine := New(pool, flows, objectstore.NewMemory(), nil, func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}, "", testLog()).WithEndpointEvents(endpoints).WithClock(func() time.Time { return now })

	const expired, boundary, fresh = "192.0.2.10", "192.0.2.11", "192.0.2.12"
	samples := []struct {
		address string
		age     time.Duration
	}{{expired, 36 * time.Hour}, {boundary, 24 * time.Hour}, {fresh, time.Hour}}
	var policies []retentionSweepPolicy
	for _, days := range []int{1, 3} {
		tenant := mkTenant(t, pool, fmt.Sprintf("it-retention-ch-%d-%d", time.Now().UnixNano(), days))
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if remaining, err := flows.DeleteTenant(cleanup, tenant); remaining != 0 || err != nil {
				t.Errorf("cleanup flow rows for %s: remaining=%d, err=%v", tenant, remaining, err)
			}
			if remaining, err := endpoints.DeleteTenant(cleanup, tenant); remaining != 0 || err != nil {
				t.Errorf("cleanup endpoint rows for %s: remaining=%d, err=%v", tenant, remaining, err)
			}
			if _, err := pool.Exec(cleanup, `DELETE FROM tenants WHERE id = $1`, tenant); err != nil {
				t.Errorf("cleanup tenant %s: %v", tenant, err)
			}
		})
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if err := engine.SetRetention(tenantCtx, RetentionPolicy{
			TenantID: tenant, FlowRetentionDays: &days, DerivedIdentityRetentionDays: &days,
		}, "retention-fixture-admin"); err != nil {
			t.Fatal(err)
		}
		policy, err := engine.RetentionFor(tenantCtx, tenant)
		if err != nil || policy.FlowRetentionDays == nil || policy.DerivedIdentityRetentionDays == nil ||
			*policy.FlowRetentionDays != days || *policy.DerivedIdentityRetentionDays != days {
			t.Fatalf("persisted retention clocks for %s: %+v, %v", tenant, policy, err)
		}
		policies = append(policies, retentionSweepPolicy{tenant: tenant, days: map[string]int{
			"flows": *policy.FlowRetentionDays, "derived_identity": *policy.DerivedIdentityRetentionDays,
		}})
		var flowRows []flowstore.Row
		var endpointRows []endpointstore.Event
		for _, sample := range samples {
			at := now.Add(-sample.age)
			flowRows = append(flowRows, flowstore.Row{
				TenantID: tenant, AgentID: "fixture", Exporter: "198.51.100.10", Protocol: "ipfix",
				TS: at, StartTS: at.Add(-time.Second), SrcAddr: "198.51.100.20", DstAddr: sample.address,
				SrcPort: 40001, DstPort: 443, Transport: "tcp", Sampling: 1,
				Bytes: 100, BytesScaled: 100, Packets: 1, PacketsScaled: 1,
			})
			endpointRows = append(endpointRows, endpointstore.Event{
				TenantID: tenant, AgentID: "fixture", Type: "endpoint.session", SignalKey: sample.address,
				Target: sample.address, ObservedAt: at, Success: true,
			})
		}
		if err := flows.Insert(tenantCtx, flowRows); err != nil {
			t.Fatal(err)
		}
		if err := endpoints.Insert(tenantCtx, endpointRows); err != nil {
			t.Fatal(err)
		}
		assertRetentionExport(tenantCtx, t, tenant, "flows", flows.ExportTenant, expired, boundary, fresh)
		assertRetentionExport(tenantCtx, t, tenant, "endpoint_events", endpoints.ExportTenant, expired, boundary, fresh)
	}

	// Use the production sweep's per-policy entry point so the shared CI
	// database's unrelated tenants can never be swept by this test.
	if err := engine.sweepRetentionPolicies(ctx, policies); err != nil {
		t.Fatalf("retention sweep: %v", err)
	}
	for _, policy := range policies {
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(policy.tenant))
		want := []string{expired, boundary, fresh}
		if policy.days["flows"] == 1 {
			want = want[1:]
		}
		assertRetentionExport(tenantCtx, t, policy.tenant, "flows", flows.ExportTenant, want...)
		assertRetentionExport(tenantCtx, t, policy.tenant, "endpoint_events", endpoints.ExportTenant, want...)
		cutoff := now.Add(-time.Duration(policy.days["flows"]) * 24 * time.Hour)
		if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			// Flow receipts record completion. Endpoint receipts also carry the
			// exact prune count. The flow export proves the removed flow count.
			err := verifyClickHouseSweepReceipt(ctx, q, policy.tenant, "flows", cutoff, "0")
			if err != nil {
				return err
			}
			return verifyClickHouseSweepReceipt(ctx, q, policy.tenant, "endpoint_events", cutoff, fmt.Sprint(len(samples)-len(want)))
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := audit.ProviderVerifyFrom(ctx, pool, providerHead); err != nil {
		t.Fatalf("provider retention audit chain: %v", err)
	}
}

func assertRetentionExport(ctx context.Context, t *testing.T, tenant, store string, export func(context.Context, string, io.Writer) (int64, error), addresses ...string) {
	t.Helper()
	var data bytes.Buffer
	if count, err := export(ctx, tenant, &data); err != nil || count != int64(len(addresses)) {
		t.Fatalf("%s export for %s: rows=%d, want=%d, err=%v", store, tenant, count, len(addresses), err)
	}
	decoder := json.NewDecoder(&data)
	for _, address := range addresses {
		var row struct {
			Tenant string `json:"tenant_id"`
			Flow   string `json:"dst_addr"`
			Target string `json:"target"`
		}
		if err := decoder.Decode(&row); err != nil || row.Tenant != tenant || (row.Flow != address && row.Target != address) {
			t.Fatalf("%s export for %s: row=%+v, want address=%s, err=%v", store, tenant, row, address, err)
		}
	}
}

func verifyClickHouseSweepReceipt(ctx context.Context, q tenancy.Querier, tenant, store string, cutoff time.Time, deleted string) error {
	rows, err := q.Query(ctx, `
		SELECT data->>'attempt_id', data->>'status', data->>'cutoff', COALESCE(data->>'deleted', '')
		FROM provider_audit_events
		WHERE target = $1 AND actor = 'probectl-retention' AND action = 'lifecycle.retention_sweep'
		  AND data->>'store' = $2 AND data->>'source' = 'tenant_policy'
		ORDER BY seq`, tenant, store)
	if err != nil {
		return err
	}
	defer rows.Close()
	var attempt string
	for index, status := range []string{"intent", "enforced"} {
		var id, state, clock, count string
		if !rows.Next() {
			return fmt.Errorf("%s retention for %s: missing %s receipt (query error: %v)", store, tenant, status, rows.Err())
		}
		if err := rows.Scan(&id, &state, &clock, &count); err != nil {
			return err
		}
		wantCount := ""
		if index == 0 {
			attempt = id
		} else {
			wantCount = deleted
		}
		if id == "" || id != attempt || state != status || clock != cutoff.Format(time.RFC3339Nano) || count != wantCount {
			return fmt.Errorf("%s retention for %s: unexpected receipt id=%q status=%q cutoff=%q deleted=%q", store, tenant, id, state, clock, count)
		}
	}
	if rows.Next() {
		return fmt.Errorf("%s retention for %s: duplicate receipts", store, tenant)
	}
	return rows.Err()
}
