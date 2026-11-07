// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestQueryLibrariesPostgresCompletePopulationKeepsRLSAndPositiveAdmission(t *testing.T) {
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "library PostgreSQL configuration unavailable")
		return
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "library PostgreSQL unavailable")
		return
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatal(err)
	}
	pool := queryLibraryRuntime(t, admin)
	tenants := store.NewTenants(pool)
	created := []*store.Tenant{}
	t.Cleanup(func() {
		engine := tenantlife.New(pool, nil, nil, nil, nil, "QA fixture has no backups", nil)
		for _, tenant := range created {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			attestation, err := engine.Erase(cleanup, tenant.ID, tenant.Slug, "qa-fixture")
			cancel()
			if err != nil || !attestation.Complete {
				t.Errorf("own library fixture erase incomplete: %+v %v", attestation, err)
			}
		}
	})
	for lane, marker := range []string{"red", "blue"} {
		tenant, err := tenants.Create(ctx, fmt.Sprintf("library-%s-%d", marker, time.Now().UnixNano()), marker)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, tenant)
		expression := flow.QueryFilterGroup{Match: "any", Mode: "include"}
		for group := 0; group < 4; group++ {
			child := flow.QueryFilterGroup{Match: "any", Mode: "include"}
			for index := group * 250; index < (group+1)*250; index++ {
				child.Conditions = append(child.Conditions, flow.QueryPredicate{Field: "src_addr", Op: flow.QueryEqual,
					Values: []string{fmt.Sprintf("10.%d.%d.%d", lane+1, index/256, index%256)}})
			}
			expression.Groups = append(expression.Groups, child)
		}
		input, err := flow.NormalizeSaveQueryFilter(flow.SaveQueryFilter{Name: marker + "-new", Expression: expression})
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Second)
		definition, err := flow.NormalizeQueryViewDefinition(flow.QueryViewDefinition{Name: marker + "-new", Visibility: "private",
			Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Hour), To: at,
				GroupBy: []string{"src_addr"}, View: "table", Filter: &input.Expression,
				Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}, at)
		if err != nil {
			t.Fatal(err)
		}
		filterWire, err := json.Marshal(input.Expression)
		if err != nil || int64(len(filterWire))*1500 <= 64<<20 {
			t.Fatal("complete PG library did not exceed the former quota", err)
		}
		viewWire, err := json.Marshal(definition)
		if err != nil {
			t.Fatal(err)
		}
		// Seed normalized synthetic configuration under the real app-role RLS
		// boundary, then exercise the actual stores at the complete population.
		// This is a database component, not production SSO or an external import.
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := scope.Q.Exec(ctx, `INSERT INTO flow_query_filters(tenant_id,id,name,description,expression,version,updated_by,created_at,updated_at)
			SELECT $1::uuid,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,$2::text||'-'||n::text,'',$3::jsonb,1,'alice',now(),now() FROM generate_series(1,1500) n`, tenant.ID, marker, string(filterWire)); err != nil {
				return err
			}
			_, err := scope.Q.Exec(ctx, `INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at)
			SELECT $1::uuid,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'alice',$2::text||'-'||n::text,'private',
			jsonb_set($3::jsonb,'{name}',to_jsonb($2::text||'-'||n::text)),1,now(),now() FROM generate_series(1,1500) n`, tenant.ID, marker, string(viewWire))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := flow.NewPostgresQueryFilterStore(pool, 64<<20, audit.TenantRecord).SaveQueryFilter(ctx, tenant.ID, "alice", input); !errors.Is(err, flow.ErrQueryFilterStorageBudget) {
			t.Fatal("old explicit library allowance did not refuse without publication", err)
		}
		if _, err := flow.NewPostgresQueryViewStore(pool, 64<<20, audit.TenantRecord).SaveQueryView(ctx, tenant.ID, "alice", flow.SaveQueryView{Definition: definition}); !errors.Is(err, flow.ErrQueryViewBudget) {
			t.Fatal("old explicit query allowance did not refuse without publication", err)
		}
		filters := flow.NewPostgresQueryFilterStore(pool, 0, audit.TenantRecord)
		views := flow.NewPostgresQueryViewStore(pool, 0, audit.TenantRecord)
		if _, err := filters.SaveQueryFilter(ctx, tenant.ID, "alice", input); err != nil {
			t.Fatal("complete PG filter library retains former quota", err)
		}
		if _, err := views.SaveQueryView(ctx, tenant.ID, "alice", flow.SaveQueryView{Definition: definition}); err != nil {
			t.Fatal("complete PG query library retains former quota", err)
		}
		filterIDs, viewIDs := map[string]bool{}, map[string]bool{}
		for after := ""; ; {
			page, err := filters.ListQueryFilters(ctx, tenant.ID, after, 32)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				actual, err := json.Marshal(item.Expression)
				if err != nil || string(actual) != string(filterWire) {
					t.Fatal("complete stored filter expression changed or crossed tenant", err)
				}
				if filterIDs[item.ID] || item.TenantID != tenant.ID || !strings.HasPrefix(item.Name, marker+"-") {
					t.Fatal("app-role filter library crossed tenant, repeated or changed a record")
				}
				filterIDs[item.ID] = true
			}
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		for after := ""; ; {
			page, err := views.ListQueryViews(ctx, tenant.ID, "alice", flow.QueryViewList{After: after, Limit: 32})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				actual, err := json.Marshal(item.Definition.Plan.Filter)
				if err != nil || string(actual) != string(filterWire) {
					t.Fatal("complete stored query expression changed or crossed tenant", err)
				}
				if viewIDs[item.ID] || item.TenantID != tenant.ID || !strings.HasPrefix(item.Definition.Name, marker+"-") {
					t.Fatal("app-role query library crossed tenant, repeated or changed a record")
				}
				viewIDs[item.ID] = true
			}
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		if len(filterIDs) != 1501 || len(viewIDs) != 1501 {
			t.Fatal("app-role complete query library truncated or published a refused write", len(filterIDs), len(viewIDs))
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, scope tenancy.Scope) error {
			for _, query := range []string{
				`SELECT count(*),min(name) FROM flow_query_filters WHERE id='00000000-0000-4000-8000-000000000001'`,
				`SELECT count(*),min(name) FROM flow_query_views WHERE id='00000000-0000-4000-8000-000000000001'`,
			} {
				var count int
				var name string
				if err := scope.Q.QueryRow(ctx, query).Scan(&count, &name); err != nil {
					return err
				}
				if count != 1 || name != marker+"-1" {
					t.Fatal("equal-id library crossed storage RLS")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := views.GetQueryView(ctx, tenant.ID, "bob", "00000000-0000-4000-8000-000000000001"); !errors.Is(err, flow.ErrQueryViewNotFound) {
			t.Fatal("app-role private library crossed owner", err)
		}
	}
}
