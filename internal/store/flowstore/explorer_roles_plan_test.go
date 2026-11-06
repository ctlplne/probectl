// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type roleExplorerProofStore interface {
	Insert(context.Context, []Row) error
	ExplorePlan(context.Context, PlanQuery) (PlanResult, error)
}

func proveRoleExplorer(t *testing.T, store roleExplorerProofStore, series []string, cleanup func(string)) {
	t.Helper()
	a, b := uuid.NewString(), uuid.NewString()
	if cleanup != nil {
		t.Cleanup(func() { cleanup(a); cleanup(b) })
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	mapped := explorerFixtureRow(a)
	mapped.AgentID, mapped.BytesScaled, mapped.ObsDomain, mapped.TS = "forged-foreign-agent", 100, 4294967295, at.Add(-time.Second)
	unmapped, foreign := mapped, mapped
	unmapped.Exporter, unmapped.BytesScaled = "192.0.2.2", 200
	foreign.TenantID, foreign.BytesScaled = b, 900
	if err := store.Insert(t.Context(), []Row{mapped, unmapped, foreign}); err != nil {
		t.Fatal(err)
	}
	lookup := func(tenant string, role entity.InterfaceRole) *InterfaceRoleQueryData {
		t.Helper()
		rows := roleQueryFixture(tenant, at)
		rows[0].Role = role
		data, err := NewInterfaceRoleQueryData(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, at, rows, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first := lookup(a, entity.InterfaceRoleTransit)
	for _, source := range series {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
		plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), DataSeries: source,
			GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		result, err := store.ExplorePlan(ctx, PlanQuery{TenantID: a, Plan: plan, Roles: first})
		if err != nil || result.Totals["bytes:total"] != "300" || len(result.Rows) != 2 || result.RoleTenantID != a || len(result.RoleDigest) != 64 || len(result.RoleSources) != 2 {
			t.Fatal("role explorer lost complete tenant totals or provenance", source, result, err)
		}
		groups := map[string]string{}
		for _, row := range result.Rows {
			groups[row.Group["in_if_role"]+"/"+row.Group["out_if_role"]] = row.Metrics["bytes:total"]
		}
		if groups["transit/customer"] != "100" || groups["other/other"] != "200" {
			t.Fatal("role explorer dropped missing metadata or selected an untrusted agent", source, groups)
		}
		plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "in_if_role", Op: flow.QueryEqual, Values: []string{"transit"}}}}
		filtered, err := store.ExplorePlan(ctx, PlanQuery{TenantID: a, Plan: plan, Roles: first})
		if err != nil || filtered.Totals["bytes:total"] != "100" || len(filtered.Rows) != 1 {
			t.Fatal("role predicate disagrees with grouping", source, filtered, err)
		}
		if _, err := store.ExplorePlan(ctx, PlanQuery{TenantID: a, Plan: plan}); !errors.Is(err, ErrInterfaceRoleQueryScope) {
			t.Fatal("selected role field invented authority without a current projection", source, err)
		}
		ctxB := tenancy.WithTenant(t.Context(), tenancy.ID(b))
		if _, err := store.ExplorePlan(ctxB, PlanQuery{TenantID: b, Plan: plan, Roles: first}); !errors.Is(err, ErrInterfaceRoleQueryScope) {
			t.Fatal("foreign tenant reused flow role projection", source, err)
		}
		plan.Filter = nil
		second, err := store.ExplorePlan(ctxB, PlanQuery{TenantID: b, Plan: plan, Roles: lookup(b, entity.InterfaceRoleBackbone)})
		if err != nil || second.Totals["bytes:total"] != "900" || len(second.Rows) != 1 || second.Rows[0].Group["in_if_role"] != "backbone" {
			t.Fatal("same-address tenant lost its independent interface role", source, second, err)
		}
		changed, err := store.ExplorePlan(ctx, PlanQuery{TenantID: a, Plan: plan, Roles: lookup(a, entity.InterfaceRolePrivate)})
		if err != nil || changed.Totals["bytes:total"] != "300" || changed.RoleDigest == result.RoleDigest {
			t.Fatal("current reclassification changed retained traffic or reused role provenance", source, changed, err)
		}
	}
}

func TestInterfaceRoleExplorerPreservesBothDirectionsMissingRowsAndTenantBoundary(t *testing.T) {
	proveRoleExplorer(t, NewMemory(), []string{"raw"}, nil)
}

func TestInterfaceRoleExplorerSQLKeepsFixedTenantJoinAndCompleteExternalValues(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	at := time.Now().UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	data, err := NewInterfaceRoleQueryData(ctx, tenant, at, roleQueryFixture(tenant, at), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	sql, _, err := planSQLWithRoleMetadata(DefaultExplorerBudget(), plan, "probectl.flows", nil, tenant, nil, data)
	if err != nil || strings.Count(sql, "ANY LEFT JOIN interface_role_lookup") != 2 {
		t.Fatal("both role directions lack a fixed external join", sql, err)
	}
	for _, side := range []string{"in", "out"} {
		for _, term := range []string{".role_tenant=tenant_id", ".role_protocol=protocol", ".role_domain=obs_domain", ".role_index=" + side + "_if"} {
			if !strings.Contains(sql, side+"_roles"+term) {
				t.Fatal("role SQL omitted exact scoped origin identity", side, term)
			}
		}
	}
	if strings.Contains(sql, "agent_id=") || strings.Contains(sql, tenant) {
		t.Fatal("role SQL trusted a raw agent or interpolated tenant identity", sql)
	}
	body, err := data.externalRows(ctx, tenant, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatal("external role table was truncated", string(body))
	}
	for _, line := range lines {
		var row map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &row) != nil || string(row["role_domain"]) != "4294967295" || string(row["role_tenant"]) != `"`+tenant+`"` {
			t.Fatal("external role table changed complete domain or tenant", line)
		}
	}
	if body, err := data.externalRows(ctx, tenant, 1); !errors.Is(err, ErrExplorerBudget) || body != nil {
		t.Fatal("external roles returned a partial admitted table", string(body), err)
	}
}
