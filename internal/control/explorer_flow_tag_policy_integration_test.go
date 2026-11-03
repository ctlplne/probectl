// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This regression also compiles against the original vulnerable candidate;
// it uses only existing APIs for a clean-worktree before/after reproduction.
func TestFlowTagsRespectCurrentContextPolicy(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "tag-policy-a"), freshTenant(t, db, "tag-policy-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("clean policy fixture: %v", err)
		}
	})
	contextIDs := []string{gouuid.NewString(), gouuid.NewString()}
	tagID := gouuid.NewString()
	for _, tenant := range []string{a, b} {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'customer')`, tenant, tagID); err != nil {
				return err
			}
			for i, id := range contextIDs {
				agent, address, value := "policy-"+id, "192.0.2.10", "red"
				if i == 1 {
					address, value = "192.0.2.20", "green"
				}
				for _, statement := range []struct {
					sql  string
					args []any
				}{
					{`INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,$2::uuid::text,'vrf')`, []any{tenant, id, gouuid.NewString(), gouuid.NewString()}},
					{`INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, []any{tenant, agent, id}},
					{`INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES ($1,$2,'flow_exporter',$3,$4)`, []any{tenant, agent, address, id}},
					{`INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,exporter_agent_id,exporter_source_kind,exporter_source_ref,value,source) VALUES ($1,$2,$3,$4,'exporter',$5,'flow_exporter',$6,$7,'manual')`, []any{tenant, id, gouuid.NewString(), tagID, agent, address, value}},
				} {
					if _, err := sc.Q.Exec(ctx, statement.sql, statement.args...); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	rows := flowstore.NewMemory()
	srv.WithFlowStore(rows)
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := rows.Insert(t.Context(), []flowstore.Row{
		{TenantID: a, TS: at, Exporter: "192.0.2.10", BytesScaled: 100},
		{TenantID: a, TS: at, Exporter: "192.0.2.20", BytesScaled: 200},
		{TenantID: b, TS: at, Exporter: "192.0.2.10", BytesScaled: 900},
		{TenantID: b, TS: at, Exporter: "192.0.2.20", BytesScaled: 800},
	}); err != nil {
		t.Fatal(err)
	}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Question: "Context policy regression", Flow: &flow.QueryPlan{
		From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"tag.customer"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}},
	}}
	read := func(tenant string) *flowstore.PlanResult {
		t.Helper()
		rec := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", tenant, query)
		var result explorerResult
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Flow == nil {
			t.Fatal("context policy query failed before the disclosure assertion")
		}
		return result.Flow
	}
	groups := func(result *flowstore.PlanResult) map[string]string {
		out := map[string]string{}
		for _, row := range result.Rows {
			out[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
		}
		return out
	}
	if before := read(a); groups(before)["red"] != "100" || before.Totals["bytes:total"] != "300" {
		t.Fatal("policy fixture did not exercise an admitted tag value")
	}
	for _, permission := range []string{permTagsRead, permFlowRead} {
		var policy *auth.Policy
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "hide one context", Enabled: true, Effect: auth.PolicyDeny, Permission: permission, Resource: map[string]string{"context_id": contextIDs[0]}, Priority: 100})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(a)
		after := read(a)
		if groups(after)["red"] != "" {
			t.Fatal("context tag value disclosed after an explicit deny")
		}
		if groups(after)["green"] != "200" || groups(after)[""] != "100" || after.Totals["bytes:total"] != "300" {
			t.Fatal("withheld metadata dropped selected flow rows or changed allowed totals")
		}
		if other := read(b); groups(other)["red"] != "900" || other.Totals["bytes:total"] != "1700" {
			t.Fatal("context deny crossed the tenant boundary")
		}
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.ABACPolicies{}).Delete(ctx, sc, policy.ID)
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(a)
	}
}
