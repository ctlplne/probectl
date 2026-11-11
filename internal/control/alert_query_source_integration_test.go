// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual application-role PostgreSQL/source-authority and HTTP handler proof;
// flow rows are in-process, not a physical sender or ClickHouse receipt.
func TestSavedQueryAlertAPIKeepsCurrentSourceAuthorityAndTwoTenants(t *testing.T) {
	s, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	tenants := []string{freshTenant(t, db, "query-alert-a"), freshTenant(t, db, "query-alert-b")}
	t.Cleanup(func() {
		_, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants)
		if err != nil {
			t.Error(err)
		}
	})
	rows := flowstore.NewMemory()
	s.WithFlowStore(rows)
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 1
	policy.QueriesPerMin = 10000
	s.WithFairness(fairness.NewGate(policy, nil))
	views := flow.NewPostgresQueryViewStore(db.Pool(), 0, audit.TenantRecord)
	s.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(db.Pool(), 0, audit.TenantRecord))
	type lane struct {
		actor *auth.Principal
		role  string
		view  flow.SavedQueryView
		rule  alert.Rule
		input alert.QuerySourceInput
	}
	lanes := []lane{}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for i, tenant := range tenants {
		current := lane{}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "query-owner@"+tenant+".invalid", "Query owner")
			if err != nil {
				return err
			}
			role, err := (store.Roles{}).Create(ctx, sc, "query-alert-owner", "Query owner", "Current source grants")
			if err != nil {
				return err
			}
			current.role = role.ID
			for _, permission := range []string{permAIQuery, permFlowRead, permAlertRead, permAlertWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
				return err
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", user.ID)
			if err != nil {
				return err
			}
			current.actor = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: user.ID}, grants)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		input := flowstore.Row{TenantID: tenant, AgentID: uuid(t), Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, StartTS: at.Add(-time.Second), SrcAddr: "192.0.2.1", DstAddr: "198.51.100.1", Transport: "tcp", Sampling: 1, Bytes: uint64(100 + i*800), BytesScaled: uint64(100 + i*800), Packets: 1, PacketsScaled: 1, SrcASN: uint32(64512 + i)}
		second := input
		second.SrcASN += 10
		if err := rows.Insert(t.Context(), []flowstore.Row{input, second}); err != nil {
			t.Fatal(err)
		}
		current.view, err = views.SaveQueryView(ctx, tenant, current.actor.UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Source AS", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"src_asn"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		current.input = alert.QuerySourceInput{ViewID: current.view.ID, ViewVersion: current.view.Version, EverySeconds: 60, Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "50"}}
		body, err := json.Marshal(alertRequest{Name: "AS traffic", QuerySource: &current.input})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(body)).WithContext(auth.WithPrincipal(ctx, current.actor))
		response := httptest.NewRecorder()
		if i == 0 {
			budget := flowstore.ExplorerQueryBudget(rows)
			small := budget
			small.ReadRows = 1
			if err := flowstore.AttachExplorerBudget(rows, small); err != nil {
				t.Fatal(err)
			}
			refused := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(body)).WithContext(auth.WithPrincipal(ctx, current.actor))
			if err := s.handleCreateAlert(httptest.NewRecorder(), refused); err == nil {
				t.Fatal("over-budget complete query was saved")
			}
			if err := flowstore.AttachExplorerBudget(rows, budget); err != nil {
				t.Fatal(err)
			}
			if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				rules, err := (store.AlertRules{}).List(ctx, sc)
				if err == nil && len(rules) != 0 {
					return fmt.Errorf("failed save retained an inert rule")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.handleCreateAlert(response, request); err != nil {
			t.Fatal("save-time complete source admission failed", err)
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &current.rule) != nil || current.rule.Metric != alert.QueryMetric {
			t.Fatal("query creation did not return its canonical rule", response.Code, response.Body.String())
		}
		lanes = append(lanes, current)
	}
	for i, current := range lanes {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(current.actor.TenantID))
		state, err := s.readAlertQuerySource(ctx, current.actor, current.rule.ID)
		if err != nil || !state.Configured || state.Source == nil || state.Source.ViewID != current.view.ID {
			t.Fatal("complete own source configuration unavailable", state, err)
		}
		encoded, _ := json.Marshal(state)
		if strings.Contains(string(encoded), "read_grants") || strings.Contains(string(encoded), "owner_user_id") || strings.Contains(string(encoded), "query_group_state") {
			t.Fatal("public configuration leaked stored authority or baseline")
		}
		foreign := lanes[1-i]
		if out, err := s.readAlertQuerySource(ctx, current.actor, foreign.rule.ID); err == nil || out.Configured {
			t.Fatal("foreign rule source crossed tenant RLS", out, err)
		}
		if out, err := s.setAlertQuerySource(ctx, current.actor, current.rule.ID, foreign.input); err == nil || out.Configured {
			t.Fatal("foreign saved view attached to own rule", out, err)
		}
		read, err := s.readAlertQueryRule(ctx, current.actor.TenantID, current.rule)
		if err != nil || len(read.Samples) != 2 || read.Samples[0].Value != 1 || read.Samples[1].Value != 1 || read.QuerySelection == nil || !read.QuerySelection.Complete {
			t.Fatal("current owned query did not produce complete grouped predicates", read, err)
		}
		if next, err := s.readAlertQueryRule(ctx, current.actor.TenantID, current.rule); err != nil || !next.Skip || len(next.Samples) != 0 {
			t.Fatal("not-due read executed or invented health", next, err)
		}
		// A saved source does not delegate a credential's absent read grant.
		limited := auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: current.actor.TenantID, UserID: current.actor.UserID, ViaBearerToken: true}, []auth.PermissionGrant{{Permission: permAlertWrite, ScopeType: auth.ScopeTenant}})
		if out, err := s.setAlertQuerySource(ctx, limited, current.rule.ID, current.input); err == nil || out.Configured {
			t.Fatal("fresh broad role widened a limited configuring credential", out, err)
		}
		// Rebind makes evaluation due, then revoke the actual owner's source role.
		state, err = s.setAlertQuerySource(ctx, current.actor, current.rule.ID, current.input)
		if err != nil {
			t.Fatal(err)
		}
		current.rule.UpdatedAt = state.RuleUpdatedAt
		err = tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, current.actor.TenantID, current.role, permFlowRead)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if read, err := s.readAlertQueryRule(ctx, current.actor.TenantID, current.rule); err == nil || len(read.Samples) != 0 || read.QuerySelection != nil {
			t.Fatal("revoked current source owner still evaluated", read, err)
		}
		cleared, err := s.clearAlertQuerySource(ctx, limited, current.rule.ID)
		if err != nil || cleared.Configured || cleared.Source != nil {
			t.Fatal("explicit clear required a revoked source read", cleared, err)
		}
		err = tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			rule, err := (store.AlertRules{}).Get(ctx, sc, current.rule.ID)
			if err == nil && rule.Enabled {
				return fmt.Errorf("cleared source left an enabled inert rule")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
