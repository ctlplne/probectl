// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAlertSupervisorEvaluatesTwoNonDefaultTenants(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	tenants := store.NewTenants(db.Pool())
	a, err := tenants.Create(ctx, fmt.Sprintf("alert-a-%d", time.Now().UnixNano()), "Alert A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	b, err := tenants.Create(ctx, fmt.Sprintf("alert-b-%d", time.Now().UnixNano()), "Alert B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	ruleIDs := map[string]string{}
	for _, tn := range []*store.Tenant{a, b} {
		ruleIDs[tn.ID] = createSupervisorRule(t, db, tn.ID, "loss-"+tn.Slug)
	}

	mem := tsdb.NewMemory()
	now := time.Now().UnixMilli()
	if err := mem.Write(ctx, []tsdb.Series{
		{Metric: "probectl_test_loss_ratio", Labels: map[string]string{"tenant_id": a.ID, "target": "a"}, Value: 0.9, TimeMillis: now},
		{Metric: "probectl_test_loss_ratio", Labels: map[string]string{"tenant_id": b.ID, "target": "b"}, Value: 0.8, TimeMillis: now},
	}); err != nil {
		t.Fatalf("write tsdb samples: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup, ok := BuildAlertEvaluatorSupervisor(db.Pool(), mem, alert.ChannelDeps{}, time.Hour,
		nil, log,
		func(tenant string, src AlertStateSource) { srv.WithAlertState(tenant, src) },
		func(tenant string) { srv.WithoutAlertState(tenant) })
	if !ok {
		t.Fatal("alert supervisor should be active with memory tsdb")
	}
	if err := sup.Sync(ctx); err != nil {
		t.Fatalf("sync tenants: %v", err)
	}
	sup.Tick(ctx)

	assertTenantActiveAlert(t, srv, a.ID, "loss-"+a.Slug)
	assertTenantActiveAlert(t, srv, b.ID, "loss-"+b.Slug)
	assertTenantAlertEvaluationReceipt(t, srv, a.ID, ruleIDs[a.ID], "a", "b")
	assertTenantAlertEvaluationReceipt(t, srv, b.ID, ruleIDs[b.ID], "b", "a")

	// The other tenant's rule UUID is not a global receipt handle. Rule lookup
	// and receipt query run inside tenant B's forced-RLS transaction first.
	cross := apiReq(t, srv.Handler(), http.MethodGet,
		"/v1/alerts/"+ruleIDs[a.ID]+"/evaluations", b.ID, nil)
	if cross.Code != http.StatusNotFound ||
		strings.Contains(cross.Body.String(), `"target":"a"`) {
		t.Fatalf("tenant B read tenant A evaluations = %d %s", cross.Code, cross.Body.String())
	}

	if _, err := tenants.UpdateStatus(ctx, a.ID, "suspended"); err != nil {
		t.Fatalf("suspend tenant A: %v", err)
	}
	if err := sup.Sync(ctx); err != nil {
		t.Fatalf("sync suspended tenant: %v", err)
	}
	assertTenantEvaluatorRunning(t, srv, a.ID, false)
	assertTenantActiveAlert(t, srv, b.ID, "loss-"+b.Slug)
}

func createSupervisorRule(t *testing.T, db *store.DB, tenantID, name string) string {
	t.Helper()
	var ruleID string
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{
				Name:       name,
				Enabled:    true,
				Metric:     "probectl_test_loss_ratio",
				Type:       alert.Threshold,
				Comparison: alert.GT,
				Threshold:  0.5,
				Severity:   alert.SeverityWarning,
			})
			if err == nil {
				ruleID = rule.ID
			}
			return err
		})
	if err != nil {
		t.Fatalf("create rule %s: %v", name, err)
	}
	return ruleID
}

func assertTenantAlertEvaluationReceipt(t *testing.T, srv *Server, tenantID, ruleID, wantTarget, denyTarget string) {
	t.Helper()
	active := readTenantActiveAlerts(t, srv, tenantID)
	if len(active.Items) != 1 {
		t.Fatalf("tenant %s active alerts = %+v", tenantID, active.Items)
	}
	path := "/v1/alerts/" + ruleID + "/evaluations?fingerprint=" +
		url.QueryEscape(active.Items[0].EvaluationFingerprint)
	rec := apiReq(t, srv.Handler(), http.MethodGet, path, tenantID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant %s evaluations = %d %s", tenantID, rec.Code, rec.Body.String())
	}
	var got alertEvaluationsResponse
	mustJSON(t, rec, &got)
	if !got.PersistenceRunning || !got.EvaluatorRunning || len(got.Items) != 1 ||
		got.Items[0].State != alert.EvaluationFiring ||
		got.Items[0].Labels["target"] != wantTarget ||
		got.Items[0].Labels["tenant_id"] != "" ||
		strings.Contains(rec.Body.String(), `"target":"`+denyTarget+`"`) ||
		strings.Contains(rec.Body.String(), tenantID) {
		t.Fatalf("tenant %s evaluation receipt = %+v body=%s", tenantID, got, rec.Body.String())
	}
}

func assertTenantActiveAlert(t *testing.T, srv *Server, tenantID, ruleName string) {
	t.Helper()
	resp := readTenantActiveAlerts(t, srv, tenantID)
	if !resp.EvaluatorRunning {
		t.Fatalf("tenant %s evaluator not running", tenantID)
	}
	if len(resp.Items) != 1 || resp.Items[0].RuleName != ruleName || resp.Items[0].Labels["tenant_id"] != tenantID {
		t.Fatalf("tenant %s active alerts = %+v, want one %q", tenantID, resp.Items, ruleName)
	}
}

func assertTenantEvaluatorRunning(t *testing.T, srv *Server, tenantID string, want bool) {
	t.Helper()
	resp := readTenantActiveAlerts(t, srv, tenantID)
	if resp.EvaluatorRunning != want {
		t.Fatalf("tenant %s evaluator_running=%v, want %v (items=%+v)", tenantID, resp.EvaluatorRunning, want, resp.Items)
	}
}

func readTenantActiveAlerts(t *testing.T, srv *Server, tenantID string) struct {
	EvaluatorRunning bool                `json:"evaluator_running"`
	Items            []alert.ActiveAlert `json:"items"`
} {
	t.Helper()
	rec := apiReq(t, srv.Handler(), http.MethodGet, "/v1/alerts/active", tenantID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant %s active alerts status=%d body=%s", tenantID, rec.Code, rec.Body.String())
	}
	var resp struct {
		EvaluatorRunning bool                `json:"evaluator_running"`
		Items            []alert.ActiveAlert `json:"items"`
	}
	mustJSON(t, rec, &resp)
	return resp
}
