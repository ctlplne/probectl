// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestAlertSupervisorEvaluatesTwoNonDefaultTenants(t *testing.T) {
	_, db := setupAPI(t)
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
	for _, tn := range []*store.Tenant{a, b} {
		createSupervisorRule(t, db, tn.ID, "loss-"+tn.Slug)
	}

	mem := tsdb.NewMemory()
	now := time.Now().UnixMilli()
	if err := mem.Write(ctx, []tsdb.Series{
		{Metric: "probectl_test_loss_ratio", Labels: map[string]string{"tenant_id": a.ID, "target": "a"}, Value: 0.9, TimeMillis: now},
		{Metric: "probectl_test_loss_ratio", Labels: map[string]string{"tenant_id": b.ID, "target": "b"}, Value: 0.8, TimeMillis: now},
	}); err != nil {
		t.Fatalf("write tsdb samples: %v", err)
	}

	srv := testServer(fakePinger{})
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

	if _, err := tenants.UpdateStatus(ctx, a.ID, "suspended"); err != nil {
		t.Fatalf("suspend tenant A: %v", err)
	}
	if err := sup.Sync(ctx); err != nil {
		t.Fatalf("sync suspended tenant: %v", err)
	}
	assertTenantEvaluatorRunning(t, srv, a.ID, false)
	assertTenantActiveAlert(t, srv, b.ID, "loss-"+b.Slug)
}

func createSupervisorRule(t *testing.T, db *store.DB, tenantID, name string) {
	t.Helper()
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{
				Name:       name,
				Enabled:    true,
				Metric:     "probectl_test_loss_ratio",
				Type:       alert.Threshold,
				Comparison: alert.GT,
				Threshold:  0.5,
				Severity:   alert.SeverityWarning,
			})
			return err
		})
	if err != nil {
		t.Fatalf("create rule %s: %v", name, err)
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
