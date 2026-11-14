// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestProviderMonthlyQueueKeepsConsentCurrentOwnerAndTenant(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	queue := f.server.MonthlyReportQueue()
	if queue == nil {
		t.Fatal("trusted metadata queue unavailable")
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	defer socket.Close()
	call := func(tenant, method, path string, input any, token string) (int, []byte) {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(raw)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if token == "" {
			token = f.tokens[tenant]
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	requestID := func() string {
		t.Helper()
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	schedules := map[string]store.ReportSchedule{}
	restricted := map[string]string{}
	original := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permMetricsWrite, permTestRead, permChangeRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		definition := reporting.DashboardDefinition{ClientReport: &reporting.ClientReportDefinition{CapacityTargets: []reporting.ClientReportCapacityTarget{}}, Provenance: []string{"owned retained monthly sources"}, RedactionState: "metadata", CoverageLimitations: []string{"empty modeled monthly history"}}
		code, raw := call(tenant, http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{Name: "Tenant monthly profile", Preset: "operator", Definition: definition}, "")
		if code != http.StatusCreated {
			t.Fatalf("create monthly profile %d: %s", code, raw)
		}
		var view store.DashboardView
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		code, raw = call(tenant, http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Owned monthly delivery", Cadence: "monthly", Format: "csv", DestinationID: reportInboxDestination, FirstRunAt: original}, "")
		if code != http.StatusCreated {
			t.Fatalf("create monthly schedule %d: %s", code, raw)
		}
		var schedule store.ReportSchedule
		if err := json.Unmarshal(raw, &schedule); err != nil {
			t.Fatal(err)
		}
		schedules[tenant] = schedule
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		restricted[tenant] = token
		if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), tenant, f.users[tenant], "monthly-trigger-write-only", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), []string{permMetricsWrite}); err != nil {
			t.Fatal(err)
		}
		code, _ = call(tenant, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedule.ID, map[string]bool{"provider_trigger_allowed": true}, token)
		if code != http.StatusForbidden {
			t.Fatal("write-only credential delegated provider source work", code)
		}
		before, err := queue.QueueMonthlyReports(t.Context(), tenant, "operator", requestID())
		if err != nil || before.Eligible != 0 || before.Queued != 0 {
			t.Fatal("unconsented profile queued", before, err)
		}
		code, raw = call(tenant, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedule.ID, map[string]bool{"provider_trigger_allowed": true}, "")
		if code != http.StatusOK {
			t.Fatalf("owner source preflight %d: %s", code, raw)
		}
	}
	sharedID := requestID()
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	for _, tenant := range f.tenants {
		result, err := queue.QueueMonthlyReports(t.Context(), tenant, "operator", sharedID)
		if err != nil || result.TenantID != tenant || result.Eligible != 1 || result.Queued != 1 || result.Pending != 1 || result.Replay {
			t.Fatal("tenant metadata enqueue", result, err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 7 {
			t.Fatal("provider metadata contract gained an unreviewed data field")
		}
		replay, err := queue.QueueMonthlyReports(t.Context(), tenant, "operator", sharedID)
		if err != nil || !replay.Replay || replay.Queued != 1 || replay.Pending != 1 {
			t.Fatal("request replay altered queued work", replay, err)
		}
		if err := supervisor.materializeTenantReports(t.Context(), tenant, time.Now().UTC()); err != nil {
			t.Fatal("owned worker failed", err)
		}
		if err := supervisor.materializeTenantReports(t.Context(), tenant, time.Now().UTC()); err != nil {
			t.Fatal("worker replay failed", err)
		}
		replay, err = queue.MonthlyReportProgress(t.Context(), tenant, "operator", sharedID)
		if err != nil || replay.Delivered != 1 || replay.Pending != 0 || replay.Inactive != 0 {
			t.Fatal("operational completion receipt", replay, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := (store.DashboardReports{}).GetSchedule(ctx, sc, schedules[tenant].ID, f.users[tenant])
			if err != nil {
				return err
			}
			if !current.NextRunAt.Equal(original) || current.ProviderRequestID != nil || current.ProviderOriginalNextRunAt != nil {
				return errors.New("provider run shifted normal delivery cadence")
			}
			var count int
			err = sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2`, tenant, current.ID).Scan(&count)
			if err == nil && count != 1 {
				return errors.New("provider or worker replay duplicated tenant packs")
			}
			return err
		})
	}
	a, b := f.tenants[0], f.tenants[1]
	if _, err := queue.MonthlyReportProgress(t.Context(), a, "operator", requestID()); err == nil {
		t.Fatal("unknown progress read created a request receipt")
	}
	if _, err := queue.QueueMonthlyReports(tenancy.WithTenant(t.Context(), tenancy.ID(a)), b, "operator", requestID()); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("metadata queue borrowed another tenant context", err)
	}
	if _, err := queue.QueueMonthlyReports(t.Context(), a, "other-operator", sharedID); err == nil {
		t.Fatal("request receipt attribution crossed operators")
	}
	revokeID := requestID()
	if _, err := queue.QueueMonthlyReports(t.Context(), a, "operator", revokeID); err != nil {
		t.Fatal(err)
	}
	var captured store.DueDashboardReport
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		due, err := (store.DashboardReports{}).ListDueForRendering(ctx, sc, time.Now().UTC(), 20)
		if err == nil && len(due) != 1 {
			return errors.New("provider work was not captured exactly once")
		}
		if err == nil {
			captured = due[0]
		}
		return err
	})
	code, raw := call(a, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedules[a].ID, map[string]bool{"provider_trigger_allowed": false}, restricted[a])
	if code != http.StatusOK {
		t.Fatalf("owner could not revoke without source delegation %d: %s", code, raw)
	}
	published, err := supervisor.materializeCapturedReport(tenancy.WithTenant(t.Context(), tenancy.ID(a)), "tenant", captured, time.Now().UTC())
	if err != nil || published {
		t.Fatal("captured provider work survived consent revocation", published, err)
	}
	replay, err := queue.MonthlyReportProgress(t.Context(), a, "operator", revokeID)
	if err != nil || replay.Pending != 0 || replay.Delivered != 0 || replay.Inactive != 1 {
		t.Fatal("revocation progress was false", replay, err)
	}
	code, _ = call(a, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedules[a].ID, map[string]bool{"provider_trigger_allowed": true}, "")
	if code != http.StatusOK {
		t.Fatal("fresh owner source grant", code)
	}
	if _, err := queue.QueueMonthlyReports(t.Context(), a, "operator", requestID()); err != nil {
		t.Fatal(err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	if err := supervisor.materializeTenantReports(t.Context(), a, time.Now().UTC()); err == nil {
		t.Fatal("provider trigger lent a withdrawn owner source grant")
	}
	replay, err = queue.MonthlyReportProgress(t.Context(), b, "operator", sharedID)
	if err != nil || replay.Delivered != 1 || replay.Pending != 0 {
		t.Fatal("source withdrawal changed sibling tenant progress", replay, err)
	}
	t.Log("real-integration: tenant-consented metadata triggers, tenant-bound request receipts, current-owner scheduled fulfillment and revocation/cadence/retry controls on PG/RLS and HTTPS; empty retained history modeled, provider adapter authentication and rendered console proof separate")
}
