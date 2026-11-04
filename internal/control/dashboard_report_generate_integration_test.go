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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func reportProofJSON(t *testing.T, socket *httptest.Server, token, method, route string, input any) (int, []byte) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var reader io.Reader
	if method != http.MethodGet {
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+route, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	client := socket.Client()
	client.Timeout = 30 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("actual report write request failed", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

// Called after the independent stored-reader controls, so new public artifacts
// cannot change their original metadata cardinality oracle. Each source still
// comes from the paired real ClickHouse fixture; no caller-supplied values.
func proveSourceReportPublicGenerationAndSchedule(t *testing.T, f *tagImportSubjectFixture, socket *httptest.Server, proofs []*reportDownloadProof, application string) {
	t.Helper()
	views := make([]store.DashboardView, len(proofs))
	for i, proof := range proofs {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(proof.tenant))
		if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, proof.role, permMetricsWrite)
		}); err != nil {
			t.Fatal(err)
		}
		definition := dashboardDefinition{FlowSources: proof.sources, Provenance: []string{"saved flow source"}, RedactionState: "tenant source policy", CoverageLimitations: []string{"selected source rows only"}}
		status, body := reportProofJSON(t, socket, proof.token, http.MethodPost, "/v1/dashboards", dashboardCreateRequest{Name: "Source report", Preset: "operator", Shared: true, Definition: definition})
		if status != http.StatusCreated {
			t.Fatal("public source dashboard creation failed", status, string(body))
		}
		if err := json.Unmarshal(body, &views[i]); err != nil {
			t.Fatal(err)
		}
		status, body = reportProofJSON(t, socket, proof.token, http.MethodPost, "/v1/dashboard-reports", reportGenerateRequest{DashboardID: views[i].ID, Format: proof.format})
		if status != http.StatusCreated {
			t.Fatal("public source report generation failed", status, string(body))
		}
		// A real write-capable bearer still cannot borrow omitted source scopes.
		limited, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(f.db.Pool()).CreateWithLifetime(ctx, proof.tenant, proof.user, "source-limited-writer", crypto.Hash([]byte(limited)), time.Now().Add(time.Hour), []string{permMetricsWrite, "metrics.read", permAIQuery}); err != nil {
			t.Fatal(err)
		}
		denied, _ := reportProofJSON(t, socket, limited, http.MethodPost, "/v1/dashboard-reports", reportGenerateRequest{DashboardID: views[i].ID, Format: proof.format})
		if denied != http.StatusForbidden {
			t.Fatal("scoped writer borrowed report source read authority", denied)
		}
		var artifact reportArtifactView
		if err := json.Unmarshal(body, &artifact); err != nil {
			t.Fatal(err)
		}
		status, headers, content := requestCapturedReport(t, socket, proof.token, artifact.ID)
		if status != http.StatusOK || len(content) == 0 || headers.Get("X-Report-SHA256") != fmt.Sprintf("%x", crypto.Hash(content)) {
			t.Fatal("public generated report did not return complete verified bytes", status)
		}
		if proof.format == "csv" && (!bytes.Contains(content, []byte("OWN-"+proof.tenant)) || bytes.Contains(content, []byte("OWN-"+proofs[1-i].tenant))) {
			t.Fatal("public generation lost actual own source rows or mixed tenants")
		}
		var metadata *store.ReportArtifactMetadata
		if err := tenancy.InTenantReadSnapshot(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			metadata, err = (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, artifact.ID, proof.user)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		requirements, err := parseReportSourceRequirements(ctx, metadata.SourceCapture)
		if err != nil || metadata.BodyStorage != "chunks" || metadata.BodyBytes != int64(len(content)) || requirements == nil || requirements.Inputs[0].ID != proof.sources[0].ID {
			t.Fatal("public generation did not persist sealed source requirements", err)
		}
		due := time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Second)
		status, body = reportProofJSON(t, socket, proof.token, http.MethodPost, "/v1/dashboard-report-schedules", reportScheduleCreateRequest{DashboardID: views[i].ID, Name: "Source delivery", Format: proof.format, Cadence: "daily", DestinationID: reportInboxDestination, FirstRunAt: due})
		if status != http.StatusCreated {
			t.Fatal("public source schedule creation failed", status, string(body))
		}
		var schedule store.ReportSchedule
		if err := json.Unmarshal(body, &schedule); err != nil {
			t.Fatal(err)
		}
		supervisor, ok := BuildDashboardReportSupervisor(f.srv.pool, time.Minute, nil)
		if !ok {
			t.Fatal("source scheduler builder unavailable")
		}
		supervisor.WithReportSources(f.srv)
		if err := supervisor.materializeTenantReports(ctx, proof.tenant, due.Add(time.Second)); err != nil {
			t.Fatal("current owner source schedule failed", err)
		}
		if err := supervisor.materializeTenantReports(ctx, proof.tenant, due.Add(time.Second)); err != nil {
			t.Fatal("delivered source schedule did not remain idempotent", err)
		}
		var deliveries int
		var last *time.Time
		if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT last_run_at FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, proof.tenant, schedule.ID).Scan(&last); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2 AND body_storage='chunks' AND content IS NULL`, proof.tenant, schedule.ID).Scan(&deliveries)
		}); err != nil {
			t.Fatal(err)
		}
		if last == nil || deliveries != 1 {
			t.Fatal("source schedule did not atomically advance exactly once", deliveries, last)
		}
		if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, proof.tenant, proof.role, permFlowRead)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		deniedDelivery := supervisor.materializeTenantReports(ctx, proof.tenant, due.Add(25*time.Hour))
		if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, proof.role, permFlowRead)
		}); err != nil {
			t.Fatal("restore source owner fixture", err)
		}
		if deniedDelivery == nil {
			t.Fatal("scheduled source delivery retained revoked owner authority")
		}
		var after int
		var lastAfter *time.Time
		if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT last_run_at FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, proof.tenant, schedule.ID).Scan(&lastAfter); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2`, proof.tenant, schedule.ID).Scan(&after)
		}); err != nil {
			t.Fatal(err)
		}
		if after != 1 || lastAfter == nil || !lastAfter.Equal(*last) {
			t.Fatal("refused source delivery committed partial advancement or bytes")
		}
	}
	status, _ := reportProofJSON(t, socket, proofs[0].token, http.MethodPost, "/v1/dashboard-reports", reportGenerateRequest{DashboardID: views[1].ID, Format: "csv"})
	if status != http.StatusNotFound {
		t.Fatal("public source generation crossed the actual token tenant", status)
	}
	for _, kind := range []string{"lifecycle", "version"} {
		proveSourcePublicationRace(t, f, socket, proofs[0], views[0], application, kind)
	}
	proveSourceReportNativeBindings(t, f, socket, proofs, views)
}

// Hold the real final publication lock until the public generator has staged
// actual source rows and is waiting. Change only persisted source state, then
// release it; no product-only renderer hook or hand-supplied table is involved.
func proveSourcePublicationRace(t *testing.T, f *tagImportSubjectFixture, socket *httptest.Server, proof *reportDownloadProof, view store.DashboardView, application, kind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	type outcome struct {
		status int
		err    error
	}
	results := make(chan outcome, 1)
	var before int
	count := func() int {
		t.Helper()
		var n int
		if err := f.db.Pool().QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND dashboard_id=$2`, proof.tenant, view.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before = count()
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(proof.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, proof.tenant); err != nil {
			return err
		}
		input, err := json.Marshal(reportGenerateRequest{DashboardID: view.ID, Format: proof.format})
		if err != nil {
			return err
		}
		go func() {
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, socket.URL+"/v1/dashboard-reports", bytes.NewReader(input))
			if err != nil {
				results <- outcome{err: err}
				return
			}
			request.Header.Set("Authorization", "Bearer "+proof.token)
			request.Header.Set("Content-Type", "application/json")
			response, err := socket.Client().Do(request)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			defer response.Body.Close()
			_, err = io.Copy(io.Discard, response.Body)
			results <- outcome{status: response.StatusCode, err: err}
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var waiting bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name=$1 AND l.locktype='advisory' AND NOT l.granted)`, application).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case result := <-results:
				return fmt.Errorf("source generation completed before final lock: status=%d err=%v", result.status, result.err)
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
		if kind == "lifecycle" {
			return flowsnapshot.InvalidateSourceGenerationInScope(ctx, sc)
		}
		_, err = sc.Q.Exec(ctx, `UPDATE flow_query_views SET version=version+1 WHERE tenant_id=$1 AND id=$2::uuid`, proof.tenant, proof.sources[0].ID)
		return err
	})
	if err != nil {
		t.Fatal("coordinate real source publication race", err)
	}
	result := <-results
	// Restore fixture state before asserting so a failed omission control can
	// still close every source admission/owned connection and preserve siblings.
	if kind == "lifecycle" {
		lifecycle := flowsnapshot.NewLifecycle(f.db.Pool(), nil, tenancy.NewPostgresWriterFence(f.db.Pool()))
		if err := lifecycle.Invalidate(ctx, proof.tenant, func(context.Context) error { return nil }); err != nil {
			t.Fatal("complete owned source invalidation", err)
		}
	} else {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(proof.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE flow_query_views SET version=version-1 WHERE tenant_id=$1 AND id=$2::uuid`, proof.tenant, proof.sources[0].ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if result.err != nil {
		t.Fatal("read real generation refusal", result.err)
	}
	if result.status != http.StatusConflict || count() != before {
		if kind == "lifecycle" {
			t.Fatal("invalidated source capture published through the public report route", result.status)
		}
		t.Fatal("changed source version published through the public report route", result.status)
	}
}
