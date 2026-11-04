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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type reportDownloadProof struct {
	tenant, user, role, token, scopedToken, foreignID, digest string
	format, media                                             string
	expected                                                  []byte
}

// This consumes the actual flow capture already proven by the required source
// fixture. Only report configuration and credentials are seeded; HTTPS, route
// authorization, source visibility, RLS, byte storage and audit use real doors.
func publishCapturedReportDownloadProof(ctx context.Context, t *testing.T, f *tagImportSubjectFixture, actor *auth.Principal, role string, capture *reportFlowCapture, format string) *reportDownloadProof {
	t.Helper()
	proof := &reportDownloadProof{tenant: actor.TenantID, user: actor.UserID, role: role, foreignID: "foreign-only-" + actor.TenantID, format: format, media: "text/csv"}
	if format == "pdf" {
		proof.media = "application/pdf"
	}
	raw, err := marshalReportSourceRequirements(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	from, to := capture.Inputs[0].From, capture.Inputs[0].To
	for _, input := range capture.Inputs {
		if input.Period == "current" {
			if input.From.Before(from) {
				from = input.From
			}
			if input.To.After(to) {
				to = input.To
			}
		}
	}
	document := reporting.Document{Title: "Captured report", TenantName: "Report tenant " + actor.TenantID, TenantScope: actor.TenantID,
		Preset: "operator", AbsoluteFrom: from, AbsoluteTo: to, GeneratedAt: time.Now().UTC(), GeneratedBy: actor.UserID,
		Provenance: []string{"current owned saved flow capture"}, RedactionState: "query redaction applied",
		CoverageLimitations: []string{"source/store/HTTPS component; release acceptance is separate"}, Tables: capture.Tables}
	stage, receipt, err := reporting.StageBody(ctx, actor.TenantID, reporting.DefaultBodyStageLimits(), func(w io.Writer) error {
		if format == "pdf" {
			_, err := reporting.WritePDF(ctx, w, document, reporting.DefaultPDFLimits())
			return err
		}
		_, err := reporting.WriteCSV(ctx, w, document, reporting.DefaultCSVLimits())
		return err
	})
	if err != nil {
		t.Fatal("stage actual captured report", err)
	}
	defer stage.Close()
	reader, err := stage.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof.expected, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	proof.digest = receipt.SHA256
	if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.Roles{}).AddPermission(ctx, sc, role, "metrics.read"); err != nil {
			return err
		}
		if _, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "same-source-view", OwnerID: actor.UserID, Name: "Source download", Preset: "operator", Shared: true, Definition: []byte(`{}`)}); err != nil {
			return err
		}
		for _, id := range []string{"same-source-artifact", proof.foreignID} {
			if _, err := (store.DashboardReports{}).CreateChunkedArtifact(ctx, sc, store.ReportArtifactInput{
				ID: id, DashboardID: "same-source-view", Format: format, MediaType: proof.media, Filename: "captured." + format, GeneratedBy: actor.UserID,
				AbsoluteFrom: from, AbsoluteTo: to, Provenance: document.Provenance, RedactionState: document.RedactionState, CoverageLimitations: document.CoverageLimitations,
			}, stage, raw); err != nil {
				return err
			}
			if _, err := audit.TenantAppend(ctx, sc, actor.UserID, "dashboard.report_export", id, map[string]any{"format": format}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal("publish actual captured report", err)
	}
	for _, credential := range []struct {
		target *string
		scopes []string
	}{{&proof.token, nil}, {&proof.scopedToken, []string{"metrics.read", permAIQuery}}} {
		value, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		*credential.target = value
		if _, err := store.NewMCPTokens(f.db.Pool()).CreateWithLifetime(ctx, actor.TenantID, actor.UserID, "report-reader", crypto.Hash([]byte(value)), time.Now().Add(time.Hour), credential.scopes); err != nil {
			t.Fatal(err)
		}
	}
	return proof
}

func reportProofRoute(id string) string {
	if id == "" {
		return "/v1/dashboard-report-artifacts"
	}
	return "/v1/dashboard-report-artifacts/" + id
}

func requestCapturedReport(t *testing.T, socket *httptest.Server, token, id string) (int, http.Header, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+reportProofRoute(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := socket.Client()
	client.Timeout = 30 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("HTTPS report request failed", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("HTTPS report body incomplete", err)
	}
	return response.StatusCode, response.Header.Clone(), body
}

func (proof *reportDownloadProof) requireOwn(t *testing.T, socket *httptest.Server) {
	t.Helper()
	status, headers, body := requestCapturedReport(t, socket, proof.token, "same-source-artifact")
	if status != http.StatusOK || !bytes.Equal(body, proof.expected) || headers.Get("Content-Length") != strconv.Itoa(len(proof.expected)) || headers.Get("X-Report-SHA256") != proof.digest || headers.Get("Cache-Control") != "no-store" || headers.Get("Content-Type") != proof.media {
		t.Fatal("owned source report download lost complete bytes, integrity headers or current authorization", status, len(body), len(proof.expected))
	}
}

func proveCapturedReportHTTPReaders(t *testing.T, f *tagImportSubjectFixture, proofs []*reportDownloadProof) {
	t.Helper()
	// Force the real token resolver; this fixture must not use dev principals.
	f.srv.cfg.AuthMode = ""
	originalPool := f.srv.pool
	configuration := originalPool.Config().Copy()
	configuration.MaxConns, configuration.MinConns = 1, 0
	application := "probectl-qa-beta-report-" + f.a
	parameters := make(map[string]string, len(configuration.ConnConfig.RuntimeParams)+1)
	for key, value := range configuration.ConnConfig.RuntimeParams {
		parameters[key] = value
	}
	parameters["application_name"] = application
	configuration.ConnConfig.RuntimeParams = parameters
	single, err := pgxpool.NewWithConfig(t.Context(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.pool = single
	socket := httptest.NewTLSServer(f.srv.Handler())
	// Close the listener and wait for handlers before restoring this pointer.
	defer func() { socket.Close(); f.srv.pool = originalPool; single.Close() }()
	for i, proof := range proofs {
		proof.requireOwn(t, socket)
		proveCurrentReportMetadataList(t, socket, proof)
		status, _, body := requestCapturedReport(t, socket, proof.scopedToken, "same-source-artifact")
		if status != http.StatusNotFound || bytes.Contains(body, proof.expected) {
			t.Fatal("scoped credential borrowed a report source grant", status)
		}
		status, _, body = requestCapturedReport(t, socket, proof.token, proofs[1-i].foreignID)
		if status != http.StatusNotFound || bytes.Contains(body, proofs[1-i].expected) {
			t.Fatal("foreign report artifact or its bytes escaped the actual token tenant", status)
		}
	}
	// Corrupt a real persisted chunk, preserving length. A complete HTTP body
	// must not start, even though its source authorization is otherwise valid.
	first := proofs[0]
	proveReportRevocationAfterVerification(t, f, socket, first, application)
	var originalRequirements []byte
	if err := f.db.Pool().QueryRow(t.Context(), `SELECT source_capture FROM dashboard_report_artifacts WHERE tenant_id=$1 AND id='same-source-artifact'`, first.tenant).Scan(&originalRequirements); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE dashboard_report_artifacts SET source_capture=jsonb_build_object('version',1,'tenant_id',tenant_id::text) WHERE tenant_id=$1 AND id='same-source-artifact'`, first.tenant); err != nil {
		t.Fatal(err)
	}
	denied, deniedHeaders, deniedBody := requestCapturedReport(t, socket, first.scopedToken, "same-source-artifact")
	missingStatus, _, missingBody := requestCapturedReport(t, socket, first.scopedToken, "missing-source-artifact")
	deniedRecord, missingRecord := httptest.NewRecorder(), httptest.NewRecorder()
	_, _ = deniedRecord.Body.Write(deniedBody)
	_, _ = missingRecord.Body.Write(missingBody)
	if denied != http.StatusNotFound || missingStatus != http.StatusNotFound || dashboardErrorShape(t, deniedRecord) != dashboardErrorShape(t, missingRecord) || deniedHeaders.Get("X-Report-SHA256") != "" || bytes.Contains(deniedBody, first.expected) {
		t.Fatal("unverifiable report source exposed existence before source authorization", denied)
	}
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE dashboard_report_artifacts SET source_capture=$2::jsonb WHERE tenant_id=$1 AND id='same-source-artifact'`, first.tenant, originalRequirements); err != nil {
		t.Fatal(err)
	}
	first.requireOwn(t, socket)
	var original []byte
	if err := f.db.Pool().QueryRow(t.Context(), `SELECT content FROM dashboard_report_artifact_chunks WHERE tenant_id=$1 AND artifact_id='same-source-artifact' AND ordinal=0`, first.tenant).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corrupted := bytes.Clone(original)
	corrupted[0] ^= 0xff
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE dashboard_report_artifact_chunks SET content=$2 WHERE tenant_id=$1 AND artifact_id='same-source-artifact' AND ordinal=0`, first.tenant, corrupted); err != nil {
		t.Fatal(err)
	}
	status, headers, body := requestCapturedReport(t, socket, first.token, "same-source-artifact")
	if status == http.StatusOK || headers.Get("X-Report-SHA256") != "" || bytes.Contains(body, first.expected) {
		t.Fatal("corrupt report started a public body", status)
	}
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE dashboard_report_artifact_chunks SET content=$2 WHERE tenant_id=$1 AND artifact_id='same-source-artifact' AND ordinal=0`, first.tenant, original); err != nil {
		t.Fatal(err)
	}
	first.requireOwn(t, socket)
	proofs[1].requireOwn(t, socket)
	// Real current role revocation must defeat an already issued broad token.
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(first.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, first.tenant, first.role, permFlowRead)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, _, body = requestCapturedReport(t, socket, first.token, "same-source-artifact")
	if status == http.StatusOK || bytes.Contains(body, first.expected) {
		t.Fatal("revoked current source role retained a public report body", status)
	}

	listed := readReportMetadataList(t, socket, first.token)
	if len(listed) != 0 {
		t.Fatal("revoked current source role retained report metadata")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(first.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, first.role, permFlowRead)
	}); err != nil {
		t.Fatal(err)
	}
	first.requireOwn(t, socket)
	proofs[1].requireOwn(t, socket)
}

// Hold the actual audit lock, then revoke after the HTTPS reader is waiting
// at its final transaction. The omission control removes only that final
// source recheck; an early/authentication failure cannot satisfy its marker.
func proveReportRevocationAfterVerification(t *testing.T, f *tagImportSubjectFixture, socket *httptest.Server, proof *reportDownloadProof, application string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	blocker, err := f.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if err := audit.LockTenantStream(ctx, blocker, proof.tenant); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		status int
		body   []byte
		err    error
	}
	results := make(chan outcome, 1)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, socket.URL+"/v1/dashboard-report-artifacts/same-source-artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+proof.token)
	client := socket.Client()
	client.Timeout = 30 * time.Second
	go func() {
		response, err := client.Do(request)
		if err != nil {
			results <- outcome{err: err}
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		results <- outcome{status: response.StatusCode, body: body, err: err}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	waiting := false
	for !waiting {
		if err := f.db.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name=$1 AND l.locktype='advisory' AND NOT l.granted)`, application).Scan(&waiting); err != nil {
			t.Fatal("observe final report lock", err)
		}
		if waiting {
			break
		}
		select {
		case result := <-results:
			t.Fatal("report completed before its held final audit lock", result.status, result.err)
		case <-ctx.Done():
			t.Fatal("report never reached its final audit lock", ctx.Err())
		case <-ticker.C:
		}
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(proof.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, proof.tenant, proof.role, permFlowRead)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(proof.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, proof.role, permFlowRead)
		}); err != nil {
			t.Fatal("restore current role fixture", err)
		}
	}
	defer func() {
		if !restored {
			restore()
		}
	}()
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatal("post-verification report response failed transport", result.err)
		}
		if result.status == http.StatusOK || bytes.Contains(result.body, proof.expected) {
			t.Fatal("revoked source reader received a report body after verification", result.status)
		}
	case <-ctx.Done():
		t.Fatal("revoked reader never completed", ctx.Err())
	}
	restore()
	restored = true
	proof.requireOwn(t, socket)
}

func readReportMetadataList(t *testing.T, socket *httptest.Server, token string) []reportArtifactView {
	t.Helper()
	status, _, raw := requestCapturedReport(t, socket, token, "")
	if status != http.StatusOK {
		t.Fatal("report metadata list failed", status)
	}
	for _, forbidden := range []string{`"source_capture"`, `"content"`, `"inputs"`, `"permissions"`, `"contexts"`} {
		if bytes.Contains(bytes.ToLower(raw), []byte(forbidden)) {
			t.Fatal("metadata list loaded a body or exposed source requirements")
		}
	}
	var result struct {
		Items []reportArtifactView `json:"items"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result.Items
}

func proveCurrentReportMetadataList(t *testing.T, socket *httptest.Server, proof *reportDownloadProof) {
	t.Helper()
	listed := readReportMetadataList(t, socket, proof.token)
	if len(listed) != 2 {
		t.Fatal("owned current report metadata is missing", len(listed))
	}
	ids := map[string]bool{}
	for _, item := range listed {
		ids[item.ID] = true
		if item.BodyBytes != int64(len(proof.expected)) || item.BodySHA256 != proof.digest || item.Format != proof.format || item.GeneratedBy != proof.user {
			t.Fatal("metadata lost stored body integrity or tenant owner")
		}
	}
	if !ids["same-source-artifact"] || !ids[proof.foreignID] {
		t.Fatal("metadata returned another tenant's artifact ids")
	}
	if listed := readReportMetadataList(t, socket, proof.scopedToken); len(listed) != 0 {
		t.Fatal("scoped credential listed private source report metadata")
	}
}
