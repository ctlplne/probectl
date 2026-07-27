// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// okPinger / downPinger drive the deep-health database check.
type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

type downPinger struct{ err error }

func (d downPinger) Ping(context.Context) error { return d.err }

// TestDeepHealthEndpoint: /v1/diagnostics aggregates component health (the
// database check follows the pinger).
func TestDeepHealthEndpoint(t *testing.T) {
	srv := testServer(okPinger{}).WithAlertingActive(true)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var report diagnosticsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	h := report.Health
	if h.Status != support.StatusOK {
		t.Fatalf("healthy db must aggregate ok: %+v", h)
	}
	if report.SelfMetrics.Goroutines < 1 ||
		report.SelfMetrics.MemAllocBytes == 0 ||
		report.SelfMetrics.MemSysBytes == 0 ||
		report.SelfMetrics.MaxProcs < 1 {
		t.Fatalf("native self-observability snapshot is incomplete: %+v", report.SelfMetrics)
	}
	if report.SelfMetrics.UptimeSeconds < 0 {
		t.Fatalf("native uptime must be non-negative: %+v", report.SelfMetrics)
	}
	if report.Build != version.Get() {
		t.Fatalf("build identity = %+v, want %+v", report.Build, version.Get())
	}
	if strings.Contains(rr.Body.String(), "tenant_id") {
		t.Fatalf("deployment-global diagnostics must not carry tenant identity: %s", rr.Body.String())
	}
	var diagnosticsPermission string
	for _, route := range srv.apiRoutes() {
		if route.Method == http.MethodGet && route.Pattern == "/v1/diagnostics" {
			diagnosticsPermission = route.Permission
		}
	}
	if diagnosticsPermission != permDiagnosticsRead {
		t.Fatalf("diagnostics permission = %q, want %q", diagnosticsPermission, permDiagnosticsRead)
	}

	// A down database drives the aggregate down.
	const rawDatabaseError = "dial postgres://operator:super-secret@private-db/probectl: deadline exceeded"
	srv = testServer(downPinger{err: errors.New(rawDatabaseError)}).WithAlertingActive(true)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil))
	report = diagnosticsResponse{}
	_ = json.Unmarshal(rr.Body.Bytes(), &report)
	h = report.Health
	if h.Status != support.StatusDown {
		t.Fatalf("down db must aggregate down: %+v", h)
	}
	var dbDown bool
	for _, c := range h.Checks {
		if c.Name == "database" && c.Status == support.StatusDown {
			dbDown = true
			if c.Finding == nil ||
				c.Finding.ID != "readiness.database" ||
				c.Finding.Severity != support.FindingCritical ||
				c.Finding.ObservedAt != h.CheckedAt ||
				c.Finding.NextAction.Href != "/v1/diagnostics/bundle" ||
				c.Finding.NextAction.Kind != support.ActionDownload {
				t.Fatalf("database finding is not stable and locally actionable: %+v", c)
			}
		}
	}
	if !dbDown {
		t.Fatalf("the database check must report down: %+v", h.Checks)
	}
	if strings.Contains(rr.Body.String(), rawDatabaseError) || strings.Contains(rr.Body.String(), "super-secret") {
		t.Fatalf("raw database error leaked into diagnostics: %s", rr.Body.String())
	}
}

func TestDeepHealthReportsAlertingInactive(t *testing.T) {
	srv := testServer(okPinger{})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var h support.Health
	if err := json.Unmarshal(rr.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != support.StatusDegraded {
		t.Fatalf("inactive evaluator must degrade diagnostics: %+v", h)
	}
	for _, check := range h.Checks {
		if check.Name == "alert_evaluator" {
			if check.Status != support.StatusDegraded || !strings.Contains(check.Detail, "not evaluated") || !strings.Contains(check.Detail, "docs/alerting.md") {
				t.Fatalf("alert evaluator check lacks actionable detail: %+v", check)
			}
			if check.Finding == nil ||
				check.Finding.ID != "readiness.alert_evaluator" ||
				check.Finding.NextAction.Href != "/alerts" ||
				check.Finding.NextAction.Kind != support.ActionNavigate {
				t.Fatalf("alert evaluator lacks a safe local finding: %+v", check)
			}
			return
		}
	}
	t.Fatalf("diagnostics omitted alert_evaluator check: %+v", h.Checks)
}

// TestSupportBundleEndpointNoSecrets: the bundle endpoint streams a tar.gz of
// the right diagnostics, and the configured secrets never appear in it.
func TestSupportBundleEndpointNoSecrets(t *testing.T) {
	const envKey = "c2VjcmV0LWVudmVsb3BlLWtleS1tYXRlcmlhbC0zMmJ5dGVz"
	const bootstrap = "prov_bootstrap_TOPSECRET_9988"
	cfg := &config.Config{
		HTTPAddr:               ":0",
		AuthMode:               "dev",
		DatabaseURL:            "postgres://probectl:dbpasshere@db:5432/probectl?sslmode=disable",
		EnvelopeKey:            envKey,
		ProviderBootstrapToken: bootstrap,
		Region:                 "us-east",
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/bundle", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("content type: %q", ct)
	}

	files, err := support.ReadBundle(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"manifest.json", "config-redacted.json", "health.json", "topology-summary.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s", want)
		}
	}
	all := bytes.Buffer{}
	for _, b := range files {
		all.Write(b)
	}
	for _, secret := range []string{envKey, bootstrap, "dbpasshere"} {
		if bytes.Contains(all.Bytes(), []byte(secret)) {
			t.Fatalf("SECRET LEAKED into the support bundle: %q", secret)
		}
	}
	// The DSN survives, password-redacted; the envelope key is only a boolean.
	var cfgMap map[string]any
	_ = json.Unmarshal(files["config-redacted.json"], &cfgMap)
	if dsn, _ := cfgMap["database_url"].(string); !bytes.Contains([]byte(dsn), []byte("xxxxx")) {
		t.Fatalf("DSN not redacted: %q", dsn)
	}
	if cfgMap["envelope_key_configured"] != true {
		t.Fatalf("envelope key must surface as a boolean: %v", cfgMap["envelope_key_configured"])
	}
}

type errTopologyRow struct{ err error }

func (r errTopologyRow) Scan(...any) error { return r.err }

type errTopologyQuerier struct{ err error }

func (q errTopologyQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, q.err
}

func (q errTopologyQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, q.err
}

func (q errTopologyQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return errTopologyRow(q)
}

func TestTopologySummaryReportsPartialProviderErrors(t *testing.T) {
	sum := support.TopologySummary{Region: "us-east", IsolationModels: map[string]int{}}
	sum = topologySummaryFromProvider(context.Background(), sum, func(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
		return fn(ctx, errTopologyQuerier{err: errors.New("metadata store unavailable")})
	})
	if !sum.Partial || len(sum.Errors) < 3 {
		t.Fatalf("provider query failures must be explicit partial errors: %+v", sum)
	}
	if sum.Region != "us-east" {
		t.Fatalf("region should remain available in partial summary: %+v", sum)
	}

	sum = topologySummaryFromProvider(context.Background(), support.TopologySummary{IsolationModels: map[string]int{}}, func(context.Context, func(context.Context, tenancy.Querier) error) error {
		return errors.New("provider role unavailable")
	})
	if !sum.Partial || len(sum.Errors) != 1 {
		t.Fatalf("provider-scope failure must be explicit partial metadata: %+v", sum)
	}
}
