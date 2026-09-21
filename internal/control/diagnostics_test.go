// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/support"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/version"
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

// TestSupportBundleRedactsDatabaseQueryCredentials proves the bundle endpoint
// strips every configured secret, including both PostgreSQL DSN query forms.
func TestSupportBundleRedactsDatabaseQueryCredentials(t *testing.T) {
	const envKey = "c2VjcmV0LWVudmVsb3BlLWtleS1tYXRlcmlhbC0zMmJ5dGVz"
	const bootstrap = "prov_bootstrap_TOPSECRET_9988"
	const writerQueryPassword = "writer_query_password_7654"
	const writerSSLPassword = "writer_ssl_password_7654"
	const readerQueryPassword = "reader_query_password_7654"
	const readerSSLPassword = "reader_ssl_password_7654"
	cfg := &config.Config{
		HTTPAddr:               ":0",
		AuthMode:               "dev",
		DatabaseURL:            "postgres://probectl:dbpasshere@db:5432/probectl?sslmode=require&password=" + writerQueryPassword + "&sslpassword=" + writerSSLPassword + "&application_name=control",
		DatabaseReadURL:        "postgres://reader@read-db:5432/probectl?sslmode=verify-full&password=" + readerQueryPassword + "&sslpassword=" + readerSSLPassword + "&application_name=read-replica",
		EnvelopeKey:            envKey,
		ProviderBootstrapToken: bootstrap,
		Region:                 "us-east",
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil)
	knownSecrets := strings.Join(srv.knownSecrets(), "\n")
	for _, secret := range []string{writerQueryPassword, writerSSLPassword, readerQueryPassword, readerSSLPassword} {
		if !strings.Contains(knownSecrets, secret) {
			t.Fatalf("database query credential missing from defense-in-depth scrub list")
		}
	}

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
	for _, secret := range []string{
		envKey, bootstrap, "dbpasshere",
		writerQueryPassword, writerSSLPassword, readerQueryPassword, readerSSLPassword,
	} {
		if bytes.Contains(all.Bytes(), []byte(secret)) {
			t.Fatalf("SECRET LEAKED into the support bundle: %q", secret)
		}
	}
	// The DSN survives, password-redacted; the envelope key is only a boolean.
	var cfgMap map[string]any
	_ = json.Unmarshal(files["config-redacted.json"], &cfgMap)
	if dsn, _ := cfgMap["database_url"].(string); !strings.Contains(dsn, "xxxxx") {
		t.Fatalf("DSN not redacted: %q", dsn)
	} else if !strings.Contains(dsn, "sslmode=require") || !strings.Contains(dsn, "application_name=control") {
		t.Fatalf("writer DSN lost non-secret metadata: %q", dsn)
	}
	if dsn, _ := cfgMap["database_read_url"].(string); !strings.Contains(dsn, "xxxxx") {
		t.Fatalf("reader DSN not redacted: %q", dsn)
	} else if !strings.Contains(dsn, "sslmode=verify-full") || !strings.Contains(dsn, "application_name=read-replica") {
		t.Fatalf("reader DSN lost non-secret metadata: %q", dsn)
	}
	if cfgMap["envelope_key_configured"] != true {
		t.Fatalf("envelope key must surface as a boolean: %v", cfgMap["envelope_key_configured"])
	}
}

func TestSupportBundleAnonymizesDeviceCollectionReceipts(t *testing.T) {
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "dev"}
	outcomes := device.NewMemoryCollectionOutcomeStore()
	now := time.Now().UTC().Truncate(time.Second)
	tenant := tenancy.DefaultTenantID.String()
	if err := outcomes.UpsertCollectionOutcome(context.Background(), tenant, device.CollectionOutcome{
		TenantID: tenant, AgentID: "agent-secret-name",
		ConfiguredTarget: "router-secret.internal", Protocol: device.NeighborProtocolLLDP,
		LastAttemptAt: &now, State: device.CollectionStateFailed,
		Reason:     device.CollectionReasonPollFailed,
		NextAction: device.CollectionActionVerifyLocalAccess,
	}); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil).
		WithDeviceCollectionOutcomes(outcomes)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/bundle", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	files, err := support.ReadBundle(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw := files["device-collection.json"]
	for _, forbidden := range []string{"agent-secret-name", "router-secret.internal", tenant} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("raw device identifier leaked into support receipt: %q in %s", forbidden, raw)
		}
	}
	for _, want := range []string{`"agent_ref": "agent-0001"`, `"target_ref": "target-0001"`, `"state": "failed"`, `"reason": "poll_failed"`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("support receipt missing %s: %s", want, raw)
		}
	}
}

func TestSupportBundleAnonymizesFlowQualityReceipts(t *testing.T) {
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "dev"}
	receipts := flow.NewMemoryQualityStore()
	now := time.Now().UTC().Truncate(time.Second)
	last := now.Add(-time.Second)
	tenant := tenancy.DefaultTenantID.String()
	receipt := flow.EvaluateQualityState(flow.QualityReceipt{
		TenantID: tenant, AgentID: "flow-agent-secret-name",
		ExporterAddress: "2001:db8:feed::44", Protocol: flow.ProtoIPFIX,
		WindowStartedAt: now.Add(-time.Minute), WindowEndedAt: now,
		LastPacketAt: last, LastValidRecordAt: &last,
		PacketsReceived: 12, RecordsDecoded: 48,
		TemplateState: flow.QualityTemplateReady,
		SamplingState: flow.QualitySamplingSampled,
	}, now)
	if err := receipts.UpsertQualityReceipt(context.Background(), tenant, receipt); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil).
		WithFlowQualityReceipts(receipts)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/bundle", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	files, err := support.ReadBundle(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw := files["flow-ingest-quality.json"]
	for _, forbidden := range []string{
		"flow-agent-secret-name", "2001:db8:feed::44", tenant,
		"raw_datagram", "src_addr", "dst_addr", "credential", "error_message",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("raw flow identifier or forbidden field leaked into support receipt: %q in %s", forbidden, raw)
		}
	}
	for _, want := range []string{
		`"agent_ref": "agent-0001"`,
		`"exporter_ref": "exporter-0001"`,
		`"state": "healthy"`,
		`"reason": "receiving_valid_records"`,
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("support receipt missing %s: %s", want, raw)
		}
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

type topologyFixtureRow struct {
	value any
	err   error
}

func (r topologyFixtureRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return fmt.Errorf("topology fixture: got %d scan destinations, want 1", len(dest))
	}
	switch out := dest[0].(type) {
	case *int:
		value, ok := r.value.(int)
		if !ok {
			return fmt.Errorf("topology fixture: cannot scan %T into *int", r.value)
		}
		*out = value
	case *string:
		value, ok := r.value.(string)
		if !ok {
			return fmt.Errorf("topology fixture: cannot scan %T into *string", r.value)
		}
		*out = value
	default:
		return fmt.Errorf("topology fixture: unsupported scan destination %T", dest[0])
	}
	return nil
}

type topologyFixtureQuerier struct {
	tenant string
	agents int
	model  string
}

func (q topologyFixtureQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("topology fixture: unexpected Exec")
}

func (q topologyFixtureQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("topology fixture: unexpected Query")
}

func (q topologyFixtureQuerier) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	if len(args) != 1 || args[0] != q.tenant {
		return topologyFixtureRow{err: fmt.Errorf("topology query was not explicitly scoped to %q: args=%v", q.tenant, args)}
	}
	if !strings.Contains(query, "WHERE tenant_id = $1") {
		return topologyFixtureRow{err: errors.New("topology query omitted the tenant predicate")}
	}
	switch {
	case strings.Contains(query, "probectl_current_tenant_topology"):
		return topologyFixtureRow{value: q.model}
	case strings.Contains(query, "FROM agents"):
		return topologyFixtureRow{value: q.agents}
	default:
		return topologyFixtureRow{err: fmt.Errorf("topology fixture: unexpected query %q", query)}
	}
}

func TestSupportBundleTopologyTwoTenantIsolation(t *testing.T) {
	for _, tc := range []struct {
		tenant string
		agents int
		model  string
	}{
		{tenant: "00000000-0000-0000-0000-0000000000aa", agents: 1, model: "pooled"},
		{tenant: "00000000-0000-0000-0000-0000000000bb", agents: 3, model: "hybrid"},
	} {
		t.Run(tc.model, func(t *testing.T) {
			sum := topologySummaryFromTenant(
				context.Background(),
				support.TopologySummary{IsolationModels: map[string]int{}},
				func(ctx context.Context, fn func(context.Context, tenancy.Scope) error) error {
					return fn(ctx, tenancy.Scope{
						Tenant: tenancy.ID(tc.tenant),
						Q: topologyFixtureQuerier{
							tenant: tc.tenant,
							agents: tc.agents,
							model:  tc.model,
						},
					})
				},
			)
			if sum.Partial || sum.Tenants != 1 || sum.Agents != tc.agents {
				t.Fatalf("tenant topology summary = %+v, want one tenant and %d agents", sum, tc.agents)
			}
			if len(sum.IsolationModels) != 1 || sum.IsolationModels[tc.model] != 1 {
				t.Fatalf("tenant isolation models = %#v, want only %q=1", sum.IsolationModels, tc.model)
			}
		})
	}
}

func TestTopologySummaryReportsPartialTenantErrors(t *testing.T) {
	sum := support.TopologySummary{Region: "us-east", IsolationModels: map[string]int{}}
	sum = topologySummaryFromTenant(context.Background(), sum, func(ctx context.Context, fn func(context.Context, tenancy.Scope) error) error {
		return fn(ctx, tenancy.Scope{
			Tenant: "00000000-0000-0000-0000-0000000000aa",
			Q:      errTopologyQuerier{err: errors.New("metadata store unavailable")},
		})
	})
	if !sum.Partial || len(sum.Errors) < 2 {
		t.Fatalf("tenant query failures must be explicit partial errors: %+v", sum)
	}
	if sum.Region != "us-east" {
		t.Fatalf("region should remain available in partial summary: %+v", sum)
	}

	sum = topologySummaryFromTenant(context.Background(), support.TopologySummary{IsolationModels: map[string]int{}}, func(context.Context, func(context.Context, tenancy.Scope) error) error {
		return errors.New("tenant role unavailable")
	})
	if !sum.Partial || len(sum.Errors) != 1 {
		t.Fatalf("tenant-scope failure must be explicit partial metadata: %+v", sum)
	}
}

func TestDiagnosticsBundleRedactsDependencyErrors(t *testing.T) {
	const rawDependencyError = "dial tcp topology-db.internal:5432 password=not-a-config-secret schema=tenant_alpha"

	sum := topologySummaryFromTenant(
		context.Background(),
		support.TopologySummary{IsolationModels: map[string]int{}},
		func(ctx context.Context, fn func(context.Context, tenancy.Scope) error) error {
			return fn(ctx, tenancy.Scope{
				Tenant: "00000000-0000-0000-0000-0000000000aa",
				Q:      errTopologyQuerier{err: errors.New(rawDependencyError)},
			})
		},
	)

	var archive bytes.Buffer
	if _, err := support.Generate(&archive, support.Sources{Topology: sum}); err != nil {
		t.Fatal(err)
	}
	files, err := support.ReadBundle(&archive)
	if err != nil {
		t.Fatal(err)
	}
	topology := files["topology-summary.json"]
	for _, sentinel := range []string{"topology-db.internal", "not-a-config-secret", "tenant_alpha", rawDependencyError} {
		if bytes.Contains(topology, []byte(sentinel)) {
			t.Fatalf("free-form dependency error leaked into topology-summary.json: %q in %s", sentinel, topology)
		}
	}
	var got support.TopologySummary
	if err := json.Unmarshal(topology, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Partial || len(got.Errors) != 2 {
		t.Fatalf("safe partial/error-count metadata was not preserved: %+v", got)
	}
	if got.Errors[0] != string(topologyErrorTenantTopology) || got.Errors[1] != string(topologyErrorAgentsCount) {
		t.Fatalf("bundle error classes are not the stable allowlist: %+v", got.Errors)
	}
}
