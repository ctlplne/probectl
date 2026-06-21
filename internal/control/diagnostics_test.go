// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// okPinger / downPinger drive the deep-health database check.
type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

type downPinger struct{ err error }

func (d downPinger) Ping(context.Context) error { return d.err }

// TestDeepHealthEndpoint: /v1/diagnostics aggregates component health (the
// database check follows the pinger).
func TestDeepHealthEndpoint(t *testing.T) {
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
	if h.Status != support.StatusOK {
		t.Fatalf("healthy db must aggregate ok: %+v", h)
	}

	// A down database drives the aggregate down.
	srv = testServer(downPinger{err: context.DeadlineExceeded})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil))
	_ = json.Unmarshal(rr.Body.Bytes(), &h)
	if h.Status != support.StatusDown {
		t.Fatalf("down db must aggregate down: %+v", h)
	}
	var dbDown bool
	for _, c := range h.Checks {
		if c.Name == "database" && c.Status == support.StatusDown {
			dbDown = true
		}
	}
	if !dbDown {
		t.Fatalf("the database check must report down: %+v", h.Checks)
	}
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
