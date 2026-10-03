// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/support"
)

// PLAT-09: /readyz and /v1/diagnostics used to probe only Postgres, so an outage
// of the result bus, the TSDB, the ClickHouse event store or the object store —
// and running in a volatile memory backend — was invisible (both reported
// healthy). These tests pin the two shapes the fix adds:
//
//  1. a configured EXTERNAL backend that fails its reachability probe drives the
//     diagnostics aggregate down and names the subsystem (pre-fix: returns ok);
//  2. a VOLATILE memory backend carries a WARNING finding for that subsystem
//     (pre-fix: silently ok).
//
// okPinger lives in diagnostics_test.go; the durable-store cfg mirrors
// volatile_stores_test.go so only the subsystem under test is unhealthy.

func subsystemTestServer(t *testing.T, modes config.Config, probes SubsystemProbes) *Server {
	t.Helper()
	modes.HTTPAddr = ":0"
	modes.HSTSEnabled = true
	modes.HSTSMaxAge = time.Hour
	modes.AuthMode = "dev"
	return New(&modes, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil).
		WithAlertingActive(true).
		WithSubsystemProbes(probes)
}

func namedCheck(h support.Health, name string) (support.Check, bool) {
	for _, c := range h.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return support.Check{}, false
}

// durableExcept returns an all-durable config so only the subsystem under test
// can be unhealthy (no volatile_stores noise).
func durableExcept() config.Config {
	return config.Config{
		BusMode: "nats", TSDBMode: "prometheus", PathStoreMode: "postgres",
		FlowStoreMode: "clickhouse", OTelStoreMode: "clickhouse",
		EBPFStoreMode: "clickhouse", EndpointStoreMode: "clickhouse",
	}
}

func TestDiagnosticsNamesUnreachableExternalBackend(t *testing.T) {
	// A ClickHouse DSN-shaped error must never reach the operator-facing body.
	const rawProbeError = "dial tcp 10.0.0.9:9090: connect: connection refused (password=super-secret)"
	modes := durableExcept()
	srv := subsystemTestServer(t, modes, SubsystemProbes{
		TSDB: func(context.Context) error { return errors.New(rawProbeError) },
	})

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

	// RED pre-fix: with the DB up and alerting active, nothing probed the TSDB,
	// so the aggregate reported ok even though the configured backend is down.
	if h.Status != support.StatusDown {
		t.Fatalf("unreachable external TSDB must drive the aggregate down, got %v: %+v", h.Status, h.Checks)
	}
	c, ok := namedCheck(h, "tsdb")
	if !ok {
		t.Fatalf("diagnostics omitted the tsdb subsystem check: %+v", h.Checks)
	}
	if c.Status != support.StatusDown {
		t.Fatalf("tsdb check status = %v, want down", c.Status)
	}
	if c.Finding == nil || c.Finding.ID != "readiness.tsdb" || c.Finding.Severity != support.FindingCritical {
		t.Fatalf("unreachable tsdb must carry the readiness.tsdb critical finding: %+v", c.Finding)
	}
	if strings.Contains(rr.Body.String(), "super-secret") || strings.Contains(rr.Body.String(), "10.0.0.9") {
		t.Fatalf("raw probe error leaked into diagnostics: %s", rr.Body.String())
	}
}

func TestDiagnosticsWarnsOnVolatileSubsystem(t *testing.T) {
	// Only the bus is volatile; every other plane is durable, so a bus warning
	// cannot be mistaken for the holistic volatile_stores finding.
	modes := durableExcept()
	modes.BusMode = "memory"
	srv := subsystemTestServer(t, modes, SubsystemProbes{})

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

	// RED pre-fix: a memory-mode bus was silently absent from the per-subsystem
	// checks, so nothing warned that published results are lost on restart.
	if h.Status != support.StatusDegraded {
		t.Fatalf("a volatile bus must drive the aggregate degraded, got %v: %+v", h.Status, h.Checks)
	}
	c, ok := namedCheck(h, "bus")
	if !ok {
		t.Fatalf("diagnostics omitted the bus subsystem check: %+v", h.Checks)
	}
	if c.Status != support.StatusDegraded {
		t.Fatalf("memory-mode bus check status = %v, want degraded", c.Status)
	}
	if c.Finding == nil || c.Finding.ID != "readiness.bus" || c.Finding.Severity != support.FindingWarning {
		t.Fatalf("volatile bus must carry the readiness.bus warning finding: %+v", c.Finding)
	}

	// An acknowledged volatile deployment stays named but does not degrade.
	modes.AllowVolatile = config.VolatileAckPhrase
	ack := subsystemTestServer(t, modes, SubsystemProbes{})
	h = ack.deepHealth(context.Background())
	c, ok = namedCheck(h, "bus")
	if !ok || c.Status != support.StatusOK || c.Finding != nil {
		t.Fatalf("acknowledged volatile bus must be ok and finding-free: %+v", c)
	}
	if !strings.Contains(c.Detail, "acknowledged") {
		t.Fatalf("acknowledged volatile bus must stay visible: %q", c.Detail)
	}
}

// TestDiagnosticsProbeNilExternalBackendStaysOK proves a pool-less replica that
// did not wire a probe reports a configured external backend as ok-but-unprobed
// (never a false outage) — the behavior that keeps the all-durable deployment
// green in volatile_stores_test.go.
func TestDiagnosticsProbeNilExternalBackendStaysOK(t *testing.T) {
	srv := subsystemTestServer(t, durableExcept(), SubsystemProbes{})
	h := srv.deepHealth(context.Background())
	if h.Status != support.StatusOK {
		t.Fatalf("all-durable, unprobed deployment must aggregate ok, got %v: %+v", h.Status, h.Checks)
	}
	for _, name := range []string{"bus", "tsdb", "event_store", "object_store"} {
		c, ok := namedCheck(h, name)
		if !ok {
			t.Fatalf("missing %s subsystem check: %+v", name, h.Checks)
		}
		if c.Status != support.StatusOK {
			t.Fatalf("%s check status = %v, want ok (unprobed external backend is not an outage)", name, c.Status)
		}
	}
}
