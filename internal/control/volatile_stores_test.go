// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/support"
)

// PLAT-01/RTO-04: memory-backed telemetry stores lose all data on restart, and
// the shipped default install runs this way. The one thing the deployment never
// did was SAY so. /v1/diagnostics must report a named, degraded finding and
// /readyz must surface the volatile planes (while staying up). okPinger lives in
// diagnostics_test.go.

// authedReadyzRequest builds a /readyz request already carrying a resolved
// principal, so a direct handleReadyz call exercises the authenticated path
// that gets the full operator posture (AUTHZ-25).
func authedReadyzRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	return r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{UserID: "ops"}))
}

func volatileStoresCheck(t *testing.T, h support.Health) (support.Check, bool) {
	t.Helper()
	for _, c := range h.Checks {
		if c.Name == "volatile_stores" {
			return c, true
		}
	}
	return support.Check{}, false
}

func volatileTestServer(modes config.Config) *Server {
	modes.HTTPAddr = ":0"
	modes.HSTSEnabled = true
	modes.HSTSMaxAge = time.Hour
	modes.AuthMode = "dev"
	return New(&modes, logging.New(io.Discard, "error", "json"), okPinger{}, nil, nil, nil).
		WithAlertingActive(true)
}

var allMemoryModes = config.Config{
	BusMode: "memory", TSDBMode: "memory", PathStoreMode: "memory",
	FlowStoreMode: "memory", OTelStoreMode: "memory", EBPFStoreMode: "memory",
	EndpointStoreMode: "memory",
}

var allDurableModes = config.Config{
	BusMode: "nats", TSDBMode: "prometheus", PathStoreMode: "postgres",
	FlowStoreMode: "clickhouse", OTelStoreMode: "clickhouse", EBPFStoreMode: "clickhouse",
	EndpointStoreMode: "clickhouse",
}

func TestDiagnosticsFlagsVolatileStores(t *testing.T) {
	t.Run("unacknowledged volatile: degraded check with the named finding", func(t *testing.T) {
		s := volatileTestServer(allMemoryModes)
		h := s.deepHealth(context.Background())
		c, ok := volatileStoresCheck(t, h)
		if !ok {
			t.Fatal("no volatile_stores check in diagnostics")
		}
		if c.Status != support.StatusDegraded {
			t.Fatalf("volatile_stores status = %v, want degraded", c.Status)
		}
		if c.Finding == nil || c.Finding.ID != "readiness.volatile_stores" {
			t.Fatalf("degraded volatile_stores must carry the readiness.volatile_stores finding, got %+v", c.Finding)
		}
		if !strings.Contains(c.Detail, "PROBECTL_BUS_MODE=memory") {
			t.Errorf("detail must name the volatile planes: %q", c.Detail)
		}
		// PLAT-01 acceptance: with the DB up and alerting active, the volatile
		// stores are what drive the overall report to degraded.
		if h.Status != support.StatusDegraded {
			t.Errorf("overall diagnostics status = %v, want degraded (driven by volatile stores)", h.Status)
		}
	})

	t.Run("acknowledged volatile: ok but still named", func(t *testing.T) {
		modes := allMemoryModes
		modes.AllowVolatile = config.VolatileAckPhrase
		s := volatileTestServer(modes)
		h := s.deepHealth(context.Background())
		c, ok := volatileStoresCheck(t, h)
		if !ok {
			t.Fatal("no volatile_stores check")
		}
		if c.Status != support.StatusOK {
			t.Fatalf("acknowledged volatile status = %v, want ok", c.Status)
		}
		if !strings.Contains(c.Detail, "acknowledged") {
			t.Errorf("even acknowledged, it must stay visible: %q", c.Detail)
		}
		if h.Status != support.StatusOK {
			t.Errorf("overall status = %v, want ok once volatility is acknowledged (DB up, alerting active)", h.Status)
		}
	})

	t.Run("durable: ok", func(t *testing.T) {
		s := volatileTestServer(allDurableModes)
		h := s.deepHealth(context.Background())
		c, ok := volatileStoresCheck(t, h)
		if !ok {
			t.Fatal("no volatile_stores check")
		}
		if c.Status != support.StatusOK {
			t.Fatalf("durable status = %v, want ok", c.Status)
		}
		if h.Status != support.StatusOK {
			t.Errorf("overall status = %v, want ok for an all-durable deployment", h.Status)
		}
	})
}

func TestReadyzFlagsVolatileStores(t *testing.T) {
	t.Run("volatile: body lists the planes and stays ready (200)", func(t *testing.T) {
		s := volatileTestServer(allMemoryModes)
		rec := httptest.NewRecorder()
		// AUTHZ-25: volatile_stores is operator posture, carried for an
		// authenticated caller (an anonymous probe gets status only).
		if err := s.handleReadyz(rec, authedReadyzRequest()); err != nil {
			t.Fatalf("handleReadyz: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("/readyz = %d, want 200 (volatility does not make the node unready)", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "volatile_stores") || !strings.Contains(body, "PROBECTL_BUS_MODE=memory") {
			t.Errorf("/readyz must flag the volatile planes: %s", body)
		}
	})

	t.Run("durable: no volatile_stores field", func(t *testing.T) {
		s := volatileTestServer(allDurableModes)
		rec := httptest.NewRecorder()
		if err := s.handleReadyz(rec, authedReadyzRequest()); err != nil {
			t.Fatalf("handleReadyz: %v", err)
		}
		if strings.Contains(rec.Body.String(), "volatile_stores") {
			t.Errorf("a durable deployment must not flag volatile stores: %s", rec.Body.String())
		}
	})
}
