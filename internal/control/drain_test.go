package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

// During a graceful shutdown, /readyz must report 503 "draining" so a load
// balancer stops routing new requests to this replica before it exits — the basis
// of a zero-downtime rolling upgrade (S34).
func TestReadyzDrains(t *testing.T) {
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev", AIMaxEvidence: 50}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)
	h := s.Handler()

	// No pinger configured → ready.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 ready, got %d: %s", rec.Code, rec.Body)
	}

	// Draining → 503, so the LB drains this replica.
	s.draining.Store(true)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining readyz should be 503, got %d", rec2.Code)
	}

	// Liveness stays 200 while draining (the process is still serving).
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("healthz should stay 200 while draining, got %d", rec3.Code)
	}
}
