//go:build integration

package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/store"
)

func integrationDSN() string {
	if v := os.Getenv("NETCTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://netctl:netctl@localhost:5432/netctl?sslmode=disable"
}

// TestReadyzAgainstRealDatabase proves the S1 Done-when: the server boots with a
// real Postgres pool and /readyz reports ready.
func TestReadyzAgainstRealDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		t.Skipf("no database available: %v", err)
	}

	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200", rec.Code)
	}
}
