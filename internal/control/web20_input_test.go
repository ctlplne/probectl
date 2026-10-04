// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/logging"
)

// TestMalformedIDMapsToBadRequestNotServerError proves WEB-20: a non-UUID path
// value reaches Postgres as a 22P02 (invalid_text_representation) error, which
// the central error seam (apiHandler → writeError) must map to 400 rather than
// a 500 — without leaking the raw SQLSTATE/query detail to the client. This is
// the same error value pgx returns for `GET /v1/agents/not-a-uuid`.
func TestMalformedIDMapsToBadRequestNotServerError(t *testing.T) {
	h := apiHandler(func(http.ResponseWriter, *http.Request) error {
		return fmt.Errorf("query agent: %w", &pgconn.PgError{
			Code:    "22P02",
			Message: `invalid input syntax for type uuid: "not-a-uuid"`,
		})
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed id status = %d, want 400 (WEB-20; was a 500)", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "22P02") || strings.Contains(body, "invalid input syntax") {
		t.Fatalf("client body leaked SQLSTATE/query detail: %s", body)
	}
}

// TestForgedRequestIDIsReplaced proves WEB-20's inbound X-Request-Id bounding:
// an oversized/off-charset id is replaced with a server-generated one (never
// echoed or logged verbatim), while a sane short id is still honored.
func TestForgedRequestIDIsReplaced(t *testing.T) {
	var sawInHandler string
	chain := requestContext(slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sawInHandler, _ = logging.RequestIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

	forged := strings.Repeat("x", 8000)
	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	req.Header.Set("X-Request-Id", forged)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	echoed := rec.Header().Get("X-Request-Id")
	if echoed == forged || len(echoed) != 32 {
		t.Fatalf("forged X-Request-Id not replaced: echoed=%q (len %d), want a 32-hex server id", echoed, len(echoed))
	}
	if sawInHandler == forged {
		t.Fatalf("forged X-Request-Id reached the request logger/context")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	req2.Header.Set("X-Request-Id", "client-abc-123")
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("X-Request-Id"); got != "client-abc-123" {
		t.Fatalf("a valid inbound X-Request-Id must be honored, got %q", got)
	}
}
