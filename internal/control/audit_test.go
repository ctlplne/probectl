package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// security.txt is served unauthenticated and is a valid RFC 9116 document.
func TestSecurityTxt(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer(nil).Handler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"Contact:", "Expires:", "Policy:"} {
		if !strings.Contains(body, want) {
			t.Errorf("security.txt missing %q:\n%s", want, body)
		}
	}
}

func TestAuditActor(t *testing.T) {
	// No principal → "system".
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := auditActor(r); got != "system" {
		t.Errorf("no principal: actor = %q, want system", got)
	}
	// Email preferred.
	r2 := r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{Email: "a@b.c", UserID: "u1"}))
	if got := auditActor(r2); got != "a@b.c" {
		t.Errorf("actor = %q, want a@b.c", got)
	}
	// Falls back to user id when email is empty.
	r3 := r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{UserID: "u1"}))
	if got := auditActor(r3); got != "u1" {
		t.Errorf("actor = %q, want u1", got)
	}
}

func TestQueryParsers(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/audit?after=42&limit=7", nil)
	if got := int64Query(r, "after", 0); got != 42 {
		t.Errorf("after = %d, want 42", got)
	}
	if got := intQuery(r, "limit", 100); got != 7 {
		t.Errorf("limit = %d, want 7", got)
	}
	// Missing / invalid → default.
	bad := httptest.NewRequest(http.MethodGet, "/v1/audit?after=-1&limit=abc", nil)
	if got := int64Query(bad, "after", 5); got != 5 {
		t.Errorf("negative after should fall back, got %d", got)
	}
	if got := intQuery(bad, "limit", 100); got != 100 {
		t.Errorf("non-numeric limit should fall back, got %d", got)
	}
}
