// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type captureOTLPTokenAuth struct {
	adds int
}

func (c *captureOTLPTokenAuth) Add(_, _ string, _ time.Time) { c.adds++ }
func (c *captureOTLPTokenAuth) Revoke(string) bool           { return false }

func withFailingOTLPTokenAudit(t *testing.T) {
	t.Helper()
	prev := recordOTLPTokenAudit
	recordOTLPTokenAudit = func(*Server, context.Context, tenancy.Scope, *http.Request, string, string, map[string]any) error {
		return errors.New("audit sink down")
	}
	t.Cleanup(func() { recordOTLPTokenAudit = prev })
}

func otlpTokenTestServer(db *store.DB, auth OTLPTokenAuthManager) *Server {
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev"}
	return New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).WithOTLPTokenAuth(auth)
}

func TestOTLPTokenCreateAuditFailureRollsBack(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "otlp-audit-create")
	authn := &captureOTLPTokenAuth{}
	withFailingOTLPTokenAudit(t)
	h := otlpTokenTestServer(db, authn).Handler()

	rec := apiReq(t, h, http.MethodPost, "/v1/otlp-tokens", tenant, map[string]any{"name": "should-rollback"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with audit failure: got %d, want 500: %s", rec.Code, rec.Body.String())
	}

	var count int
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM otlp_tokens WHERE tenant_id = $1`, tenant).Scan(&count); err != nil {
		t.Fatalf("count otlp_tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit failure must roll back token create; found %d token rows", count)
	}
	if authn.adds != 0 {
		t.Fatalf("audit failure must not hot-activate token; Add calls = %d", authn.adds)
	}
}

func TestOTLPTokenRevokeAuditFailureRollsBack(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "otlp-audit-revoke")
	seed := time.Now().UnixNano()
	tokenHash := crypto.Hash([]byte(fmt.Sprintf("token-to-revoke-%d", seed)))
	id, err := store.NewOTLPTokens(db.Pool()).Create(context.Background(), tenant, fmt.Sprintf("revoke-me-%d", seed), tokenHash)
	if err != nil {
		t.Fatalf("seed otlp token: %v", err)
	}

	withFailingOTLPTokenAudit(t)
	h := otlpTokenTestServer(db, nil).Handler()

	rec := apiReq(t, h, http.MethodDelete, "/v1/otlp-tokens/"+id, tenant, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("revoke with audit failure: got %d, want 500: %s", rec.Code, rec.Body.String())
	}

	var revokedAt *time.Time
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT revoked_at FROM otlp_tokens WHERE id = $1`, id).Scan(&revokedAt); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revokedAt != nil {
		t.Fatalf("audit failure must roll back token revoke; revoked_at = %v", *revokedAt)
	}
}
