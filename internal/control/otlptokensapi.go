// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/otel/otlp"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// OTLP token admin surface (WIRE-008): POST /v1/otlp-tokens (mint) and
// DELETE /v1/otlp-tokens/{id} (revoke). Tokens are hashed at rest via
// internal/crypto; the in-process TokenAuthenticator is updated immediately
// for hot-revocation (no restart required).
//
// Requires permMetricsWrite — the same permission governing OTLP remote-write.

// OTLPTokenAuthManager is the in-process authenticator seam: the handler calls
// these methods after persisting the change so the live OTLP receiver reflects
// it without a restart (hot-revocation / hot-activation).
type OTLPTokenAuthManager interface {
	Add(token, tenant string, expires time.Time)
	Revoke(token string) bool
}

// WithOTLPTokenAuth attaches the in-process OTLP authenticator so the admin
// API can hot-activate new tokens (Add) and signal revocation (Revoke). The DB
// store is accessed via s.pool (same pattern as scim/mcp tokens). nil is a
// no-op (the /v1/otlp-tokens surface hides when pool is nil).
func (s *Server) WithOTLPTokenAuth(auth OTLPTokenAuthManager) *Server {
	if auth != nil {
		s.otlpTokenAuth = auth
	}
	return s
}

// otlpTokenStore returns a store accessor for OTLP tokens. Returns false when
// the pool is not wired (unit tests of operational-only endpoints).
func (s *Server) otlpTokenStore() (store.OTLPTokens, bool) {
	if s.pool == nil {
		return store.OTLPTokens{}, false
	}
	return store.NewOTLPTokens(s.pool), true
}

// handleOTLPTokenCreate serves POST /v1/otlp-tokens — mints a new bearer token,
// stores its hash in the DB, and seeds the in-process authenticator for
// zero-downtime activation.
func (s *Server) handleOTLPTokenCreate(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}

	st, ok := s.otlpTokenStore()
	if !ok {
		return apierror.NotFound("not found")
	}

	var in struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Name == "" {
		in.Name = "token-" + time.Now().UTC().Format("20060102150405")
	}

	// Mint a high-entropy random token (32 bytes of crypto-random; FIPS guardrail 3).
	raw, err := crypto.Random(32)
	if err != nil {
		return apierror.Internal("failed to generate token").Wrap(err)
	}
	token := hex.EncodeToString(raw)

	// Hash via internal/crypto (SHA-256; the token itself has 256-bit entropy).
	tokenHash := crypto.Hash([]byte(token))

	id, err := st.Create(r.Context(), tid, in.Name, tokenHash)
	if err != nil {
		s.log.Warn("otlp token create failed", "tenant", tid, "error", err)
		return apierror.Internal("failed to persist token").Wrap(err)
	}

	// Seed the in-process authenticator immediately — the new token is usable
	// without a restart (WIRE-008 hot-activation).
	if s.otlpTokenAuth != nil {
		s.otlpTokenAuth.Add(token, tid, time.Time{})
	}

	// Audit the creation.
	_ = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "security.otlp_token_create", tid, map[string]any{
			"id": id, "name": in.Name,
		})
	})

	// Return the plaintext token ONCE (never retrievable again from the DB).
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":    id,
		"name":  in.Name,
		"token": token, // plaintext: the caller must treat this as a secret
	})
	return nil
}

// handleOTLPTokenRevoke serves DELETE /v1/otlp-tokens/{id} — marks the token
// revoked in the DB. Subsequent auth calls via DBTokenAuthenticator hit the DB
// and see the revoked state immediately (no restart required).
func (s *Server) handleOTLPTokenRevoke(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if id == "" {
		return apierror.Validation("token id is required")
	}

	st, ok := s.otlpTokenStore()
	if !ok {
		return apierror.NotFound("not found")
	}

	if err := st.Revoke(r.Context(), tid, id); err != nil {
		if err == store.ErrInvalidOTLPToken {
			return apierror.NotFound("token not found or already revoked")
		}
		s.log.Warn("otlp token revoke failed", "tenant", tid, "id", id, "error", err)
		return apierror.Internal("failed to revoke token").Wrap(err)
	}

	// The DBTokenAuthenticator consults the DB on every Authenticate call so
	// the revoked token is rejected on the NEXT request without a restart.
	// Config-seeded tokens (without a DB record) require a config change + restart.

	_ = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "security.otlp_token_revoke", tid, map[string]any{
			"id": id,
		})
	})

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleOTLPTokenList serves GET /v1/otlp-tokens — lists the tenant's OTLP
// tokens (metadata only — never the token hash or plaintext).
func (s *Server) handleOTLPTokenList(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}

	st, ok := s.otlpTokenStore()
	if !ok {
		return apierror.NotFound("not found")
	}

	tokens, err := st.List(r.Context(), tid)
	if err != nil {
		s.log.Warn("otlp token list failed", "tenant", tid, "error", err)
		return apierror.Internal("failed to list tokens").Wrap(err)
	}
	if tokens == nil {
		tokens = []store.OTLPToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
	return nil
}

// compile-time check: DBTokenAuthenticator satisfies OTLPTokenAuthManager.
var _ OTLPTokenAuthManager = (*otlp.DBTokenAuthenticator)(nil)
