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
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

var recordSCIMTokenAudit = func(s *Server, ctx context.Context, sc tenancy.Scope, r *http.Request, action, target string, data map[string]any) error {
	return s.recordAudit(ctx, sc, r, action, target, data)
}

func (s *Server) scimTokenStore() (store.ScimTokens, bool) {
	if s.pool == nil {
		return store.ScimTokens{}, false
	}
	return store.NewScimTokens(s.pool), true
}

// handleSCIMTokenList serves GET /v1/directory/scim-tokens. It returns metadata
// only: the plaintext token is shown exactly once, at create time.
func (s *Server) handleSCIMTokenList(w http.ResponseWriter, r *http.Request) error {
	if auth.PrincipalFrom(r.Context()) == nil {
		return apierror.Unauthorized("authentication required")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	st, ok := s.scimTokenStore()
	if !ok {
		return apierror.NotFound("not found")
	}

	var tokens []store.ScimToken
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var listErr error
		tokens, listErr = st.ListScoped(ctx, sc)
		return listErr
	}); err != nil {
		s.log.Warn("scim token list failed", "tenant", tid, "error", err)
		return apierror.Internal("failed to list SCIM tokens").Wrap(err)
	}
	if tokens == nil {
		tokens = []store.ScimToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
	return nil
}

// handleSCIMTokenCreate serves POST /v1/directory/scim-tokens. The returned
// token is the IdP's bearer secret and is never retrievable again.
func (s *Server) handleSCIMTokenCreate(w http.ResponseWriter, r *http.Request) error {
	if auth.PrincipalFrom(r.Context()) == nil {
		return apierror.Unauthorized("authentication required")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	st, ok := s.scimTokenStore()
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
		in.Name = "scim-" + time.Now().UTC().Format("20060102150405")
	}

	raw, err := crypto.Random(32)
	if err != nil {
		return apierror.Internal("failed to generate SCIM token").Wrap(err)
	}
	token := hex.EncodeToString(raw)
	tokenHash := crypto.Hash([]byte(token))

	var id string
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var createErr error
		id, createErr = st.CreateScoped(ctx, sc, in.Name, tokenHash)
		if createErr != nil {
			s.log.Warn("scim token create failed", "tenant", tid, "error", createErr)
			return apierror.Internal("failed to persist SCIM token").Wrap(createErr)
		}
		if auditErr := recordSCIMTokenAudit(s, ctx, sc, r, "directory.scim_token_create", tid, map[string]any{
			"id": id, "name": in.Name,
		}); auditErr != nil {
			s.log.Warn("scim token create audit failed", "tenant", tid, "id", id, "error", auditErr)
			return apierror.Internal("failed to audit SCIM token creation").Wrap(auditErr)
		}
		return nil
	}); err != nil {
		return err
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":    id,
		"name":  in.Name,
		"token": token,
	})
	return nil
}

// handleSCIMTokenRevoke serves DELETE /v1/directory/scim-tokens/{id}. Revoked
// tokens stop authenticating on the next SCIM request.
func (s *Server) handleSCIMTokenRevoke(w http.ResponseWriter, r *http.Request) error {
	if auth.PrincipalFrom(r.Context()) == nil {
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
	st, ok := s.scimTokenStore()
	if !ok {
		return apierror.NotFound("not found")
	}

	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if revokeErr := st.RevokeScoped(ctx, sc, id); revokeErr != nil {
			if revokeErr == store.ErrInvalidScimToken {
				return apierror.NotFound("SCIM token not found or already revoked")
			}
			s.log.Warn("scim token revoke failed", "tenant", tid, "id", id, "error", revokeErr)
			return apierror.Internal("failed to revoke SCIM token").Wrap(revokeErr)
		}
		if auditErr := recordSCIMTokenAudit(s, ctx, sc, r, "directory.scim_token_revoke", tid, map[string]any{"id": id}); auditErr != nil {
			s.log.Warn("scim token revoke audit failed", "tenant", tid, "id", id, "error", auditErr)
			return apierror.Internal("failed to audit SCIM token revocation").Wrap(auditErr)
		}
		return nil
	}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
