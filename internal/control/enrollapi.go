package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Agent enrollment surface (Sprint 11; ADR docs/adr/agent-enrollment.md).
// Both routes are PRE-IDENTITY by design — /enroll is authenticated by the
// one-time join token, /rotate by cryptographic proof of the current SVID
// (chain + key possession). Both ride the U-024 per-IP throttle: an
// unauthenticated caller can only burn its own rate budget; no signing
// happens before the token/proof check.

// SetEnrollService installs the issuance service (nil = enrollment not
// configured; the routes answer 503 with the init instruction).
func (s *Server) SetEnrollService(svc *enroll.Service) { s.enrollSvc = svc }

// SetAgentRevocationPush installs the LIVE deny-list hook (Sprint 12,
// WIRE-003): main wires it to the agent transport's RevocationList so an API
// revocation refuses handshakes immediately — persistence (and the periodic
// refresher) covers restarts and CLI-side revocations.
func (s *Server) SetAgentRevocationPush(push func(serials []string, spiffeIDs []string)) {
	s.revokePush = push
}

// handleRevokeAgent is the operator path that FEEDS the handshake deny-list
// (WIRE-003 residual): resolves the agent's issued serials + SPIFFE id from
// the registry, persists the revocation, pushes it live, audits it. The
// caller's tenant scopes the revocation (admin RBAC: agents.write).
func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	agentID := r.PathValue("id")
	var out struct {
		AgentID     string `json:"agent_id"`
		SPIFFEID    string `json:"spiffe_id"`
		LiveSerials int    `json:"live_serials_revoked"`
	}
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		serials, spiffeID, err := s.enrollSvc.Revoke(ctx, sc.Tenant.String(), agentID, auditActor(r))
		if err != nil {
			return err
		}
		out.AgentID, out.SPIFFEID, out.LiveSerials = agentID, spiffeID, len(serials)
		if s.revokePush != nil {
			s.revokePush(serials, []string{spiffeID})
		}
		return s.recordAudit(ctx, sc, r, "agent.revoked", agentID, map[string]any{
			"spiffe_id": spiffeID, "live_serials": len(serials),
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	var req enroll.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		return apierror.BadRequest("malformed enrollment request")
	}
	id, err := s.enrollSvc.Enroll(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrInvalidToken):
			// Count the failure against the caller's IP dimension and refuse
			// uninformatively (replay / expiry / unknown look identical).
			s.authLimiter.Fail("ip:" + clientIP(r))
			return apierror.Unauthorized("invalid enrollment token")
		case errors.Is(err, enroll.ErrBadCSR):
			return apierror.BadRequest("invalid CSR")
		}
		s.log.Error("agent enrollment failed", "error", err.Error())
		return apierror.Internal("enrollment failed")
	}
	writeJSON(w, http.StatusOK, id)
	return nil
}

// handleMintEnrollToken is the ADMIN mint surface (founder decision: API +
// CLI). The token is scoped to the CALLER's tenant — a tenant admin can only
// enroll agents into their own tenant; minting is audited.
func (s *Server) handleMintEnrollToken(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	var req struct {
		AgentID    string `json:"agent_id,omitempty"` // optional pin
		Name       string `json:"name,omitempty"`
		TTLSeconds int    `json:"ttl_seconds,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	var out struct {
		Token     string    `json:"token"` // shown once, never stored
		ID        string    `json:"id"`
		TenantID  string    `json:"tenant_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID := sc.Tenant.String()
		display, id, err := s.enrollSvc.MintToken(ctx, tenantID, req.AgentID, req.Name, auditActor(r), ttl)
		if err != nil {
			return err
		}
		effTTL := ttl
		if effTTL <= 0 {
			effTTL = enroll.DefaultTokenTTL
		}
		out.Token, out.ID, out.TenantID, out.ExpiresAt = display, id, tenantID, time.Now().Add(effTTL).UTC()
		return s.recordAudit(ctx, sc, r, "agent.enroll_token_minted", id, map[string]any{
			"agent_pin": req.AgentID, "name": req.Name, "ttl": effTTL.String(),
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	var req enroll.RotateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		return apierror.BadRequest("malformed rotation request")
	}
	id, err := s.enrollSvc.Rotate(r.Context(), req)
	if err != nil {
		if errors.Is(err, enroll.ErrNotOurs) || errors.Is(err, enroll.ErrBadCSR) {
			s.authLimiter.Fail("ip:" + clientIP(r))
			return apierror.Unauthorized("rotation refused")
		}
		s.log.Error("agent rotation failed", "error", err.Error())
		return apierror.Internal("rotation failed")
	}
	writeJSON(w, http.StatusOK, id)
	return nil
}
