// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
// caller's tenant scopes the revocation (admin RBAC: the `agent.write` permission).
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
	var req enroll.Request
	if err := decodeJSONLimit(r, 64<<10, &req); err != nil {
		return err
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
		Token         string    `json:"token"` // shown once, never stored
		ID            string    `json:"id"`
		TenantID      string    `json:"tenant_id"`
		ExpiresAt     time.Time `json:"expires_at"`
		ServerCertPin string    `json:"server_cert_pin,omitempty"`
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
		if s.cfg != nil && s.cfg.TLSCertFile != "" {
			pin, perr := crypto.CertificatePinFile(s.cfg.TLSCertFile)
			if perr == nil {
				out.ServerCertPin = pin
			}
		}
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

type collectorConfigHint struct {
	Env  map[string]string `json:"env"`
	YAML map[string]string `json:"yaml"`
}

type collectorRegistrationResponse struct {
	TenantID     string              `json:"tenant_id"`
	AgentID      string              `json:"agent_id"`
	Plane        string              `json:"plane"`
	Hostname     string              `json:"hostname,omitempty"`
	Capabilities []string            `json:"capabilities"`
	Config       collectorConfigHint `json:"config"`
}

// handleRegisterCollector is the tenant-admin on-ramp for bus-publishing
// collectors. It mirrors enroll-token semantics but consumes the token through
// the caller's tenant first: a stolen token from another tenant is simply
// invalid and remains unspent.
func (s *Server) handleRegisterCollector(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	var req struct {
		Token    string `json:"token"`
		Plane    string `json:"plane"`
		Hostname string `json:"hostname,omitempty"`
	}
	if err := decodeJSONLimit(r, 16<<10, &req); err != nil {
		return err
	}
	hostname := strings.TrimSpace(req.Hostname)
	var out collectorRegistrationResponse
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		id, err := s.enrollSvc.RegisterCollectorForTenant(ctx, sc.Tenant.String(), req.Token, hostname, req.Plane)
		if err != nil {
			return err
		}
		out = collectorRegistrationResponse{
			TenantID:     id.TenantID,
			AgentID:      id.AgentID,
			Plane:        id.Plane,
			Hostname:     hostname,
			Capabilities: []string{"collector", id.Plane},
			Config:       collectorConfig(id.Plane, id.TenantID, id.AgentID),
		}
		return s.recordAudit(ctx, sc, r, "collector.registered", id.AgentID, map[string]any{
			"plane": id.Plane, "hostname": hostname,
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrInvalidToken):
			s.authLimiter.Fail("ip:" + clientIP(r))
			return apierror.Unauthorized("invalid enrollment token")
		case errors.Is(err, enroll.ErrInvalidCollectorPlane):
			return apierror.BadRequest("collector plane must be one of: flow, device, ebpf, endpoint")
		}
		s.log.Error("collector registration failed", "error", err.Error())
		return apierror.Internal("collector registration failed")
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func collectorConfig(plane, tenantID, agentID string) collectorConfigHint {
	h := collectorConfigHint{Env: map[string]string{}, YAML: map[string]string{"tenant_id": tenantID}}
	switch plane {
	case "flow":
		h.Env["PROBECTL_FLOW_TENANT"] = tenantID
		h.Env["PROBECTL_FLOW_AGENT_ID"] = agentID
		h.YAML["agent_id"] = agentID
	case "device":
		h.Env["PROBECTL_DEVICE_TENANT"] = tenantID
		h.Env["PROBECTL_DEVICE_AGENT_ID"] = agentID
		h.YAML["agent_id"] = agentID
	case "endpoint":
		h.Env["PROBECTL_ENDPOINT_TENANT_ID"] = tenantID
		h.Env["PROBECTL_ENDPOINT_AGENT_ID"] = agentID
		h.YAML["agent_id"] = agentID
	case "ebpf":
		h.Env["PROBECTL_EBPF_TENANT_ID"] = tenantID
		h.Env["PROBECTL_EBPF_HOST"] = agentID
		h.YAML["host"] = agentID
	}
	return h
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) error {
	if s.enrollSvc == nil {
		return apierror.Unavailable("agent enrollment is not configured (run: probectl-control agent-ca init)")
	}
	var req enroll.RotateRequest
	if err := decodeJSONLimit(r, 64<<10, &req); err != nil {
		return err
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
