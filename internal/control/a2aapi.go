// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/a2a"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// ARCH-009: the A2A broker brokered agent-to-agent measurement sessions but had
// no caller — the comment said "started by the test API in a later sprint", so
// the whole coordination plane was dormant. This is that seam: a tenant- and
// RBAC-scoped, audited session-start API over the existing Broker.StartSession.
// The broker remains in-process; this only exposes its start path.

// WithA2ABroker attaches the agent-to-agent session broker backing
// POST /v1/a2a/sessions and /v1/a2a/mesh. nil leaves the endpoints reporting 503.
func (s *Server) WithA2ABroker(b *a2a.Broker) *Server {
	s.a2aBroker = b
	if b != nil {
		s.a2aMesh = a2a.NewMeshScheduler(b)
	}
	return s
}

type a2aSessionRequest struct {
	ResponderAgent string `json:"responder_agent"`
	InitiatorAgent string `json:"initiator_agent"`
	Mode           string `json:"mode"`
	Count          uint32 `json:"count"`
}

type a2aMeshRequest struct {
	Agents []a2a.SiteAgent `json:"agents"`
	Mode   string          `json:"mode"`
	Count  uint32          `json:"count"`
}

type a2aMeshResponse struct {
	Sessions []a2a.MeshSession  `json:"sessions"`
	Topology []a2a.TopologyEdge `json:"topology"`
}

// handleStartA2ASession starts a brokered session between two of the CALLER's
// tenant's agents. The tenant comes from the authenticated principal (boundary
// first), never the body, so a caller can only ever broker within its own
// tenant (guardrail §7.1). RBAC is enforced by the route's permAgentWrite.
func (s *Server) handleStartA2ASession(w http.ResponseWriter, r *http.Request) error {
	if s.a2aBroker == nil {
		return apierror.Unavailable("agent-to-agent coordination is not enabled")
	}
	var req a2aSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.ResponderAgent == "" || req.InitiatorAgent == "" || req.Mode == "" {
		return apierror.BadRequest("responder_agent, initiator_agent, and mode are required")
	}

	var sessionID string
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		id, e := s.a2aBroker.StartSession(sc.Tenant.String(), req.ResponderAgent, req.InitiatorAgent, req.Mode, req.Count)
		if e != nil {
			return apierror.BadRequest(e.Error())
		}
		sessionID = id
		return s.recordAudit(ctx, sc, r, "a2a.session.start", id, map[string]any{
			"responder_agent": req.ResponderAgent,
			"initiator_agent": req.InitiatorAgent,
			"mode":            req.Mode,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"session_id": sessionID})
	return nil
}

// handleStartA2AMesh starts a directed full mesh across the caller tenant's
// site-labeled agents. The tenant is still the authenticated tenant, never a
// request field; site labels only shape the matrix.
func (s *Server) handleStartA2AMesh(w http.ResponseWriter, r *http.Request) error {
	if s.a2aMesh == nil {
		return apierror.Unavailable("agent-to-agent mesh coordination is not enabled")
	}
	var req a2aMeshRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	var resp a2aMeshResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		sessions, e := s.a2aMesh.StartMesh(sc.Tenant.String(), req.Agents, req.Mode, req.Count)
		if e != nil {
			return apierror.BadRequest(e.Error())
		}
		resp = a2aMeshResponse{
			Sessions: sessions,
			Topology: s.a2aMesh.TopologyOverlay(sc.Tenant.String()),
		}
		return s.recordAudit(ctx, sc, r, "a2a.mesh.start", "", map[string]any{
			"site_edges":    len(resp.Topology),
			"session_count": len(resp.Sessions),
			"mode":          req.Mode,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, resp)
	return nil
}
