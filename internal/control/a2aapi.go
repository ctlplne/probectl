// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	guuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// validateMeshAgents rejects a mesh request naming any agent_id that is not an
// enrolled agent of the caller's tenant (AI-01), so a caller cannot inflate the
// broker/scheduler with never-polling ghost agents. agent ids are UUIDs
// (agents.id), so a non-UUID id is rejected up front — issuing it to the
// UUID-typed column would raise a 22P02 that aborts the tenant transaction.
// Existence is checked in one scoped query (not N round-trips).
func (s *Server) validateMeshAgents(ctx context.Context, sc tenancy.Scope, agents []a2a.SiteAgent) error {
	ids := make([]string, 0, len(agents))
	seen := make(map[string]struct{}, len(agents))
	for _, a := range agents {
		if a.AgentID == "" {
			continue // StartMesh rejects empty ids with its own validation error
		}
		if _, dup := seen[a.AgentID]; dup {
			continue
		}
		seen[a.AgentID] = struct{}{}
		if _, err := guuid.Parse(a.AgentID); err != nil {
			return apierror.BadRequest(fmt.Sprintf("unknown agent_id %q for this tenant", a.AgentID))
		}
		ids = append(ids, a.AgentID)
	}
	if len(ids) == 0 {
		return nil
	}
	present, err := (store.Agents{}).ExistingIDs(ctx, sc, ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, ok := present[id]; !ok {
			return apierror.BadRequest(fmt.Sprintf("unknown agent_id %q for this tenant", id))
		}
	}
	return nil
}

// ARCH-009: the A2A broker brokered agent-to-agent measurement sessions but had
// no caller — the comment said "started by the test API in a later sprint", so
// the whole coordination plane was dormant. This is that seam: a tenant- and
// RBAC-scoped, audited session-start API over the existing Broker.StartSession.
// The broker remains in-process; this only exposes its start path.

// a2aJanitorInterval is how often the background janitor sweeps expired A2A
// broker tasks and mesh sessions (AI-01). Well under meshSessionTTL / the broker
// TTL, so state is emptied within one interval of the TTL.
const a2aJanitorInterval = 1 * time.Minute

// runA2AJanitor periodically releases A2A state whose agents never polled, until
// ctx is canceled. Started from Server.Run only when A2A is attached.
func (s *Server) runA2AJanitor(ctx context.Context) {
	t := time.NewTicker(a2aJanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.a2aBroker != nil {
				s.a2aBroker.SweepNow()
			}
			if s.a2aMesh != nil {
				s.a2aMesh.SweepExpired()
			}
		}
	}
}

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
		// AI-01: both agents must be enrolled in the caller tenant, so this
		// endpoint cannot seed ghost broker tasks any more than /mesh can.
		if e := s.validateMeshAgents(ctx, sc, []a2a.SiteAgent{
			{AgentID: req.ResponderAgent, Site: "responder"},
			{AgentID: req.InitiatorAgent, Site: "initiator"},
		}); e != nil {
			return e
		}
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
		// AI-01: every agent_id must be one of this tenant's ENROLLED agents.
		// Without this, a caller inflates the broker's in-memory queues with
		// never-polling ghost agent ids — the quadratic-work / retention DoS.
		// Rejected cheaply, before any O(n^2) scheduling.
		if e := s.validateMeshAgents(ctx, sc, req.Agents); e != nil {
			return e
		}
		sessions, e := s.a2aMesh.StartMesh(sc.Tenant.String(), req.Agents, req.Mode, req.Count)
		if e != nil {
			// INJ-06: an exhausted per-tenant task queue is a transient "retry
			// later" condition (429), not a permanent client error (400).
			if errors.Is(e, a2a.ErrPendingFull) {
				return apierror.RateLimited(e.Error())
			}
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
