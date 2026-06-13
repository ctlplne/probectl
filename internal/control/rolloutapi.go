// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// OPS-002: an operator surface over the staged-rollout engine (internal/agent
// RolloutPlan), which previously had NO API or CLI — the engine existed but
// nothing drove it. /v1/rollouts plans a wave-staged rollout across the live
// fleet and advance/halt/resume/verify step the wave state machine. Every
// mutation is RBAC'd (agent:write) and audited. The plan is observe-only /
// human-gated by construction (guardrail §7.8): the engine never deploys —
// it computes waves and gates advancement; the operator's orchestrator acts.
//
// State is held per control-plane instance (in-RAM); the engine is itself an
// in-RAM state machine. Durable cross-restart persistence of in-flight rollout
// state is a follow-up; an interrupted rollout is re-planned from the current
// fleet, which is safe (planning is deterministic over the live registry).

// rolloutManager holds active rollout plans, tenant-scoped.
type rolloutManager struct {
	mu   sync.Mutex
	seq  int
	byID map[string]map[string]*agent.RolloutPlan // tenant -> id -> plan
}

func newRolloutManager() *rolloutManager {
	return &rolloutManager{byID: map[string]map[string]*agent.RolloutPlan{}}
}

func (m *rolloutManager) put(tenant string, p *agent.RolloutPlan) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	id := fmt.Sprintf("rollout-%d", m.seq)
	if m.byID[tenant] == nil {
		m.byID[tenant] = map[string]*agent.RolloutPlan{}
	}
	m.byID[tenant][id] = p
	return id
}

func (m *rolloutManager) get(tenant, id string) (*agent.RolloutPlan, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[tenant][id]
	return p, ok
}

func (m *rolloutManager) list(tenant string) map[string]*agent.RolloutPlan {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]*agent.RolloutPlan{}
	for id, p := range m.byID[tenant] {
		out[id] = p
	}
	return out
}

type rolloutCreateRequest struct {
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	VerifyMethod  string `json:"verify_method"`
	CanaryPercent int    `json:"canary_percent,omitempty"`
	EarlyPercent  int    `json:"early_percent,omitempty"`
}

func (s *Server) rolloutMgr() *rolloutManager {
	s.rolloutsOnce.Do(func() { s.rollouts = newRolloutManager() })
	return s.rollouts
}

// handleCreateRollout plans a wave-staged rollout over the caller's live fleet.
func (s *Server) handleCreateRollout(w http.ResponseWriter, r *http.Request) error {
	var req rolloutCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Version == "" || req.Digest == "" || req.VerifyMethod == "" {
		return apierror.BadRequest("version, digest, and verify_method are required (an unverified artifact never enters the fleet)")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var fleet []agent.FleetAgent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		agents, e := (store.Agents{}).List(ctx, sc)
		if e != nil {
			return e
		}
		for _, a := range agents {
			fa := agent.FleetAgent{ID: a.ID, TenantID: a.TenantID, Version: a.AgentVersion}
			if a.LastSeenAt != nil {
				fa.LastSeen = *a.LastSeenAt
			}
			fleet = append(fleet, fa)
		}
		return nil
	}); err != nil {
		return err
	}
	split := lifecycle.DefaultSplit()
	if req.CanaryPercent > 0 || req.EarlyPercent > 0 {
		split = lifecycle.Split{CanaryPercent: req.CanaryPercent, EarlyPercent: req.EarlyPercent}
	}
	artifact := agent.VerifiedArtifact{
		Version: req.Version, Digest: req.Digest, Method: req.VerifyMethod,
		VerifiedBy: auditActor(r),
	}
	plan, perr := agent.PlanRollout(fleet, artifact, split, version.Get().Version, lifecycle.DefaultPolicy())
	if perr != nil {
		return apierror.BadRequest(perr.Error())
	}
	id := s.rolloutMgr().put(tid, plan)
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "rollout.create", id, map[string]any{
			"version": req.Version, "digest": req.Digest, "waves": len(plan.Waves),
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/rollouts/"+id)
	writeJSON(w, http.StatusCreated, rolloutView(id, plan))
	return nil
}

func (s *Server) handleListRollouts(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	plans := s.rolloutMgr().list(tid)
	ids := make([]string, 0, len(plans))
	for id := range plans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		items = append(items, rolloutView(id, plans[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) handleGetRollout(w http.ResponseWriter, r *http.Request) error {
	p, err := s.lookupRollout(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, rolloutView(r.PathValue("id"), p))
	return nil
}

func (s *Server) handleAdvanceRollout(w http.ResponseWriter, r *http.Request) error {
	return s.rolloutAction(w, r, "rollout.advance", func(p *agent.RolloutPlan) error {
		_, e := p.Advance(time.Now())
		return e
	})
}

func (s *Server) handleHaltRollout(w http.ResponseWriter, r *http.Request) error {
	return s.rolloutAction(w, r, "rollout.halt", func(p *agent.RolloutPlan) error {
		p.Halt("halted by operator via API")
		return nil
	})
}

func (s *Server) handleResumeRollout(w http.ResponseWriter, r *http.Request) error {
	return s.rolloutAction(w, r, "rollout.resume", func(p *agent.RolloutPlan) error {
		return p.Resume("resumed by operator via API", time.Now())
	})
}

// rolloutAction runs a state-machine step on a looked-up rollout and audits it.
func (s *Server) rolloutAction(w http.ResponseWriter, r *http.Request, action string, step func(*agent.RolloutPlan) error) error {
	p, err := s.lookupRollout(r)
	if err != nil {
		return err
	}
	if serr := step(p); serr != nil {
		return apierror.BadRequest(serr.Error())
	}
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, action, id, nil)
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, rolloutView(id, p))
	return nil
}

func (s *Server) lookupRollout(r *http.Request) (*agent.RolloutPlan, error) {
	tid, err := s.principalTenant(r)
	if err != nil {
		return nil, err
	}
	p, ok := s.rolloutMgr().get(tid, r.PathValue("id"))
	if !ok {
		return nil, apierror.NotFound("no such rollout")
	}
	return p, nil
}

func rolloutView(id string, p *agent.RolloutPlan) map[string]any {
	waves := make([]map[string]any, 0, len(p.Waves))
	for _, wv := range p.Waves {
		waves = append(waves, map[string]any{
			"cohort": string(wv.Cohort), "agents": len(wv.AgentIDs), "status": string(wv.Status),
		})
	}
	return map[string]any{
		"id":          id,
		"target":      p.Target.Version,
		"digest":      p.Target.Digest,
		"halted":      p.Halted,
		"halt_reason": p.HaltReason,
		"done":        p.Done(),
		"progress":    p.Progress(),
		"waves":       waves,
	}
}
