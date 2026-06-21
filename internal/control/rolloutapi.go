// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
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
// RolloutPlan). /v1/rollouts plans a wave-staged rollout across the live fleet;
// the probectl rollout CLI group and API advance/halt/resume/verify the wave
// state machine. Every mutation is RBAC'd (agent:write) and audited. The plan
// is observe-only / human-gated by construction (guardrail §7.8): the engine
// never deploys — it computes waves and gates advancement; the operator's
// orchestrator acts.
//
// State is persisted in tenant-scoped Postgres rows and mirrored in this
// process as a hot cache. The database row is the truth: after a restart,
// list/get/action paths rebuild the cache from storage before returning.

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
	id := m.nextIDLocked(time.Now())
	m.putLocked(tenant, id, p)
	return id
}

func (m *rolloutManager) reserveID(now time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextIDLocked(now)
}

func (m *rolloutManager) remember(tenant, id string, p *agent.RolloutPlan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putLocked(tenant, id, p)
}

func (m *rolloutManager) nextIDLocked(now time.Time) string {
	m.seq++
	return fmt.Sprintf("rollout-%d-%d", now.UnixNano(), m.seq)
}

func (m *rolloutManager) putLocked(tenant, id string, p *agent.RolloutPlan) {
	if m.byID[tenant] == nil {
		m.byID[tenant] = map[string]*agent.RolloutPlan{}
	}
	m.byID[tenant][id] = p
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

type rolloutReasonRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) rolloutMgr() *rolloutManager {
	s.rolloutsOnce.Do(func() { s.rollouts = newRolloutManager() })
	return s.rollouts
}

func (s *Server) rolloutFleet(ctx context.Context, sc tenancy.Scope) ([]agent.FleetAgent, error) {
	if sc.Q == nil {
		return nil, apierror.Unavailable("agent registry is not available")
	}
	var fleet []agent.FleetAgent
	// SCALE-008: enumerate the fleet via the bounded cursor (ListPage) instead
	// of one unbounded List — a tens-of-thousands-agent fleet would otherwise
	// load every row into memory in a single query.
	after := ""
	for {
		page, err := (store.Agents{}).ListPage(ctx, sc, after, store.DefaultAgentPageSize)
		if err != nil {
			return nil, err
		}
		for _, a := range page {
			fa := agent.FleetAgent{ID: a.ID, TenantID: a.TenantID, Version: a.AgentVersion}
			if a.LastSeenAt != nil {
				fa.LastSeen = *a.LastSeenAt
			}
			fleet = append(fleet, fa)
		}
		if len(page) < store.DefaultAgentPageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	return fleet, nil
}

func encodeRolloutPlan(p *agent.RolloutPlan) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("rollout plan is nil")
	}
	return json.Marshal(p)
}

func decodeRolloutPlan(rec *store.RolloutRecord) (*agent.RolloutPlan, error) {
	if rec == nil {
		return nil, apierror.NotFound("rollout not found")
	}
	var p agent.RolloutPlan
	if err := json.Unmarshal(rec.Plan, &p); err != nil {
		return nil, err
	}
	return &p, nil
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
	id := s.rolloutMgr().reserveID(time.Now())
	var plan *agent.RolloutPlan
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		fleet, err := s.rolloutFleet(ctx, sc)
		if err != nil {
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
		p, perr := agent.PlanRollout(fleet, artifact, split, version.Get().Version, lifecycle.DefaultPolicy())
		if perr != nil {
			return apierror.BadRequest(perr.Error())
		}
		raw, err := encodeRolloutPlan(p)
		if err != nil {
			return err
		}
		if _, err := (store.Rollouts{}).Create(ctx, sc, id, raw); err != nil {
			return err
		}
		if err := (store.Rollouts{}).AppendEvent(ctx, sc, id, "rollout.create", raw); err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "rollout.create", id, map[string]any{
			"version": req.Version, "digest": req.Digest, "waves": len(p.Waves),
		}); err != nil {
			return err
		}
		plan = p
		return nil
	}); err != nil {
		return err
	}
	s.rolloutMgr().remember(tid, id, plan)
	w.Header().Set("Location", "/v1/rollouts/"+id)
	writeJSON(w, http.StatusCreated, rolloutView(id, plan))
	return nil
}

func (s *Server) handleListRollouts(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool != nil {
		var records []store.RolloutRecord
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			var e error
			records, e = (store.Rollouts{}).List(ctx, sc)
			return e
		}); err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(records))
		for _, rec := range records {
			p, err := decodeRolloutPlan(&rec)
			if err != nil {
				return err
			}
			s.rolloutMgr().remember(tid, rec.ID, p)
			items = append(items, rolloutView(rec.ID, p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return nil
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
	return s.rolloutAction(w, r, "rollout.advance", func(_ context.Context, _ tenancy.Scope, p *agent.RolloutPlan) (map[string]any, error) {
		_, e := p.Advance(time.Now())
		return map[string]any{"progress": p.Progress()}, e
	})
}

func (s *Server) handleVerifyRollout(w http.ResponseWriter, r *http.Request) error {
	return s.rolloutAction(w, r, "rollout.verify", func(ctx context.Context, sc tenancy.Scope, p *agent.RolloutPlan) (map[string]any, error) {
		fleet, err := s.rolloutFleet(ctx, sc)
		if err != nil {
			return nil, err
		}
		complete, err := p.Verify(fleet, time.Now())
		return map[string]any{"complete": complete, "progress": p.Progress()}, err
	})
}

func (s *Server) handleHaltRollout(w http.ResponseWriter, r *http.Request) error {
	reason, err := rolloutReason(r, "halted by operator via API")
	if err != nil {
		return err
	}
	return s.rolloutAction(w, r, "rollout.halt", func(_ context.Context, _ tenancy.Scope, p *agent.RolloutPlan) (map[string]any, error) {
		p.Halt(reason)
		return map[string]any{"progress": p.Progress()}, nil
	})
}

func (s *Server) handleResumeRollout(w http.ResponseWriter, r *http.Request) error {
	reason, err := rolloutReason(r, "resumed by operator via API")
	if err != nil {
		return err
	}
	return s.rolloutAction(w, r, "rollout.resume", func(_ context.Context, _ tenancy.Scope, p *agent.RolloutPlan) (map[string]any, error) {
		err := p.Resume(reason, time.Now())
		return map[string]any{"progress": p.Progress()}, err
	})
}

func rolloutReason(r *http.Request, fallback string) (string, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return fallback, nil
	}
	var req rolloutReasonRequest
	if err := decodeJSON(r, &req); err != nil {
		return "", err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return "", apierror.BadRequest("reason is required when a rollout action body is provided")
	}
	return reason, nil
}

// rolloutAction runs a state-machine step on a looked-up rollout and audits it.
func (s *Server) rolloutAction(w http.ResponseWriter, r *http.Request, action string, step func(context.Context, tenancy.Scope, *agent.RolloutPlan) (map[string]any, error)) error {
	id := r.PathValue("id")
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		p, err := s.lookupRollout(r)
		if err != nil {
			return err
		}
		_, serr := step(r.Context(), tenancy.Scope{}, p)
		if serr != nil {
			return rolloutStepErr(serr)
		}
		writeJSON(w, http.StatusOK, rolloutView(id, p))
		return nil
	}
	var view *agent.RolloutPlan
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		rec, err := (store.Rollouts{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		p, err := decodeRolloutPlan(rec)
		if err != nil {
			return err
		}
		meta, serr := step(ctx, sc, p)
		if serr != nil {
			return rolloutStepErr(serr)
		}
		raw, err := encodeRolloutPlan(p)
		if err != nil {
			return err
		}
		if _, err := (store.Rollouts{}).Update(ctx, sc, id, rec.Revision, raw); err != nil {
			return err
		}
		if err := (store.Rollouts{}).AppendEvent(ctx, sc, id, action, raw); err != nil {
			return err
		}
		if meta == nil {
			meta = map[string]any{}
		}
		if err := s.recordAudit(ctx, sc, r, action, id, meta); err != nil {
			return err
		}
		view = p
		return nil
	}); err != nil {
		return err
	}
	s.rolloutMgr().remember(tid, id, view)
	writeJSON(w, http.StatusOK, rolloutView(id, view))
	return nil
}

func rolloutStepErr(err error) error {
	if _, ok := apierror.As(err); ok {
		return err
	}
	return apierror.BadRequest(err.Error())
}

func (s *Server) lookupRollout(r *http.Request) (*agent.RolloutPlan, error) {
	tid, err := s.principalTenant(r)
	if err != nil {
		return nil, err
	}
	if s.pool != nil {
		id := r.PathValue("id")
		var rec *store.RolloutRecord
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			var e error
			rec, e = (store.Rollouts{}).Get(ctx, sc, id)
			return e
		}); err != nil {
			return nil, err
		}
		p, err := decodeRolloutPlan(rec)
		if err != nil {
			return nil, err
		}
		s.rolloutMgr().remember(tid, id, p)
		return p, nil
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
