// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/incident"
)

const (
	meshStatusPending  = "pending"
	meshStatusHealthy  = "healthy"
	meshStatusDegraded = "degraded"

	// INJ-06: a full directed mesh is n*(n-1) sessions, allocated and scheduled
	// up front in the request goroutine. Unbounded, a ~1 MiB request body (tens
	// of thousands of sites) demanded a ~1e9-element, ~157 GB slice and burned
	// the CPU for minutes — a single editor request could OOM the stateless
	// control plane. Cap the distinct sites per request (64 sites = 4032
	// sessions, a few hundred KB) so the work is bounded, and cap the sessions a
	// tenant retains (they have no TTL) so repeated requests cannot leak memory.
	maxMeshSites             = 64
	maxMeshSessionsPerTenant = 50_000

	// meshSessionTTL bounds how long mesh metadata/results are retained
	// (AI-01): without a TTL, state for agents that never poll lingered until the
	// FIFO cap alone evicted it. Expired sessions are swept lazily on the tenant's
	// next StartMesh, matching the broker's lazy TTL model.
	meshSessionTTL = 15 * time.Minute
)

// SiteAgent is an A2A-capable agent with the operator's site label. Tenant is
// deliberately absent: the caller's authenticated tenant owns the mesh.
type SiteAgent struct {
	AgentID string `json:"agent_id"`
	Site    string `json:"site"`
}

// MeshSession is one directed site-to-site A2A measurement session.
type MeshSession struct {
	TenantID       string    `json:"tenant_id"`
	SessionID      string    `json:"session_id"`
	FromSite       string    `json:"from_site"`
	ToSite         string    `json:"to_site"`
	InitiatorAgent string    `json:"initiator_agent"`
	ResponderAgent string    `json:"responder_agent"`
	Mode           string    `json:"mode"`
	Count          uint32    `json:"count"`
	CreatedAt      time.Time `json:"created_at"`
}

// MeshResult stores one reported canary result in mesh context.
type MeshResult struct {
	TenantID       string             `json:"tenant_id"`
	SessionID      string             `json:"session_id"`
	FromSite       string             `json:"from_site"`
	ToSite         string             `json:"to_site"`
	InitiatorAgent string             `json:"initiator_agent"`
	ResponderAgent string             `json:"responder_agent"`
	AgentID        string             `json:"agent_id"`
	Role           string             `json:"role"`
	Success        bool               `json:"success"`
	LossRatio      float64            `json:"loss_ratio"`
	Metrics        map[string]float64 `json:"metrics,omitempty"`
	RecordedAt     time.Time          `json:"recorded_at"`
}

// TopologyEdge is the site-to-site overlay the mesh contributes to topology.
type TopologyEdge struct {
	TenantID       string             `json:"tenant_id"`
	FromSite       string             `json:"from_site"`
	ToSite         string             `json:"to_site"`
	InitiatorAgent string             `json:"initiator_agent"`
	ResponderAgent string             `json:"responder_agent"`
	SessionID      string             `json:"session_id"`
	Status         string             `json:"status"`
	Metrics        map[string]float64 `json:"metrics,omitempty"`
}

// MeshScheduler turns a list of site-labeled agents into a directed full mesh.
// It stores only tenant-owned mesh metadata/results; probe execution still goes
// through Broker so agents receive normal A2A tasks.
type MeshScheduler struct {
	broker *Broker
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]MeshSession
	byTenant map[string][]string
	results  map[string][]MeshResult
}

// NewMeshScheduler returns a tenant-scoped mesh scheduler over broker.
func NewMeshScheduler(broker *Broker) *MeshScheduler {
	if broker == nil {
		broker = NewBroker()
	}
	return &MeshScheduler{
		broker:   broker,
		now:      time.Now,
		sessions: map[string]MeshSession{},
		byTenant: map[string][]string{},
		results:  map[string][]MeshResult{},
	}
}

// StartMesh schedules one directed session for every ordered pair of distinct
// sites. When a site has multiple agents, the lexicographically first agent is
// chosen so retries generate a stable matrix.
func (m *MeshScheduler) StartMesh(tenantID string, agents []SiteAgent, mode string, count uint32) ([]MeshSession, error) {
	if tenantID == "" {
		return nil, errors.New("a2a mesh: tenant is required")
	}
	if mode == "" {
		mode = "udp"
	}
	if mode != "udp" && mode != "tcp" {
		return nil, fmt.Errorf("a2a mesh: unknown mode %q (want udp|tcp)", mode)
	}

	bySite := map[string][]string{}
	for _, a := range agents {
		if a.AgentID == "" || a.Site == "" {
			return nil, errors.New("a2a mesh: agent_id and site are required")
		}
		bySite[a.Site] = append(bySite[a.Site], a.AgentID)
	}
	if len(bySite) < 2 {
		return nil, errors.New("a2a mesh: at least two sites are required")
	}
	// INJ-06: reject before the O(n^2) allocation. The handler maps this to 400.
	if len(bySite) > maxMeshSites {
		return nil, fmt.Errorf("a2a mesh: too many sites %d (max %d); a full mesh schedules sites*(sites-1) sessions", len(bySite), maxMeshSites)
	}
	// INJ-06: a mesh queues one responder task per session (sites*(sites-1)).
	// Refuse up front if that would push the tenant past the broker's unpolled-
	// task cap — otherwise a burst of meshes naming never-polling agent ids pins
	// memory in the broker until the TTL ages it out. Agents that poll keep the
	// count near zero; this only bites a flood of work no agent is draining.
	wantSessions := len(bySite) * (len(bySite) - 1)
	if have := m.broker.PendingCount(tenantID); have+wantSessions > maxPendingPerTenant {
		return nil, fmt.Errorf("a2a mesh: %w (tenant has %d unpolled tasks, this mesh needs %d, cap %d)", ErrPendingFull, have, wantSessions, maxPendingPerTenant)
	}

	sites := make([]string, 0, len(bySite))
	agentForSite := make(map[string]string, len(bySite))
	for site, siteAgents := range bySite {
		sort.Strings(siteAgents)
		sites = append(sites, site)
		agentForSite[site] = siteAgents[0]
	}
	sort.Strings(sites)

	created := make([]MeshSession, 0, len(sites)*(len(sites)-1))
	for _, from := range sites {
		for _, to := range sites {
			if from == to {
				continue
			}
			initiator := agentForSite[from]
			responder := agentForSite[to]
			sessionID, err := m.broker.StartSession(tenantID, responder, initiator, mode, count)
			if err != nil {
				return nil, err
			}
			created = append(created, MeshSession{
				TenantID:       tenantID,
				SessionID:      sessionID,
				FromSite:       from,
				ToSite:         to,
				InitiatorAgent: initiator,
				ResponderAgent: responder,
				Mode:           mode,
				Count:          count,
				CreatedAt:      m.now(),
			})
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Sweep this tenant's expired sessions before adding new ones (AI-01).
	m.evictExpiredLocked(tenantID, m.now())
	for _, s := range created {
		m.sessions[s.SessionID] = s
		m.byTenant[tenantID] = append(m.byTenant[tenantID], s.SessionID)
	}
	m.evictOldestLocked(tenantID)
	return append([]MeshSession(nil), created...), nil
}

// evictExpiredLocked drops a tenant's sessions older than meshSessionTTL
// (AI-01): state for agents that never poll must not be retained indefinitely.
// Swept lazily on the tenant's next StartMesh.
func (m *MeshScheduler) evictExpiredLocked(tenantID string, now time.Time) {
	ids := m.byTenant[tenantID]
	if len(ids) == 0 {
		return
	}
	cutoff := now.Add(-meshSessionTTL)
	kept := make([]string, 0, len(ids))
	var drop []string
	for _, id := range ids {
		s, ok := m.sessions[id]
		if !ok {
			continue
		}
		if s.CreatedAt.Before(cutoff) {
			drop = append(drop, id)
			continue
		}
		kept = append(kept, id)
	}
	m.forgetSessionsLocked(tenantID, kept, drop)
}

// evictOldestLocked bounds a tenant's retained sessions (INJ-06): mesh sessions
// are FIFO-capped, so repeated requests cannot leak session + result state until
// OOM. The oldest session ids are dropped down to the cap, along with their
// stored results.
func (m *MeshScheduler) evictOldestLocked(tenantID string) {
	ids := m.byTenant[tenantID]
	if len(ids) <= maxMeshSessionsPerTenant {
		return
	}
	drop := ids[:len(ids)-maxMeshSessionsPerTenant]
	kept := append([]string(nil), ids[len(ids)-maxMeshSessionsPerTenant:]...)
	m.forgetSessionsLocked(tenantID, kept, drop)
}

// forgetSessionsLocked removes the dropped sessions from m.sessions and prunes
// their results from the tenant's result slice (results are keyed by tenant, not
// by session id — the earlier per-id delete was a silent no-op), then sets the
// tenant's retained id list to kept.
func (m *MeshScheduler) forgetSessionsLocked(tenantID string, kept, drop []string) {
	if len(drop) == 0 {
		return
	}
	dropped := make(map[string]struct{}, len(drop))
	for _, id := range drop {
		delete(m.sessions, id)
		dropped[id] = struct{}{}
	}
	if results := m.results[tenantID]; len(results) > 0 {
		pruned := results[:0]
		for _, r := range results {
			if _, gone := dropped[r.SessionID]; !gone {
				pruned = append(pruned, r)
			}
		}
		if len(pruned) == 0 {
			delete(m.results, tenantID)
		} else {
			m.results[tenantID] = pruned
		}
	}
	if len(kept) == 0 {
		delete(m.byTenant, tenantID)
	} else {
		m.byTenant[tenantID] = kept
	}
}

// recordResult attaches one canary result to a tenant-owned mesh session.
func (m *MeshScheduler) recordResult(tenantID, sessionID, agentID string, res canary.Result) (MeshResult, error) {
	if tenantID == "" || sessionID == "" || agentID == "" {
		return MeshResult{}, errors.New("a2a mesh: tenant, session, and agent are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok || s.TenantID != tenantID {
		return MeshResult{}, errors.New("a2a mesh: unknown session for tenant")
	}
	role := roleForResult(s, agentID, res)
	if role == "" {
		return MeshResult{}, errors.New("a2a mesh: reporting agent is not part of the session")
	}
	recordedAt := res.StartedAt
	if recordedAt.IsZero() {
		recordedAt = m.now()
	}
	mr := MeshResult{
		TenantID:       tenantID,
		SessionID:      sessionID,
		FromSite:       s.FromSite,
		ToSite:         s.ToSite,
		InitiatorAgent: s.InitiatorAgent,
		ResponderAgent: s.ResponderAgent,
		AgentID:        agentID,
		Role:           role,
		Success:        res.Success,
		LossRatio:      res.Metrics["loss.ratio"],
		Metrics:        copyMetrics(res.Metrics),
		RecordedAt:     recordedAt,
	}
	m.results[tenantID] = append(m.results[tenantID], mr)
	return mr, nil
}

// Results returns only the requested tenant's mesh results.
func (m *MeshScheduler) Results(tenantID string) []MeshResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]MeshResult(nil), m.results[tenantID]...)
	for i := range out {
		out[i].Metrics = copyMetrics(out[i].Metrics)
	}
	return out
}

// TopologyOverlay returns one directed edge per tenant-owned mesh session.
func (m *MeshScheduler) TopologyOverlay(tenantID string) []TopologyEdge {
	m.mu.Lock()
	defer m.mu.Unlock()
	resultsBySession := map[string][]MeshResult{}
	for _, r := range m.results[tenantID] {
		resultsBySession[r.SessionID] = append(resultsBySession[r.SessionID], r)
	}
	edges := make([]TopologyEdge, 0, len(m.byTenant[tenantID]))
	for _, id := range m.byTenant[tenantID] {
		s, ok := m.sessions[id]
		if !ok || s.TenantID != tenantID {
			continue
		}
		edges = append(edges, TopologyEdge{
			TenantID:       tenantID,
			FromSite:       s.FromSite,
			ToSite:         s.ToSite,
			InitiatorAgent: s.InitiatorAgent,
			ResponderAgent: s.ResponderAgent,
			SessionID:      s.SessionID,
			Status:         statusForResults(resultsBySession[id]),
			Metrics:        latestMetrics(resultsBySession[id]),
		})
	}
	return edges
}

// incidentSignals maps degraded mesh results to cross-plane incident signals.
func (m *MeshScheduler) incidentSignals(tenantID string) []incident.Signal {
	results := m.Results(tenantID)
	signals := make([]incident.Signal, 0, len(results))
	for _, r := range results {
		if r.Success && r.LossRatio <= 0 {
			continue
		}
		signals = append(signals, incident.Signal{
			TenantID:   tenantID,
			Plane:      "synthetic",
			Kind:       "a2a.mesh.degraded",
			Severity:   incident.SeverityWarning,
			Title:      "A2A site-to-site mesh degraded",
			Summary:    fmt.Sprintf("%s to %s reported loss %.4f", r.FromSite, r.ToSite, r.LossRatio),
			Target:     meshTarget(r.FromSite, r.ToSite),
			OccurredAt: r.RecordedAt,
			Attributes: map[string]string{
				"session_id":      r.SessionID,
				"from_site":       r.FromSite,
				"to_site":         r.ToSite,
				"initiator_agent": r.InitiatorAgent,
				"responder_agent": r.ResponderAgent,
				"agent_id":        r.AgentID,
				"a2a.role":        r.Role,
			},
		})
	}
	return signals
}

func roleForResult(s MeshSession, agentID string, res canary.Result) string {
	role := ""
	if res.Attributes != nil {
		role = res.Attributes["a2a.role"]
	}
	switch agentID {
	case s.InitiatorAgent:
		if role == "" {
			return "initiator"
		}
		return role
	case s.ResponderAgent:
		if role == "" {
			return "responder"
		}
		return role
	default:
		return ""
	}
}

func statusForResults(results []MeshResult) string {
	if len(results) == 0 {
		return meshStatusPending
	}
	for _, r := range results {
		if !r.Success || r.LossRatio > 0 {
			return meshStatusDegraded
		}
	}
	return meshStatusHealthy
}

func latestMetrics(results []MeshResult) map[string]float64 {
	if len(results) == 0 {
		return nil
	}
	latest := results[0]
	for _, r := range results[1:] {
		if r.RecordedAt.After(latest.RecordedAt) {
			latest = r
		}
	}
	return copyMetrics(latest.Metrics)
}

func copyMetrics(in map[string]float64) map[string]float64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]float64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func meshTarget(from, to string) string {
	return "site:" + from + "->site:" + to
}
