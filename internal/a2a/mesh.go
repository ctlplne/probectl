// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

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
	TenantID              string             `json:"tenant_id"`
	FromSite              string             `json:"from_site"`
	ToSite                string             `json:"to_site"`
	InitiatorAgent        string             `json:"initiator_agent"`
	ResponderAgent        string             `json:"responder_agent"`
	SessionID             string             `json:"session_id"`
	CreatedAt             time.Time          `json:"created_at"`
	ObservedAt            *time.Time         `json:"observed_at,omitempty"`
	Status                string             `json:"status"`
	Metrics               map[string]float64 `json:"metrics,omitempty"`
	InitiatorRegisteredAt time.Time          `json:"-"`
	ResponderRegisteredAt time.Time          `json:"-"`
}

// MeshScheduler turns a list of site-labeled agents into a directed full mesh.
// It stores only tenant-owned mesh metadata/results; probe execution still goes
// through Broker so agents receive normal A2A tasks.
type MeshScheduler struct {
	broker *Broker
	now    func() time.Time

	mu          sync.Mutex
	sessions    map[sessionKey]MeshSession
	assignments map[sessionKey]*meshAssignment
	byTenant    map[string][]string
	results     map[sessionKey][]MeshResult
}

// NewMeshScheduler returns a tenant-scoped mesh scheduler over broker.
func NewMeshScheduler(broker *Broker) *MeshScheduler {
	if broker == nil {
		broker = NewBroker()
	}
	return &MeshScheduler{
		broker:      broker,
		now:         time.Now,
		sessions:    map[sessionKey]MeshSession{},
		assignments: map[sessionKey]*meshAssignment{},
		byTenant:    map[string][]string{},
		results:     map[sessionKey][]MeshResult{},
	}
}

// StartMesh schedules one directed session for every ordered pair of distinct
// sites. When a site has multiple agents, the lexicographically first agent is
// chosen so retries generate a stable matrix.
func (m *MeshScheduler) StartMesh(tenantID string, agents []SiteAgent, mode string, count uint32) ([]MeshSession, error) {
	return m.StartMeshAfterAudit(tenantID, agents, mode, count, nil)
}

// StartMeshAfterAudit prepares the whole mesh before invoking commitAudit.
// Dispatch begins only after the callback commits and returns the exact
// registration times it validated in the audited tenant transaction.
func (m *MeshScheduler) StartMeshAfterAudit(tenantID string, agents []SiteAgent, mode string, count uint32, commitAudit func(int, string) (map[string]time.Time, error)) ([]MeshSession, error) {
	if tenantID == "" {
		return nil, errors.New("a2a mesh: tenant is required")
	}
	if mode == "" {
		mode = "udp"
	}
	if mode != "udp" && mode != "tcp" {
		return nil, fmt.Errorf("a2a mesh: unknown mode %q (want udp|tcp)", mode)
	}
	if count == 0 {
		count = 5
	}
	if count > MaxSessionCount {
		return nil, ErrSessionCountTooLarge
	}

	bySite := map[string][]string{}
	for _, a := range agents {
		if a.AgentID == "" || a.Site == "" || !boundedMeshText(a.Site, 128) {
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
	release, err := m.broker.reserveMeshCapacity(tenantID, wantSessions)
	if err != nil {
		return nil, err
	}
	defer release()

	sites := make([]string, 0, len(bySite))
	agentForSite := make(map[string]string, len(bySite))
	selected := make(map[string]bool, len(bySite))
	for site, siteAgents := range bySite {
		sort.Strings(siteAgents)
		if selected[siteAgents[0]] {
			return nil, errors.New("a2a mesh: one agent cannot represent multiple sites")
		}
		selected[siteAgents[0]] = true
		sites = append(sites, site)
		agentForSite[site] = siteAgents[0]
	}
	sort.Strings(sites)

	created := make([]MeshSession, 0, wantSessions)
	type preparedAssignment struct {
		reporters    *meshAssignment
		probeSession string
	}
	assignments := make(map[sessionKey]preparedAssignment, wantSessions)
	for _, from := range sites {
		for _, to := range sites {
			if from == to {
				continue
			}
			initiator := agentForSite[from]
			responder := agentForSite[to]
			probeSession, err := m.broker.newID()
			if err != nil {
				return nil, err
			}
			sessionID := MeshSessionHandle(probeSession)
			if sessionID == "" {
				return nil, errors.New("a2a mesh: invalid probe credential")
			}
			key := sessionKey{tenantID, sessionID}
			if _, exists := assignments[key]; exists {
				return nil, errors.New("a2a mesh: repeated session id")
			}
			assignment, err := newMeshAssignment()
			if err != nil {
				return nil, err
			}
			assignments[key] = preparedAssignment{assignment, probeSession}
			created = append(created, MeshSession{
				TenantID:       tenantID,
				SessionID:      sessionID,
				FromSite:       from,
				ToSite:         to,
				InitiatorAgent: initiator,
				ResponderAgent: responder,
				Mode:           mode,
				Count:          count,
			})
		}
	}
	if commitAudit != nil {
		registrations, err := commitAudit(len(created), mode)
		if err != nil {
			return nil, err
		}
		for _, s := range created {
			assignment := assignments[sessionKey{tenantID, s.SessionID}].reporters
			assignment.initiator.registeredAt = registrations[s.InitiatorAgent]
			assignment.responder.registeredAt = registrations[s.ResponderAgent]
			if assignment.initiator.registeredAt.IsZero() || assignment.responder.registeredAt.IsZero() {
				return nil, errors.New("a2a mesh: missing audited agent registration")
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.broker.mu.Lock()
	defer m.broker.mu.Unlock()
	// Sweep this tenant's expired sessions before adding new ones (AI-01).
	createdAt := m.now()
	m.evictExpiredLocked(tenantID, createdAt)
	for index := range created {
		created[index].CreatedAt = createdAt
		s := created[index]
		key := sessionKey{tenantID, s.SessionID}
		assignment := assignments[key]
		m.sessions[key] = s
		m.assignments[key] = assignment.reporters
		m.byTenant[tenantID] = append(m.byTenant[tenantID], s.SessionID)
		m.broker.activateLocked(sessionKey{tenantID, assignment.probeSession}, &session{responder: s.ResponderAgent, initiator: s.InitiatorAgent,
			mode: s.Mode, count: s.Count, createdAt: m.broker.now(), mesh: assignment.reporters})
	}
	m.evictOldestLocked(tenantID)
	return append([]MeshSession(nil), created...), nil
}

// SweepExpired evicts EVERY tenant's sessions older than meshSessionTTL
// (AI-01). StartMesh only sweeps the calling tenant, so a tenant that stops
// calling — or any tenant's state while other tenants are active — would never
// be reclaimed. The control plane's janitor calls this on a ticker so mesh state
// for agents that never poll is emptied after the TTL regardless of traffic.
func (m *MeshScheduler) SweepExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for tenantID := range m.byTenant {
		m.evictExpiredLocked(tenantID, now)
	}
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
		s, ok := m.sessions[sessionKey{tenantID, id}]
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

// forgetSessionsLocked removes dropped sessions and their attached data.
func (m *MeshScheduler) forgetSessionsLocked(tenantID string, kept, drop []string) {
	if len(drop) == 0 {
		return
	}
	for _, id := range drop {
		key := sessionKey{tenantID, id}
		delete(m.sessions, key)
		delete(m.assignments, key)
		delete(m.results, key)
	}
	if len(kept) == 0 {
		delete(m.byTenant, tenantID)
	} else {
		m.byTenant[tenantID] = kept
	}
}

// RememberReport updates the live overlay after durable acceptance or an exact
// replay. The stored receipt and its incident are committed before this call.
func (m *MeshScheduler) RememberReport(report VerifiedMeshReport) {
	m.rememberResult(report.MeshResult)
}

func (m *MeshScheduler) rememberResult(report MeshResult) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sessionKey{report.TenantID, report.SessionID}
	session, present := m.sessions[key]
	if !present || !m.now().Before(session.CreatedAt.Add(meshSessionTTL)) {
		return false
	}
	for _, current := range m.results[key] {
		if current.Role == report.Role {
			return false
		}
	}
	report.Metrics = copyMetrics(report.Metrics)
	m.results[key] = append(m.results[key], report)
	return true
}

// TopologyOverlay returns one directed edge per tenant-owned mesh session.
func (m *MeshScheduler) TopologyOverlay(tenantID string) []TopologyEdge {
	return m.topologyOverlay(tenantID, nil, 0)
}

// TopologyForSessions returns only the edges allocated by a mesh start.
func (m *MeshScheduler) TopologyForSessions(tenantID string, sessions []MeshSession) []TopologyEdge {
	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.SessionID)
	}
	return m.topologyOverlay(tenantID, ids, 0)
}

// RecentTopology returns at most limit current edges, or the exact session
// when a session was requested. Scope is applied before every lookup.
func (m *MeshScheduler) RecentTopology(tenantID, sessionID string, limit int) []TopologyEdge {
	var ids []string
	if sessionID != "" {
		ids = []string{sessionID}
	}
	return m.topologyOverlay(tenantID, ids, limit)
}

func (m *MeshScheduler) topologyOverlay(tenantID string, ids []string, limit int) []TopologyEdge {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ids == nil {
		ids = m.byTenant[tenantID]
	}
	if limit > 0 && len(ids) > limit {
		ids = ids[len(ids)-limit:]
	}
	edges := make([]TopologyEdge, 0, len(ids))
	now := m.now()
	for _, id := range ids {
		key := sessionKey{tenantID, id}
		s, ok := m.sessions[key]
		if !ok || !now.Before(s.CreatedAt.Add(meshSessionTTL)) {
			continue
		}
		metrics, observedAt := topologyMetrics(m.results[key])
		edge := TopologyEdge{
			TenantID:       tenantID,
			FromSite:       s.FromSite,
			ToSite:         s.ToSite,
			InitiatorAgent: s.InitiatorAgent,
			ResponderAgent: s.ResponderAgent,
			SessionID:      s.SessionID,
			CreatedAt:      s.CreatedAt,
			ObservedAt:     observedAt,
			Status:         statusForResults(m.results[key]),
			Metrics:        metrics,
		}
		if assignment := m.assignments[key]; assignment != nil {
			edge.InitiatorRegisteredAt = assignment.initiator.registeredAt
			edge.ResponderRegisteredAt = assignment.responder.registeredAt
		}
		edges = append(edges, edge)
	}
	return edges
}

// DegradedSignal turns an admitted measurement reporting loss into evidence.
func (r MeshResult) DegradedSignal() (incident.Signal, bool) {
	if r.Success && r.LossRatio <= 0 {
		return incident.Signal{}, false
	}
	return incident.Signal{
		TenantID:   r.TenantID,
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
	}, true
}

func statusForResults(results []MeshResult) string {
	for _, r := range results {
		if !r.Success || r.LossRatio > 0 {
			return meshStatusDegraded
		}
	}
	if len(results) < 2 {
		return meshStatusPending
	}
	return meshStatusHealthy
}

// Prefer the worse outcome when the two roles disagree. For equal loss, the
// initiator's measurements include round-trip latency as well as loss.
func topologyMetrics(results []MeshResult) (map[string]float64, *time.Time) {
	if len(results) == 0 {
		return nil, nil
	}
	selected := results[0]
	for _, r := range results[1:] {
		if r.LossRatio > selected.LossRatio || r.LossRatio == selected.LossRatio && r.Role == "initiator" {
			selected = r
		}
	}
	return copyMetrics(selected.Metrics), &selected.RecordedAt
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
	return "site:" + url.PathEscape(from) + "->site:" + url.PathEscape(to)
}
