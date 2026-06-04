package endpoint

import (
	"sort"
	"sync"
	"time"
)

// The endpoint DEM read model (S-FE4 surface for S37). The agent emits one
// canary Result per DEM signal (attribution/wifi/gateway/lastmile/session);
// this store retains the LATEST of each per (tenant, agent) and assembles them
// into per-endpoint views — the fleet list + detail the surface renders.
//
// Privacy (S37) is upstream and absolute: identifiers the agent withheld
// (SSID/BSSID/gateway IP/public hops) are simply ABSENT from the results and
// therefore absent here — the store never re-derives or back-fills them, and
// the UI renders absence honestly ("withheld"), never a fabricated value.
// Tenant partitioning makes cross-tenant reads impossible by construction
// (CLAUDE.md §7 guardrail 1); both the agent count per tenant and the session
// targets per agent are bounded (evict-stalest).

// ResultView is the latest observation of one DEM signal type on one endpoint.
type ResultView struct {
	Type       string             `json:"type"`
	Target     string             `json:"target,omitempty"`
	Success    bool               `json:"success"`
	Error      string             `json:"error,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Attributes map[string]string  `json:"attributes,omitempty"`
	ObservedAt time.Time          `json:"observed_at"`
}

// View is one endpoint's assembled DEM state.
type View struct {
	AgentID    string    `json:"agent_id"`
	LastSeenAt time.Time `json:"last_seen_at"`

	// The attribution headline (from the latest endpoint.attribution result).
	Cause      string  `json:"cause,omitempty"`
	Summary    string  `json:"summary,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Slow       bool    `json:"slow"`

	Attribution *ResultView  `json:"attribution,omitempty"`
	WiFi        *ResultView  `json:"wifi,omitempty"`
	Gateway     *ResultView  `json:"gateway,omitempty"`
	LastMile    *ResultView  `json:"last_mile,omitempty"`
	Sessions    []ResultView `json:"sessions,omitempty"`
}

// Bounds (evict-stalest beyond these).
const (
	DefaultMaxEndpointsPerTenant = 2000
	maxSessionTargetsPerAgent    = 10
)

type agentState struct {
	lastSeen time.Time
	byType   map[string]ResultView // attribution/wifi/gateway/lastmile -> latest
	sessions map[string]ResultView // session target -> latest
}

// SnapshotStore retains the latest DEM state per (tenant, agent).
type SnapshotStore struct {
	mu      sync.Mutex
	max     int
	tenants map[string]map[string]*agentState
}

// NewSnapshotStore builds a store; maxPerTenant <= 0 takes the default.
func NewSnapshotStore(maxPerTenant int) *SnapshotStore {
	if maxPerTenant <= 0 {
		maxPerTenant = DefaultMaxEndpointsPerTenant
	}
	return &SnapshotStore{max: maxPerTenant, tenants: map[string]map[string]*agentState{}}
}

// Record stores one DEM result as the agent's latest of its type. Unscoped or
// non-endpoint results are dropped (fail closed); out-of-order older
// observations never overwrite newer ones.
func (s *SnapshotStore) Record(tenant, agent string, rv ResultView) {
	if tenant == "" || agent == "" {
		return
	}
	switch rv.Type {
	case TypeAttribution, TypeWiFi, TypeGateway, TypeLastMile, TypeSession:
	default:
		return // not a DEM signal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	part, ok := s.tenants[tenant]
	if !ok {
		part = map[string]*agentState{}
		s.tenants[tenant] = part
	}
	st, ok := part[agent]
	if !ok {
		if len(part) >= s.max {
			stalest, found := "", false
			for id, a := range part {
				if !found || a.lastSeen.Before(part[stalest].lastSeen) {
					stalest, found = id, true
				}
			}
			if found {
				delete(part, stalest)
			}
		}
		st = &agentState{byType: map[string]ResultView{}, sessions: map[string]ResultView{}}
		part[agent] = st
	}
	if rv.ObservedAt.After(st.lastSeen) {
		st.lastSeen = rv.ObservedAt
	}
	if rv.Type == TypeSession {
		if prev, exists := st.sessions[rv.Target]; exists && rv.ObservedAt.Before(prev.ObservedAt) {
			return
		}
		if _, exists := st.sessions[rv.Target]; !exists && len(st.sessions) >= maxSessionTargetsPerAgent {
			stalest, found := "", false
			for tgt, v := range st.sessions {
				if !found || v.ObservedAt.Before(st.sessions[stalest].ObservedAt) {
					stalest, found = tgt, true
				}
			}
			if found {
				delete(st.sessions, stalest)
			}
		}
		st.sessions[rv.Target] = rv
		return
	}
	if prev, exists := st.byType[rv.Type]; exists && rv.ObservedAt.Before(prev.ObservedAt) {
		return
	}
	st.byType[rv.Type] = rv
}

// List assembles the tenant's endpoint views: impaired (slow) endpoints first,
// then most recently seen.
func (s *SnapshotStore) List(tenant string) []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.tenants[tenant]
	out := make([]View, 0, len(part))
	for agent, st := range part {
		v := View{AgentID: agent, LastSeenAt: st.lastSeen}
		if a, ok := st.byType[TypeAttribution]; ok {
			av := a
			v.Attribution = &av
			v.Cause = a.Attributes["endpoint.cause"]
			v.Summary = a.Attributes["endpoint.summary"]
			v.Confidence = a.Metrics["confidence"]
			v.Slow = a.Metrics["slow"] > 0
		}
		if w, ok := st.byType[TypeWiFi]; ok {
			wv := w
			v.WiFi = &wv
		}
		if g, ok := st.byType[TypeGateway]; ok {
			gv := g
			v.Gateway = &gv
		}
		if lm, ok := st.byType[TypeLastMile]; ok {
			lv := lm
			v.LastMile = &lv
		}
		if len(st.sessions) > 0 {
			sessions := make([]ResultView, 0, len(st.sessions))
			for _, sv := range st.sessions {
				sessions = append(sessions, sv)
			}
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Target < sessions[j].Target })
			v.Sessions = sessions
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slow != out[j].Slow {
			return out[i].Slow
		}
		if !out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

// Len reports one tenant's endpoint count.
func (s *SnapshotStore) Len(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tenants[tenant])
}
