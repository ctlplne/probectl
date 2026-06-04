package threat

import (
	"sort"
	"sync"
)

// PostureStore retains the LATEST analyzed TLS posture per (tenant, target) —
// the certificate inventory behind the S-FE2 surface. It is rebuilt from the
// result stream (like the device correlator): in-memory, tenant-partitioned,
// and bounded per tenant (evict-oldest-observation) so a hostile or
// misconfigured fleet cannot grow it without limit. Clean postures are
// retained too — an inventory that only listed broken certs would hide the
// fleet. Cross-tenant reads are impossible by construction: every method takes
// the tenant first and only touches that tenant's partition (CLAUDE.md §7
// guardrail 1).
type PostureStore struct {
	mu      sync.Mutex
	max     int
	tenants map[string]map[string]Posture // tenant -> target -> latest posture
}

// DefaultMaxTargetsPerTenant bounds each tenant's inventory partition.
const DefaultMaxTargetsPerTenant = 5000

// NewPostureStore builds a store; maxPerTenant <= 0 takes the default.
func NewPostureStore(maxPerTenant int) *PostureStore {
	if maxPerTenant <= 0 {
		maxPerTenant = DefaultMaxTargetsPerTenant
	}
	return &PostureStore{max: maxPerTenant, tenants: map[string]map[string]Posture{}}
}

// Record stores the posture as the target's latest (newer observations win;
// an out-of-order older observation never overwrites a newer one). When a
// tenant's partition is full, the stalest target is evicted.
func (s *PostureStore) Record(tenant string, p Posture) {
	if tenant == "" || p.Target == "" {
		return // never store unscoped data (fail closed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	part, ok := s.tenants[tenant]
	if !ok {
		part = map[string]Posture{}
		s.tenants[tenant] = part
	}
	if prev, exists := part[p.Target]; exists {
		if p.ObservedAt.Before(prev.ObservedAt) {
			return
		}
		part[p.Target] = p
		return
	}
	if len(part) >= s.max {
		stalest, found := "", false
		for tgt, q := range part {
			if !found || q.ObservedAt.Before(part[stalest].ObservedAt) {
				stalest, found = tgt, true
			}
		}
		if found {
			delete(part, stalest)
		}
	}
	part[p.Target] = p
}

// List returns the tenant's inventory: highest severity first, then soonest
// leaf expiry, then target (a stable, worklist-friendly order).
func (s *PostureStore) List(tenant string) []Posture {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.tenants[tenant]
	out := make([]Posture, 0, len(part))
	for _, p := range part {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := sevRank(out[i].Severity), sevRank(out[j].Severity); ri != rj {
			return ri > rj
		}
		li, lj := out[i].Leaf, out[j].Leaf
		switch {
		case li != nil && lj != nil && !li.NotAfter.Equal(lj.NotAfter):
			return li.NotAfter.Before(lj.NotAfter)
		case (li != nil) != (lj != nil):
			return li != nil // certs before cert-less observations
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// Len reports one tenant's inventory size.
func (s *PostureStore) Len(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tenants[tenant])
}
