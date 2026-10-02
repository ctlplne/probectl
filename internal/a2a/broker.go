// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Role is an agent's role in an agent-to-agent session.
type Role int

const (
	// RoleResponder opens a listener and echoes probes.
	RoleResponder Role = iota + 1
	// RoleInitiator connects to the responder and measures.
	RoleInitiator
)

// Task is one brokered assignment handed to an agent when it polls.
type Task struct {
	SessionID     string
	Role          Role
	Mode          string // "udp" | "tcp"
	Count         uint32
	ResponderHost string // set for the initiator
	ResponderPort uint32 // set for the initiator
	PeerAgentID   string
}

type session struct {
	tenantID         string
	responder        string
	initiator        string
	mode             string
	count            uint32
	createdAt        time.Time
	endpointReported bool
}

type agentKey struct{ tenant, agent string }

// pendingTask is a queued task plus the time it was enqueued, so the broker can
// reclaim tasks that were never polled (INJ-06): an initiator or responder that
// never comes back to poll — a ghost or never-enrolled agent id named in a mesh
// request — would otherwise leave its task in b.pending forever, and gcLocked
// only ever reclaimed sessions.
type pendingTask struct {
	task Task
	at   time.Time
}

// gcMinInterval throttles the pending/session sweep (AI-01/RTA-02): gcLocked
// scans b.pending and b.sessions, so running it on every StartSession made a
// single 64-site mesh (4032 StartSessions) O(sites^2 * pending) — up to seconds
// of CPU once a tenant had inflated the pending backlog. The sweep now runs at
// most once per interval regardless of call rate (O(1) amortized per call); the
// per-tenant caps bound a single sweep's cost, and TTL reclamation still happens
// within one interval of the TTL. An injected clock jump (tests) always sweeps.
const gcMinInterval = 1 * time.Second

// maxPendingPerTenant bounds the tasks a single tenant can have queued but
// unpolled at once (INJ-06). Age-out (gcLocked) reclaims tasks for agents that
// never poll, but only after the TTL; this cap bounds the memory a burst of
// mesh requests naming never-polling agent ids can pin WITHIN one TTL window.
// A full 64-site mesh queues 64*63 = 4032 responder tasks, so this admits ~24
// outstanding full meshes per tenant (~a few MiB) before new sessions are
// refused until the queue drains or ages out — a stateless control plane must
// never let one editor's requests grow memory without bound (docs/guardrails.md
// G7-1 fail-closed).
const maxPendingPerTenant = 100_000

// Broker coordinates agent-to-agent sessions. All methods are safe for
// concurrent use and tenant-scoped.
type Broker struct {
	mu       sync.Mutex
	now      func() time.Time
	ttl      time.Duration
	newID    func() (string, error)
	sessions map[string]*session
	pending  map[agentKey][]pendingTask
	// pendingByTenant counts queued tasks per tenant so the per-tenant cap is
	// O(1) to check without scanning every agent key.
	pendingByTenant map[string]int
	// lastGC is when the sweep last ran, so gcLocked can throttle to at most once
	// per gcMinInterval (AI-01/RTA-02). Zero means never, so the first call runs.
	lastGC time.Time
}

// NewBroker returns a broker with a 60s session TTL.
func NewBroker() *Broker {
	return &Broker{
		now:             time.Now,
		ttl:             60 * time.Second,
		newID:           randomID,
		sessions:        map[string]*session{},
		pending:         map[agentKey][]pendingTask{},
		pendingByTenant: map[string]int{},
	}
}

// ErrPendingFull is returned when a tenant already holds the maximum number of
// unpolled tasks. The mesh/session handlers map it to HTTP 429/400 — the
// control plane refuses new work rather than growing memory (INJ-06).
var ErrPendingFull = errors.New("a2a: tenant has too many unpolled tasks; let agents poll or retry later")

func randomID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// StartSession brokers a session between two agents in a tenant: responderAgent
// opens a listener, initiatorAgent measures to it. It queues the responder's
// task and returns the session id.
func (b *Broker) StartSession(tenantID, responderAgent, initiatorAgent, mode string, count uint32) (string, error) {
	if tenantID == "" || responderAgent == "" || initiatorAgent == "" {
		return "", errors.New("a2a: tenant, responder, and initiator are required")
	}
	if responderAgent == initiatorAgent {
		return "", errors.New("a2a: responder and initiator must differ")
	}
	if mode != "udp" && mode != "tcp" {
		return "", fmt.Errorf("a2a: unknown mode %q (want udp|tcp)", mode)
	}
	if count == 0 {
		count = 5
	}
	id, err := b.newID()
	if err != nil {
		return "", err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcLocked()
	// Fail closed before allocating a session id's worth of state if the tenant
	// is already at its unpolled-task cap (INJ-06).
	if b.pendingByTenant[tenantID] >= maxPendingPerTenant {
		return "", ErrPendingFull
	}
	b.sessions[id] = &session{
		tenantID: tenantID, responder: responderAgent, initiator: initiatorAgent,
		mode: mode, count: count, createdAt: b.now(),
	}
	b.enqueueLocked(tenantID, responderAgent, Task{
		SessionID: id, Role: RoleResponder, Mode: mode, Count: count, PeerAgentID: initiatorAgent,
	})
	return id, nil
}

// SweepNow forces the pending/session reclaim immediately, bypassing the gc
// throttle (AI-01). The control plane's janitor calls it on a ticker so a broker
// with no live traffic still releases tasks whose agents never polled, rather
// than waiting for the next StartSession/PollFor to trigger a throttled sweep.
func (b *Broker) SweepNow() {
	b.mu.Lock()
	b.lastGC = time.Time{}
	b.gcLocked()
	b.mu.Unlock()
}

// PendingCount returns the number of queued-but-unpolled tasks for a tenant,
// after reclaiming any that have aged out. Callers use it to reject work that
// would exceed the per-tenant cap before doing O(n^2) scheduling.
func (b *Broker) PendingCount(tenantID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcLocked()
	return b.pendingByTenant[tenantID]
}

// PollFor returns and removes the next pending task for an agent (at-most-once).
func (b *Broker) PollFor(tenantID, agentID string) (Task, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcLocked()
	k := agentKey{tenantID, agentID}
	q := b.pending[k]
	if len(q) == 0 {
		return Task{}, false
	}
	t := q[0]
	if len(q) == 1 {
		delete(b.pending, k)
	} else {
		b.pending[k] = q[1:]
	}
	b.decPendingLocked(tenantID, 1)
	return t.task, true
}

// ReportEndpoint records where the responder is listening and queues the
// initiator's task. Only the session's responder, in the session's tenant, may
// report — preventing cross-tenant or cross-agent endpoint injection.
func (b *Broker) ReportEndpoint(tenantID, agentID, sessionID, host string, port uint32) error {
	if host == "" || port == 0 {
		return errors.New("a2a: endpoint host and port are required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcLocked()
	s, ok := b.sessions[sessionID]
	if !ok {
		return errors.New("a2a: unknown or expired session")
	}
	if s.tenantID != tenantID || s.responder != agentID {
		return errors.New("a2a: caller is not the responder for this session")
	}
	if s.endpointReported {
		return nil // idempotent
	}
	s.endpointReported = true
	b.enqueueLocked(tenantID, s.initiator, Task{
		SessionID: sessionID, Role: RoleInitiator, Mode: s.mode, Count: s.count,
		ResponderHost: host, ResponderPort: port, PeerAgentID: s.responder,
	})
	return nil
}

func (b *Broker) enqueueLocked(tenant, agent string, t Task) {
	k := agentKey{tenant, agent}
	b.pending[k] = append(b.pending[k], pendingTask{task: t, at: b.now()})
	b.pendingByTenant[tenant]++
}

func (b *Broker) decPendingLocked(tenant string, n int) {
	if n <= 0 {
		return
	}
	b.pendingByTenant[tenant] -= n
	if b.pendingByTenant[tenant] <= 0 {
		delete(b.pendingByTenant, tenant)
	}
}

func (b *Broker) gcLocked() {
	// Throttle the scan to O(1) amortized per call (AI-01/RTA-02): a burst of
	// StartSessions from one mesh sweeps at most once, not once per session.
	now := b.now()
	if !b.lastGC.IsZero() && now.Sub(b.lastGC) < gcMinInterval {
		return
	}
	b.lastGC = now
	cutoff := now.Add(-b.ttl)
	for id, s := range b.sessions {
		if s.createdAt.Before(cutoff) {
			delete(b.sessions, id)
		}
	}
	// Reclaim tasks that were enqueued before the cutoff and never polled
	// (INJ-06): a task for an expired session is useless, and an agent id that
	// never comes back to poll must not pin memory forever. Without this,
	// b.pending (unlike b.sessions) grew without bound.
	for k, q := range b.pending {
		kept := q[:0]
		dropped := 0
		for _, pt := range q {
			if pt.at.Before(cutoff) {
				dropped++
				continue
			}
			kept = append(kept, pt)
		}
		if dropped > 0 {
			b.decPendingLocked(k.tenant, dropped)
		}
		if len(kept) == 0 {
			delete(b.pending, k)
		} else {
			b.pending[k] = kept
		}
	}
}
