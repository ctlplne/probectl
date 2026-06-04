package a2a

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

// Broker coordinates agent-to-agent sessions. All methods are safe for
// concurrent use and tenant-scoped.
type Broker struct {
	mu       sync.Mutex
	now      func() time.Time
	ttl      time.Duration
	newID    func() (string, error)
	sessions map[string]*session
	pending  map[agentKey][]Task
}

// NewBroker returns a broker with a 60s session TTL.
func NewBroker() *Broker {
	return &Broker{
		now:      time.Now,
		ttl:      60 * time.Second,
		newID:    randomID,
		sessions: map[string]*session{},
		pending:  map[agentKey][]Task{},
	}
}

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
	b.sessions[id] = &session{
		tenantID: tenantID, responder: responderAgent, initiator: initiatorAgent,
		mode: mode, count: count, createdAt: b.now(),
	}
	b.enqueueLocked(tenantID, responderAgent, Task{
		SessionID: id, Role: RoleResponder, Mode: mode, Count: count, PeerAgentID: initiatorAgent,
	})
	return id, nil
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
	return t, true
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
	b.pending[k] = append(b.pending[k], t)
}

func (b *Broker) gcLocked() {
	cutoff := b.now().Add(-b.ttl)
	for id, s := range b.sessions {
		if s.createdAt.Before(cutoff) {
			delete(b.sessions, id)
		}
	}
}
