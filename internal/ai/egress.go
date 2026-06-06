package ai

import (
	"context"
	"errors"
	"sort"
)

// Remote-model egress controls (U-013). A REMOTE model means tenant telemetry
// leaves the operator's network: that requires (1) the operator's explicit
// config-time acknowledgment (enforced by internal/config — the server
// refuses to start without it), (2) the TENANT's policy opting in
// (tenant_governance.ai_remote_egress, default false), and (3) an audit
// event for every call that leaves. The local/air-gapped path (builtin, or a
// loopback Ollama/vLLM) is exempt from all three.

// RemoteEgresser is implemented by adapters whose Synthesize sends data off
// the local host. The built-in model does not implement it; HTTPModel
// reports true only for non-loopback endpoints.
type RemoteEgresser interface {
	RemoteEgress() bool
	Endpoint() string
}

// EgressEvent describes one remote-model call for the audit trail: WHAT
// leaves (data categories, never the content), WHERE to, and for WHOM.
type EgressEvent struct {
	TenantID      string
	Endpoint      string
	Model         string
	EvidenceCount int
	Planes        []string // sorted, de-duplicated evidence planes (data categories)
}

// EgressPolicy reports whether tenantID's data may be sent to a remote
// model. The control plane backs it with tenant_governance.ai_remote_egress.
type EgressPolicy func(ctx context.Context, tenantID string) (bool, error)

// EgressAudit observes every remote-model call (the control plane appends it
// to the tenant's tamper-evident audit stream as "ai.remote_egress").
type EgressAudit func(ctx context.Context, ev EgressEvent)

// WithEgressPolicy sets the per-tenant remote-egress gate.
func WithEgressPolicy(p EgressPolicy) AnalyzerOption {
	return func(a *Analyzer) { a.egressPolicy = p }
}

// WithEgressAudit sets the egress audit hook.
func WithEgressAudit(h EgressAudit) AnalyzerOption {
	return func(a *Analyzer) { a.egressAudit = h }
}

// ErrEgressDenied is returned when the model is remote and the tenant has not
// opted in to remote-model egress.
var ErrEgressDenied = errors.New(
	"ai: this tenant has not consented to sending data to a remote model (tenant_governance.ai_remote_egress; ask an operator) — " +
		"the air-gapped builtin and loopback local models need no consent")

// checkEgress gates a remote model behind the tenant policy (fail closed:
// remote + no policy wired = denied) and returns the audit event to emit on
// success. A local model returns (nil, nil).
func (a *Analyzer) checkEgress(ctx context.Context, tenantID string, in SynthesisInput) (*EgressEvent, error) {
	rm, ok := a.model.(RemoteEgresser)
	if !ok || !rm.RemoteEgress() {
		return nil, nil // air-gapped builtin or loopback local model: no egress
	}
	if a.egressPolicy == nil {
		return nil, ErrEgressDenied
	}
	allowed, err := a.egressPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrEgressDenied
	}
	planeSet := map[string]bool{}
	for _, e := range in.Evidence {
		planeSet[planeLabel(e)] = true
	}
	planes := make([]string, 0, len(planeSet))
	for p := range planeSet {
		planes = append(planes, p)
	}
	sort.Strings(planes)
	return &EgressEvent{
		TenantID:      tenantID,
		Endpoint:      rm.Endpoint(),
		Model:         a.model.Name(),
		EvidenceCount: len(in.Evidence),
		Planes:        planes,
	}, nil
}
