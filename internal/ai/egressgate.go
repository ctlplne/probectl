package ai

import (
	"context"
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// EgressGate is THE gate for external-AI egress (AIRCA-001/005): every
// surface that sends tenant data to an external AI — the RCA analyzer's
// remote model, the MCP server's tool results (the MCP caller IS an external
// AI client), and the test-authoring model — draws consent, redaction, and
// audit from one instance, constructed once in the control plane. No surface
// carries its own copy of the policy, so no surface can drift or bypass.
//
// Provider selection stays as decided elsewhere (config: builtin air-gapped
// is the default — stricter than a local Ollama; remote requires the
// operator's config-time acknowledgment). The gate adds the PER-TENANT
// consent (tenant_governance.ai_remote_egress, default deny), the C8
// redaction policy, and the audit emission.
type EgressGate struct {
	policy EgressPolicy
	audit  EgressAudit
	redact RedactionPolicy
}

// NewEgressGate builds the gate. A nil policy means NO consent source:
// every remote egress is denied (fail closed).
func NewEgressGate(policy EgressPolicy, audit EgressAudit, redact RedactionPolicy) *EgressGate {
	return &EgressGate{policy: policy, audit: audit, redact: redact}
}

// Authorize checks the tenant's egress consent. Fail closed: no policy
// wired, a policy error, or no consent — all deny.
func (g *EgressGate) Authorize(ctx context.Context, tenantID string) error {
	if g == nil || g.policy == nil {
		return ErrEgressDenied
	}
	if tenantID == "" {
		return ErrNoTenant
	}
	allowed, err := g.policy(ctx, tenantID)
	if err != nil {
		return ErrEgressDenied
	}
	if !allowed {
		return ErrEgressDenied
	}
	return nil
}

// Redact applies the gate's redaction policy to one string (secrets always;
// IPs/hostnames/PII/custom per policy).
func (g *EgressGate) Redact(s string) string {
	if g == nil {
		return redactText(s, DefaultRedaction)
	}
	return redactText(s, g.redact)
}

// Redaction exposes the gate's policy for adapters that redact structured
// inputs themselves (the RCA model adapter).
func (g *EgressGate) Redaction() RedactionPolicy {
	if g == nil {
		return DefaultRedaction
	}
	return g.redact
}

// Policy exposes the consent source so the Analyzer's existing egress seam
// can draw from the same instance.
func (g *EgressGate) Policy() EgressPolicy {
	if g == nil {
		return nil
	}
	return g.policy
}

// AuditHook exposes the audit sink for the same reason.
func (g *EgressGate) AuditHook() EgressAudit {
	if g == nil {
		return nil
	}
	return g.audit
}

// Emit records one egress event (no-op without a sink).
func (g *EgressGate) Emit(ctx context.Context, ev EgressEvent) {
	if g == nil || g.audit == nil {
		return
	}
	g.audit(ctx, ev)
}

// WithEgressGate wires the Analyzer's consent + audit from the shared gate —
// the construction-site guarantee that RCA and every other surface enforce
// the SAME policy.
func WithEgressGate(g *EgressGate) AnalyzerOption {
	return func(a *Analyzer) {
		a.egressPolicy = g.Policy()
		a.egressAudit = g.AuditHook()
	}
}

// RemoteCompleter is the chat seam a GatedCompleter wraps (satisfied by
// *HTTPModel). RemoteEgresser (when implemented) tells the gate whether
// calls leave the host.
type RemoteCompleter interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// GatedCompleter routes the generic chat seam (test authoring, AIRCA-005)
// through the egress gate: per-tenant consent (from the request principal on
// ctx), redaction of the outbound prompt, and an audit event per call.
// Local/loopback models pass through untouched — the same exemption as RCA.
type GatedCompleter struct {
	inner RemoteCompleter
	gate  *EgressGate
}

// NewGatedCompleter wraps a model's chat seam with the gate.
func NewGatedCompleter(inner RemoteCompleter, gate *EgressGate) *GatedCompleter {
	return &GatedCompleter{inner: inner, gate: gate}
}

// Name identifies the underlying model.
func (c *GatedCompleter) Name() string { return c.inner.Name() }

// Complete enforces the gate, then delegates. The tenant comes from the
// authenticated principal on ctx — absent principal = no egress (fail
// closed), exactly like an unauthenticated API call.
func (c *GatedCompleter) Complete(ctx context.Context, system, user string) (string, error) {
	rm, ok := c.inner.(RemoteEgresser)
	if !ok || !rm.RemoteEgress() {
		return c.inner.Complete(ctx, system, user) // local model: exempt
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil || p.TenantID == "" {
		return "", fmt.Errorf("ai: authoring egress without an authenticated tenant: %w", ErrNoTenant)
	}
	if err := c.gate.Authorize(ctx, p.TenantID); err != nil {
		return "", err
	}
	// The adapter redacts again on its own remote path (defense in depth);
	// masking is stable so double application cannot leak or churn tokens.
	out, err := c.inner.Complete(ctx, system, c.gate.Redact(user))
	if err != nil {
		return "", err
	}
	c.gate.Emit(ctx, EgressEvent{
		TenantID: p.TenantID,
		Endpoint: rm.Endpoint(),
		Model:    c.inner.Name(),
		Surface:  "author",
	})
	return out, nil
}
