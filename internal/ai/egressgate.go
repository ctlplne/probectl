// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"fmt"

	"github.com/ctlplne/probectl/internal/auth"
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

// denialReason checks the tenant's egress consent and returns a bounded audit
// category. It deliberately discards policy error text so datastore details and
// policy content can never enter an immutable egress record.
func (g *EgressGate) denialReason(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", ErrNoTenant
	}
	if g == nil || g.policy == nil {
		return "policy_unavailable", nil
	}
	allowed, err := g.policy(ctx, tenantID)
	if err != nil {
		return "policy_error", nil
	}
	if !allowed {
		return "consent_missing", nil
	}
	return "", nil
}

// AuthorizeAttempt checks consent for a known-tenant remote attempt and durably
// records any denial before returning it. A failed/missing audit sink supersedes
// the policy denial with ErrEgressAuditUnavailable, ensuring callers never
// mistake an unrecorded decision for a completed gate.
//
// This is the ONLY consent entry point. A record-free variant used to exist
// beside it, and the MCP surface used it — so MCP denials were absent from the
// egress stream while RCA and author denials were in it (S-063994f7). Deleting
// the variant is what makes "every refused egress attempt is durably recorded"
// a property of the type rather than a convention callers must remember.
func (g *EgressGate) AuthorizeAttempt(ctx context.Context, ev EgressEvent) error {
	reason, err := g.denialReason(ctx, ev.TenantID)
	if err != nil {
		return err
	}
	if reason == "" {
		return nil
	}
	ev.Denied = true
	ev.DenialReason = reason
	if err := g.Emit(ctx, ev); err != nil {
		return err
	}
	return ErrEgressDenied
}

// RedactForTenant applies the gate's redaction policy with tenant-scoped
// keyed tokens. Use this for every real egress surface; Redact remains only
// as the tenantless test/helper wrapper.
func (g *EgressGate) RedactForTenant(s, tenantID string) string {
	if g == nil {
		return redactTextForTenant(s, DefaultRedaction, tenantID)
	}
	return redactTextForTenant(s, g.redact, tenantID)
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

// Emit durably records one egress event. Missing or failed storage is a
// fail-closed error that callers must handle before dispatch/output.
func (g *EgressGate) Emit(ctx context.Context, ev EgressEvent) error {
	if g == nil {
		return ErrEgressAuditUnavailable
	}
	return emitEgressAudit(ctx, g.audit, ev)
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
	ev := EgressEvent{
		TenantID: p.TenantID,
		Endpoint: rm.Endpoint(),
		Model:    c.inner.Name(),
		Surface:  "author",
	}
	if err := c.gate.AuthorizeAttempt(ctx, ev); err != nil {
		return "", err
	}
	if err := c.gate.Emit(ctx, ev); err != nil {
		return "", err
	}
	// The adapter redacts again on its own remote path (defense in depth);
	// masking is stable so double application cannot leak or churn tokens.
	out, err := c.inner.Complete(ctx, system, c.gate.RedactForTenant(user, p.TenantID))
	if err != nil {
		return "", err
	}
	return out, nil
}
