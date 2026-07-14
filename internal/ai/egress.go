// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// EgressEvent describes one external-AI egress for the audit trail: WHAT
// leaves (data categories, never the content), WHERE to, for WHOM, and from
// WHICH surface.
type EgressEvent struct {
	TenantID      string
	Endpoint      string
	Model         string
	EvidenceCount int
	Planes        []string // sorted, de-duplicated evidence planes (data categories)
	// Surface is the egress path: "rca" (remote synthesis model), "author"
	// (test-authoring model), or "mcp" (tool results to an external AI
	// client). One gate, three doors — the audit says which (AIRCA-001).
	Surface string
	// Denied is true when the gate refused the attempted external call before
	// any tenant evidence left the deployment. DenialReason is a bounded
	// machine-readable category; it never contains policy errors or telemetry.
	Denied       bool
	DenialReason string
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
	planeSet := map[string]bool{}
	for _, e := range in.Evidence {
		planeSet[planeLabel(e)] = true
	}
	planes := make([]string, 0, len(planeSet))
	for p := range planeSet {
		planes = append(planes, p)
	}
	sort.Strings(planes)
	event := &EgressEvent{
		TenantID:      tenantID,
		Endpoint:      rm.Endpoint(),
		Model:         a.model.Name(),
		EvidenceCount: len(in.Evidence),
		Planes:        planes,
		Surface:       "rca",
	}
	deny := func(reason string) (*EgressEvent, error) {
		event.Denied = true
		event.DenialReason = reason
		if a.egressAudit != nil {
			a.egressAudit(ctx, *event)
		}
		return nil, ErrEgressDenied
	}
	if a.egressPolicy == nil {
		return deny("policy_unavailable")
	}
	allowed, err := a.egressPolicy(ctx, tenantID)
	if err != nil {
		// Policy lookup failures are indistinguishable from no consent. Fail
		// closed and keep the internal datastore error out of the response.
		return deny("policy_error")
	}
	if !allowed {
		return deny("consent_missing")
	}
	return event, nil
}
