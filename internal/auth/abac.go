// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

// ABAC over RBAC (S31, F25). The two-level boundary already resolves the tenant
// then RBAC; ABAC is a THIRD check layered on top: tenant-scoped attribute
// policies that can DENY a permission an RBAC role grants, based on the subject's
// attributes (e.g. department, mfa) and the resource's attributes (e.g. org/team/
// project — delegated admin). The model is intentionally deny-override: RBAC is
// the baseline grant, and ABAC narrows it. An allow policy is a silent permit
// (RBAC already permitted), so ABAC never widens access beyond RBAC.

// PolicyEffect is a policy's decision.
type PolicyEffect string

const (
	PolicyAllow PolicyEffect = "allow"
	PolicyDeny  PolicyEffect = "deny"
)

// Policy is one tenant-scoped attribute policy. It applies to a permission (or "*"
// for any) and matches when EVERY listed subject attribute and EVERY listed
// resource attribute equals the request's value. Among matching policies the
// highest Priority decides; a deny wins ties (deny-override).
type Policy struct {
	ID         string            `json:"id,omitempty"`
	Name       string            `json:"name"`
	Effect     PolicyEffect      `json:"effect"`
	Permission string            `json:"permission"` // "*" = any
	Subject    map[string]string `json:"subject,omitempty"`
	Resource   map[string]string `json:"resource,omitempty"`
	Priority   int               `json:"priority"`
	Enabled    bool              `json:"enabled"`
}

// Evaluate returns the ABAC decision for a permission given the subject/resource
// attributes, or "" when no policy applies (ABAC is silent — RBAC governs).
func Evaluate(policies []Policy, permission string, subject, resource map[string]string) PolicyEffect {
	decided := PolicyEffect("")
	bestPriority := 0
	for i := range policies {
		p := policies[i]
		if !p.Enabled {
			continue
		}
		if p.Permission != "*" && p.Permission != permission {
			continue
		}
		if !attrsSubset(p.Subject, subject) || !attrsSubset(p.Resource, resource) {
			continue
		}
		switch {
		case decided == "" || p.Priority > bestPriority:
			decided, bestPriority = p.Effect, p.Priority
		case p.Priority == bestPriority && p.Effect == PolicyDeny:
			decided = PolicyDeny // deny-override on ties
		}
	}
	return decided
}

// permit is Decide's boolean shadow for the abac unit tests; Decide is the
// full ordered evaluation every surface routes through.
func permit(p *Principal, permission string, policies []Policy, resource map[string]string) bool {
	return Decide(p, permission, RBACGlobal, policies, resource) == DecisionAllowed
}

// ResourceTenantKey is the resource-attribute key carrying the tenant a resource
// belongs to. Authorize compares it against the principal's tenant so a request
// can never be authorized against another tenant's resource (defense-in-depth
// ABOVE the storage-layer RLS, per CLAUDE.md guardrail 1 — "tenant first, then
// RBAC"). When the key is absent the resource is tenant-agnostic (no boundary
// check applies; RBAC/ABAC still do).
const ResourceTenantKey = "tenant"

// Authorize is the single access decision in the documented order: the TENANT
// BOUNDARY is checked first (fail closed on a cross-tenant resource), THEN RBAC
// (the permission must be held), THEN ABAC (no deny policy fires). It returns
// false the moment any layer refuses — there is no path where a stronger inner
// grant overrides the outer tenant boundary. A nil principal is never authorized.
//
// This is the one place the "tenant first, then RBAC" rule (guardrail 1, also the
// AI/MCP enforcement order) is encoded; handlers and the MCP tool layer route
// their decision through it rather than re-implementing the order ad hoc.
func Authorize(p *Principal, permission string, policies []Policy, resource map[string]string) bool {
	return Decide(p, permission, RBACGlobal, policies, resource) == DecisionAllowed
}

// attrsSubset reports whether every key/value in required is present and equal in
// actual. An empty requirement matches anything.
func attrsSubset(required, actual map[string]string) bool {
	for k, v := range required {
		if actual[k] != v {
			return false
		}
	}
	return true
}

func attrsOf(p *Principal) map[string]string {
	if p == nil {
		return nil
	}
	return p.Attributes
}

// RBACCheck selects how the RBAC layer of a Decision evaluates.
type RBACCheck int

const (
	// RBACGlobal requires the permission tenant-wide (Principal.Has).
	RBACGlobal RBACCheck = iota
	// RBACAnyScope admits a scoped grant at the route edge (Principal.HasAny);
	// the handler then re-checks against the resolved resource lineage.
	RBACAnyScope
	// RBACPreverified records that a FINER RBAC check (HasAt on a resolved
	// lineage, or a route-edge check for a different permission) already
	// happened upstream; the decision applies only the tenant boundary and the
	// ABAC deny layer. Use it to bring post-resolution re-authorizations
	// through the same door, never to skip RBAC where none ran.
	RBACPreverified
)

// DecisionReason says which layer refused (or that none did).
type DecisionReason int

const (
	DecisionAllowed DecisionReason = iota
	DecisionUnauthenticated
	DecisionTenantBoundary
	DecisionRBAC
	DecisionPolicyDeny
)

// Decide is the S-6357f747 authorization chokepoint: ONE evaluation of the
// documented order — tenant boundary first, then RBAC (per mode), then ABAC
// deny-override — reporting which layer refused. Authorize is its boolean
// shadow; the control plane's Server.decide and the MCP dispatch both route
// here, so no surface re-implements the sequence.
func Decide(p *Principal, permission string, mode RBACCheck, policies []Policy, resource map[string]string) DecisionReason {
	if p == nil {
		return DecisionUnauthenticated
	}
	if rt, ok := resource[ResourceTenantKey]; ok && rt != "" && rt != p.TenantID {
		return DecisionTenantBoundary
	}
	switch mode {
	case RBACGlobal:
		if !p.Has(permission) {
			return DecisionRBAC
		}
	case RBACAnyScope:
		if !p.HasAny(permission) {
			return DecisionRBAC
		}
	case RBACPreverified:
		// RBAC already evaluated upstream against a finer scope.
	}
	if Evaluate(policies, permission, attrsOf(p), resource) == PolicyDeny {
		return DecisionPolicyDeny
	}
	return DecisionAllowed
}
