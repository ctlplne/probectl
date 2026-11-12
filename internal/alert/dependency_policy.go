// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"math"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// DependencyPolicyInput configures notification handling, never collection,
// evaluation or remediation. A context selects current operator-owned identity
// and dependency sources; an address cannot implicitly select a context.
type DependencyPolicyInput struct {
	ContextID        string `json:"context_id"`
	FreshnessSeconds int64  `json:"freshness_seconds"`
}

type DependencyPolicyState struct {
	RuleID        string                 `json:"rule_id"`
	RuleUpdatedAt time.Time              `json:"rule_updated_at"`
	Configured    bool                   `json:"configured"`
	Policy        *DependencyPolicyInput `json:"policy,omitempty"`
}

func NormalizeDependencyPolicyInput(input DependencyPolicyInput) (DependencyPolicyInput, error) {
	if !canonicalQueryID(input.ContextID) {
		return DependencyPolicyInput{}, ErrDependencyEvidence
	}
	if input.FreshnessSeconds == 0 {
		input.FreshnessSeconds = 300
	}
	if input.FreshnessSeconds <= 0 || input.FreshnessSeconds > math.MaxInt64/int64(time.Second) {
		return DependencyPolicyInput{}, ErrDependencyEvidence
	}
	return input, nil
}

// DependencyPolicy is stored on the existing tenant-owned alert rule. Owner
// and read ceiling come only from its authenticated configuring credential.
// Every use must intersect them with current user/RBAC/ABAC/source authority.
type DependencyPolicy struct {
	Version          int              `json:"version"`
	OwnerUserID      string           `json:"owner_user_id"`
	ContextID        string           `json:"context_id"`
	FreshnessSeconds int64            `json:"freshness_seconds"`
	ReadGrants       []QueryReadGrant `json:"read_grants"`
}

func (policy DependencyPolicy) Input() DependencyPolicyInput {
	return DependencyPolicyInput{ContextID: policy.ContextID, FreshnessSeconds: policy.FreshnessSeconds}
}

func (policy DependencyPolicy) Validate() error {
	if policy.Version != 1 || !canonicalQueryID(policy.OwnerUserID) || len(policy.ReadGrants) == 0 {
		return ErrDependencyEvidence
	}
	normalized, err := NormalizeDependencyPolicyInput(policy.Input())
	if err != nil || normalized != policy.Input() {
		return ErrDependencyEvidence
	}
	for _, grant := range policy.ReadGrants {
		switch grant.Permission {
		case "topology.read", "entities.read", "test.read", "metrics.read", "events.read", "flow.read", "incident.read":
		default:
			return ErrDependencyEvidence
		}
		switch grant.ScopeType {
		case auth.ScopeTenant:
			if grant.ScopeID != "" {
				return ErrDependencyEvidence
			}
		case auth.ScopeOrganization, auth.ScopeTeam, auth.ScopeProject:
			if !canonicalQueryID(grant.ScopeID) {
				return ErrDependencyEvidence
			}
		default:
			return ErrDependencyEvidence
		}
	}
	return nil
}

func (policy DependencyPolicy) CredentialCeiling(tenant string) (*auth.Principal, error) {
	if err := policy.Validate(); err != nil || !canonicalQueryID(tenant) {
		return nil, ErrDependencyEvidence
	}
	grants := make([]auth.PermissionGrant, len(policy.ReadGrants))
	for i, grant := range policy.ReadGrants {
		grants[i] = auth.PermissionGrant{Permission: grant.Permission, ScopeType: grant.ScopeType, ScopeID: grant.ScopeID}
	}
	return auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: policy.OwnerUserID, ViaBearerToken: true}, grants), nil
}
