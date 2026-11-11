// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"math"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

const QueryMetric = "probectl_explorer_query_condition"

// QuerySourceInput accepts query configuration only. Owner and credential
// ceilings are always derived from the actual authenticated configuring user.
type QuerySourceInput struct {
	ViewID       string         `json:"view_id"`
	ViewVersion  string         `json:"view_version"`
	EverySeconds int64          `json:"every_seconds"`
	Condition    QueryCondition `json:"condition"`
}

// QueryRuleInput creates a saved-query rule without exposing its internal
// Boolean metric adapter. Delivery remains the existing human-configured path.
type QueryRuleInput struct {
	Name            string           `json:"name"`
	Enabled         *bool            `json:"enabled,omitempty"`
	QuerySource     QuerySourceInput `json:"query_source"`
	ForN            int              `json:"for_n,omitempty"`
	RenotifySeconds int              `json:"renotify_seconds,omitempty"`
	Severity        string           `json:"severity,omitempty"`
	Channels        []ChannelSpec    `json:"channels,omitempty"`
}

type QuerySourceState struct {
	RuleID        string            `json:"rule_id"`
	RuleUpdatedAt time.Time         `json:"rule_updated_at"`
	Configured    bool              `json:"configured"`
	Source        *QuerySourceInput `json:"source,omitempty"`
	NextAt        *time.Time        `json:"next_at,omitempty"`
	StaleRevision bool              `json:"stale_revision"`
}

func NormalizeQuerySourceInput(input QuerySourceInput) (QuerySourceInput, error) {
	if !canonicalQueryID(input.ViewID) {
		return QuerySourceInput{}, ErrQueryGroups
	}
	if _, err := flow.QueryViewVersion(input.ViewVersion); err != nil {
		return QuerySourceInput{}, err
	}
	if input.EverySeconds == 0 {
		input.EverySeconds = 60
	}
	if input.EverySeconds <= 0 || input.EverySeconds > math.MaxInt64/int64(time.Second) {
		return QuerySourceInput{}, ErrQueryGroups
	}
	if err := input.Condition.validateShape(); err != nil {
		return QuerySourceInput{}, err
	}
	return input, nil
}

func (s QuerySource) Input() QuerySourceInput {
	return QuerySourceInput{ViewID: s.ViewID, ViewVersion: s.ViewVersion, EverySeconds: s.EverySeconds, Condition: s.Condition}
}

// QueryReadGrant is a captured read-only credential ceiling. It is intersected
// with the active user's current RBAC and ABAC before every source read; it
// carries no bearer, session, attributes or reusable MFA assertion.
type QueryReadGrant struct {
	Permission string               `json:"permission"`
	ScopeType  auth.PermissionScope `json:"scope_type"`
	ScopeID    string               `json:"scope_id,omitempty"`
}

// QuerySource is configuration on an existing tenant-owned alert rule. The
// saved query remains the source of its plan, visibility and immutable tag IDs.
// An edit of that exact saved revision withholds work until explicitly rebound.
type QuerySource struct {
	Version      int              `json:"version"`
	OwnerUserID  string           `json:"owner_user_id"`
	ViewID       string           `json:"view_id"`
	ViewVersion  string           `json:"view_version"`
	EverySeconds int64            `json:"every_seconds"`
	Condition    QueryCondition   `json:"condition"`
	ReadGrants   []QueryReadGrant `json:"read_grants"`
}

func canonicalQueryID(id string) bool {
	value, err := gouuid.Parse(id)
	return err == nil && value != gouuid.Nil && value.String() == id
}

// Validate checks stored shape only; it does not authorize source access.
func (s QuerySource) Validate() error {
	if s.Version != 1 || !canonicalQueryID(s.OwnerUserID) || !canonicalQueryID(s.ViewID) || s.EverySeconds <= 0 || s.EverySeconds > math.MaxInt64/int64(time.Second) || len(s.ReadGrants) == 0 {
		return ErrQueryGroups
	}
	if _, err := flow.QueryViewVersion(s.ViewVersion); err != nil {
		return ErrQueryGroups
	}
	if err := s.Condition.validateShape(); err != nil {
		return err
	}
	for _, grant := range s.ReadGrants {
		// Saved Explorer reads also use the existing ai.query capability. It
		// authorizes a read operation, never remediation or source mutation.
		if (!strings.HasSuffix(grant.Permission, ".read") && grant.Permission != "ai.query") || strings.TrimSpace(grant.Permission) != grant.Permission {
			return ErrQueryGroups
		}
		switch grant.ScopeType {
		case auth.ScopeTenant:
			if grant.ScopeID != "" {
				return ErrQueryGroups
			}
		case auth.ScopeOrganization, auth.ScopeTeam, auth.ScopeProject:
			if !canonicalQueryID(grant.ScopeID) {
				return ErrQueryGroups
			}
		default:
			return ErrQueryGroups
		}
	}
	return nil
}

func (s QuerySource) Binding(tenant, rule string) QueryGroupBinding {
	return QueryGroupBinding{TenantID: tenant, RuleID: rule, ViewID: s.ViewID, ViewVersion: s.ViewVersion, Condition: s.Condition}
}

// CredentialCeiling never restores a credential or a stored role. It is only
// the maximum read grants the actual configuring credential could exercise;
// currentUserAuthority applies today's user, hierarchy and ABAC separately.
func (s QuerySource) CredentialCeiling(tenant string) (*auth.Principal, error) {
	if err := s.Validate(); err != nil || !canonicalQueryID(tenant) {
		return nil, ErrQueryGroups
	}
	grants := make([]auth.PermissionGrant, len(s.ReadGrants))
	for i, grant := range s.ReadGrants {
		grants[i] = auth.PermissionGrant{Permission: grant.Permission, ScopeType: grant.ScopeType, ScopeID: grant.ScopeID}
	}
	return auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: s.OwnerUserID, ViaBearerToken: true}, grants), nil
}
