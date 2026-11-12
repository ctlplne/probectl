// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func dependencySourcePermission(permission string) bool {
	switch permission {
	case "topology.read", "entities.read", "test.read", "metrics.read", "events.read", "flow.read", "incident.read":
		return true
	default:
		return false
	}
}

// All source publication uses this scope, never a second connection or a stored
// role. The caller owns lifecycle/audit ordering and passes the actual credential
// (a captured read ceiling for background work, a live reader for inspection).
func (s *Server) dependencyContextAuthority(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, contextID string, sources bool, graph *alert.DependencyGraphInput, maxBytes int64) error {
	if actor == nil || actor.TenantID != sc.Tenant.String() || actor.UserID == "" {
		return apierror.Forbidden("current dependency source identity is unavailable")
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return entityAPIError(err)
	}
	permissions := []string{"topology.read", "entities.read"}
	if sources {
		permissions = append(permissions, "test.read", "metrics.read")
	}
	for _, permission := range permissions {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
			return err
		}
	}
	if graph != nil {
		for _, node := range graph.Nodes {
			resource := entityContextResource(record)
			resource["entity_id"], resource["agent_id"], resource["test_id"] = node.EntityID, node.AgentID, node.TestID
			for _, permission := range permissions {
				if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
					return err
				}
			}
		}
		if err := store.ValidateDependencyGraphInScope(ctx, sc, contextID, graph, maxBytes); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func alertDependencyStoreError(err error) error {
	if errors.Is(err, store.ErrAlertDependencyBudget) {
		return apierror.TooLarge("complete dependency configuration exceeds this operation's admitted memory; increase the deployment query memory budget").Wrap(err)
	}
	if errors.Is(err, store.ErrAlertDependencyChanged) {
		return apierror.Conflict("alert dependency configuration changed; refresh before retrying").Wrap(err)
	}
	return err
}

func (s *Server) setAlertDependencyPolicy(ctx context.Context, actor *auth.Principal, id string, input alert.DependencyPolicyInput) (alert.DependencyPolicyState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.DependencyPolicyState{}, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertWrite)
	if err != nil {
		return alert.DependencyPolicyState{}, err
	}
	if ctx.Value(dependencyWriteLeaseKey{}) != actor.TenantID {
		if s.fairnessGate == nil {
			return alert.DependencyPolicyState{}, apierror.Unavailable("dependency configuration admission is unavailable")
		}
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return alert.DependencyPolicyState{}, tagQueryAdmissionError(err)
		}
		defer release()
	}
	input, err = alert.NormalizeDependencyPolicyInput(input)
	if err != nil {
		return alert.DependencyPolicyState{}, apierror.Validation("dependency policy requires its exact context and a finite positive source freshness").Wrap(err)
	}
	policy := alert.DependencyPolicy{Version: 1, OwnerUserID: actor.UserID, ContextID: input.ContextID, FreshnessSeconds: input.FreshnessSeconds, Graph: input.Graph, ReadGrants: alertReadGrants(actor, dependencySourcePermission)}
	ceiling, err := policy.CredentialCeiling(actor.TenantID)
	if err != nil {
		return alert.DependencyPolicyState{}, apierror.Forbidden("the configuring credential must carry dependency source read capabilities").Wrap(err)
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.DependencyPolicyState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	var updated *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		// Authorize every proposed reference before storage existence checks.
		// Publication repeats this after the lifecycle/rule/audit locks, so a
		// concurrent owner or source withdrawal cannot reuse this preliminary read.
		if policy.Graph != nil {
			if err := s.dependencyContextAuthority(ctx, sc, ceiling, policy.ContextID, true, policy.Graph, budget.MemoryBytes/8); err != nil {
				return err
			}
		}
		updated, err = (store.AlertRules{}).SetDependencyPolicy(ctx, sc, id, current.UpdatedAt, &policy, budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				if err := s.publishAlertQuery(ctx, sc, actor, nil); err != nil {
					return err
				}
				return s.dependencyContextAuthority(ctx, sc, ceiling, policy.ContextID, true, policy.Graph, budget.MemoryBytes/8)
			})
		if err != nil {
			return err
		}
		body, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		return audit.TenantRecord(ctx, sc, actor.UserID, "alert.dependency_policy.set", id, map[string]any{"configuration_sha256": hex.EncodeToString(crypto.Hash(body))})
	})
	if err != nil {
		return alert.DependencyPolicyState{}, alertDependencyStoreError(err)
	}
	return alert.DependencyPolicyState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt, Configured: true, Policy: &input}, nil
}

func (s *Server) clearAlertDependencyPolicy(ctx context.Context, actor *auth.Principal, id string) (alert.DependencyPolicyState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.DependencyPolicyState{}, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertWrite)
	if err != nil {
		return alert.DependencyPolicyState{}, err
	}
	var updated *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		updated, err = (store.AlertRules{}).SetDependencyPolicy(ctx, sc, id, current.UpdatedAt, nil, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error { return s.publishAlertQuery(ctx, sc, actor, nil) })
		if err != nil {
			return err
		}
		return audit.TenantRecord(ctx, sc, actor.UserID, "alert.dependency_policy.clear", id, nil)
	})
	if err != nil {
		return alert.DependencyPolicyState{}, alertDependencyStoreError(err)
	}
	return alert.DependencyPolicyState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt}, nil
}

func (s *Server) readAlertDependencyPolicy(ctx context.Context, actor *auth.Principal, id string) (alert.DependencyPolicyState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.DependencyPolicyState{}, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return alert.DependencyPolicyState{}, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.DependencyPolicyState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate == nil {
		return alert.DependencyPolicyState{}, apierror.Unavailable("dependency policy admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return alert.DependencyPolicyState{}, tagQueryAdmissionError(err)
	}
	defer release()
	var out alert.DependencyPolicyState
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		policy, err := (store.AlertRules{}).GetDependencyPolicy(ctx, sc, id, rule.UpdatedAt, budget.MemoryBytes/8)
		if err != nil {
			return err
		}
		out = alert.DependencyPolicyState{RuleID: id, RuleUpdatedAt: rule.UpdatedAt}
		if policy == nil {
			return nil
		}
		if err := s.dependencyContextAuthority(ctx, sc, actor, policy.ContextID, policy.Graph != nil, policy.Graph, budget.MemoryBytes/8); err != nil {
			return err
		}
		input := policy.Input()
		out.Configured, out.Policy = true, &input
		return nil
	})
	if err != nil {
		return alert.DependencyPolicyState{}, alertDependencyStoreError(err)
	}
	return out, nil
}
