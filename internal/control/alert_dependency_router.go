// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) alertDependencyRouter(tenant tenancy.ID, publication ...dependencyIncidentPublication) alert.DependencyRouter {
	return func(ctx context.Context, rule alert.Rule, attempts []alert.DependencyAttempt) ([]alert.DependencyOutcome, error) {
		if s == nil || s.pool == nil || s.fairnessGate == nil || tenant.String() == "" || rule.TenantID != tenant.String() {
			return nil, alert.ErrDependencyEvidence
		}
		budget := flowstore.ExplorerQueryBudget(s.flowStore)
		if err := budget.Validate(); err != nil {
			return nil, err
		}
		if len(attempts) == 0 || int64(len(attempts)) > budget.MemoryBytes/4096 {
			return nil, store.ErrAlertDependencyBudget
		}
		timeout := 5 * time.Minute
		if s.cfg != nil && s.cfg.AlertDependencyPublicationTimeout != 0 {
			timeout = s.cfg.AlertDependencyPublicationTimeout
		}
		if timeout <= 0 {
			return nil, store.ErrAlertDependencyBudget
		}
		ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenant), timeout)
		defer cancel()
		ctx, flush := scopedABACDenial(ctx)
		defer flush(s)
		release, err := s.fairnessGate.BeginQuery(ctx, tenant.String())
		if err != nil {
			return nil, err
		}
		defer release()
		var pending []dependencyIncidentEvent
		cfg := dependencyIncidentPublication{pending: &pending}
		if len(publication) > 0 {
			cfg.window, cfg.observer = publication[0].window, publication[0].observer
		}
		var outcomes []alert.DependencyOutcome
		err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertRules{}).WithDependencyPublication(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/8,
				func(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy) error {
					var publishErr error
					outcomes, publishErr = s.publishDependencyAttempts(ctx, sc, rule, policy, attempts, budget.MemoryBytes/2, &cfg)
					return publishErr
				})
		})
		if err != nil {
			return nil, err // no successful prefix or uncommitted acknowledgement
		}
		if cfg.observer != nil {
			for _, event := range pending {
				cfg.observer(ctx, event.incident, event.opened)
			}
		}
		return outcomes, nil
	}
}

// All evidence and effects share the current tenant transaction. No decoded
// parent, stale read credential or numeric metric label grants a hold.
func (s *Server) publishDependencyAttempts(ctx context.Context, sc tenancy.Scope, rule alert.Rule, policy *alert.DependencyPolicy, attempts []alert.DependencyAttempt, maxBytes int64, publication ...*dependencyIncidentPublication) ([]alert.DependencyOutcome, error) {
	ceiling, err := policy.CredentialCeiling(sc.Tenant.String())
	if err != nil {
		return nil, err
	}
	if err := s.dependencyContextAuthority(ctx, sc, ceiling, policy.ContextID, true, policy.Graph, maxBytes/2); err != nil {
		return nil, err
	}
	if err := s.dependencyIncidentAuthority(ctx, sc, ceiling, policy); err != nil {
		return nil, err
	}
	// Match the incident store's tenant correlation serialization before any
	// source-row locks, so another source cannot create a competing root case.
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return nil, err
	}
	if err := store.LockDependencySourcesInScope(ctx, sc, policy.ContextID, policy.Graph, maxBytes/2); err != nil {
		return nil, fmt.Errorf("dependency publication source locks: %w", err)
	}
	graph, health, err := s.dependencyHealthSnapshot(ctx, sc, policy, maxBytes/2)
	if err != nil {
		return nil, fmt.Errorf("dependency publication health snapshot: %w", err)
	}
	cfg := &dependencyIncidentPublication{}
	if len(publication) > 0 && publication[0] != nil {
		cfg = publication[0]
	}
	roots, err := s.publishDependencyRoots(ctx, sc, rule, policy, &graph, health, attempts, maxBytes/2, cfg)
	if err != nil {
		return nil, fmt.Errorf("dependency publication roots: %w", err)
	}
	decider, err := alert.PrepareDependencyNotifications(ctx, graph, maxBytes/2, maxBytes/2)
	if err != nil {
		return nil, err
	}
	nodes := make(map[string]alert.DependencyNodeInput, len(policy.Graph.Nodes))
	for _, node := range policy.Graph.Nodes {
		nodes[node.TestID] = node
	}
	signals, err := dependencyPublicationSignals(sc, rule, policy.ContextID, policy.Graph.Nodes[0], nodes, attempts)
	if err != nil {
		return nil, err
	}
	overrides, err := (store.Incidents{}).ActiveCanonicalOverrideMatches(ctx, sc, signals, maxBytes/2)
	if err != nil {
		return nil, fmt.Errorf("dependency publication child policies: %w", err)
	}
	out := make([]alert.DependencyOutcome, len(attempts))
	for i, attempt := range attempts {
		if attempt.Alert.TenantID != sc.Tenant.String() || attempt.Alert.RuleID != rule.ID || !attempt.RuleUpdatedAt.Equal(rule.UpdatedAt) || attempt.FiringSince.IsZero() {
			return nil, alert.ErrDependencyEvidence
		}
		node, matched := nodes[attempt.Alert.Labels["test_id"]]
		if !matched {
			node = policy.Graph.Nodes[0] // independent; never a hold target
		}
		reachability := matched && dependencyReachabilityAttempt(rule, attempt, node, health[node.EntityID])
		sig := signals[i]
		if overrides[i] {
			reachability = false // explicit operator detachment always wins
		}
		decision, err := decider.Decide(ctx, attempt, node.EntityID, reachability)
		if err != nil {
			return nil, err
		}
		out[i].Decision = decision
		out[i].IncidentPublished = roots[decision.NotificationFingerprint()]
		if !decision.Held() {
			if attempt.PreviouslyHeld && matched {
				if err := publishReleasedDependency(ctx, sc, policy.OwnerUserID, attempt, decision, sig, maxBytes/4); err != nil {
					return nil, err
				}
				if attempt.Alert.State == alert.StateResolved && attempt.LastNotified.IsZero() {
					out[i].IncidentPublished = true // closes the existing visible parent; no fictitious child incident
				}
			}
			continue
		}
		if err := publishHeldDependency(ctx, sc, policy.OwnerUserID, attempt, decision, sig, maxBytes/4); err != nil {
			return nil, fmt.Errorf("dependency publication held child %d of %d: %w", i+1, len(attempts), err)
		}
		out[i].IncidentPublished, out[i].NotificationStatePublished = true, true
	}
	// The preliminary source authorization cannot stand in for current
	// publication authority. Reuse the same loaded-user/RBAC/ABAC door here.
	if err := s.dependencyContextAuthority(ctx, sc, ceiling, policy.ContextID, true, policy.Graph, maxBytes/2); err != nil {
		return nil, err
	}
	if err := s.dependencyIncidentAuthority(ctx, sc, ceiling, policy); err != nil {
		return nil, err
	}
	var publishedAt time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&publishedAt); err != nil {
		return nil, err
	}
	for _, value := range health {
		if !value.FreshUntil.After(publishedAt) || value.Observation.ObservedAt.After(publishedAt) {
			return nil, alert.ErrDependencyEvidence
		}
	}
	return out, nil
}

func dependencyPublicationSignals(sc tenancy.Scope, rule alert.Rule, contextID string, fallback alert.DependencyNodeInput, nodes map[string]alert.DependencyNodeInput, attempts []alert.DependencyAttempt) ([]incident.Signal, error) {
	out := make([]incident.Signal, len(attempts))
	for i, attempt := range attempts {
		if attempt.Alert.TenantID != sc.Tenant.String() || attempt.Alert.RuleID != rule.ID || !attempt.RuleUpdatedAt.Equal(rule.UpdatedAt) || attempt.FiringSince.IsZero() {
			return nil, alert.ErrDependencyEvidence
		}
		node, found := nodes[attempt.Alert.Labels["test_id"]]
		if !found {
			node = fallback
		}
		out[i] = signalFromAlert(attempt.Alert)
		out[i].IdentityLookupAttempted = true
		out[i].IdentityContextID, out[i].IdentityEntityID = contextID, node.EntityID
	}
	return out, nil
}

func publishReleasedDependency(ctx context.Context, sc tenancy.Scope, owner string, attempt alert.DependencyAttempt, decision alert.DependencyDecision, sig incident.Signal, maxBytes int64) error {
	key := hex.EncodeToString(crypto.Hash([]byte(sc.Tenant.String() + "|" + decision.NotificationFingerprint())))
	notification, err := (store.AlertNotifications{}).Get(ctx, sc, decision.NotificationFingerprint())
	if err != nil {
		return err
	}
	transition := ""
	if notification != nil && notification.Dependency != nil {
		transition = notification.Dependency.TransitionID
	}
	parents, err := (store.Incidents{}).DependencyParentIncidents(ctx, sc, decision.ContextID(), sig.IdentityEntityID, key, transition, attempt.FiringSince, maxBytes)
	if err != nil {
		return err
	}
	sig.Summary = decision.Reason()
	sig.Attributes["dependency.state"] = "released"
	if attempt.Alert.State == alert.StateResolved {
		sig.Attributes["dependency.state"] = "resolved"
	}
	sig.Attributes["dependency.notification_key"] = key
	sig.Attributes["dependency.firing_since"] = attempt.FiringSince.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	sig.Attributes["dependency.transition_id"] = transition
	for _, parent := range parents {
		sig.Attributes["correlation.state"] = "grouped"
		sig.Attributes["correlation.parent_incident_id"] = parent
		sig.Attributes["correlation.reason"] = "current_dependency_hold_ended"
		if err := (store.Incidents{}).AppendDependencyRelease(ctx, sc, parent, sig); err != nil {
			return err
		}
	}
	if notification != nil {
		if !notification.FiringSince.Equal(attempt.FiringSince.UTC().Truncate(time.Microsecond)) {
			return alert.ErrDependencyEvidence
		}
		notification.Dependency = &alert.DependencyNotificationState{TransitionID: transition}
		if err := (store.AlertNotifications{}).Upsert(ctx, sc, *notification); err != nil {
			return err
		}
	}
	return audit.TenantRecord(ctx, sc, owner, "alert.dependency."+sig.Attributes["dependency.state"], attempt.Alert.RuleID, map[string]any{"notification_key": key, "parent_count": len(parents), "execution": "background"})
}

func (s *Server) dependencyIncidentAuthority(ctx context.Context, sc tenancy.Scope, ceiling *auth.Principal, policy *alert.DependencyPolicy) error {
	current, err := readCurrentUserAuthorityScope(ctx, sc, ceiling.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, ceiling)
	if err != nil {
		return err
	}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, policy.ContextID)
	if err != nil {
		return err
	}
	for _, node := range policy.Graph.Nodes {
		resource := entityContextResource(record)
		resource["entity_id"], resource["agent_id"], resource["test_id"] = node.EntityID, node.AgentID, node.TestID
		if err := s.authorize(ctx, principal, "incident.read", auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *Server) dependencyHealthSnapshot(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy, maxBytes int64) (alert.DependencySnapshot, map[string]store.ICMPHealth, error) {
	graph := alert.DependencySnapshot{TenantID: sc.Tenant.String(), ContextID: policy.ContextID, Complete: true}
	health := make(map[string]store.ICMPHealth, len(policy.Graph.Nodes))
	scope := entity.Scope{TenantID: sc.Tenant.String(), ContextID: policy.ContextID}
	registry := store.NewEntityRegistry(s.pool)
	requests := make([]store.ICMPHealthRequest, len(policy.Graph.Nodes))
	for i, node := range policy.Graph.Nodes {
		requests[i] = store.ICMPHealthRequest{Source: entity.SourceKey{AgentID: node.AgentID, Kind: entity.PathAgent, SourceRef: node.TestID}, EntityID: node.EntityID}
	}
	values, err := registry.ReadICMPHealthPopulationInScope(ctx, sc, scope, requests, time.Duration(policy.FreshnessSeconds)*time.Second, maxBytes-maxBytes/4)
	if err != nil {
		return graph, nil, err
	}
	aliases := make([]entity.AliasKey, len(values))
	for i, value := range values {
		if value.State != "up" && value.State != "down" {
			return graph, nil, alert.ErrDependencyEvidence
		}
		aliases[i] = value.Observation.Alias
	}
	resolved, err := store.ResolveAliasPopulationInScope(ctx, sc, scope, aliases, maxBytes/4)
	if err != nil {
		return graph, nil, err
	}
	down := make([]string, 0, len(values))
	for i, node := range policy.Graph.Nodes {
		value := values[i]
		if resolved[i].Status != entity.Resolved || resolved[i].MoreCandidates || resolved[i].EntityID != node.EntityID {
			return graph, nil, alert.ErrDependencyEvidence
		}
		if value.State == "down" {
			down = append(down, node.EntityID)
		}
		health[node.EntityID] = value
		graph.Vertices = append(graph.Vertices, alert.DependencyVertex{EntityID: node.EntityID, Parents: node.Parents, FreshUntil: value.FreshUntil})
	}
	if len(down) > 0 {
		cases, err := (store.Incidents{}).DependencyCauseIncidents(ctx, sc, policy.ContextID, down, maxBytes/4)
		if err != nil {
			return graph, nil, err
		}
		for _, id := range down {
			if incidentID := cases[id]; incidentID != "" {
				value := health[id]
				graph.Causes = append(graph.Causes, alert.DependencyCause{TenantID: scope.TenantID, ContextID: scope.ContextID, EntityID: id, IncidentID: incidentID, ObservedAt: value.Observation.ObservedAt, FreshUntil: value.FreshUntil})
			}
		}
	}
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&graph.At); err != nil {
		return graph, nil, err
	}
	return graph, health, ctx.Err()
}

func dependencyReachabilityAttempt(rule alert.Rule, attempt alert.DependencyAttempt, node alert.DependencyNodeInput, health store.ICMPHealth) bool {
	// The zero-valued raw metric only nominates an already-authorized source.
	// Current, complete, sender-bound echo loss must independently prove the
	// reachability symptom. Other metrics, send/local errors and healthy targets
	// cannot inherit a network hold.
	agent := attempt.Alert.Labels["agent_id"]
	return rule.Metric == "probectl_probe_success" && rule.Comparison == alert.EQ && rule.Threshold == 0 &&
		attempt.Alert.Value == 0 && health.State == "down" && agent != "" && agent == node.AgentID
}

func publishHeldDependency(ctx context.Context, sc tenancy.Scope, owner string, attempt alert.DependencyAttempt, decision alert.DependencyDecision, sig incident.Signal, maxBytes int64) error {
	if decision.ContextID() != sig.IdentityContextID || sig.TenantID != sc.Tenant.String() {
		return alert.ErrDependencyEvidence
	}
	key := hex.EncodeToString(crypto.Hash([]byte(sc.Tenant.String() + "|" + decision.NotificationFingerprint())))
	firingSince := attempt.FiringSince.UTC().Truncate(time.Microsecond)
	notification, err := (store.AlertNotifications{}).Get(ctx, sc, decision.NotificationFingerprint())
	if err != nil {
		return err
	}
	parents := make([]string, 0, len(decision.Causes()))
	for _, cause := range decision.Causes() {
		parents = append(parents, cause.IncidentID)
	}
	slices.Sort(parents)
	transition, reused := "", false
	if notification != nil && notification.FiringSince.After(firingSince) {
		return alert.ErrDependencyEvidence
	}
	if notification != nil && notification.FiringSince.Equal(firingSince) && notification.Dependency != nil && notification.Dependency.Held {
		transition = notification.Dependency.TransitionID
		prior, err := (store.Incidents{}).DependencyParentIncidents(ctx, sc, decision.ContextID(), sig.IdentityEntityID, key, transition, firingSince, maxBytes)
		if err != nil {
			return err
		}
		reused = slices.Equal(prior, parents)
		if !reused {
			if err := publishReleasedDependency(ctx, sc, owner, attempt, decision, sig, maxBytes); err != nil {
				return err
			}
		}
	}
	if !reused {
		transition, err = crypto.UUIDv4()
		if err != nil {
			return err
		}
	}
	sig.Summary = decision.Reason()
	sig.Attributes["dependency.state"] = "held"
	sig.Attributes["dependency.notification_key"] = key
	sig.Attributes["dependency.firing_since"] = firingSince.Format(time.RFC3339Nano)
	sig.Attributes["dependency.transition_id"] = transition
	if !reused {
		for _, parent := range parents {
			sig.Attributes["correlation.state"] = "grouped"
			sig.Attributes["correlation.parent_incident_id"] = parent
			sig.Attributes["correlation.reason"] = "current_verified_dependency_cut"
			if _, err := (store.Incidents{}).AppendSignal(ctx, sc, parent, sig); err != nil {
				return err
			}
		}
	}
	if err := (store.AlertNotifications{}).Upsert(ctx, sc, store.AlertNotification{Fingerprint: decision.NotificationFingerprint(), FiringSince: firingSince, LastNotified: attempt.LastNotified, Dependency: &alert.DependencyNotificationState{Held: true, TransitionID: transition}}); err != nil {
		return err
	}
	if !reused {
		return audit.TenantRecord(ctx, sc, owner, "alert.dependency.held", attempt.Alert.RuleID, map[string]any{"notification_key": key, "transition_id": transition, "cause_count": len(parents), "execution": "background"})
	}
	return nil
}
