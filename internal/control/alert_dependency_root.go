// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type dependencyIncidentEvent struct {
	incident *incident.Incident
	opened   bool
}

type dependencyIncidentPublication struct {
	window   time.Duration
	observer incident.Observer
	pending  *[]dependencyIncidentEvent
}

// Only this transaction-local adapter implements stored-evidence resolution.
// The ordinary transport adapter continues to require a live mTLS source.
type dependencyCurrentIncidentStore struct {
	pgIncidentTxStore
	fingerprint string
	identity    incident.IdentityResolution
}

func (p dependencyCurrentIncidentStore) ResolveCurrentEvidenceIdentity(ctx context.Context, sig incident.Signal) (incident.IdentityResolution, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != p.scope.Tenant || sig.TenantID != bound.String() || sig.Fingerprint() != p.fingerprint {
		return incident.IdentityResolution{}, alert.ErrDependencyEvidence
	}
	return p.identity, ctx.Err()
}

// Analyze eligible source failures first, then publish only ordinary roots
// through the normal correlator. Provisional IDs are never returned as hold
// causes: all actual cases are reread before the final notification decisions.
func (s *Server) publishDependencyRoots(ctx context.Context, sc tenancy.Scope, rule alert.Rule, policy *alert.DependencyPolicy, graph *alert.DependencySnapshot, health map[string]store.ICMPHealth, attempts []alert.DependencyAttempt, maxBytes int64, publication *dependencyIncidentPublication) (map[string]bool, error) {
	nodes := make(map[string]alert.DependencyNodeInput, len(policy.Graph.Nodes))
	for _, node := range policy.Graph.Nodes {
		nodes[node.TestID] = node
	}
	provisional := *graph
	provisional.Causes = slices.Clone(graph.Causes)
	known := map[string]bool{}
	for _, cause := range graph.Causes {
		known[cause.EntityID] = true
	}
	for _, attempt := range attempts {
		if attempt.Alert.TenantID != sc.Tenant.String() || attempt.Alert.RuleID != rule.ID || !attempt.RuleUpdatedAt.Equal(rule.UpdatedAt) || attempt.FiringSince.IsZero() {
			return nil, alert.ErrDependencyEvidence
		}
		node, ok := nodes[attempt.Alert.Labels["test_id"]]
		if !ok || !dependencyRootCandidate(rule, attempt, node, health[node.EntityID]) || known[node.EntityID] {
			continue
		}
		id, err := crypto.UUIDv4()
		if err != nil {
			return nil, err
		}
		value := health[node.EntityID]
		provisional.Causes = append(provisional.Causes, alert.DependencyCause{TenantID: sc.Tenant.String(), ContextID: policy.ContextID, EntityID: node.EntityID, IncidentID: id, ObservedAt: value.Observation.ObservedAt, FreshUntil: value.FreshUntil})
		known[node.EntityID] = true
	}
	decider, err := alert.PrepareDependencyNotifications(ctx, provisional, maxBytes, maxBytes)
	if err != nil {
		return nil, err
	}
	published := map[string]bool{}
	for _, attempt := range attempts {
		node, ok := nodes[attempt.Alert.Labels["test_id"]]
		if ok && dependencyRootResolution(rule, attempt, node, health[node.EntityID]) {
			decision, err := decider.Decide(ctx, attempt, node.EntityID, false)
			if err != nil {
				return nil, err
			}
			done, err := publishDependencyRootResolution(ctx, sc, policy, attempt, decision, node, health[node.EntityID], maxBytes, publication)
			if err != nil {
				return nil, err
			}
			published[decision.NotificationFingerprint()] = done
			continue
		}
		if !ok || !dependencyRootCandidate(rule, attempt, node, health[node.EntityID]) {
			continue
		}
		decision, err := decider.Decide(ctx, attempt, node.EntityID, true)
		if err != nil {
			return nil, err
		}
		if decision.Held() {
			continue
		}
		if err := s.publishDependencyRoot(ctx, sc, policy, attempt, decision, node, health[node.EntityID], publication); err != nil {
			return nil, err
		}
		published[decision.NotificationFingerprint()] = true
	}
	if len(published) == 0 {
		return published, nil
	}
	ids := make([]string, 0, len(health))
	for id, value := range health {
		if value.State == "down" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		graph.Causes = nil
		return published, nil
	}
	cases, err := (store.Incidents{}).DependencyCauseIncidents(ctx, sc, policy.ContextID, ids, maxBytes)
	if err != nil {
		return nil, err
	}
	graph.Causes = nil
	for id, caseID := range cases {
		value := health[id]
		graph.Causes = append(graph.Causes, alert.DependencyCause{TenantID: sc.Tenant.String(), ContextID: policy.ContextID, EntityID: id, IncidentID: caseID, ObservedAt: value.Observation.ObservedAt, FreshUntil: value.FreshUntil})
	}
	return published, nil
}

func dependencyRootCandidate(rule alert.Rule, attempt alert.DependencyAttempt, node alert.DependencyNodeInput, value store.ICMPHealth) bool {
	return attempt.NotificationDue && attempt.Alert.State == alert.StateFiring && dependencyReachabilityAttempt(rule, attempt, node, value)
}

func (s *Server) publishDependencyRoot(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy, attempt alert.DependencyAttempt, decision alert.DependencyDecision, node alert.DependencyNodeInput, value store.ICMPHealth, publication *dependencyIncidentPublication) error {
	sig := signalFromAlert(attempt.Alert)
	sig.Target = value.Observation.Alias.Value
	sig.Attributes["test_id"], sig.Attributes["agent_id"] = value.Observation.Source.SourceRef, value.Observation.Source.AgentID
	sig.Attributes["probectl.entity.evidence.id"] = value.EvidenceID
	sig.Attributes["dependency.notification_key"] = hex.EncodeToString(crypto.Hash([]byte(sc.Tenant.String() + "|" + decision.NotificationFingerprint())))
	st := dependencyCurrentIncidentStore{pgIncidentTxStore: pgIncidentTxStore{scope: sc}, fingerprint: sig.Fingerprint(),
		identity: incident.IdentityResolution{ContextID: policy.ContextID, EntityID: node.EntityID}}
	if st.identity.EntityID == "" {
		return alert.ErrDependencyEvidence
	}
	correlator := incident.NewCorrelator(st, publication.window, s.log, incident.WithObserver(func(_ context.Context, inc *incident.Incident, opened bool) {
		if publication.pending != nil {
			*publication.pending = append(*publication.pending, dependencyIncidentEvent{incident: inc, opened: opened})
		}
	}))
	inc, err := correlator.Ingest(ctx, sig)
	if err != nil {
		return err
	}
	return audit.TenantRecord(ctx, sc, policy.OwnerUserID, "alert.dependency.root_published", attempt.Alert.RuleID, map[string]any{"incident_id": inc.ID, "execution": "background"})
}

func dependencyRootResolution(rule alert.Rule, attempt alert.DependencyAttempt, node alert.DependencyNodeInput, value store.ICMPHealth) bool {
	return attempt.NotificationDue && attempt.Alert.State == alert.StateResolved && !attempt.LastNotified.IsZero() && value.State == "up" &&
		rule.Metric == "probectl_probe_success" && rule.Comparison == alert.EQ && rule.Threshold == 0 && attempt.Alert.Labels["agent_id"] == node.AgentID
}

func publishDependencyRootResolution(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy, attempt alert.DependencyAttempt, decision alert.DependencyDecision, node alert.DependencyNodeInput, value store.ICMPHealth, maxBytes int64, publication *dependencyIncidentPublication) (bool, error) {
	cases, err := (store.Incidents{}).DependencyCauseIncidents(ctx, sc, policy.ContextID, []string{node.EntityID}, maxBytes)
	if err != nil || cases[node.EntityID] == "" {
		return false, err
	}
	parent := cases[node.EntityID]
	sig := signalFromAlert(attempt.Alert)
	sig.Target = value.Observation.Alias.Value
	sig.IdentityLookupAttempted = true
	sig.IdentityContextID, sig.IdentityEntityID = policy.ContextID, node.EntityID
	sig.Attributes["correlation.state"], sig.Attributes["correlation.parent_incident_id"] = "grouped", parent
	sig.Attributes["correlation.reason"] = "current_dependency_root_resolution"
	sig.Attributes["dependency.notification_key"] = hex.EncodeToString(crypto.Hash([]byte(sc.Tenant.String() + "|" + decision.NotificationFingerprint())))
	inc, err := (store.Incidents{}).AppendSignal(ctx, sc, parent, sig)
	if err != nil {
		return false, err
	}
	if publication.pending != nil {
		*publication.pending = append(*publication.pending, dependencyIncidentEvent{incident: inc})
	}
	return true, audit.TenantRecord(ctx, sc, policy.OwnerUserID, "alert.dependency.root_resolved", attempt.Alert.RuleID, map[string]any{"incident_id": inc.ID, "execution": "background"})
}
