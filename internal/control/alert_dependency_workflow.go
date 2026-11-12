// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type alertDependencyWorkflow = alert.DependencyWorkflow
type alertDependencyWorkflowCause = alert.DependencyWorkflowCause

// The notification marker is never read authority. Inspection repeats the
// reader's live source grants and the policy owner's captured/current ceiling,
// using the same RLS, source and lifecycle boundary as actual publication.
func (s *Server) dependencyWorkflowInScope(ctx context.Context, sc tenancy.Scope, reader *auth.Principal, active *alert.ActiveAlert) (*alertDependencyWorkflow, error) {
	if active == nil {
		return nil, nil
	}
	rule, err := (store.AlertRules{}).Get(ctx, sc, active.RuleID)
	if err != nil {
		var domain *apierror.Error
		if errors.As(err, &domain) && domain.Kind == apierror.KindNotFound {
			return nil, nil // a removed rule may still have operator history
		}
		return nil, err
	}
	if !rule.HasDependencyPolicy {
		return nil, nil
	}
	if !rule.Enabled || active.Metric != rule.Metric {
		return &alertDependencyWorkflow{State: "recheck_required", Reason: "The active series must be reevaluated against the current rule."}, nil
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate == nil {
		return nil, apierror.Unavailable("dependency explanation admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, sc.Tenant.String())
	if err != nil {
		return nil, tagQueryAdmissionError(err)
	}
	defer release()
	var out *alertDependencyWorkflow
	err = (store.AlertRules{}).WithDependencyPublication(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/8, func(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy) error {
		ceiling, err := policy.CredentialCeiling(sc.Tenant.String())
		if err != nil {
			return err
		}
		if err := s.dependencyWorkflowAuthority(ctx, sc, reader, ceiling, policy, budget.MemoryBytes/4); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
			return err
		}
		if err := store.LockDependencySourcesInScope(ctx, sc, policy.ContextID, policy.Graph, budget.MemoryBytes/4); err != nil {
			return err
		}
		graph, health, err := s.dependencyHealthSnapshot(ctx, sc, policy, budget.MemoryBytes/2)
		if err != nil {
			return err
		}
		out, err = dependencyWorkflowDecision(ctx, sc, *rule, policy, active, graph, health, budget.MemoryBytes/4)
		if err != nil {
			return err
		}
		if err := s.dependencyWorkflowAuthority(ctx, sc, reader, ceiling, policy, budget.MemoryBytes/4); err != nil {
			return err
		}
		var now time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		for _, value := range health {
			if !value.FreshUntil.After(now) || value.Observation.ObservedAt.After(now) {
				return alert.ErrDependencyEvidence
			}
		}
		return ctx.Err()
	})
	if err != nil {
		var domain *apierror.Error
		if errors.As(err, &domain) && (domain.Kind == apierror.KindForbidden || domain.Kind == apierror.KindUnauthorized || domain.Kind == apierror.KindNotFound) {
			return &alertDependencyWorkflow{State: "withheld", Reason: "Current reader and policy-owner source permissions are required."}, nil
		}
		if errors.Is(err, alert.ErrDependencyEvidence) || errors.Is(err, store.ErrAlertDependencyChanged) {
			return &alertDependencyWorkflow{State: "recheck_required", Reason: "Complete current dependency evidence is unavailable; a stored hold does not establish current routing authority."}, nil
		}
		return nil, err
	}
	return out, nil
}

func (s *Server) dependencyWorkflowAuthority(ctx context.Context, sc tenancy.Scope, reader, ceiling *auth.Principal, policy *alert.DependencyPolicy, maxBytes int64) error {
	for _, actor := range []*auth.Principal{reader, ceiling} {
		if err := s.dependencyContextAuthority(ctx, sc, actor, policy.ContextID, true, policy.Graph, maxBytes); err != nil {
			return err
		}
		if err := s.dependencyIncidentAuthority(ctx, sc, actor, policy); err != nil {
			return err
		}
	}
	return nil
}

func dependencyWorkflowDecision(ctx context.Context, sc tenancy.Scope, rule alert.Rule, policy *alert.DependencyPolicy, active *alert.ActiveAlert, graph alert.DependencySnapshot, health map[string]store.ICMPHealth, maxBytes int64) (*alertDependencyWorkflow, error) {
	out := &alertDependencyWorkflow{State: "ordinary", Reason: "This series does not match a configured dependency source."}
	for _, node := range policy.Graph.Nodes {
		if node.TestID != active.Labels["test_id"] {
			continue
		}
		value := health[node.EntityID]
		attempt := alert.DependencyAttempt{Alert: alert.Alert{TenantID: sc.Tenant.String(), RuleID: rule.ID, Metric: active.Metric, State: alert.StateFiring, Labels: active.Labels, Value: active.Value}, FiringSince: active.Since, RuleUpdatedAt: rule.UpdatedAt}
		sig := signalFromAlert(attempt.Alert)
		sig.IdentityLookupAttempted = true
		sig.IdentityContextID, sig.IdentityEntityID = policy.ContextID, node.EntityID
		overrides, err := (store.Incidents{}).ActiveCorrelationOverrides(ctx, sc, sig)
		if err != nil {
			return nil, err
		}
		decider, err := alert.PrepareDependencyNotifications(ctx, graph, maxBytes, maxBytes)
		if err != nil {
			return nil, err
		}
		decision, err := decider.Decide(ctx, attempt, node.EntityID, len(overrides) == 0 && dependencyReachabilityAttempt(rule, attempt, node, value))
		if err != nil || decision.NotificationFingerprint() != active.Fingerprint {
			return nil, alert.ErrDependencyEvidence
		}
		marker, err := (store.AlertNotifications{}).Get(ctx, sc, active.Fingerprint)
		if err != nil {
			return nil, err
		}
		out.Reason, out.ContextID, out.EntityID = decision.Reason(), policy.ContextID, node.EntityID
		out.EvidenceID, out.ObservationID = value.EvidenceID, value.Observation.ID
		out.AsOf, out.FreshUntil = &graph.At, &value.FreshUntil
		published := marker != nil && marker.FiringSince.Equal(active.Since.UTC().Truncate(time.Microsecond)) && marker.Dependency != nil && marker.Dependency.Held
		if published {
			out.State = "recheck_required"
		}
		if !decision.Held() {
			return out, nil
		}
		out.State = "pending"
		var parents []string
		if published {
			key := hex.EncodeToString(crypto.Hash([]byte(sc.Tenant.String() + "|" + active.Fingerprint)))
			parents, err = (store.Incidents{}).DependencyParentIncidents(ctx, sc, policy.ContextID, node.EntityID, key, marker.Dependency.TransitionID, active.Since, maxBytes)
			if err != nil {
				return nil, err
			}
		}
		var expected []string
		for _, cause := range decision.Causes() {
			expected = append(expected, cause.IncidentID)
			out.Causes = append(out.Causes, alertDependencyWorkflowCause{EntityID: cause.EntityID, IncidentID: cause.IncidentID, ObservedAt: cause.ObservedAt, FreshUntil: cause.FreshUntil})
		}
		slices.Sort(expected)
		if published && slices.Equal(parents, expected) {
			out.State = "held"
		}
		return out, nil
	}
	return out, nil
}
