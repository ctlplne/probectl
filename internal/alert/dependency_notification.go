// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DependencyAttempt is engine-owned input, never a wire or authorization
// document. One router invocation covers the complete rule population so it
// can share current evidence and resource admission across all its series.
type DependencyAttempt struct {
	Alert           Alert
	NotificationDue bool
	PreviouslyHeld  bool
	FiringSince     time.Time
	LastNotified    time.Time
	RuleUpdatedAt   time.Time
}

// DependencyNotificationState is durable episode bookkeeping on the existing
// notification row. It never supplies evidence, source grants or hold authority.
// A fresh source decision is required after every reload and before delivery.
type DependencyNotificationState struct {
	Held         bool
	TransitionID string
}

func (state DependencyNotificationState) Validate() error {
	if !state.Held && state.TransitionID == "" {
		return nil // explicitly clear current bookkeeping, without source reads
	}
	if !canonicalQueryID(state.TransitionID) {
		return ErrDependencyEvidence
	}
	return nil
}

// DependencyDecision is opaque outside this package. The source adapter must
// construct it from current, authorized storage evidence and recheck authority
// when publishing the incident relationship. A decoded JSON claim cannot
// manufacture a decision, and a decision cannot be moved to another series.
type DependencyDecision struct {
	selection     dependencySelection
	tenant        string
	contextID     string
	key           string
	labels        map[string]string
	state         State
	validUntil    time.Time
	ruleUpdatedAt time.Time
}

func (d DependencyDecision) Held() bool { return d.selection.Held }

// NotificationFingerprint is the exact engine-owned series key. Publication
// uses it only in the same tenant transaction as the incident relationship.
func (d DependencyDecision) NotificationFingerprint() string { return d.key }

func (d DependencyDecision) ContextID() string         { return d.contextID }
func (d DependencyDecision) Reason() string            { return d.selection.Reason }
func (d DependencyDecision) Causes() []DependencyCause { return slices.Clone(d.selection.Causes) }

// DependencyDecider belongs to one serialized router operation. Its shared
// budget covers the whole population; callers cannot reuse it across tenants
// or retain authority beyond the original source snapshot's validity.
type DependencyDecider struct{ graph *preparedDependencyGraph }

func PrepareDependencyNotifications(ctx context.Context, graph DependencySnapshot, memoryBytes, workUnits int64) (*DependencyDecider, error) {
	p, err := prepareDependencyGraph(ctx, graph, dependencyBudget{memory: memoryBytes, work: workUnits})
	if err != nil {
		return nil, err
	}
	return &DependencyDecider{graph: p}, nil
}

func (decider *DependencyDecider) Decide(ctx context.Context, attempt DependencyAttempt, target string, reachabilitySymptom bool) (DependencyDecision, error) {
	a := attempt.Alert
	tenant, ok := tenancy.FromContext(ctx)
	if decider == nil || decider.graph == nil || !ok || tenant.String() != a.TenantID || decider.graph.tenant != a.TenantID || !canonicalQueryID(a.RuleID) || a.State != StateFiring && a.State != StateResolved {
		return DependencyDecision{}, ErrDependencyEvidence
	}
	p := decider.graph
	if err := admitDependencyDecisionLabels(ctx, a.Labels, &p.budget); err != nil {
		return DependencyDecision{}, err
	}
	selected, err := p.selectHold(ctx, target, reachabilitySymptom)
	if err != nil {
		return DependencyDecision{}, err
	}
	if a.State == StateResolved {
		selected.Held = false
		selected.Reason = "the dependent alert resolved"
	}
	return DependencyDecision{selection: selected, tenant: a.TenantID, contextID: p.contextID,
		key: stateKey(a.RuleID, a.Labels), labels: maps.Clone(a.Labels), state: a.State, validUntil: p.until, ruleUpdatedAt: attempt.RuleUpdatedAt}, nil
}

func admitDependencyDecisionLabels(ctx context.Context, labels map[string]string, budget *dependencyBudget) error {
	if err := budget.charge(4096, 4096); err != nil {
		return err
	}
	for key, value := range labels {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := budget.charge(256, 256); err != nil {
			return err
		}
		for _, text := range []string{key, value} {
			size := int64(len(text))
			if size > budget.memory/4 || size > budget.work/4 {
				return ErrDependencyEvidence
			}
			if err := budget.charge(4*size, 4*size); err != nil {
				return err
			}
		}
	}
	return nil
}

func minDependencyTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// The adapter acknowledges both the current tenant's incident relationship and
// pending notification state only after durable publication. A held notification
// must remain visible and restartable; a successful prefix refuses the hold.
type DependencyOutcome struct {
	Decision                   DependencyDecision
	IncidentPublished          bool
	NotificationStatePublished bool
}

type DependencyRouter func(context.Context, Rule, []DependencyAttempt) ([]DependencyOutcome, error)

// WithDependencyRouter installs the deployment's tenant-bound publication
// adapter. An unavailable/incomplete result retains ordinary delivery.
func WithDependencyRouter(router DependencyRouter) EngineOption {
	return func(en *Engine) { en.dependencyRouter = router }
}

func (d DependencyDecision) matches(a Alert, now time.Time) bool {
	return d.tenant == a.TenantID && d.key == stateKey(a.RuleID, a.Labels) && maps.Equal(d.labels, a.Labels) && d.state == a.State &&
		!d.selection.At.IsZero() && !d.selection.At.After(now) && d.validUntil.After(now)
}
