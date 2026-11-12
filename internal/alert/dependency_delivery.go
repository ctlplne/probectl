// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"time"
)

type dependencyDelivery struct {
	attempt      DependencyAttempt
	key          string
	since        time.Time
	lastNotified time.Time
	pending      *pendingNotify
}

func (en *Engine) rememberDependencyRuleLocked(id string) {
	if en.dependencyRules == nil {
		en.dependencyRules = map[string]bool{}
	}
	en.dependencyRules[id] = true
}

func (en *Engine) needsDependencyRouting(rule Rule) bool {
	en.mu.Lock()
	defer en.mu.Unlock()
	return en.dependencyRouter != nil && rule.HasDependencyPolicy || en.dependencyRules[rule.ID]
}

// A persisted held marker is an incident-visible episode, independently of
// whether it previously delivered. Restore it before evaluating a
// current sample so a recovered series closes without sending a fictitious
// resolution, and a still-failing series retains its original episode clock.
func (en *Engine) dependencyBeforeSample(rule Rule, s Sample) (time.Time, bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	key := stateKey(rule.ID, s.Labels)
	st := en.states[key]
	if restored, ok := en.restoredNotify[key]; st == nil && ok && restoredDependencyHeld(restored) && !restored.FiringSince.IsZero() {
		st = en.stateForLocked(rule, s.Labels)
		st.firing, st.dependencyRestored = true, true
		st.since, st.breachCount = restored.FiringSince, requiredBreaches(rule)
		st.lastNotified = restored.LastNotified
		delete(en.restoredNotify, key)
		if op, ok := en.restored[key]; ok {
			delete(en.restored, key)
			if op.SilencedUntil.After(en.clock()) {
				st.silencedUntil = op.SilencedUntil
			}
			st.ackedBy, st.ackedAt = op.AckedBy, op.AckedAt
		}
	}
	if st == nil {
		if restored, ok := en.restoredNotify[key]; ok {
			return restored.LastNotified, false
		}
		return time.Time{}, false
	}
	return st.lastNotified, st.dependency != nil && st.dependency.Held() || st.dependencyRestored
}

func restoredDependencyHeld(state NotifyState) bool {
	if state.Dependency != nil {
		return state.Dependency.Held
	}
	return state.LastNotified.IsZero() // compatibility with the original marker
}

func (en *Engine) dependencyCandidate(rule Rule, s Sample, acted Alert, notify bool, receipt *EvaluationReceipt) (Alert, time.Time, bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	st := en.states[stateKey(rule.ID, s.Labels)]
	if st == nil {
		return Alert{}, time.Time{}, false
	}
	if notify {
		return acted, st.since, true
	}
	if !st.firing || receipt != nil && (receipt.State == EvaluationWarming || receipt.State == EvaluationPending) {
		return Alert{}, time.Time{}, false
	}
	return en.alert(rule, s, StateFiring, st.lastReason), st.since, true
}

func (en *Engine) evaluateDependencyRule(ctx context.Context, rule Rule, read RuleMetricRead) []Alert {
	entries := make([]dependencyDelivery, 0, len(read.Samples))
	attempts := make([]DependencyAttempt, 0, len(read.Samples))
	for _, s := range read.Samples {
		previous, held := en.dependencyBeforeSample(rule, s)
		a, due, receipt, pending := en.evalSample(rule, s, read.TagSelection)
		en.recordEvaluation(ctx, receipt)
		candidate, since, present := en.dependencyCandidate(rule, s, a, due, receipt)
		if !present {
			continue
		}
		attempt := DependencyAttempt{Alert: candidate, NotificationDue: due, PreviouslyHeld: held, FiringSince: since, LastNotified: previous, RuleUpdatedAt: rule.UpdatedAt}
		attempts = append(attempts, attempt)
		entries = append(entries, dependencyDelivery{attempt: attempt, key: stateKey(rule.ID, s.Labels), since: since, lastNotified: previous, pending: pending})
	}
	outcomes := en.routeDependencies(ctx, rule, attempts)
	var acted []Alert
	for i, entry := range entries {
		var outcome DependencyOutcome
		if len(outcomes) != 0 {
			outcome = outcomes[i]
		}
		if a, changed := en.applyDependencyDelivery(ctx, rule, entry, outcome); changed {
			acted = append(acted, a)
		}
	}
	return acted
}

func (en *Engine) routeDependencies(ctx context.Context, rule Rule, attempts []DependencyAttempt) []DependencyOutcome {
	if !rule.HasDependencyPolicy || en.dependencyRouter == nil || len(attempts) == 0 {
		return nil
	}
	outcomes, err := en.dependencyRouter(ctx, rule, attempts)
	if err == nil && en.completeDependencyOutcomes(rule, attempts, outcomes) {
		return outcomes
	}
	// No stale or successful prefix can justify hiding a notification. Do not
	// log adapter errors: they may contain source or SQL values.
	reason := "source_or_publication_unavailable"
	if errors.Is(err, ErrDependencyBudget) {
		reason = "resource_admission"
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		reason = "deadline_or_canceled"
	}
	en.log.WarnContext(ctx, "alert dependency routing unavailable; ordinary delivery retained", "tenant_id", rule.TenantID, "rule_id", rule.ID, "reason", reason)
	return nil
}

func (en *Engine) completeDependencyOutcomes(rule Rule, attempts []DependencyAttempt, outcomes []DependencyOutcome) bool {
	if len(outcomes) != len(attempts) {
		return false
	}
	seen := make(map[string]bool, len(attempts))
	for i, outcome := range outcomes {
		a := attempts[i].Alert
		key := stateKey(a.RuleID, a.Labels)
		if a.TenantID != rule.TenantID || a.RuleID != rule.ID || seen[key] || !outcome.Decision.matches(a, en.clock()) || !outcome.Decision.ruleUpdatedAt.Equal(rule.UpdatedAt) || outcome.Decision.Held() && (!outcome.IncidentPublished || !outcome.NotificationStatePublished) {
			return false
		}
		seen[key] = true
	}
	return true
}

func (en *Engine) applyDependencyDelivery(ctx context.Context, rule Rule, entry dependencyDelivery, outcome DependencyOutcome) (Alert, bool) {
	a := entry.attempt.Alert
	held := outcome.Decision.Held()
	if !outcome.Decision.selection.At.IsZero() {
		decision := outcome.Decision
		a.Dependency = &decision
	}
	en.mu.Lock()
	if st := en.states[entry.key]; st != nil && st.since.Equal(entry.since) {
		st.dependency, st.dependencyRestored = nil, false
		if held && st.firing {
			decision := outcome.Decision
			st.dependency = &decision
			st.lastNotified = entry.lastNotified
			en.rememberDependencyRuleLocked(rule.ID)
		}
	}
	en.mu.Unlock()
	if held {
		if !entry.attempt.PreviouslyHeld && en.onNotify != nil {
			en.onNotify(entry.key, NotifyState{FiringSince: entry.since, LastNotified: entry.lastNotified})
		}
		return a, !entry.attempt.PreviouslyHeld
	}
	// Never send a resolution for a firing that was held from its first
	// attempt. Existing delivered episodes retain ordinary resolve behavior.
	send := entry.attempt.NotificationDue && (a.State != StateResolved || !entry.attempt.PreviouslyHeld || !entry.lastNotified.IsZero())
	if send && en.notifier != nil {
		en.notifier.Deliver(ctx, rule, a)
	}
	if !outcome.IncidentPublished && (entry.attempt.NotificationDue || entry.attempt.PreviouslyHeld) && en.sink != nil {
		en.sink(ctx, a)
	}
	if entry.pending != nil && en.onNotify != nil {
		entry.pending.state.Dependency = &DependencyNotificationState{}
		en.onNotify(entry.pending.key, entry.pending.state)
	} else if entry.attempt.PreviouslyHeld && a.State == StateFiring && en.onNotify != nil {
		en.onNotify(entry.key, NotifyState{FiringSince: entry.since, LastNotified: entry.lastNotified, Dependency: &DependencyNotificationState{}})
	}
	if a.State == StateResolved && en.onResolve != nil {
		// The router must consume and close durable dependency state before
		// cleanup. Do not leave an old asynchronous delete racing a new episode.
		en.onResolve(entry.key)
	}
	return a, entry.attempt.NotificationDue || entry.attempt.PreviouslyHeld
}
