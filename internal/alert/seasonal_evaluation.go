// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	SeasonalEvidenceBytes  = 8 << 10
	SeasonalFlowScopeBytes = 256 << 10
)

type SeasonalEvaluationEvidence struct {
	Subject        string                       `json:"subject"`
	Calendar       SeasonalEvaluationCalendar   `json:"calendar"`
	ObservedAt     time.Time                    `json:"observed_at"`
	TrainingWindow anomaly.TrainingWindow       `json:"training_window"`
	Citations      []anomaly.Citation           `json:"citations"`
	IncidentID     string                       `json:"incident_id,omitempty"`
	Exact          *anomaly.SeasonalDecimalBand `json:"exact,omitempty"`
	FlowScope      []byte                       `json:"-"`
}

// SeasonalEvaluationCalendar reports the civil slot and comparable dates. A
// metric supplies floating bounds here. A flow measure uses its exact band.
type SeasonalEvaluationCalendar struct {
	Timezone     string       `json:"timezone"`
	Weekday      time.Weekday `json:"weekday"`
	Hour         int          `json:"hour"`
	TrainingDays []string     `json:"training_days"`
	Median       *float64     `json:"median,omitempty"`
	Spread       *float64     `json:"robust_spread,omitempty"`
	Lower        *float64     `json:"lower,omitempty"`
	Upper        *float64     `json:"upper,omitempty"`
}

// SeasonalPublisher commits the cited incident before delivery may proceed.
type SeasonalPublisher func(context.Context, Rule, Alert, SeasonalEvaluationEvidence, *SeasonalReadPublication, *EvaluationReceipt) (string, error)

// SeasonalReadPublication carries one source capture for the entire complete
// current evaluation. It is never part of a response or a notification.
type SeasonalReadPublication struct {
	Revalidate func(context.Context, tenancy.Scope) error
	Finish     func(context.Context) error
	Close      func()
	Scope      []byte
}

func (p *SeasonalReadPublication) close() {
	if p != nil && p.Close != nil {
		p.Close()
	}
}

func evaluationSeriesFingerprint(ruleID string, labels map[string]string, seasonalSubject string) string {
	if seasonalSubject != "" {
		labels = map[string]string{"seasonal_series_id": seasonalSubject}
	}
	return evaluationFingerprint(ruleID, labels)
}

func (s *seriesState) active() bool {
	return s.firing && (s.seasonalSubject == "" || s.seasonalPublished)
}

type seasonalAttempt struct {
	key         string
	previous    *seriesState
	next        *seriesState
	priorOp     RestoredOp
	operator    RestoredOp
	hasOperator bool
	notifyState NotifyState
	hasNotify   bool
	alert       Alert
	channelDue  bool
	receipt     *EvaluationReceipt
}

// Retire episodes and restored operator actions for withdrawn or superseded
// seasonal selections. Every surviving seasonal episode belongs to the same
// exact rule revision that admitted its observations.
func (en *Engine) retainSeasonalRules(rules []Rule) {
	seasonal := make(map[string]string)
	for _, rule := range rules {
		if rule.Enabled && rule.HasSeasonalSource {
			seasonal[rule.ID] = seasonalSeriesPrefix(rule)
		}
	}
	en.mu.Lock()
	retired := make(map[string]bool)
	for key := range en.states {
		if seasonalEpisodeRetired(key, seasonal) {
			delete(en.states, key)
			retired[key] = true
		}
	}
	for key := range en.restoredNotify {
		if seasonalEpisodeRetired(key, seasonal) {
			delete(en.restoredNotify, key)
			retired[key] = true
		}
	}
	for key := range en.restored {
		if seasonalEpisodeRetired(key, seasonal) {
			delete(en.restored, key)
			retired[key] = true
		}
	}
	en.mu.Unlock()
	if en.onResolve != nil {
		for key := range retired {
			en.onResolve(key)
		}
	}
}

func seasonalEpisodeRetired(key string, seasonal map[string]string) bool {
	rule, series, found := strings.Cut(key, "|")
	if !found {
		return false
	}
	prefix := seasonal[rule]
	if strings.HasPrefix(series, "seasonal:") {
		return prefix == "" || !strings.HasPrefix(series, prefix)
	}
	return prefix != ""
}

func seasonalSeriesPrefix(rule Rule) string { return "seasonal:" + ruleRevision(rule) + "|" }

func (en *Engine) evaluateSeasonalRead(ctx context.Context, rule Rule, read RuleMetricRead) ([]Alert, error) {
	publication := read.SeasonalPublication
	defer publication.close()
	if len(read.Samples) == 0 {
		en.recordNoData(ctx, rule, nil)
		return nil, nil // later-arriving records can still complete this window
	}
	en.mu.Lock()
	delete(en.noDataRules, rule.ID)
	en.mu.Unlock()
	acted, err := en.evaluateSeasonalSamples(ctx, rule, read.Samples, publication)
	if err != nil || publication == nil {
		return acted, err
	}
	return acted, publication.Finish(ctx)
}

func (en *Engine) evaluateSeasonalSamples(ctx context.Context, rule Rule, samples []Sample, publication *SeasonalReadPublication) ([]Alert, error) {
	var acted []Alert
	for _, sample := range samples {
		if err := ctx.Err(); err != nil {
			return acted, err
		}
		attempt, current := en.stageSeasonalSample(rule, sample)
		if !current {
			continue
		}
		if publication != nil && attempt.receipt != nil && attempt.receipt.Expectation.Seasonal != nil {
			attempt.receipt.Expectation.Seasonal.FlowScope = publication.Scope
		}
		if attempt.alert.State != "" {
			evidence := seasonalRuleDecision(sample.Seasonal).expectation.Seasonal
			if evidence == nil {
				en.rollbackSeasonalSample(attempt)
				return acted, ErrSeasonalSource
			}
			incidentID, err := en.seasonalPublisher(ctx, rule, attempt.alert, *evidence, publication, attempt.receipt)
			if err != nil || incidentID == "" {
				en.rollbackSeasonalSample(attempt)
				if err == nil {
					err = ErrSeasonalSource
				}
				return acted, err
			}
			if attempt.receipt != nil && attempt.receipt.Expectation.Seasonal != nil {
				attempt.receipt.Expectation.Seasonal.IncidentID = incidentID
			}
			en.finishSeasonalSample(ctx, rule, attempt, incidentID)
			acted = append(acted, attempt.alert)
			if publication != nil {
				continue // the transition receipt committed with the incident
			}
		}
		en.recordEvaluation(ctx, attempt.receipt)
	}
	return acted, nil
}

func (en *Engine) stageSeasonalSample(rule Rule, sample Sample) (seasonalAttempt, bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	item := sample.Seasonal.Observed
	key := rule.ID + "|" + seasonalSeriesPrefix(rule) + item.Subject
	attempt := seasonalAttempt{key: key}
	if previous := en.states[key]; previous != nil {
		if !item.TS.After(previous.seasonalObservedAt) {
			return seasonalAttempt{}, false
		}
		attempt.previous = previous
		attempt.priorOp = seasonalOperatorState(previous)
		staged := *previous
		en.states[key] = &staged
	}
	attempt.operator, attempt.hasOperator = en.restored[key]
	attempt.notifyState, attempt.hasNotify = en.restoredNotify[key]
	st := en.stateForKeyLocked(rule, key)
	st.seasonalSubject, st.seasonalObservedAt = item.Subject, item.TS
	if attempt.hasNotify && !attempt.notifyState.FiringSince.IsZero() {
		st.seasonalPublished = true // this episode already reached the durable incident path
		st.firing, st.since, st.lastNotified = true, attempt.notifyState.FiringSince, attempt.notifyState.LastNotified
		st.breachCount = requiredBreaches(rule)
		delete(en.restoredNotify, key)
		if attempt.hasOperator {
			st.silencedUntil, st.ackedBy, st.ackedAt = attempt.operator.SilencedUntil, attempt.operator.AckedBy, attempt.operator.AckedAt
			delete(en.restored, key)
		}
	}
	attempt.alert, attempt.channelDue, attempt.receipt, _ = en.evalSampleLocked(key, rule, sample, nil)
	// Maintenance and explicit silence govern channels. Once a finding fires,
	// its scoped evidence still has to reach the incident before it is visible.
	if attempt.alert.State == "" && !st.seasonalPublished && attempt.receipt != nil && attempt.receipt.State == EvaluationFiring {
		attempt.alert = en.alert(rule, sample, StateFiring, attempt.receipt.Reason)
	}
	if attempt.alert.State != "" {
		attempt.next = st
		if attempt.previous == nil {
			delete(en.states, key)
		} else {
			en.states[key] = attempt.previous
		}
	}
	return attempt, true
}

func seasonalOperatorState(st *seriesState) RestoredOp {
	return RestoredOp{SilencedUntil: st.silencedUntil, AckedBy: st.ackedBy, AckedAt: st.ackedAt}
}

func (en *Engine) rollbackSeasonalSample(attempt seasonalAttempt) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if attempt.hasOperator {
		en.restored[attempt.key] = attempt.operator
	}
	if attempt.hasNotify {
		en.restoredNotify[attempt.key] = attempt.notifyState
	}
}

func (en *Engine) finishSeasonalSample(ctx context.Context, rule Rule, attempt seasonalAttempt, incidentID string) {
	en.mu.Lock()
	st := attempt.next
	// Keep operator changes made to a previously visible episode during the
	// publication. A succeeding resolution clears the old episode as usual.
	if st.firing && attempt.previous != nil {
		current := seasonalOperatorState(attempt.previous)
		if !current.SilencedUntil.Equal(attempt.priorOp.SilencedUntil) {
			st.silencedUntil = current.SilencedUntil
		}
		if current.AckedBy != attempt.priorOp.AckedBy || !current.AckedAt.Equal(attempt.priorOp.AckedAt) {
			st.ackedBy, st.ackedAt = current.AckedBy, current.AckedAt
		}
	}
	st.seasonalPublished = attempt.alert.State == StateFiring
	st.seasonalIncidentID = incidentID
	en.states[attempt.key] = st
	channelDue := attempt.channelDue
	if st.firing && attempt.previous != nil && st.silencedUntil.After(en.clock()) && channelDue {
		st.lastNotified = attempt.previous.lastNotified
		channelDue = false
	}
	note := NotifyState{FiringSince: st.since, LastNotified: st.lastNotified}
	en.mu.Unlock()
	if channelDue && en.notifier != nil {
		en.notifier.Deliver(ctx, rule, attempt.alert)
	}
	if attempt.alert.State == StateResolved && en.onResolve != nil {
		en.onResolve(attempt.key)
	}
	if attempt.alert.State == StateFiring && en.onNotify != nil {
		en.onNotify(attempt.key, note)
	}
}

func checkedSeasonalRead(ctx context.Context, rule Rule, at time.Time, read RuleMetricRead) (RuleMetricRead, error) {
	if read.TagSelection != nil || read.QuerySelection != nil || (read.Skip && len(read.Samples) != 0) || rule.TenantID == "" || rule.Type != Baseline {
		return RuleMetricRead{}, ErrSeasonalSource
	}
	proof := read.SeasonalPublication
	if (rule.Metric == SeasonalFlowMetric && !read.Skip) != (proof != nil) ||
		(proof != nil && (proof.Revalidate == nil || proof.Finish == nil || proof.Close == nil || len(proof.Scope) == 0)) {
		return RuleMetricRead{}, ErrSeasonalSource
	}
	seen := make(map[string]bool, len(read.Samples))
	for _, sample := range read.Samples {
		comparison := sample.Seasonal
		if comparison == nil || !seasonalObservationMatches(rule, at, sample) || seen[comparison.Observed.Subject] {
			return RuleMetricRead{}, ErrSeasonalSource
		}
		seen[comparison.Observed.Subject] = true
	}
	if err := ctx.Err(); err != nil {
		return RuleMetricRead{}, err
	}
	return read, nil
}

func seasonalObservationMatches(rule Rule, at time.Time, sample Sample) bool {
	comparison := sample.Seasonal
	row := comparison.Observed
	if row.TenantID != rule.TenantID || sample.Labels[promapi.TenantLabel] != rule.TenantID || row.Metric != rule.Metric ||
		row.Subject == "" || row.TS.IsZero() || row.TS.After(at) || math.IsNaN(row.Value) || math.IsInf(row.Value, 0) || row.Value != sample.Value {
		return false
	}
	switch comparison.State {
	case anomaly.SeasonalUnavailable, anomaly.SeasonalExcluded, anomaly.SeasonalWarming:
		return comparison.Evidence == nil
	case anomaly.SeasonalNormal, anomaly.SeasonalUp, anomaly.SeasonalDown:
		return comparison.Evidence != nil && len(comparison.Evidence.TrainingDays) >= SeasonalMinimumTrainingDays && ((comparison.Exact != nil) == (rule.Metric == SeasonalFlowMetric))
	default:
		return false
	}
}

func seasonalRuleDecision(comparison *anomaly.SeasonalComparison) evaluationDecision {
	expectation := EvaluationExpectation{Kind: Baseline}
	if comparison == nil {
		return evaluationDecision{warming: true, reason: "The current seasonal observation is unavailable", expectation: expectation}
	}
	switch comparison.State {
	case anomaly.SeasonalUnavailable:
		return evaluationDecision{warming: true, reason: "The current seasonal observation is unavailable", expectation: expectation}
	case anomaly.SeasonalExcluded:
		return evaluationDecision{warming: true, reason: "The current local date is excluded by the holiday calendar", expectation: expectation}
	case anomaly.SeasonalWarming:
		return evaluationDecision{warming: true, reason: "Waiting for comparable dates in the retained history", expectation: expectation,
			warmupSamples: comparison.ComparableDays, warmupNeeded: SeasonalMinimumTrainingDays}
	}
	calendar := *comparison.Evidence
	evidence := SeasonalEvaluationEvidence{Subject: comparison.Observed.Subject, ObservedAt: comparison.Observed.TS,
		Calendar:       SeasonalEvaluationCalendar{Timezone: calendar.Timezone, Weekday: calendar.Weekday, Hour: calendar.Hour, TrainingDays: calendar.TrainingDays},
		TrainingWindow: comparison.TrainingWindow, Citations: comparison.Citations, Exact: comparison.Exact}
	expectation.Seasonal = &evidence
	if comparison.Exact != nil {
		return exactSeasonalDecision(comparison, expectation)
	}
	evidence.Calendar.Median, evidence.Calendar.Spread = floatRef(calendar.Median), floatRef(calendar.RobustSpread)
	evidence.Calendar.Lower, evidence.Calendar.Upper = floatRef(calendar.Lower), floatRef(calendar.Upper)
	expectation.Lower, expectation.Upper = evidence.Calendar.Lower, evidence.Calendar.Upper
	reason := fmt.Sprintf("%s %02d:00 in %s normally ranges from %g to %g. Observed %g.",
		calendar.Weekday, calendar.Hour, calendar.Timezone, calendar.Lower, calendar.Upper, comparison.Observed.Value)
	return evaluationDecision{breached: comparison.State == anomaly.SeasonalUp || comparison.State == anomaly.SeasonalDown,
		reason: reason, expectation: expectation}
}

func exactSeasonalDecision(comparison *anomaly.SeasonalComparison, expectation EvaluationExpectation) evaluationDecision {
	changed := comparison.State == anomaly.SeasonalUp || comparison.State == anomaly.SeasonalDown
	if changed {
		return evaluationDecision{breached: true, reason: "Saved flow measure outside its weekly band", expectation: expectation}
	}
	return evaluationDecision{reason: "Saved flow measure within its weekly band", expectation: expectation}
}
