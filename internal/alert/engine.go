// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Sample is one current value of a metric series.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// MetricSource yields the current samples of a metric matching the given labels
// (the read side of the TSDB). Implementations are tenant-scoped by the caller.
type MetricSource interface {
	Current(ctx context.Context, metric string, match map[string]string) ([]Sample, error)
}

// Engine evaluates rules against a MetricSource, holding per-series state so it
// can debounce (ForN), dedupe/renotify, and emit resolved transitions.
type Engine struct {
	source   MetricSource
	notifier *Notifier
	log      *slog.Logger
	clock    func() time.Time

	sink func(context.Context, Alert) // optional: every acted alert is forwarded here
	// evaluationSink records a bounded explanation after tenant-scoped metric
	// evaluation. A persistence failure is logged but never blocks alerting.
	evaluationSink EvaluationSink

	mu     sync.Mutex
	states map[string]*seriesState
	// noDataRules suppresses duplicate rule-level no-data receipts.
	noDataRules map[string]bool

	maintenance map[string]MaintenanceWindow

	// Persisted operator state (Sprint 16, ARCH-005 — the volatile-stores
	// ADR's documented exception): silences/acks restored from the store are
	// re-applied when their series fires again; onResolve lets the API layer
	// delete the persisted row when an episode ends.
	restored  map[string]RestoredOp
	onResolve func(fingerprint string)
}

// RestoredOp is one persisted silence/ack awaiting its series to fire again.
type RestoredOp struct {
	SilencedUntil time.Time
	AckedBy       string
	AckedAt       time.Time
}

// RestoreOps seeds persisted operator actions (boot reload). An op applies
// the first time its fingerprint fires; expired silences are skipped.
func (en *Engine) RestoreOps(ops map[string]RestoredOp) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if en.restored == nil {
		en.restored = map[string]RestoredOp{}
	}
	for fp, op := range ops {
		en.restored[fp] = op
	}
}

// SetResolveHook wires the persisted-op cleanup: called (outside the lock)
// whenever a firing episode resolves, so the store row is deleted and a
// FUTURE episode starts clean — restart-restored state never outlives the
// episode semantics the in-memory engine always had.
func (en *Engine) SetResolveHook(fn func(fingerprint string)) { en.onResolve = fn }

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithAlertSink forwards every fired/resolved alert to fn (in addition to channel
// delivery) — used to feed alerts into the incident correlator (S17).
func WithAlertSink(fn func(context.Context, Alert)) EngineOption {
	return func(e *Engine) { e.sink = fn }
}

// WithEvaluationSink records deterministic evaluation receipts. The caller
// binds this sink to exactly one tenant before constructing the engine.
func WithEvaluationSink(fn EvaluationSink) EngineOption {
	return func(e *Engine) { e.evaluationSink = fn }
}

// NewEngine builds an engine. clock defaults to time.Now (overridable in tests).
func NewEngine(source MetricSource, notifier *Notifier, log *slog.Logger, opts ...EngineOption) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{
		source:      source,
		notifier:    notifier,
		log:         log,
		clock:       time.Now,
		states:      make(map[string]*seriesState),
		noDataRules: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Evaluate evaluates one rule against the current samples and delivers
// notifications for any state transitions. It returns the alerts it acted on.
func (en *Engine) Evaluate(ctx context.Context, rule Rule) ([]Alert, error) {
	if !rule.Enabled {
		return nil, nil
	}
	samples, err := en.source.Current(ctx, rule.Metric, rule.Match)
	if err != nil {
		return nil, fmt.Errorf("alert: query %q: %w", rule.Metric, err)
	}
	if len(samples) == 0 {
		en.recordNoData(ctx, rule)
		return nil, nil
	}
	en.mu.Lock()
	en.noDataRules[rule.ID] = false
	en.mu.Unlock()

	var acted []Alert
	for _, s := range samples {
		alert, notify, receipt := en.evalSample(rule, s)
		en.recordEvaluation(ctx, receipt)
		if notify {
			if en.notifier != nil {
				en.notifier.Deliver(ctx, rule, alert)
			}
			if en.sink != nil {
				en.sink(ctx, alert)
			}
			acted = append(acted, alert)
		}
	}
	return acted, nil
}

// evalSample evaluates one sample under the engine lock: the same state is read
// by the active-alert surface (Active/Silence/Acknowledge), so every mutation
// happens locked. Notification delivery stays outside the lock.
func (en *Engine) evalSample(rule Rule, s Sample) (Alert, bool, *EvaluationReceipt) {
	en.mu.Lock()
	defer en.mu.Unlock()
	key := stateKey(rule.ID, s.Labels)
	st := en.stateForLocked(rule, s.Labels)
	decision := en.breached(rule, st, s.Value)

	// Capture the rendered state the surface serves (engine truth).
	st.ruleID, st.ruleName = rule.ID, rule.Name
	st.severity, st.metric = rule.Severity, rule.Metric
	st.labels = s.Labels
	st.lastValue, st.lastReason = s.Value, decision.reason
	st.lastSeen = en.clock()

	acted, notify, state := en.transition(key, rule, st, s, decision)
	record := state != st.lastEvaluationState || state == EvaluationWarming
	st.lastEvaluationState = state
	if !record {
		return acted, notify, nil
	}
	value := s.Value
	return acted, notify, &EvaluationReceipt{
		ContractVersion:  EvaluationReceiptVersion,
		Fingerprint:      evaluationFingerprint(rule.ID, s.Labels),
		RuleID:           rule.ID,
		RuleRevision:     ruleRevision(rule),
		State:            state,
		ObservedAt:       st.lastSeen,
		ObservedValue:    &value,
		Expectation:      decision.expectation,
		BreachCount:      st.breachCount,
		RequiredBreaches: requiredBreaches(rule),
		WarmupSamples:    decision.warmupSamples,
		WarmupRequired:   decision.warmupNeeded,
		Reason:           decision.reason,
		Labels:           receiptLabels(s.Labels),
	}
}

// stateForLocked returns (creating if needed) the per-series state. en.mu held.
func (en *Engine) stateForLocked(rule Rule, labels map[string]string) *seriesState {
	key := stateKey(rule.ID, labels)
	st, ok := en.states[key]
	if !ok {
		st = &seriesState{}
		if rule.Type == Baseline {
			st.base = newBaseline(rule.Window)
		}
		en.states[key] = st
	}
	return st
}

// breached decides whether the value breaches the rule, returning a reason.
func (en *Engine) breached(rule Rule, st *seriesState, value float64) evaluationDecision {
	switch rule.Type {
	case Baseline:
		if st.base == nil {
			st.base = newBaseline(rule.Window)
		}
		evaluation := st.base.evaluate(value, rule.Sensitivity)
		expectation := EvaluationExpectation{
			Kind:   Baseline,
			Mean:   floatRef(evaluation.mean),
			StdDev: floatRef(evaluation.std),
			Lower:  floatRef(evaluation.mean - rule.Sensitivity*evaluation.std),
			Upper:  floatRef(evaluation.mean + rule.Sensitivity*evaluation.std),
		}
		if evaluation.warming {
			return evaluationDecision{
				warming: true, reason: "baseline warming",
				expectation: expectation, warmupSamples: evaluation.samples,
				warmupNeeded: evaluation.required,
			}
		}
		reason := fmt.Sprintf("%s=%g is within its baseline band", rule.Metric, value)
		if evaluation.anomalous {
			reason = fmt.Sprintf("%s=%g deviates from its baseline (>%g sigma)", rule.Metric, value, rule.Sensitivity)
		}
		return evaluationDecision{
			breached:    evaluation.anomalous,
			reason:      reason,
			expectation: expectation, warmupSamples: evaluation.samples,
			warmupNeeded: evaluation.required,
		}
	default: // Threshold
		b := breaches(rule.Comparison, value, rule.Threshold)
		return evaluationDecision{
			breached: b,
			reason:   fmt.Sprintf("%s=%g %s %g", rule.Metric, value, rule.Comparison, rule.Threshold),
			expectation: EvaluationExpectation{
				Kind: Threshold, Comparison: rule.Comparison, Threshold: floatRef(rule.Threshold),
			},
		}
	}
}

// transition advances the series state machine and returns an alert to notify (if
// any), applying ForN debounce, renotify dedupe, and resolved transitions.
func (en *Engine) transition(key string, rule Rule, st *seriesState, s Sample, decision evaluationDecision) (Alert, bool, EvaluationState) {
	forN := rule.ForN
	if forN < 1 {
		forN = 1
	}

	if decision.warming {
		st.breachCount = 0
		return Alert{}, false, EvaluationWarming
	}

	if decision.breached {
		st.breachCount++
		if st.breachCount < forN {
			return Alert{}, false, EvaluationPending // still pending (debounce)
		}
		firstFiring := !st.firing
		st.firing = true
		now := en.clock()
		if firstFiring {
			st.since = now // a new firing episode
			// ARCH-005: re-apply a persisted silence/ack the first time this
			// series fires after a restart (expired silences are skipped).
			if op, ok := en.restored[key]; ok {
				delete(en.restored, key)
				if op.SilencedUntil.After(now) {
					st.silencedUntil = op.SilencedUntil
				}
				if op.AckedBy != "" {
					st.ackedBy, st.ackedAt = op.AckedBy, op.AckedAt
				}
			}
		}
		if occ, ok := en.activeMaintenanceLocked(rule, s, now); ok {
			if occ.EndsAt.After(st.silencedUntil) {
				st.silencedUntil = occ.EndsAt
			}
			if firstFiring {
				return Alert{}, false, EvaluationFiring
			}
			return Alert{}, false, EvaluationSteady
		}
		// A silence (S-FE1) suppresses firing notifications until its deadline;
		// the series keeps evaluating and stays visible as firing.
		if st.silencedUntil.After(now) {
			if firstFiring {
				return Alert{}, false, EvaluationFiring
			}
			return Alert{}, false, EvaluationSteady
		}
		renotify := rule.RenotifySeconds > 0 &&
			now.Sub(st.lastNotified) >= time.Duration(rule.RenotifySeconds)*time.Second
		if firstFiring || st.lastNotified.IsZero() || renotify {
			st.lastNotified = now
			state := EvaluationSteady
			if firstFiring {
				state = EvaluationFiring
			}
			return en.alert(rule, s, StateFiring, decision.reason), true, state
		}
		return Alert{}, false, EvaluationSteady // already firing, within the renotify window (dedupe)
	}

	// Not breached.
	st.breachCount = 0
	if st.firing {
		st.firing = false
		// The episode is over: operator state does not leak into the next one.
		st.silencedUntil = time.Time{}
		st.ackedBy, st.ackedAt = "", time.Time{}
		if en.onResolve != nil {
			// Delete the persisted op so a future episode starts clean.
			go en.onResolve(key)
		}
		return en.alert(rule, s, StateResolved, "value recovered"), true, EvaluationResolved
	}
	return Alert{}, false, EvaluationNormal
}

func (en *Engine) recordNoData(ctx context.Context, rule Rule) {
	en.mu.Lock()
	if en.noDataRules[rule.ID] {
		en.mu.Unlock()
		return
	}
	en.noDataRules[rule.ID] = true
	observedAt := en.clock()
	en.mu.Unlock()
	en.recordEvaluation(ctx, &EvaluationReceipt{
		ContractVersion:  EvaluationReceiptVersion,
		Fingerprint:      noDataEvaluationFingerprint(rule.ID),
		RuleID:           rule.ID,
		RuleRevision:     ruleRevision(rule),
		State:            EvaluationNoData,
		ObservedAt:       observedAt,
		Expectation:      expectationForNoData(rule),
		RequiredBreaches: requiredBreaches(rule),
		Reason:           "no matching series returned by the tenant-scoped metric source",
	})
}

func expectationForNoData(rule Rule) EvaluationExpectation {
	if rule.Type == Baseline {
		return EvaluationExpectation{Kind: Baseline}
	}
	return EvaluationExpectation{
		Kind: Threshold, Comparison: rule.Comparison, Threshold: floatRef(rule.Threshold),
	}
}

func (en *Engine) recordEvaluation(ctx context.Context, receipt *EvaluationReceipt) {
	if receipt == nil || en.evaluationSink == nil {
		return
	}
	if err := en.evaluationSink(ctx, *receipt); err != nil {
		en.log.Warn("alert evaluation receipt persistence failed",
			"rule_id", receipt.RuleID, "state", receipt.State, "error", err)
	}
}

func (en *Engine) alert(rule Rule, s Sample, state State, reason string) Alert {
	return Alert{
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		TenantID:   rule.TenantID,
		State:      state,
		Severity:   rule.Severity,
		Metric:     rule.Metric,
		Labels:     s.Labels,
		Value:      s.Value,
		Threshold:  rule.Threshold,
		Comparison: rule.Comparison,
		Reason:     reason,
		At:         en.clock(),
	}
}

// RuleProvider supplies the rules to evaluate on each tick.
type RuleProvider interface {
	Rules(ctx context.Context) ([]Rule, error)
}

// Evaluator periodically evaluates a provider's rules with an Engine.
type Evaluator struct {
	engine   *Engine
	rules    RuleProvider
	interval time.Duration
	log      *slog.Logger
}

// NewEvaluator builds a ticking evaluator.
func NewEvaluator(engine *Engine, rules RuleProvider, interval time.Duration, log *slog.Logger) *Evaluator {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Evaluator{engine: engine, rules: rules, interval: interval, log: log}
}

// Engine exposes the evaluator's engine — the active-alert state surface
// (S-FE1) reads firing state and applies silence/acknowledge through it.
func (ev *Evaluator) Engine() *Engine {
	return ev.engine
}

// Tick runs one evaluation pass over all rules.
func (ev *Evaluator) Tick(ctx context.Context) error {
	rules, err := ev.rules.Rules(ctx)
	if err != nil {
		return fmt.Errorf("alert: load rules: %w", err)
	}
	for _, rule := range rules {
		if _, err := ev.engine.Evaluate(ctx, rule); err != nil {
			// A single rule's evaluation failure must not stop the others.
			ev.log.Warn("alert rule evaluation failed", "rule", rule.Name, "error", err)
		}
	}
	return nil
}

// Run evaluates on a ticker until ctx is canceled.
func (ev *Evaluator) Run(ctx context.Context) {
	ticker := time.NewTicker(ev.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ev.Tick(ctx); err != nil {
				ev.log.Warn("alert evaluation tick failed", "error", err)
			}
		}
	}
}
