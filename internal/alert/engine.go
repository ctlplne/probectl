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

	mu     sync.Mutex
	states map[string]*seriesState
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithAlertSink forwards every fired/resolved alert to fn (in addition to channel
// delivery) — used to feed alerts into the incident correlator (S17).
func WithAlertSink(fn func(context.Context, Alert)) EngineOption {
	return func(e *Engine) { e.sink = fn }
}

// NewEngine builds an engine. clock defaults to time.Now (overridable in tests).
func NewEngine(source MetricSource, notifier *Notifier, log *slog.Logger, opts ...EngineOption) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{
		source:   source,
		notifier: notifier,
		log:      log,
		clock:    time.Now,
		states:   make(map[string]*seriesState),
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

	var acted []Alert
	for _, s := range samples {
		alert, notify := en.evalSample(rule, s)
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
func (en *Engine) evalSample(rule Rule, s Sample) (Alert, bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	st := en.stateForLocked(rule, s.Labels)
	breached, reason := en.breached(rule, st, s.Value)

	// Capture the rendered state the surface serves (engine truth).
	st.ruleID, st.ruleName = rule.ID, rule.Name
	st.severity, st.metric = rule.Severity, rule.Metric
	st.labels = s.Labels
	st.lastValue, st.lastReason = s.Value, reason
	st.lastSeen = en.clock()

	return en.transition(rule, st, s, breached, reason)
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
func (en *Engine) breached(rule Rule, st *seriesState, value float64) (bool, string) {
	switch rule.Type {
	case Baseline:
		if st.base == nil {
			st.base = newBaseline(rule.Window)
		}
		anomalous, warming := st.base.evaluate(value, rule.Sensitivity)
		if warming {
			return false, ""
		}
		return anomalous, fmt.Sprintf("%s=%g deviates from its baseline (>%g sigma)", rule.Metric, value, rule.Sensitivity)
	default: // Threshold
		b := breaches(rule.Comparison, value, rule.Threshold)
		return b, fmt.Sprintf("%s=%g %s %g", rule.Metric, value, rule.Comparison, rule.Threshold)
	}
}

// transition advances the series state machine and returns an alert to notify (if
// any), applying ForN debounce, renotify dedupe, and resolved transitions.
func (en *Engine) transition(rule Rule, st *seriesState, s Sample, breached bool, reason string) (Alert, bool) {
	forN := rule.ForN
	if forN < 1 {
		forN = 1
	}

	if breached {
		st.breachCount++
		if st.breachCount < forN {
			return Alert{}, false // still pending (debounce)
		}
		firstFiring := !st.firing
		st.firing = true
		now := en.clock()
		if firstFiring {
			st.since = now // a new firing episode
		}
		// A silence (S-FE1) suppresses firing notifications until its deadline;
		// the series keeps evaluating and stays visible as firing.
		if st.silencedUntil.After(now) {
			return Alert{}, false
		}
		renotify := rule.RenotifySeconds > 0 &&
			now.Sub(st.lastNotified) >= time.Duration(rule.RenotifySeconds)*time.Second
		if firstFiring || renotify {
			st.lastNotified = now
			return en.alert(rule, s, StateFiring, reason), true
		}
		return Alert{}, false // already firing, within the renotify window (dedupe)
	}

	// Not breached.
	st.breachCount = 0
	if st.firing {
		st.firing = false
		// The episode is over: operator state does not leak into the next one.
		st.silencedUntil = time.Time{}
		st.ackedBy, st.ackedAt = "", time.Time{}
		return en.alert(rule, s, StateResolved, "value recovered"), true
	}
	return Alert{}, false
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
