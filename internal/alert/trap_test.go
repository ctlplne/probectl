// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeTrapSource returns per-device trap samples and records the rule it was
// asked about.
type fakeTrapSource struct {
	samples []Sample
	err     error
	asked   []Rule
}

func (f *fakeTrapSource) ActiveTraps(_ context.Context, rule Rule, _ time.Time) ([]Sample, error) {
	f.asked = append(f.asked, rule)
	return f.samples, f.err
}

func trapRule() Rule {
	r := Rule{
		ID: "r-trap", TenantID: "t1", Name: "uplink down", Enabled: true, Type: Trap,
		Severity: SeverityCritical,
		Trap:     &TrapMatch{TrapOID: "1.3.6.1.6.3.1.1.5.3", ClearTrapOID: ".1.3.6.1.6.3.1.1.5.4"},
	}
	NormalizeTrapRule(&r)
	return r
}

func TestTrapRuleValidation(t *testing.T) {
	ok := []TrapMatch{
		{TrapOID: ".1.3.6.1.6.3.1.1.5.3"},
		{TrapOID: "1.3.6.1.6.3.1.1.5.3", ClearTrapOID: "1.3.6.1.6.3.1.1.5.4", Device: "10.0.0.1",
			VarBindOID: ".1.3.6.1.2.1.2.2.1.1.3", VarBindValue: "3", HoldSeconds: 300},
		{TrapOID: ".1.3.6.1.4.1.9.9.41.2.0.1", VarBindOID: ".1.3.6.1.4.1.9.9.41.1.2.3.1.2"}, // value "" allowed
	}
	for i, m := range ok {
		m := m
		r := Rule{Name: "n", Type: Trap, Trap: &m, Severity: SeverityWarning}
		if err := r.Validate(); err != nil {
			t.Errorf("trap match %d rejected: %v", i, err)
		}
	}
	bad := map[string]Rule{
		"no match":            {Name: "n", Type: Trap},
		"bad oid":             {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "linkDown"}},
		"empty arc":           {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: ".1..3"}},
		"clear equals fire":   {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", ClearTrapOID: ".1.3.6"}},
		"bad clear":           {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", ClearTrapOID: "up"}},
		"value without oid":   {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", VarBindValue: "3"}},
		"bad varbind oid":     {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", VarBindOID: "ifIndex"}},
		"long value":          {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", VarBindOID: "1.3", VarBindValue: strings.Repeat("v", 513)}},
		"hold too short":      {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", HoldSeconds: 5}},
		"hold too long":       {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", HoldSeconds: MaxTrapHoldSeconds + 1}},
		"padded device":       {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6", Device: " 10.0.0.1"}},
		"foreign metric":      {Name: "n", Type: Trap, Metric: "probectl_probe_success", Trap: &TrapMatch{TrapOID: "1.3.6"}},
		"match labels":        {Name: "n", Type: Trap, Match: map[string]string{"device": "x"}, Trap: &TrapMatch{TrapOID: "1.3.6"}},
		"trap on a threshold": {Name: "n", Type: Threshold, Metric: "m", Comparison: GT, Trap: &TrapMatch{TrapOID: "1.3.6"}},
		"bad channel":         {Name: "n", Type: Trap, Trap: &TrapMatch{TrapOID: "1.3.6"}, Channels: []ChannelSpec{{Type: "webhook"}}},
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, r)
		}
	}
}

func TestNormalizeTrapRule(t *testing.T) {
	r := trapRule()
	if r.Metric != TrapMetric || r.Comparison != GTE || r.Threshold != 1 ||
		r.Trap.TrapOID != ".1.3.6.1.6.3.1.1.5.3" || r.Trap.HoldSeconds != DefaultTrapHoldSeconds {
		t.Fatalf("normalized = %+v trap=%+v", r, *r.Trap)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("a normalized trap rule no longer validates: %v", err)
	}
	other := thresholdRule()
	NormalizeTrapRule(&other)
	if other.Metric != "probectl_probe_loss_ratio" || other.Comparison != GT {
		t.Fatalf("NormalizeTrapRule touched a threshold rule: %+v", other)
	}
}

func TestTrapRuleFiresAndResolvesThroughTheEngine(t *testing.T) {
	src := &fakeTrapSource{}
	var got []Alert
	en := NewEngine(&fakeSource{}, nil, discard(), WithTrapSource(src),
		WithAlertSink(func(_ context.Context, a Alert) { got = append(got, a) }))
	rule := trapRule()
	labels := map[string]string{"device": "10.0.0.1", "trap_oid": rule.Trap.TrapOID, "trap_name": "linkDown"}
	ctx := context.Background()

	src.samples = []Sample{{Labels: labels, Value: 0, Reason: "clear trap linkUp from 10.0.0.1"}}
	if acted, err := en.Evaluate(ctx, rule); err != nil || len(acted) != 0 {
		t.Fatalf("a cleared device acted %v err=%v", acted, err)
	}
	src.samples = []Sample{{Labels: labels, Value: 1, Reason: "linkDown trap from 10.0.0.1 at T"}}
	if acted, err := en.Evaluate(ctx, rule); err != nil || len(acted) != 1 || acted[0].State != StateFiring {
		t.Fatalf("a matching trap did not fire: %v err=%v", acted, err)
	}
	// Still held: dedupe, no second notification.
	if acted, _ := en.Evaluate(ctx, rule); len(acted) != 0 {
		t.Fatalf("a held trap re-notified: %v", acted)
	}
	src.samples = []Sample{{Labels: labels, Value: 0, Reason: "clear trap linkUp from 10.0.0.1 at T2"}}
	acted, err := en.Evaluate(ctx, rule)
	if err != nil || len(acted) != 1 || acted[0].State != StateResolved || !strings.Contains(acted[0].Reason, "clear trap linkUp") {
		t.Fatalf("the clear trap did not resolve with its reason: %v err=%v", acted, err)
	}
	if len(got) != 2 || got[0].Metric != TrapMetric || got[0].Labels["device"] != "10.0.0.1" ||
		got[0].Comparison != GTE || got[0].Threshold != 1 || got[0].Reason != "linkDown trap from 10.0.0.1 at T" {
		t.Fatalf("delivered alerts = %+v", got)
	}
	if len(src.asked) != 4 || src.asked[0].Trap.TrapOID != rule.Trap.TrapOID {
		t.Fatalf("trap source asked %d times about %+v", len(src.asked), src.asked)
	}
}

func TestTrapRuleFailsLoudlyWithoutASource(t *testing.T) {
	en := NewEngine(&fakeSource{samples: []Sample{{Value: 1}}}, nil, discard())
	if _, err := en.Evaluate(context.Background(), trapRule()); err == nil {
		t.Fatal("a trap rule evaluated against the metric source")
	}
	src := &fakeTrapSource{err: errors.New("postgres unavailable")}
	en = NewEngine(&fakeSource{}, nil, discard(), WithTrapSource(src))
	if _, err := en.Evaluate(context.Background(), trapRule()); err == nil {
		t.Fatal("a trap read failure was swallowed")
	}
}

func TestTrapRuleEvaluationReceiptReadsAsAThreshold(t *testing.T) {
	var receipts []EvaluationReceipt
	src := &fakeTrapSource{samples: []Sample{{Labels: map[string]string{"device": "d"}, Value: 1, Reason: "linkDown trap"}}}
	en := NewEngine(nil, nil, discard(), WithTrapSource(src),
		WithEvaluationSink(func(_ context.Context, r EvaluationReceipt) error { receipts = append(receipts, r); return nil }))
	if _, err := en.Evaluate(context.Background(), trapRule()); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].State != EvaluationFiring || receipts[0].Expectation.Kind != Threshold ||
		receipts[0].Expectation.Comparison != GTE || *receipts[0].Expectation.Threshold != 1 || receipts[0].Reason != "linkDown trap" {
		t.Fatalf("receipts = %+v", receipts)
	}
}

// TestTrapEpisodeResolvesAfterEvaluatorDowntime is the regression for a trap
// series that fired, then had its hold run out while no evaluator was
// running: the fresh engine (restart or new leader) must deliver the
// resolution and drop the persisted state, whether the trap source still
// returns the series at 0 (inside its read window) or not at all (past it).
func TestTrapEpisodeResolvesAfterEvaluatorDowntime(t *testing.T) {
	rule := trapRule()
	labels := map[string]string{"device": "10.0.0.1", "trap_oid": rule.Trap.TrapOID, "trap_name": "linkDown"}
	key := stateKey(rule.ID, labels)

	// The first evaluator fires and persists its notification state.
	persisted := map[string]NotifyState{}
	first := NewEngine(nil, nil, discard(), WithTrapSource(&fakeTrapSource{samples: []Sample{{Labels: labels, Value: 1, Reason: "linkDown trap"}}}))
	first.SetNotifyHook(func(k string, ns NotifyState) { persisted[k] = ns })
	if acted, err := first.Evaluate(context.Background(), rule); err != nil || len(acted) != 1 || acted[0].State != StateFiring {
		t.Fatalf("first evaluator acted %v err=%v", acted, err)
	}
	if _, ok := persisted[key]; !ok {
		t.Fatalf("firing state was not persisted under %q: %v", key, persisted)
	}

	cases := map[string]struct {
		samples []Sample
		reason  string
	}{
		"past the read window": {samples: nil, reason: staleTrapReason},
		"inside the read window": {
			samples: []Sample{{Labels: labels, Value: 0, Reason: "no linkDown trap from 10.0.0.1 since T; the 15m0s hold ran out"}},
			reason:  "the 15m0s hold ran out",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var delivered []Alert
			var resolvedKeys []string
			restarted := NewEngine(nil, nil, discard(), WithTrapSource(&fakeTrapSource{samples: tc.samples}),
				WithAlertSink(func(_ context.Context, a Alert) { delivered = append(delivered, a) }))
			restarted.RestoreNotifications(persisted)
			restarted.SetResolveHook(func(k string) { resolvedKeys = append(resolvedKeys, k) })
			acted, err := restarted.Evaluate(context.Background(), rule)
			if err != nil {
				t.Fatal(err)
			}
			if len(acted) != 1 || acted[0].State != StateResolved || len(delivered) != 1 ||
				delivered[0].Labels["device"] != "10.0.0.1" || !strings.Contains(delivered[0].Reason, tc.reason) {
				t.Fatalf("restarted engine acted %+v delivered %+v, want one resolution of the 10.0.0.1 series", acted, delivered)
			}
			if len(resolvedKeys) != 1 || resolvedKeys[0] != key {
				t.Fatalf("resolve hook got %v, want the persisted row %q dropped", resolvedKeys, key)
			}
			if again, _ := restarted.Evaluate(context.Background(), rule); len(again) != 0 {
				t.Fatalf("the resolution repeated on the next pass: %+v", again)
			}
		})
	}

	// Still held after the restart: no re-notify and no resolution.
	held := NewEngine(nil, nil, discard(), WithTrapSource(&fakeTrapSource{samples: []Sample{{Labels: labels, Value: 1, Reason: "linkDown trap"}}}))
	held.RestoreNotifications(persisted)
	if acted, _ := held.Evaluate(context.Background(), rule); len(acted) != 0 {
		t.Fatalf("a still-held restored trap acted %+v", acted)
	}

	// Mid-debounce (for_n = 2, first breach after the restart): left alone.
	debounced := rule
	debounced.ForN = 2
	pending := NewEngine(nil, nil, discard(), WithTrapSource(&fakeTrapSource{samples: []Sample{{Labels: labels, Value: 1}}}))
	pending.RestoreNotifications(persisted)
	if acted, _ := pending.Evaluate(context.Background(), debounced); len(acted) != 0 {
		t.Fatalf("a debouncing restored trap acted %+v", acted)
	}

	// Metric rules keep their existing semantics: nothing is resolved for them.
	metric := thresholdRule()
	other := NewEngine(&fakeSource{}, nil, discard())
	other.RestoreNotifications(map[string]NotifyState{stateKey(metric.ID, map[string]string{"target": "db"}): {LastNotified: time.Now()}})
	if acted, _ := other.Evaluate(context.Background(), metric); len(acted) != 0 {
		t.Fatalf("a metric rule's restored series was resolved: %+v", acted)
	}
}
