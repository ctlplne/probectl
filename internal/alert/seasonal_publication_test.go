// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
)

type seasonalSourceFixture struct{ sample Sample }

func (*seasonalSourceFixture) Current(context.Context, string, map[string]string) ([]Sample, error) {
	return nil, errors.New("ordinary source should not read a seasonal rule")
}

func (s *seasonalSourceFixture) CurrentSeasonalRule(context.Context, Rule, time.Time) (RuleMetricRead, error) {
	return RuleMetricRead{Samples: []Sample{s.sample}}, nil
}

func TestSeasonalAlertRequiresCitedPublicationAndRetriesTheSameObservation(t *testing.T) {
	const tenant = "owned"
	at := time.Date(2026, 12, 8, 10, 15, 0, 0, time.UTC)
	model, err := anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{Timezone: "UTC", MinimumDays: 3, MinimumDeviation: 5})
	if err != nil {
		t.Fatal(err)
	}
	makeSample := func(observed time.Time, value float64) Sample {
		t.Helper()
		var input []anomaly.Feature
		for _, window := range model.ComparableWindows(observed) {
			input = append(input, anomaly.Feature{TenantID: tenant, Metric: "rate", Subject: "series-a", TS: window.Start, Value: 40, Citation: window.Start.Format(time.RFC3339Nano)})
		}
		input = append(input, anomaly.Feature{TenantID: tenant, Metric: "rate", Subject: "series-a", TS: observed, Value: value, Citation: observed.Format(time.RFC3339Nano)})
		result, err := model.Compare(t.Context(), input, anomaly.Query{TenantID: tenant})
		if err != nil || len(result) != 1 {
			t.Fatalf("fixture comparison: %+v (%v)", result, err)
		}
		return Sample{Labels: map[string]string{"tenant_id": tenant}, Value: value, Seasonal: &result[0]}
	}
	source := &seasonalSourceFixture{sample: makeSample(at, 70)}
	rule := Rule{ID: "rule-a", TenantID: tenant, Type: Baseline, Metric: "rate", Enabled: true, HasSeasonalSource: true, UpdatedAt: at.Add(-time.Hour)}
	blocked := errors.New("fixture incident store unavailable")
	var publishes []State
	var channelReceipt, resolved int
	var engine *Engine
	var receipts []EvaluationReceipt
	engine = NewEngine(source, nil, nil, WithAlertSink(func(context.Context, Alert) { t.Fatal("seasonal path bypassed cited publication") }),
		WithEvaluationSink(func(_ context.Context, receipt EvaluationReceipt) error {
			receipts = append(receipts, receipt)
			return nil
		}),
		WithSeasonalPublisher(func(_ context.Context, got Rule, a Alert, evidence SeasonalEvaluationEvidence) (string, error) {
			if evidence.ObservedAt != source.sample.Seasonal.Observed.TS || len(evidence.Citations) != 3 || evidence.Calendar.Lower != 35 ||
				evidence.Calendar.Upper != 45 || evidence.Subject != "series-a" || a.TenantID != tenant || got.ID != rule.ID {
				t.Fatalf("bad current cited alert: %+v %+v", a, evidence)
			}
			publishes = append(publishes, a.State)
			if len(publishes) == 1 {
				return "", blocked
			}
			visible := engine.Active()
			if (a.State == StateResolved && len(visible) != 1) || (a.State == StateFiring && len(visible) != 0) {
				t.Fatal("the prior published alert state changed before incident commit")
			}
			return "owned-incident", nil
		}))
	engine.clock = func() time.Time { return at }
	engine.SetNotifyHook(func(string, NotifyState) { channelReceipt++ })
	engine.SetResolveHook(func(string) { resolved++ })
	if out, err := engine.Evaluate(t.Context(), rule); !errors.Is(err, blocked) || len(out) != 0 || len(engine.Active()) != 0 || channelReceipt != 0 {
		t.Fatal("unpublished finding escaped the incident boundary", err)
	}
	if out, err := engine.Evaluate(t.Context(), rule); err != nil || len(out) != 1 || out[0].State != StateFiring || len(engine.Active()) != 1 || channelReceipt != 1 {
		t.Fatal("the same observed event did not retry cleanly", err)
	}
	if engine.Active()[0].IncidentID != "owned-incident" || len(receipts) != 1 || receipts[0].Expectation.Seasonal.IncidentID != "owned-incident" {
		t.Fatal("the live alert or its persisted receipt lost the exact incident link")
	}
	if out, err := engine.Evaluate(t.Context(), rule); err != nil || len(out) != 0 || len(publishes) != 2 {
		t.Fatal("repeated clock evaluation inflated the observed population", err)
	}
	at = at.Add(time.Minute)
	source.sample = makeSample(at, 40)
	if out, err := engine.Evaluate(t.Context(), rule); err != nil || len(out) != 1 || out[0].State != StateResolved || len(engine.Active()) != 0 || resolved != 1 {
		t.Fatal("cited recovery did not close the published episode", err)
	}
}
