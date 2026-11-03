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
)

type tagFallbackCounter struct {
	legacy, selected int
	result           []Sample
	err              error
}

func (s *tagFallbackCounter) Current(context.Context, string, map[string]string) ([]Sample, error) {
	s.legacy++
	return []Sample{{Labels: map[string]string{"secret": "unfiltered"}, Value: 999}}, nil
}

type ruleTagCounter struct{ *tagFallbackCounter }

func (s ruleTagCounter) CurrentRule(context.Context, Rule) ([]Sample, error) {
	s.selected++
	return s.result, s.err
}

func TestTagRuleNeverFallsBackOrCallsFailureHealthy(t *testing.T) {
	rule := Rule{ID: "rule", TenantID: "tenant", Name: "Scoped", Enabled: true, Metric: "latency", HasTagFilter: true, Type: Threshold, Comparison: GT, Threshold: 1, Severity: SeverityWarning}
	for _, mode := range []string{"missing", "source-error", "canceled", "empty"} {
		t.Run(mode, func(t *testing.T) {
			counter := &tagFallbackCounter{}
			var source MetricSource = ruleTagCounter{counter}
			switch mode {
			case "missing":
				source = counter
			case "source-error":
				counter.err = errors.New("current owner/source refused")
			case "canceled":
				counter.err = context.Canceled
			}
			var receipts []EvaluationReceipt
			engine := NewEngine(source, nil, discard(), WithEvaluationSink(func(_ context.Context, r EvaluationReceipt) error { receipts = append(receipts, r); return nil }))
			acted, err := engine.Evaluate(t.Context(), rule)
			if counter.legacy != 0 || len(acted) != 0 {
				t.Fatal("tag source failure acquired unfiltered telemetry or acted")
			}
			if mode == "empty" {
				if err != nil || len(receipts) != 1 || receipts[0].State != EvaluationNoData {
					t.Fatal("legitimate empty metadata selection was not no_data")
				}
			} else if err == nil || len(receipts) != 0 {
				t.Fatal("missing/failed metadata source was evaluated as healthy or empty")
			}
		})
	}
}
