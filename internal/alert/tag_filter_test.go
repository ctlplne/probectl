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
)

type tagFallbackCounter struct {
	legacy, selected int
	result           []Sample
	selection        *TagSelectionReceipt
	err              error
}

func (s *tagFallbackCounter) Current(context.Context, string, map[string]string) ([]Sample, error) {
	s.legacy++
	return []Sample{{Labels: map[string]string{"secret": "unfiltered"}, Value: 999}}, nil
}

type ruleTagCounter struct{ *tagFallbackCounter }

func (s ruleTagCounter) CurrentRule(context.Context, Rule) (RuleMetricRead, error) {
	s.selected++
	return RuleMetricRead{Samples: s.result, TagSelection: s.selection}, s.err
}

func TestTagRuleNeverFallsBackOrCallsFailureHealthy(t *testing.T) {
	rule := Rule{ID: "rule", TenantID: "tenant", Name: "Scoped", Enabled: true, Metric: "latency", HasTagFilter: true, Type: Threshold, Comparison: GT, Threshold: 1, Severity: SeverityWarning}
	for _, mode := range []string{"missing", "source-error", "canceled", "missing-clock", "invalid-clock", "empty"} {
		t.Run(mode, func(t *testing.T) {
			counter := &tagFallbackCounter{selection: &TagSelectionReceipt{TargetKind: "test", TagRevision: "9007199254740993", AsOf: time.Now().UTC()}}
			var source MetricSource = ruleTagCounter{counter}
			switch mode {
			case "missing":
				source = counter
			case "missing-clock":
				counter.selection = nil
			case "invalid-clock":
				counter.selection.TagRevision = "01"
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

func TestTagExecutionReceiptsTrackSnapshotWithoutChangingSeries(t *testing.T) {
	now := time.Date(2026, 11, 3, 22, 0, 0, 0, time.UTC)
	counter := &tagFallbackCounter{result: []Sample{{Labels: map[string]string{"test_id": "owned", "tenant_id": "tenant"}, Value: 0}}, selection: &TagSelectionReceipt{TargetKind: "test", TagRevision: "9007199254740993", AsOf: now}}
	var receipts []EvaluationReceipt
	engine := NewEngine(ruleTagCounter{counter}, nil, discard(), WithEvaluationSink(func(_ context.Context, r EvaluationReceipt) error { receipts = append(receipts, r); return nil }))
	engine.clock = func() time.Time { return now }
	rule := Rule{ID: "rule", TenantID: "tenant", Name: "Scoped", Enabled: true, Metric: "latency", HasTagFilter: true, Type: Threshold, Comparison: GT, Threshold: 1, Severity: SeverityWarning, UpdatedAt: now}
	evaluate := func() {
		t.Helper()
		if acted, err := engine.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 {
			t.Fatalf("evaluation acted or failed: %v", err)
		}
	}
	evaluate()
	if len(receipts) != 1 || receipts[0].TagSelection.TagRevision != "9007199254740993" || receipts[0].TagSelection == counter.selection || receipts[0].Labels["tenant_id"] != "" {
		t.Fatal("selection clock was aliased, rounded or added to labels")
	}
	firstFingerprint := receipts[0].Fingerprint
	now = now.Add(time.Second)
	counter.selection.AsOf = now
	evaluate()
	if len(receipts) != 1 {
		t.Fatal("as_of-only tick duplicated a steady receipt")
	}
	counter.selection.TagRevision = "9007199254740994"
	evaluate()
	if len(receipts) != 2 || receipts[1].Fingerprint != firstFingerprint || receipts[1].State != EvaluationNormal || receipts[0].TagSelection.TagRevision != "9007199254740993" {
		t.Fatal("revision transition changed series identity or prior proof")
	}
	rule.UpdatedAt = now
	evaluate()
	if len(receipts) != 3 || receipts[2].RuleRevision == receipts[1].RuleRevision {
		t.Fatal("rule revision changed without a new selection receipt")
	}
	counter.result = nil
	evaluate()
	if len(receipts) != 4 || receipts[3].State != EvaluationNoData || receipts[3].TagSelection.TagRevision != "9007199254740994" {
		t.Fatal("authorized empty selection lost its execution clock")
	}
	now = now.Add(time.Second)
	counter.selection.AsOf = now
	evaluate()
	if len(receipts) != 4 {
		t.Fatal("no_data duplicated on as_of-only change")
	}
	counter.selection.TagRevision = "9007199254740995"
	evaluate()
	if len(receipts) != 5 || receipts[4].State != EvaluationNoData {
		t.Fatal("no_data hid a new metadata snapshot")
	}
	counter.selection = nil
	if _, err := engine.Evaluate(t.Context(), rule); err == nil || len(receipts) != 5 {
		t.Fatal("missing source evidence was evaluated as no_data")
	}
}

func TestTagExecutionClockRefusesInvalidAuthorityAndRevision(t *testing.T) {
	for _, selection := range []*TagSelectionReceipt{nil, {}, {TargetKind: "device", TagRevision: "1", AsOf: time.Now()}, {TargetKind: "test", TagRevision: "0", AsOf: time.Now()}, {TargetKind: "test", TagRevision: "+1", AsOf: time.Now()}, {TargetKind: "test", TagRevision: "9223372036854775808", AsOf: time.Now()}, {TargetKind: "test", TagRevision: "1"}} {
		if selection.Validate() == nil {
			t.Fatal("invalid source evidence was accepted")
		}
	}
}
