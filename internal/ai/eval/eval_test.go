// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package eval

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
)

// TestRCAEval runs the U-049 eval set through the real pipeline and reports
// the scores. Beyond the structural assertions (the set is big enough, every
// scenario executed, the report is well-formed) the deterministic builtin path
// is BLOCKING: answer accuracy and mean citation precision are gated at a
// committed 0.85/0.85 floor (AIRCA-004) both here and in the rca-eval CI job,
// which is part of verify-all — a regression below the floor fails the build.
// Set PROBECTL_RCA_EVAL_REPORT=<path> to write the JSON report.
func TestRCAEval(t *testing.T) {
	scenarios := Scenarios()
	if len(scenarios) < 20 {
		t.Fatalf("eval set has %d scenarios, want >= 20", len(scenarios))
	}

	rep := Run(context.Background(), scenarios, nil)

	if len(rep.Results) != len(scenarios) {
		t.Fatalf("scored %d of %d scenarios", len(rep.Results), len(scenarios))
	}
	for _, r := range rep.Results {
		if r.Err != "" {
			t.Errorf("scenario %s errored: %s", r.Name, r.Err)
		}
	}
	// The harness itself must discriminate: a 0.0 across the board means the
	// pipeline broke (e.g. nothing gathered), not that the model is weak.
	if rep.AnswerAccuracy == 0 {
		t.Error("answer accuracy 0.0 — the harness is not gathering/synthesizing at all")
	}
	if !rep.HonestyPass {
		t.Error("negative control fabricated an answer (insufficient-evidence honesty broke)")
	}

	// AIRCA-004: a committed regression FLOOR on the deterministic builtin path.
	// The builtin model is fully deterministic, so its scores cannot drift on
	// model noise — a drop below these floors means a real grounding/accuracy
	// regression (e.g. a scenario's expected label was dropped from the builtin
	// output, or citation grounding loosened). This makes rca-eval BLOCKING for
	// the builtin (remote/nondeterministic adapters stay artifact-only via
	// Run(..., model)). Floors sit safely below the observed baseline
	// (accuracy 0.91, precision 0.92) so legitimate scenario churn has headroom;
	// ratchet UP, never down (anti-vacuous-green §3).
	const (
		minAnswerAccuracy        = 0.85
		minMeanCitationPrecision = 0.85
	)
	if rep.AnswerAccuracy < minAnswerAccuracy {
		t.Errorf("builtin answer_accuracy %.2f < floor %.2f (AIRCA-004 regression)", rep.AnswerAccuracy, minAnswerAccuracy)
	}
	if rep.MeanCitationPrecision < minMeanCitationPrecision {
		t.Errorf("builtin mean_citation_precision %.2f < floor %.2f (AIRCA-004 regression)", rep.MeanCitationPrecision, minMeanCitationPrecision)
	}

	t.Log(rep.Summary())
	for _, r := range rep.Results {
		t.Logf("  %-36s answer=%-5t precision=%.2f cited=%d conf=%s", r.Name, r.AnswerCorrect, r.CitationPrecision, r.Cited, r.Confidence)
	}

	if path := os.Getenv("PROBECTL_RCA_EVAL_REPORT"); path != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
		t.Logf("report written to %s", path)
	}
}

func TestRCAEvalAdversarialDuplicateEventTimeFixture(t *testing.T) {
	sc, ok := scenarioByName("adversarial-bgp-near-duplicate-event-time")
	if !ok {
		t.Fatal("missing RED-003 adversarial RCA scenario")
	}

	ans, err := analyzeScenario(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !answerMatches(ans.RootCause, sc.ExpectLabels) {
		t.Fatalf("root cause = %q, want labels %v", ans.RootCause, sc.ExpectLabels)
	}
	if len(ans.RootCauseCitations) != 1 {
		t.Fatalf("root cause citations = %+v, want one primary citation", ans.RootCauseCitations)
	}

	byID := map[string]ai.Evidence{}
	for _, e := range ans.Evidence {
		byID[e.ID] = e
	}
	primary := byID[ans.RootCauseCitations[0].EvidenceID]
	wantAt := time.Date(2026, 7, 1, 10, 5, 0, 0, time.UTC)
	if primary.Title != "Current BGP origin change for 192.0.2.0/24" {
		t.Fatalf("primary evidence = %+v, want current BGP event", primary)
	}
	if !primary.OccurredAt.Equal(wantAt) {
		t.Fatalf("primary occurred_at = %s, want collector event time %s", primary.OccurredAt, wantAt)
	}
	if primary.Fields["prefix"] != "192.0.2.0/24" || primary.Fields["source"] != "ris-live:rrc00" {
		t.Fatalf("primary source attributes lost: %+v", primary.Fields)
	}
	if detail, _ := primary.Fields["detail"].(string); !strings.Contains(detail, "origin_asn=64500") || !strings.Contains(detail, "peer_asn=64496") {
		t.Fatalf("primary detail does not carry original attributes: %+v", primary.Fields)
	}

	var stale *ai.Evidence
	for i := range ans.Evidence {
		if ans.Evidence[i].Title == "Recovered BGP origin change for 192.0.2.0/24" {
			stale = &ans.Evidence[i]
			break
		}
	}
	if stale == nil {
		t.Fatal("stale near-duplicate event was collapsed out of the evidence set")
	}
	if stale.ID == primary.ID {
		t.Fatalf("distinct near-duplicate events share evidence id %s", stale.ID)
	}
	if !stale.OccurredAt.Before(primary.OccurredAt) {
		t.Fatalf("stale duplicate event time = %s, current = %s", stale.OccurredAt, primary.OccurredAt)
	}

	rep := Run(context.Background(), []Scenario{sc}, nil)
	if len(rep.Results) != 1 {
		t.Fatalf("adversarial scenario produced %d results, want 1", len(rep.Results))
	}
	res := rep.Results[0]
	if !res.AnswerCorrect {
		t.Fatalf("eval scorer rejected adversarial scenario: %+v", res)
	}
}

func scenarioByName(name string) (Scenario, bool) {
	for _, sc := range Scenarios() {
		if sc.Name == name {
			return sc, true
		}
	}
	return Scenario{}, false
}

func analyzeScenario(ctx context.Context, sc Scenario) (ai.Answer, error) {
	opts := []ai.Option{}
	if len(sc.Metrics) > 0 {
		opts = append(opts, ai.WithMetrics(staticSource{rows: sc.Metrics}))
	}
	if len(sc.Events) > 0 {
		opts = append(opts, ai.WithEvents(staticSource{rows: sc.Events}))
	}
	if len(sc.Entities) > 0 {
		opts = append(opts, ai.WithEntities(staticSource{rows: sc.Entities}))
	}
	if len(sc.Topology) > 0 {
		opts = append(opts, ai.WithTopology(staticSource{rows: sc.Topology}))
	}
	analyzer := ai.NewAnalyzer(ai.NewEngine(opts...))
	return analyzer.Analyze(ctx, evalPrincipal(), ai.Question{Text: sc.Text, Subject: sc.Subject})
}
