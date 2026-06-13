// SPDX-License-Identifier: LicenseRef-probectl-TBD

package eval

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// TestRCAEval runs the U-049 eval set through the real pipeline and reports
// the scores. STRUCTURAL assertions only (the set is big enough, every
// scenario executed, the report is well-formed) — quality scores are tracked
// as a CI artifact, NOT gated (non-blocking initially, per the register).
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
