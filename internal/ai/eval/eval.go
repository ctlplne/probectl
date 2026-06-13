// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package eval is the RCA quality eval harness (U-049): a fixed scenario set
// spanning probectl's planes (change, BGP/routing, path, device, threat,
// metrics/SLO), each with planted evidence and an expected root-cause label,
// plus a scoring harness measuring (a) answer accuracy — does the root cause
// name the planted true cause, (b) citation precision — what fraction of the
// evidence the findings cite is genuinely relevant, and (c) honesty — does the
// analyzer say "insufficient evidence" when nothing was planted.
//
// The harness runs the REAL pipeline (planner → engine → synthesize →
// citation-grounding) against the air-gapped builtin model, so the score is a
// deterministic baseline tracked over time; a model-adapter change that
// regresses grounding shows up as a score drop. Wired into CI as the rca-eval
// job that uploads the JSON report as an artifact. The builtin path is now
// gated by a committed regression FLOOR (AIRCA-004) on answer accuracy and mean
// citation precision in eval_test.go, so a grounding/accuracy regression fails
// the build; nondeterministic remote adapters (Run with a non-nil model) stay
// artifact-only and are never floor-gated.
package eval

import (
	"context"
	"fmt"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// Scenario is one labeled RCA case: a question, planted per-domain evidence
// rows, and the expected outcome.
type Scenario struct {
	Name    string            `json:"name"`
	Planes  []string          `json:"planes"` // documentation: which planes the case spans
	Text    string            `json:"question"`
	Subject map[string]string `json:"subject,omitempty"`

	Entities []ai.Row `json:"-"` // incidents + cross-plane signals
	Events   []ai.Row `json:"-"` // change/BGP/threat events
	Metrics  []ai.Row `json:"-"` // symptom metrics
	Topology []ai.Row `json:"-"` // graph context

	// ExpectLabels must ALL appear (case-insensitive) in the root cause for
	// answer credit. Empty + ExpectInsufficient set = negative control.
	ExpectLabels       []string `json:"expect_labels,omitempty"`
	ExpectInsufficient bool     `json:"expect_insufficient,omitempty"`
	// RelevantTitles are the titles of planted rows that genuinely bear on the
	// root cause; citing anything else costs citation precision.
	RelevantTitles []string `json:"relevant_titles,omitempty"`
}

// Result is one scenario's score.
type Result struct {
	Name              string  `json:"name"`
	AnswerCorrect     bool    `json:"answer_correct"`
	CitationPrecision float64 `json:"citation_precision"` // NaN-free: 1.0 when nothing cited and nothing expected
	Cited             int     `json:"cited"`
	Relevant          int     `json:"relevant_cited"`
	Insufficient      bool    `json:"insufficient"`
	Confidence        string  `json:"confidence"`
	RootCause         string  `json:"root_cause"`
	Err               string  `json:"error,omitempty"`
}

// Report is the aggregate the CI job tracks as an artifact.
type Report struct {
	Scenarios             int      `json:"scenarios"`
	AnswerAccuracy        float64  `json:"answer_accuracy"`
	MeanCitationPrecision float64  `json:"mean_citation_precision"`
	HonestyPass           bool     `json:"honesty_pass"` // every negative control said "insufficient"
	Model                 string   `json:"model"`
	Results               []Result `json:"results"`
}

// staticSource serves planted rows for every query — selector-blind on
// purpose: planted distractors MUST reach the model so precision means
// something.
type staticSource struct{ rows []ai.Row }

func (s staticSource) QueryMetrics(_ context.Context, _ string, _ map[string]string, _ ai.TimeRange, limit int) ([]ai.Row, error) {
	return capRows(s.rows, limit), nil
}
func (s staticSource) QueryEvents(_ context.Context, _ string, _ map[string]string, _ ai.TimeRange, limit int) ([]ai.Row, error) {
	return capRows(s.rows, limit), nil
}
func (s staticSource) QueryEntities(_ context.Context, _ string, _ map[string]string, limit int) ([]ai.Row, error) {
	return capRows(s.rows, limit), nil
}
func (s staticSource) QueryTopology(_ context.Context, _ string, _ ai.Query) ([]ai.Row, error) {
	return s.rows, nil
}

func capRows(rows []ai.Row, limit int) []ai.Row {
	if limit > 0 && limit < len(rows) {
		return rows[:limit]
	}
	return rows
}

// evalPrincipal can read every domain — the eval grades quality, not RBAC
// (RBAC/tenancy have their own tests).
func evalPrincipal() *auth.Principal {
	return &auth.Principal{TenantID: "eval-tenant", Permissions: map[string]bool{
		"metrics.read": true, "events.read": true, "entities.read": true, "topology.read": true,
	}}
}

// Run scores every scenario against the given model (nil = the builtin).
func Run(ctx context.Context, scenarios []Scenario, model ai.ModelAdapter) Report {
	if model == nil {
		model = ai.NewBuiltinModel()
	}
	rep := Report{Model: model.Name(), HonestyPass: true}
	var answerHits, precisionSum float64
	scored := 0

	for _, sc := range scenarios {
		res := runOne(ctx, sc, model)
		rep.Results = append(rep.Results, res)
		if sc.ExpectInsufficient {
			if !res.Insufficient {
				rep.HonestyPass = false
			}
			continue // negative controls don't enter accuracy/precision means
		}
		scored++
		if res.AnswerCorrect {
			answerHits++
		}
		precisionSum += res.CitationPrecision
	}
	rep.Scenarios = len(scenarios)
	if scored > 0 {
		rep.AnswerAccuracy = answerHits / float64(scored)
		rep.MeanCitationPrecision = precisionSum / float64(scored)
	}
	return rep
}

func runOne(ctx context.Context, sc Scenario, model ai.ModelAdapter) Result {
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
	analyzer := ai.NewAnalyzer(ai.NewEngine(opts...), ai.WithModel(model))

	ans, err := analyzer.Analyze(ctx, evalPrincipal(), ai.Question{Text: sc.Text, Subject: sc.Subject})
	res := Result{Name: sc.Name}
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Insufficient = ans.InsufficientEvidence
	res.Confidence = string(ans.Confidence)
	res.RootCause = ans.RootCause
	res.AnswerCorrect = answerMatches(ans.RootCause, sc.ExpectLabels)
	res.Cited, res.Relevant, res.CitationPrecision = citationPrecision(ans, sc.RelevantTitles)
	return res
}

// answerMatches: every expected label appears (case-insensitive) in the root cause.
func answerMatches(rootCause string, labels []string) bool {
	if len(labels) == 0 {
		return false
	}
	rc := strings.ToLower(rootCause)
	for _, l := range labels {
		if !strings.Contains(rc, strings.ToLower(l)) {
			return false
		}
	}
	return true
}

// citationPrecision resolves every finding citation to its evidence and counts
// how many of the distinct cited signals are in the relevant-title set.
func citationPrecision(ans ai.Answer, relevant []string) (cited, hit int, precision float64) {
	rel := make(map[string]bool, len(relevant))
	for _, t := range relevant {
		rel[strings.ToLower(t)] = true
	}
	byID := make(map[string]ai.Evidence, len(ans.Evidence))
	for _, e := range ans.Evidence {
		byID[e.ID] = e
	}
	seen := map[string]bool{}
	for _, f := range ans.Findings {
		for _, c := range f.Citations {
			if seen[c.EvidenceID] {
				continue
			}
			seen[c.EvidenceID] = true
			cited++
			if e, ok := byID[c.EvidenceID]; ok && rel[strings.ToLower(e.Title)] {
				hit++
			}
		}
	}
	if cited == 0 {
		if len(relevant) == 0 {
			return 0, 0, 1 // nothing to cite, nothing cited
		}
		return 0, 0, 0
	}
	return cited, hit, float64(hit) / float64(cited)
}

// Summary renders the one-line score the CI log greps for.
func (r Report) Summary() string {
	return fmt.Sprintf("rca-eval: scenarios=%d answer_accuracy=%.2f citation_precision=%.2f honesty=%t model=%s",
		r.Scenarios, r.AnswerAccuracy, r.MeanCitationPrecision, r.HonestyPass, r.Model)
}
