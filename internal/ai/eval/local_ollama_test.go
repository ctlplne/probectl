// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package eval

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
)

type localEvalCase struct {
	Name             string `json:"name"`
	ExpectAbstention bool   `json:"expect_abstention"`
	Correct          bool   `json:"correct"`
	Grounded         bool   `json:"grounded_root_cause"`
	Abstained        bool   `json:"abstained"`
	Execution        string `json:"execution,omitempty"`
	ElapsedMicros    int64  `json:"elapsed_us"`
	AdapterCalls     int    `json:"adapter_calls"`
	RawCitations     int    `json:"raw_citations"`
	RawResolved      int    `json:"raw_resolved_citations"`
	UncitedClaims    int    `json:"uncited_claims"`
	Published        int    `json:"published_citations"`
	PublishedInvalid int    `json:"published_invalid_citations"`
	AdapterError     string `json:"adapter_error,omitempty"`
	PipelineError    string `json:"pipeline_error,omitempty"`
}

type localModelEval struct {
	Model              string          `json:"model"`
	Cases              []localEvalCase `json:"cases"`
	P50Micros          int64           `json:"p50_us"`
	P95Micros          int64           `json:"p95_us"`
	AdapterAnswers     int             `json:"adapter_answers"`
	FallbackAnswers    int             `json:"fallback_answers"`
	PositiveCases      int             `json:"positive_cases"`
	GroundedCorrect    int             `json:"grounded_correct"`
	AdapterCorrect     int             `json:"adapter_grounded_correct"`
	AbstentionCases    int             `json:"abstention_cases"`
	CorrectAbstentions int             `json:"correct_abstentions"`
	RawCitations       int             `json:"raw_citations"`
	RawResolved        int             `json:"raw_resolved_citations"`
	UncitedClaims      int             `json:"uncited_claims"`
	PublishedCitations int             `json:"published_citations"`
	PublishedInvalid   int             `json:"published_invalid_citations"`
}

type localEvalMatrix struct {
	StartedAt      time.Time        `json:"started_at"`
	ScenarioCount  int              `json:"scenario_count"`
	ScenarioFrom   int              `json:"scenario_from"`
	ScenarioTo     int              `json:"scenario_to"`
	ModelTimeoutNS int64            `json:"model_timeout_ns"`
	Models         []localModelEval `json:"models"`
}

// observedModel measures the provider output before the analyzer drops invalid
// citations or replaces an unsupported headline. One eval case at a time
// calls the production adapter through its normal resilience layer.
type observedModel struct {
	ai.ModelAdapter
	current *localEvalCase
}

func (m *observedModel) Synthesize(ctx context.Context, input ai.SynthesisInput) (ai.Synthesis, error) {
	m.current.AdapterCalls++
	out, err := m.ModelAdapter.Synthesize(ctx, input)
	if err != nil {
		m.current.AdapterError = err.Error()
		return out, err
	}
	m.current.RawCitations, m.current.RawResolved = citationResolution(input.Evidence, out.RootCauseCitations, out.Findings)
	if !out.InsufficientEvidence && len(out.RootCauseCitations) == 0 {
		m.current.UncitedClaims++
	}
	for _, finding := range out.Findings {
		if len(finding.Citations) == 0 {
			m.current.UncitedClaims++
		}
	}
	return out, nil
}

func measureLocalModel(ctx context.Context, cases []Scenario, adapter ai.ModelAdapter, budget time.Duration) localModelEval {
	probe := &observedModel{ModelAdapter: adapter}
	var model ai.ModelAdapter = probe
	if adapter.Name() != ai.NewBuiltinModel().Name() {
		model = ai.NewResilientModel(probe, ai.NewBuiltinModel(), budget)
	}

	report := localModelEval{Model: model.Name(), Cases: make([]localEvalCase, 0, len(cases))}
	timings := make([]int64, 0, len(cases))
	for _, sc := range cases {
		row := localEvalCase{Name: sc.Name, ExpectAbstention: sc.ExpectInsufficient}
		probe.current = &row
		start := time.Now()
		answer, err := scenarioAnswer(ctx, sc, model)
		row.ElapsedMicros = time.Since(start).Microseconds()
		timings = append(timings, row.ElapsedMicros)
		if err != nil {
			row.PipelineError = err.Error()
		} else {
			row.Execution = answer.Reasoning.Execution
			row.Grounded = answer.RootCauseGrounded
			row.Abstained = answer.InsufficientEvidence
			row.Correct = row.Grounded && !row.Abstained && answerMatches(answer.RootCause, sc.ExpectLabels)
			if sc.ExpectInsufficient {
				row.Correct = row.Abstained
			}
			var resolved int
			row.Published, resolved = citationResolution(answer.Evidence, answer.RootCauseCitations, answer.Findings)
			row.PublishedInvalid = row.Published - resolved
		}
		switch row.Execution {
		case ai.ReasoningLocalAdapter, ai.ReasoningBuiltin:
			report.AdapterAnswers++
		case ai.ReasoningBuiltinFallback:
			report.FallbackAnswers++
		}
		if sc.ExpectInsufficient {
			report.AbstentionCases++
			if row.Correct {
				report.CorrectAbstentions++
			}
		} else {
			report.PositiveCases++
			if row.Correct {
				report.GroundedCorrect++
				if row.Execution == ai.ReasoningLocalAdapter || row.Execution == ai.ReasoningBuiltin {
					report.AdapterCorrect++
				}
			}
		}
		report.RawCitations += row.RawCitations
		report.RawResolved += row.RawResolved
		report.UncitedClaims += row.UncitedClaims
		report.PublishedCitations += row.Published
		report.PublishedInvalid += row.PublishedInvalid
		report.Cases = append(report.Cases, row)
	}
	slices.Sort(timings)
	if len(timings) != 0 {
		report.P50Micros = timings[(len(timings)+1)/2-1]
		report.P95Micros = timings[(95*len(timings)+99)/100-1]
	}
	return report
}

// TestRCAEvalLocalOllama runs the committed scenarios against the builtin
// engine and locally admitted Ollama weights. Each model gets a fresh cache,
// and this run reports builtin fallbacks separately from native answers.
func TestRCAEvalLocalOllama(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_RCA_OLLAMA_ENDPOINT")
	models := strings.Fields(os.Getenv("PROBECTL_RCA_OLLAMA_MODELS"))
	output := os.Getenv("PROBECTL_RCA_OLLAMA_REPORT")
	if endpoint == "" && len(models) == 0 && output == "" {
		t.Skip("set the local Ollama endpoint, model names and report path")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.Scheme != "http" ||
		u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("the local evaluation requires a literal loopback origin with a port")
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !addr.Unmap().IsLoopback() || len(models) == 0 || output == "" {
		t.Fatal("a literal loopback origin, local model names and report path are required")
	}
	modelTimeout := time.Minute
	if value := os.Getenv("PROBECTL_AI_MODEL_TIMEOUT"); value != "" {
		configured, err := time.ParseDuration(value)
		if err != nil || configured <= 0 {
			t.Fatal("PROBECTL_AI_MODEL_TIMEOUT must be a positive duration")
		}
		modelTimeout = configured
	}

	scenarios := Scenarios()
	matrix := localEvalMatrix{StartedAt: time.Now().UTC(), ScenarioCount: len(scenarios), ScenarioTo: len(scenarios),
		ModelTimeoutNS: modelTimeout.Nanoseconds()}
	if raw := os.Getenv("PROBECTL_RCA_OLLAMA_RANGE"); raw != "" {
		from, to, found := strings.Cut(raw, ":")
		first, fromErr := strconv.Atoi(from)
		last, toErr := strconv.Atoi(to)
		if !found || fromErr != nil || toErr != nil || first < 0 || last <= first || first >= len(scenarios) {
			t.Fatal("the optional scenario range requires a valid zero-based first:last interval")
		}
		matrix.ScenarioFrom, matrix.ScenarioTo = first, min(last, len(scenarios))
		scenarios = scenarios[matrix.ScenarioFrom:matrix.ScenarioTo]
	}
	complete := matrix.ScenarioFrom == 0 && matrix.ScenarioTo == matrix.ScenarioCount
	matrix.Models = append(matrix.Models, measureLocalModel(t.Context(), scenarios, ai.NewBuiltinModel(), modelTimeout))
	for _, name := range models {
		adapter, err := ai.NewHTTPModel(ai.HTTPModelConfig{Kind: ai.KindOllama, Endpoint: endpoint, Model: name, Timeout: modelTimeout})
		if err != nil || adapter.RemoteEgress() {
			t.Fatalf("cannot build local model %q: %v", name, err)
		}
		report := measureLocalModel(t.Context(), scenarios, adapter, modelTimeout)
		matrix.Models = append(matrix.Models, report)
		if complete && report.AdapterAnswers == 0 {
			t.Errorf("%s never supplied an answer through the Ollama adapter", report.Model)
		}
		if report.PublishedInvalid > 0 || complete && report.PublishedCitations == 0 {
			t.Errorf("%s supplied no grounded citation evidence or published invalid references", report.Model)
		}
		for _, row := range report.Cases {
			if row.PipelineError != "" {
				t.Errorf("%s/%s: %s", report.Model, row.Name, row.PipelineError)
			}
		}
	}
	data, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
