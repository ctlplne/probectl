package ai

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/auth"
)

// Answer is the result of an RCA: a cited, RBAC-scoped root cause. ID ties an
// answer to any feedback the user later gives. InsufficientEvidence is set when
// nothing grounded supports a conclusion — netctl prefers saying so over guessing.
type Answer struct {
	ID                   string        `json:"id"`
	Tenant               string        `json:"tenant"`
	Question             string        `json:"question"`
	RootCause            string        `json:"root_cause"`
	Confidence           Confidence    `json:"confidence"`
	Findings             []Finding     `json:"findings"`
	Evidence             []Evidence    `json:"evidence"`
	Model                string        `json:"model"`
	InsufficientEvidence bool          `json:"insufficient_evidence"`
	Elapsed              time.Duration `json:"-"`
}

// Analyzer runs the RCA pipeline: plan (deterministic) → gather (via the S23
// engine, tenant-first then RBAC) → synthesize (a model with no tools) →
// citation-integrity. It is the AI assistant's brain; the model is swappable and
// never sees data outside the caller's tenant + permissions.
type Analyzer struct {
	engine      *Engine
	model       ModelAdapter
	planner     Planner
	maxEvidence int
	newID       func() string
}

// AnalyzerOption configures an Analyzer.
type AnalyzerOption func(*Analyzer)

// WithModel sets the synthesis backend (default: the built-in air-gapped model).
func WithModel(m ModelAdapter) AnalyzerOption { return func(a *Analyzer) { a.model = m } }

// WithPlanner overrides the query planner (default: HeuristicPlanner).
func WithPlanner(p Planner) AnalyzerOption { return func(a *Analyzer) { a.planner = p } }

// WithMaxEvidence caps how many signals an answer may gather (cost guard).
func WithMaxEvidence(n int) AnalyzerOption {
	return func(a *Analyzer) {
		if n > 0 {
			a.maxEvidence = n
		}
	}
}

// NewAnalyzer builds an Analyzer over the S23 engine. The default model is the
// fully air-gapped built-in synthesizer, so RCA works with zero external calls.
func NewAnalyzer(engine *Engine, opts ...AnalyzerOption) *Analyzer {
	a := &Analyzer{
		engine:      engine,
		model:       NewBuiltinModel(),
		planner:     HeuristicPlanner{},
		maxEvidence: 50,
		newID:       defaultIDGen,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Analyze answers a natural-language question with a cited, RBAC-scoped root
// cause. The tenant boundary is enforced first (fail closed on a tenantless
// principal); every plane is gathered through the S23 engine, so a caller only
// ever sees evidence from domains they may read.
func (a *Analyzer) Analyze(ctx context.Context, p *auth.Principal, q Question) (Answer, error) {
	if p == nil || p.TenantID == "" {
		return Answer{}, ErrNoTenant
	}
	start := time.Now()

	// 1. Plan deterministically (netctl code, never the model).
	queries := a.planner.Plan(q)

	// 2. Gather evidence via the engine. Domains the caller cannot read
	// (ErrForbidden) or that aren't configured (ErrNoSource) are skipped — the
	// answer is grounded only in what the caller is permitted to see.
	var evidence []Evidence
	n := 0
	for _, query := range queries {
		if len(evidence) >= a.maxEvidence {
			break
		}
		res, err := a.engine.Query(ctx, p, query)
		if err != nil {
			if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNoSource) || errors.Is(err, ErrUnknownDomain) {
				continue
			}
			return Answer{}, err
		}
		evidence = append(evidence, collectEvidence(query.Domain, res.Rows, &n)...)
	}
	if len(evidence) > a.maxEvidence {
		evidence = evidence[:a.maxEvidence]
	}

	// 3. Synthesize over the gathered evidence (the model has no tools).
	syn, err := a.model.Synthesize(ctx, SynthesisInput{Question: q.Text, Evidence: evidence})
	if err != nil {
		return Answer{}, err
	}

	// 4. Citation integrity: drop any finding citing evidence that doesn't exist,
	// so a hallucinated reference can never reach the user.
	syn.Findings = groundFindings(syn.Findings, evidence)
	insufficient := syn.InsufficientEvidence || len(syn.Findings) == 0

	ans := Answer{
		ID:                   a.newID(),
		Tenant:               p.TenantID,
		Question:             q.Text,
		RootCause:            syn.RootCause,
		Confidence:           syn.Confidence,
		Findings:             syn.Findings,
		Evidence:             evidence,
		Model:                a.model.Name(),
		InsufficientEvidence: insufficient,
		Elapsed:              time.Since(start),
	}
	if insufficient {
		ans.Confidence = ConfidenceLow
		if len(syn.Findings) == 0 {
			if len(evidence) == 0 {
				ans.RootCause = "Insufficient evidence: no signals were found for this question within your scope."
			} else {
				ans.RootCause = "Insufficient evidence: the gathered signals do not support a confident root cause."
			}
		}
	}
	return ans, nil
}

// groundFindings keeps only findings whose citations resolve to real gathered
// evidence — the adapter-agnostic citation-integrity guarantee.
func groundFindings(findings []Finding, evidence []Evidence) []Finding {
	ids := make(map[string]bool, len(evidence))
	for _, e := range evidence {
		ids[e.ID] = true
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		kept := make([]Citation, 0, len(f.Citations))
		for _, c := range f.Citations {
			if ids[c.EvidenceID] {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			continue // ungrounded claim — drop it
		}
		f.Citations = kept
		out = append(out, f)
	}
	return out
}

var answerCounter atomic.Uint64

func defaultIDGen() string {
	return fmt.Sprintf("ans_%d_%d", time.Now().UnixNano(), answerCounter.Add(1))
}
