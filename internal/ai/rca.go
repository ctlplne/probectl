package ai

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// DefaultMaxConcurrent is the default process-wide cap on concurrent Analyze
// calls (U-048) — a backstop that holds even with no fairness gate configured.
const DefaultMaxConcurrent = 8

// Answer is the result of an RCA: a cited, RBAC-scoped root cause. ID ties an
// answer to any feedback the user later gives. InsufficientEvidence is set when
// nothing grounded supports a conclusion — probectl prefers saying so over guessing.
type Answer struct {
	ID        string `json:"id"`
	Tenant    string `json:"tenant"`
	Question  string `json:"question"`
	RootCause string `json:"root_cause"`
	// RootCauseCitations are the VALIDATED citations grounding the headline
	// claim (RED-005); RootCauseGrounded is false when the model's root
	// cause was rejected for citing nothing real (the claim is replaced,
	// never surfaced).
	RootCauseCitations   []Citation    `json:"root_cause_citations,omitempty"`
	RootCauseGrounded    bool          `json:"root_cause_grounded"`
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

	// sem caps concurrent Analyze calls process-wide (U-048): a default
	// backstop so a burst of AI calls cannot exhaust the control plane even
	// when no per-tenant fairness gate is configured. Fail-fast: a saturated
	// analyzer returns ErrBusy (HTTP 429) instead of queueing.
	sem chan struct{}

	// Remote-model egress controls (U-013): consulted only when the model
	// reports RemoteEgress() — the air-gapped default never touches them.
	egressPolicy EgressPolicy
	egressAudit  EgressAudit
}

// AnalyzerOption configures an Analyzer.
type AnalyzerOption func(*Analyzer)

// WithModel sets the synthesis backend (default: the built-in air-gapped model).
func WithModel(m ModelAdapter) AnalyzerOption { return func(a *Analyzer) { a.model = m } }

// WithPlanner overrides the query planner (default: HeuristicPlanner).
func WithPlanner(p Planner) AnalyzerOption { return func(a *Analyzer) { a.planner = p } }

// WithMaxConcurrent caps concurrent Analyze calls (U-048; default 8). The cap
// is process-wide and fail-fast (ErrBusy), a backstop under the per-tenant
// fairness gate when one is configured.
func WithMaxConcurrent(n int) AnalyzerOption {
	return func(a *Analyzer) {
		if n > 0 {
			a.sem = make(chan struct{}, n)
		}
	}
}

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
		sem:         make(chan struct{}, DefaultMaxConcurrent),
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
	// U-048: process-wide concurrency backstop, fail-fast (429 at the API).
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		return Answer{}, ErrBusy
	}
	start := time.Now()

	// 1. Plan deterministically (probectl code, never the model).
	queries := a.planner.Plan(q)

	// 2. Gather evidence via the engine. Domains the caller cannot read
	// (ErrForbidden) or that aren't configured (ErrNoSource) are skipped — the
	// answer is grounded only in what the caller is permitted to see.
	// Evidence IDs carry a per-session random nonce (U-037): non-sequential,
	// unguessable — injected telemetry text cannot fabricate a citable ID.
	idPrefix := sessionIDPrefix()
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
		evidence = append(evidence, collectEvidence(query.Domain, res.Rows, idPrefix, &n)...)
	}
	if len(evidence) > a.maxEvidence {
		evidence = evidence[:a.maxEvidence]
	}

	// 3. Synthesize over the gathered evidence (the model has no tools). A
	// REMOTE model is gated on the tenant's egress consent and audited
	// (U-013); the air-gapped builtin and loopback local models skip both.
	in := SynthesisInput{Question: q.Text, Evidence: evidence}
	egress, err := a.checkEgress(ctx, p.TenantID, in)
	if err != nil {
		return Answer{}, err
	}
	syn, err := a.model.Synthesize(ctx, in)
	if err != nil {
		return Answer{}, err
	}
	if egress != nil && a.egressAudit != nil {
		a.egressAudit(ctx, *egress)
	}

	// 4. Citation integrity: drop any finding citing evidence that doesn't exist,
	// so a hallucinated reference can never reach the user.
	syn.Findings = groundFindings(syn.Findings, evidence)
	insufficient := syn.InsufficientEvidence || len(syn.Findings) == 0

	// RED-005: the ROOT CAUSE itself must be grounded. Previously a model
	// (or a prompt injection riding the evidence) could emit any headline
	// claim and pass as long as ONE finding survived grounding — the
	// citation check never looked at the root_cause string. Now an uncited
	// or fake-cited root cause is REJECTED on every adapter path: the claim
	// is replaced with a grounded fallback and confidence drops to low.
	rcCitations := groundCitations(syn.RootCauseCitations, evidence)
	rootCauseGrounded := len(rcCitations) > 0
	if !insufficient && !rootCauseGrounded {
		syn.RootCause = rejectedRootCause(syn.Findings)
		syn.Confidence = ConfidenceLow
		rcCitations = nil
	}

	// U-092: the API response carries only allow-listed evidence fields — the
	// raw row (which may include keys a future source adds) stays in-process.
	sanitizeEvidenceFields(evidence)

	ans := Answer{
		ID:                   a.newID(),
		Tenant:               p.TenantID,
		Question:             q.Text,
		RootCause:            syn.RootCause,
		RootCauseCitations:   rcCitations,
		RootCauseGrounded:    rootCauseGrounded && !insufficient,
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

// groundCitations keeps only citations that resolve to real gathered
// evidence (the root-cause variant of groundFindings; RED-005).
func groundCitations(cits []Citation, evidence []Evidence) []Citation {
	ids := make(map[string]bool, len(evidence))
	for _, e := range evidence {
		ids[e.ID] = true
	}
	kept := make([]Citation, 0, len(cits))
	for _, c := range cits {
		if ids[c.EvidenceID] {
			kept = append(kept, c)
		}
	}
	return kept
}

// rejectedRootCause is the replacement when the model's headline failed
// citation integrity: it makes NO new claim — it points at the grounded
// findings, which carry their own validated citations.
func rejectedRootCause(grounded []Finding) string {
	if len(grounded) == 0 {
		return "Insufficient evidence: the gathered signals do not support a confident root cause."
	}
	return "The model's root-cause statement was rejected by citation integrity (it cited no gathered evidence). " +
		"The grounded findings below stand on their own; the strongest is: " + grounded[0].Statement
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

// sessionIDPrefix returns a short random nonce for one Analyze call's
// evidence IDs (U-037). On the vanishingly unlikely RNG failure it falls
// back to a time-derived value — still non-guessable from telemetry text
// written before the session existed.
func sessionIDPrefix() string {
	if b, err := crypto.Random(4); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
