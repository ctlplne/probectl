package ai

import "context"

// Confidence is the assistant's qualitative trust level in a root cause — a
// trust cue for the surface (S24). Ordered low < medium < high.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Citation links a finding to one piece of gathered evidence by its stable ID.
// Every claim the assistant makes MUST carry at least one citation to a real,
// tenant-and-RBAC-scoped signal — the pipeline drops any finding whose citations
// do not resolve, so a hallucinated reference can never reach the user
// (ground every claim; prefer "insufficient evidence" over guessing — S24).
type Citation struct {
	EvidenceID string `json:"evidence_id"`
}

// Finding is one grounded statement in a root-cause answer.
type Finding struct {
	Statement string     `json:"statement"`
	Citations []Citation `json:"citations"`
}

// SynthesisInput is the read-only material handed to a ModelAdapter: the user's
// question and the already-gathered evidence (tenant-and-RBAC-scoped by the S23
// engine before it ever reaches a model). A model has NO tools and cannot issue
// queries or actions — it only synthesizes prose over this evidence, so even
// hostile evidence content (prompt injection) can never drive behavior: the
// worst it can do is produce a claim the citation-integrity check then rejects.
type SynthesisInput struct {
	Question string
	Evidence []Evidence
}

// Synthesis is a model's structured answer. It is structured (not free text) on
// purpose: the pipeline verifies that every finding cites real evidence
// regardless of which adapter produced it, so the trust guarantee does not
// depend on the model.
type Synthesis struct {
	RootCause            string
	Confidence           Confidence
	Findings             []Finding
	InsufficientEvidence bool
}

// ModelAdapter is the pluggable synthesis backend: the built-in deterministic
// synthesizer (the default — fully air-gapped, no network, no phone-home), a
// local Ollama/vLLM (sovereignty), or a cloud provider. Every remote adapter
// dials over TLS with certificate validation (CLAUDE.md §7 guardrail 12). An
// adapter only ever SYNTHESIZES over evidence; it is never handed tools or the
// ability to act.
type ModelAdapter interface {
	// Name identifies the adapter/model for provenance in the answer + audit.
	Name() string
	// Synthesize produces a structured, cited answer from the evidence. It must
	// not fabricate: when the evidence does not support a conclusion it returns
	// InsufficientEvidence rather than guessing.
	Synthesize(ctx context.Context, in SynthesisInput) (Synthesis, error)
}
