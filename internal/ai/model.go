// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
// tenant-and-RBAC/ABAC-scoped signal — the pipeline drops any finding whose citations
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
// question and the already-gathered evidence (tenant-and-RBAC/ABAC-scoped by the S23
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
	RootCause string
	// RootCauseCitations ground the headline claim itself (RED-005): the
	// pipeline validates them like finding citations, and an uncited
	// root_cause is REJECTED on every path — a prompt-injected headline
	// cannot ride along on one valid finding.
	RootCauseCitations []Citation
	Confidence         Confidence
	// Silent names the cause-bearing planes that contributed NO evidence to this
	// verdict (DPR-143). DPR-061 established the rule on the endpoint verdict:
	// an unmeasured layer reported as healthy is a guess, and must be reported
	// as one. A cross-plane root cause built from one plane while four others
	// said nothing read exactly like one built from five where four were clean.
	// It no longer does: the silent planes are named and confidence is capped.
	Silent               []string
	Findings             []Finding
	InsufficientEvidence bool
	// Degraded marks an answer served by the FALLBACK (air-gapped builtin)
	// because the remote provider was unavailable (AIRCA-004). The root
	// cause carries the partial-result banner; the flag makes it machine-
	// readable for the UI.
	Degraded bool
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
