package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// BuiltinModel is netctl's default synthesis backend: a deterministic,
// evidence-grounded root-cause synthesizer that runs entirely in-process — no
// network, no phone-home (CLAUDE.md §7 guardrail 2). It is the first-class
// air-gapped path and the safe default, and it never fabricates: with no
// evidence it returns InsufficientEvidence. It is also the reference oracle the
// golden-set tests assert against.
type BuiltinModel struct{}

// NewBuiltinModel returns the built-in synthesizer.
func NewBuiltinModel() BuiltinModel { return BuiltinModel{} }

// Name identifies the adapter for provenance.
func (BuiltinModel) Name() string { return "builtin" }

// planeCauseWeight ranks how likely a plane is to be the *cause* (vs a symptom)
// of a degradation. A change or a routing event is a more likely root cause than
// a latency metric, which is usually a symptom.
func planeCauseWeight(plane string) int {
	switch strings.ToLower(plane) {
	case "change":
		return 6
	case "bgp", "routing":
		return 5
	case "path", "network":
		return 4
	case "threat":
		return 3
	case "events":
		return 3
	case "metrics":
		return 2
	case "entities":
		return 2
	case "topology":
		return 1
	default:
		return 2
	}
}

func severityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 3
	case "warning", "warn":
		return 2
	case "info":
		return 1
	default:
		return 1
	}
}

// Synthesize ranks the evidence by cause-likelihood (plane) × severity × recency,
// names the top-ranked signal as the probable root cause, and emits one grounded
// finding per contributing signal — each citing real evidence by construction.
func (BuiltinModel) Synthesize(_ context.Context, in SynthesisInput) (Synthesis, error) {
	if len(in.Evidence) == 0 {
		return Synthesis{
			RootCause:            "Insufficient evidence: no signals were found for this question within the caller's scope.",
			Confidence:           ConfidenceLow,
			InsufficientEvidence: true,
		}, nil
	}

	// Stable ranking: score desc, then most-recent first, then ID for determinism.
	ranked := make([]Evidence, len(in.Evidence))
	copy(ranked, in.Evidence)
	score := func(e Evidence) int { return planeCauseWeight(e.Plane)*10 + severityWeight(e.Severity)*3 }
	sort.SliceStable(ranked, func(i, j int) bool {
		si, sj := score(ranked[i]), score(ranked[j])
		if si != sj {
			return si > sj
		}
		if !ranked[i].OccurredAt.Equal(ranked[j].OccurredAt) {
			return ranked[i].OccurredAt.After(ranked[j].OccurredAt)
		}
		return ranked[i].ID < ranked[j].ID
	})

	primary := ranked[0]
	var b strings.Builder
	fmt.Fprintf(&b, "Most likely root cause: %s", describe(primary))
	if primary.Severity != "" {
		fmt.Fprintf(&b, " (%s)", strings.ToLower(primary.Severity))
	}
	b.WriteByte('.')

	findings := make([]Finding, 0, len(ranked))
	findings = append(findings, Finding{
		Statement: fmt.Sprintf("The highest cause-likelihood signal is %s on the %s plane.", describe(primary), planeLabel(primary)),
		Citations: []Citation{{EvidenceID: primary.ID}},
	})
	// Corroborating / symptom signals, most-relevant first (cap to keep answers tight).
	planes := map[string]bool{strings.ToLower(primary.Plane): true}
	for _, e := range ranked[1:] {
		if len(findings) >= 6 {
			break
		}
		findings = append(findings, Finding{
			Statement: fmt.Sprintf("Corroborating signal: %s on the %s plane.", describe(e), planeLabel(e)),
			Citations: []Citation{{EvidenceID: e.ID}},
		})
		planes[strings.ToLower(e.Plane)] = true
	}

	return Synthesis{
		RootCause:  b.String(),
		Confidence: confidenceFor(primary, len(planes)),
		Findings:   findings,
	}, nil
}

// confidenceFor: corroboration across planes + a strong, cause-likely primary
// raise confidence; a lone weak signal stays low.
func confidenceFor(primary Evidence, distinctPlanes int) Confidence {
	strong := planeCauseWeight(primary.Plane) >= 5 && severityWeight(primary.Severity) >= 2
	switch {
	case strong && distinctPlanes >= 2:
		return ConfidenceHigh
	case strong || distinctPlanes >= 2:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func describe(e Evidence) string {
	switch {
	case e.Title != "" && e.Summary != "":
		return fmt.Sprintf("%q — %s", e.Title, e.Summary)
	case e.Title != "":
		return fmt.Sprintf("%q", e.Title)
	case e.Summary != "":
		return e.Summary
	default:
		return string(e.Domain) + " signal"
	}
}

func planeLabel(e Evidence) string {
	if e.Plane != "" {
		return e.Plane
	}
	return string(e.Domain)
}
