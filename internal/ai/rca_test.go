package ai

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fixtureSource returns fixed rows per domain — a "recorded" multi-plane scenario
// for the golden-set RCA tests.
type fixtureSource struct {
	metrics, events, entities, topology []Row
}

func (f fixtureSource) QueryMetrics(_ context.Context, _ string, _ map[string]string, _ TimeRange, _ int) ([]Row, error) {
	return f.metrics, nil
}
func (f fixtureSource) QueryEvents(_ context.Context, _ string, _ map[string]string, _ TimeRange, _ int) ([]Row, error) {
	return f.events, nil
}
func (f fixtureSource) QueryEntities(_ context.Context, _ string, _ map[string]string, _ int) ([]Row, error) {
	return f.entities, nil
}
func (f fixtureSource) QueryTopology(_ context.Context, _ string, _ Query) ([]Row, error) {
	return f.topology, nil
}

func engineWith(fs fixtureSource) *Engine {
	return NewEngine(WithMetrics(fs), WithEvents(fs), WithEntities(fs), WithTopology(fs))
}

func allReadPerms() []string {
	return []string{PermMetricsRead, PermEventsRead, PermEntitiesRead, PermTopologyRead}
}

func citationsResolve(a Answer) bool {
	ids := map[string]bool{}
	for _, e := range a.Evidence {
		ids[e.ID] = true
	}
	for _, f := range a.Findings {
		if len(f.Citations) == 0 {
			return false
		}
		for _, c := range f.Citations {
			if !ids[c.EvidenceID] {
				return false
			}
		}
	}
	return true
}

// Golden-set: a recorded scenario where a BGP-plane incident is the cause and a
// latency metric is the symptom. The built-in synthesizer must name the routing
// signal as the root cause (cause-likely plane), corroborate with the metric, and
// every finding must cite real evidence.
func TestAnalyzeGoldenRootCauseClassAndCitations(t *testing.T) {
	now := time.Now()
	fs := fixtureSource{
		entities: []Row{{
			"id": "inc-1", "kind": "incident", "plane": "bgp", "severity": "critical",
			"title": "Possible prefix hijack for 10.0.0.0/24", "summary": "AS64500 originated a more-specific",
			"occurred_at": now.Add(-5 * time.Minute),
		}},
		metrics: []Row{{
			"metric": "http_latency_ms", "plane": "metrics", "severity": "warning",
			"title": "p95 latency 950ms", "summary": "elevated since 5m ago",
		}},
	}
	a := NewAnalyzer(engineWith(fs))
	ans, err := a.Analyze(context.Background(), principal("tenant-a", allReadPerms()...), Question{Text: "why is api.example.com slow?"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.InsufficientEvidence {
		t.Fatal("expected a confident answer, got insufficient evidence")
	}
	if ans.Model != "builtin" {
		t.Errorf("model = %q, want builtin", ans.Model)
	}
	if !strings.Contains(strings.ToLower(ans.RootCause), "hijack") {
		t.Errorf("root cause should name the routing signal, got %q", ans.RootCause)
	}
	if ans.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high (cause-likely plane + corroboration)", ans.Confidence)
	}
	if len(ans.Evidence) != 2 {
		t.Errorf("evidence count = %d, want 2", len(ans.Evidence))
	}
	if !citationsResolve(ans) {
		t.Errorf("every finding must cite real evidence; findings=%+v evidence=%+v", ans.Findings, ans.Evidence)
	}
}

// mockModel returns a fixed Synthesis — used to drive citation-integrity + error
// paths independent of the built-in synthesizer.
type mockModel struct {
	syn Synthesis
	err error
}

func (mockModel) Name() string { return "mock" }
func (m mockModel) Synthesize(context.Context, SynthesisInput) (Synthesis, error) {
	return m.syn, m.err
}

// A hallucinated citation (to evidence that was never gathered) must be dropped,
// and a finding left with no resolving citation must be removed entirely — the
// adapter-agnostic citation-integrity guarantee.
func TestAnalyzeDropsHallucinatedCitations(t *testing.T) {
	fs := fixtureSource{entities: []Row{{"id": "inc-1", "kind": "incident", "plane": "network", "severity": "warning", "title": "real signal"}}}
	model := mockModel{syn: Synthesis{
		RootCause:  "something",
		Confidence: ConfidenceHigh,
		Findings: []Finding{
			{Statement: "grounded + hallucinated", Citations: []Citation{{EvidenceID: "E1"}, {EvidenceID: "E999"}}},
			{Statement: "fully hallucinated", Citations: []Citation{{EvidenceID: "E999"}}},
		},
	}}
	a := NewAnalyzer(engineWith(fs), WithModel(model))
	ans, err := a.Analyze(context.Background(), principal("t", PermEntitiesRead), Question{Text: "what broke?"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Findings) != 1 {
		t.Fatalf("ungrounded finding should be dropped; got %d findings: %+v", len(ans.Findings), ans.Findings)
	}
	if len(ans.Findings[0].Citations) != 1 || ans.Findings[0].Citations[0].EvidenceID != "E1" {
		t.Errorf("dangling citation should be dropped, kept=%+v", ans.Findings[0].Citations)
	}
	if !citationsResolve(ans) {
		t.Error("no citation may reference non-existent evidence after grounding")
	}
}

// RBAC scoping: a caller without events.read must never get event-plane evidence,
// even though the source would return it — proving the answer is scoped by the
// caller's permissions at the S23 boundary, not by the model.
func TestAnalyzeRBACScopesEvidence(t *testing.T) {
	fs := fixtureSource{
		entities: []Row{{"id": "inc-1", "kind": "incident", "plane": "network", "severity": "warning", "title": "incident"}},
		events:   []Row{{"id": "ev-1", "kind": "change", "plane": "change", "severity": "info", "title": "SECRET-CHANGE"}},
	}
	q := Question{Text: "did a config change or route change cause this?"} // plans events too

	// Without events.read: the event evidence must be absent.
	a := NewAnalyzer(engineWith(fs))
	ans, err := a.Analyze(context.Background(), principal("t", PermEntitiesRead, PermMetricsRead, PermTopologyRead), q)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ans.Evidence {
		if e.Domain == DomainEvents || strings.Contains(e.Title, "SECRET") {
			t.Fatalf("caller without events.read leaked event evidence: %+v", e)
		}
	}

	// With events.read: the same query now includes it (proves the source WOULD
	// have returned it — the exclusion above was RBAC, not absence).
	ans2, err := a.Analyze(context.Background(), principal("t", allReadPerms()...), q)
	if err != nil {
		t.Fatal(err)
	}
	var sawEvent bool
	for _, e := range ans2.Evidence {
		if e.Domain == DomainEvents {
			sawEvent = true
		}
	}
	if !sawEvent {
		t.Error("caller with events.read should receive event evidence")
	}
}

// No evidence → an honest "insufficient evidence" answer, never a fabricated
// cause; and a tenantless principal fails closed.
func TestAnalyzeInsufficientAndNoTenant(t *testing.T) {
	a := NewAnalyzer(engineWith(fixtureSource{}))
	ans, err := a.Analyze(context.Background(), principal("t", allReadPerms()...), Question{Text: "why is everything down?"})
	if err != nil {
		t.Fatal(err)
	}
	if !ans.InsufficientEvidence || ans.Confidence != ConfidenceLow {
		t.Errorf("no evidence should yield low-confidence insufficient answer, got %+v", ans)
	}
	if len(ans.Findings) != 0 {
		t.Errorf("insufficient answer must make no claims, got %+v", ans.Findings)
	}
	if _, err := a.Analyze(context.Background(), principal(""), Question{Text: "x"}); err != ErrNoTenant {
		t.Errorf("tenantless principal must fail closed, got %v", err)
	}
}
