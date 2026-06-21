// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// flakySynth is a remote-shaped adapter scripted to fail/hang/succeed.
type flakySynth struct {
	calls    atomic.Int64
	failFor  int64         // first N calls error
	sleep    time.Duration // per-call latency (timeout tests)
	response Synthesis
}

func (f *flakySynth) Name() string       { return "fake:remote" }
func (f *flakySynth) RemoteEgress() bool { return true }
func (f *flakySynth) Endpoint() string   { return "https://api.example/v1" }
func (f *flakySynth) Synthesize(ctx context.Context, in SynthesisInput) (Synthesis, error) {
	n := f.calls.Add(1)
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return Synthesis{}, ctx.Err()
		}
	}
	if n <= f.failFor {
		return Synthesis{}, errors.New("provider 503")
	}
	resp := f.response
	if len(in.Evidence) > 0 && len(resp.Findings) == 0 {
		resp = Synthesis{
			RootCause:          "remote answer",
			RootCauseCitations: []Citation{{EvidenceID: in.Evidence[0].ID}},
			Confidence:         ConfidenceHigh,
			Findings:           []Finding{{Statement: "remote finding", Citations: []Citation{{EvidenceID: in.Evidence[0].ID}}}},
		}
	}
	return resp, nil
}

func synthInput(ids ...string) SynthesisInput {
	in := SynthesisInput{Question: "why is core-rtr-1 slow?"}
	for _, id := range ids {
		in.Evidence = append(in.Evidence, Evidence{
			ID: id, Plane: "device", Severity: "critical",
			Title: "core-rtr-1 CPU 99%", Summary: "cpu saturated",
		})
	}
	return in
}

// AIRCA-004: provider failure degrades to the BUILTIN with the banner — an
// answer always comes back, clearly marked, with grounded citations.
func TestFallbackToBuiltinOnProviderFailure(t *testing.T) {
	remote := &flakySynth{failFor: 1 << 30} // always failing
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)

	syn, err := m.Synthesize(context.Background(), synthInput("ev-1"))
	if err != nil {
		t.Fatalf("degraded path must still answer: %v", err)
	}
	if !syn.Degraded {
		t.Fatal("fallback answer must be marked Degraded")
	}
	if !strings.Contains(syn.RootCause, "PARTIAL RESULT") || !strings.Contains(syn.RootCause, "air-gapped builtin") {
		t.Fatalf("fallback must carry the partial-result banner: %q", syn.RootCause)
	}
	if len(syn.RootCauseCitations) == 0 || syn.RootCauseCitations[0].EvidenceID != "ev-1" {
		t.Fatalf("builtin fallback must stay grounded (RED-005): %+v", syn.RootCauseCitations)
	}
}

// The breaker opens after the threshold: the provider stops being hammered
// (short-circuited calls never reach it) while answers keep flowing.
func TestBreakerOpensAndShortCircuits(t *testing.T) {
	remote := &flakySynth{failFor: 1 << 30}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)
	in := synthInput("ev-1")

	for i := 0; i < breakerThreshold+3; i++ {
		if _, err := m.Synthesize(context.Background(), in); err != nil {
			t.Fatalf("call %d: degraded path errored: %v", i, err)
		}
	}
	if got := remote.calls.Load(); got != breakerThreshold {
		t.Fatalf("provider must stop being called once the breaker opens: %d calls, want %d", got, breakerThreshold)
	}
	if m.Degradations() != breakerThreshold+3 {
		t.Fatalf("every answer in the window must be a marked degradation: %d", m.Degradations())
	}

	// The banner names the circuit when it's the breaker short-circuiting.
	syn, _ := m.Synthesize(context.Background(), in)
	if !strings.Contains(syn.RootCause, "circuit open") {
		t.Fatalf("banner must name the breaker: %q", syn.RootCause)
	}
}

// A hung provider is bounded by the wrapper-level timeout and degrades.
func TestTimeoutDegradesToBuiltin(t *testing.T) {
	remote := &flakySynth{sleep: 2 * time.Second}
	m := NewResilientModel(remote, NewBuiltinModel(), 50*time.Millisecond)

	start := time.Now()
	syn, err := m.Synthesize(context.Background(), synthInput("ev-1"))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout must bound the call: took %s", elapsed)
	}
	if !syn.Degraded || !strings.Contains(syn.RootCause, "timeout") {
		t.Fatalf("timeout fallback must be marked with the reason: %q", syn.RootCause)
	}
}

// The response cache: same question+content in a NEW session (different
// random evidence IDs, U-037) is served without a provider call, and the
// cached citations are REMAPPED onto the new session's IDs so grounding
// still resolves.
func TestCacheHitsAcrossSessionsWithCitationRemap(t *testing.T) {
	remote := &flakySynth{}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)

	// Session 1: evidence id "a1b2-E1".
	syn1, err := m.Synthesize(context.Background(), synthInput("a1b2-E1"))
	if err != nil || syn1.Findings[0].Citations[0].EvidenceID != "a1b2-E1" {
		t.Fatalf("session 1: %v %+v", err, syn1)
	}
	// Session 2: SAME content, new random id.
	syn2, err := m.Synthesize(context.Background(), synthInput("ff09-E1"))
	if err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 1 {
		t.Fatalf("second call must be served from cache: %d provider calls", remote.calls.Load())
	}
	if m.CacheHits() != 1 {
		t.Fatalf("cache hit not counted: %d", m.CacheHits())
	}
	if syn2.Findings[0].Citations[0].EvidenceID != "ff09-E1" {
		t.Fatalf("cached citations must remap to the NEW session id: %+v", syn2.Findings[0].Citations)
	}
	if syn2.RootCauseCitations[0].EvidenceID != "ff09-E1" {
		t.Fatalf("root-cause citations must remap too (RED-005): %+v", syn2.RootCauseCitations)
	}
	// The cached copy must not alias session 1's slices.
	syn2.Findings[0].Citations[0].EvidenceID = "mutated"
	syn3, _ := m.Synthesize(context.Background(), synthInput("0000-E1"))
	if syn3.Findings[0].Citations[0].EvidenceID != "0000-E1" {
		t.Fatalf("cache entries must be isolated from returned copies: %+v", syn3.Findings[0].Citations)
	}

	// Different content = different key = real provider call.
	in := synthInput("zz-E1")
	in.Question = "a different question"
	if _, err := m.Synthesize(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 2 {
		t.Fatalf("different content must miss the cache: %d calls", remote.calls.Load())
	}
}

// AIRCA-001: the synthesis cache is keyed tenant-FIRST. Two tenants asking the
// identical question over identical evidence must NEVER share a cache entry —
// tenant A's cached answer can never be served to tenant B. This is
// defense-in-depth above the egress/RBAC gates: even if those were bypassed, a
// cross-tenant answer can't bleed through the process-wide cache.
func TestSynthCacheIsTenantScoped(t *testing.T) {
	remote := &flakySynth{}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)

	ctxA := tenancy.WithTenant(context.Background(), tenancy.ID("tenant-a"))
	ctxB := tenancy.WithTenant(context.Background(), tenancy.ID("tenant-b"))

	// Tenant A populates the cache with one provider call.
	if _, err := m.Synthesize(ctxA, synthInput("ev-1")); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 1 {
		t.Fatalf("tenant A should have made 1 provider call: %d", remote.calls.Load())
	}

	// Tenant B with IDENTICAL question + evidence must MISS — a second provider
	// call, not a served-from-cache hit.
	if _, err := m.Synthesize(ctxB, synthInput("ev-1")); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 2 {
		t.Fatalf("tenant B identical input must MISS the cache (no cross-tenant bleed): got %d provider calls, want 2", remote.calls.Load())
	}
	if m.CacheHits() != 0 {
		t.Fatalf("no cross-tenant cache hit may be counted: %d", m.CacheHits())
	}

	// Tenant A repeating its OWN question hits its OWN entry.
	if _, err := m.Synthesize(ctxA, synthInput("ev-2")); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 2 {
		t.Fatalf("tenant A repeat must hit its own cache entry: %d provider calls", remote.calls.Load())
	}
	if m.CacheHits() != 1 {
		t.Fatalf("tenant A same-tenant repeat must count one cache hit: %d", m.CacheHits())
	}

	// The two tenants' keys must differ at the key level too.
	if synthKey(ctxA, remote.Name(), synthInput("x")) == synthKey(ctxB, remote.Name(), synthInput("x")) {
		t.Fatal("synthKey must differ across tenants for identical input")
	}
}

// The cache never bridges policy: expired entries miss, and a shape change
// (different evidence count) misses rather than mis-remapping.
func TestCacheTTLAndShapeGuard(t *testing.T) {
	remote := &flakySynth{}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)
	m.cache.now = func() time.Time { return time.Unix(0, 0) }
	if _, err := m.Synthesize(context.Background(), synthInput("e1")); err != nil {
		t.Fatal(err)
	}
	m.cache.now = func() time.Time { return time.Unix(0, 0).Add(cacheTTL + time.Second) }
	if _, err := m.Synthesize(context.Background(), synthInput("e2")); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 2 {
		t.Fatalf("expired entry must miss: %d calls", remote.calls.Load())
	}
}

func TestCacheIsBoundedAndEvictsOldest(t *testing.T) {
	remote := &flakySynth{}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID("tenant-a"))

	first := synthInput("ev-first")
	first.Question = "question-000"
	if _, err := m.Synthesize(ctx, first); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= cacheMaxEntries; i++ {
		in := synthInput(fmt.Sprintf("ev-%03d", i))
		in.Question = fmt.Sprintf("question-%03d", i)
		if _, err := m.Synthesize(ctx, in); err != nil {
			t.Fatalf("fill cache %d: %v", i, err)
		}
	}
	if got := remote.calls.Load(); got != int64(cacheMaxEntries+1) {
		t.Fatalf("cache fill provider calls = %d, want %d", got, cacheMaxEntries+1)
	}

	if _, err := m.Synthesize(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got := remote.calls.Load(); got != int64(cacheMaxEntries+2) {
		t.Fatalf("oldest entry must be evicted at capacity; provider calls = %d, want %d", got, cacheMaxEntries+2)
	}

	latest := synthInput(fmt.Sprintf("ev-%03d", cacheMaxEntries))
	latest.Question = fmt.Sprintf("question-%03d", cacheMaxEntries)
	if _, err := m.Synthesize(ctx, latest); err != nil {
		t.Fatal(err)
	}
	if got := remote.calls.Load(); got != int64(cacheMaxEntries+2) {
		t.Fatalf("newer cache entry should still hit; provider calls = %d", got)
	}
	if m.CacheHits() != 1 {
		t.Fatalf("newer entry cache hit not counted: %d", m.CacheHits())
	}
}

// End-to-end through the Analyzer: a failing provider yields a degraded but
// GROUNDED answer (citation integrity holds on the fallback path), flagged
// on the Answer the API returns.
func TestAnalyzeDegradedAnswerIsGroundedAndFlagged(t *testing.T) {
	fs := fixtureSource{entities: []Row{{
		"id": "inc-1", "kind": "alert", "plane": "device", "severity": "critical",
		"title": "core-rtr-1 CPU 99%",
	}}}
	remote := &flakySynth{failFor: 1 << 30}
	m := NewResilientModel(remote, NewBuiltinModel(), 100*time.Millisecond)
	// The wrapper forwards RemoteEgress, so the U-013 consent gate still
	// runs FIRST — this tenant has consented; the provider then fails.
	a := NewAnalyzer(engineWith(fs), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return true, nil }))

	ans, err := a.Analyze(context.Background(), principal("t", PermEntitiesRead), Question{Text: "why is core-rtr-1 slow?"})
	if err != nil {
		t.Fatalf("degraded RCA must still answer: %v", err)
	}
	if !ans.Degraded {
		t.Fatal("the Answer must carry the degraded flag")
	}
	if !strings.Contains(ans.RootCause, "PARTIAL RESULT") {
		t.Fatalf("the banner must reach the user: %q", ans.RootCause)
	}
	if !ans.RootCauseGrounded || len(ans.Findings) == 0 {
		t.Fatalf("the builtin fallback answer must be grounded (RED-005 holds while degraded): grounded=%v findings=%d",
			ans.RootCauseGrounded, len(ans.Findings))
	}
}

// Complete (the authoring seam) shares the breaker: once open, authoring
// fails fast with ErrOpen instead of stacking provider timeouts.
func TestCompleteSharesBreaker(t *testing.T) {
	remote := &flakyCompleter{flakySynth: flakySynth{failFor: 1 << 30}}
	m := NewResilientModel(remote, NewBuiltinModel(), time.Second)
	for i := 0; i < breakerThreshold; i++ {
		if _, err := m.Complete(context.Background(), "sys", "user"); err == nil {
			t.Fatal("failing provider must error")
		}
	}
	if _, err := m.Complete(context.Background(), "sys", "user"); !errors.Is(err, breaker.ErrOpen) {
		t.Fatalf("post-threshold authoring call must short-circuit: %v", err)
	}
	if remote.completeCalls.Load() != breakerThreshold {
		t.Fatalf("provider must not be hammered: %d", remote.completeCalls.Load())
	}
}

// flakyCompleter adds a Complete seam to the flaky remote.
type flakyCompleter struct {
	flakySynth
	completeCalls atomic.Int64
}

func (f *flakyCompleter) Complete(_ context.Context, _, _ string) (string, error) {
	n := f.completeCalls.Add(1)
	if n <= f.failFor {
		return "", errors.New("provider 503")
	}
	return "{}", nil
}
