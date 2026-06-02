package author

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/netctl/internal/testspec"
)

func mustAuthor(t *testing.T, e *Engine, prompt string) Proposal {
	t.Helper()
	p, err := e.Author(context.Background(), prompt)
	if err != nil {
		t.Fatalf("author(%q): %v", prompt, err)
	}
	if err := testspec.Validate(p.Spec); err != nil {
		t.Fatalf("authored spec invalid: %v (%+v)", err, p.Spec)
	}
	return p
}

func TestHeuristicAuthoring(t *testing.T) {
	e := NewEngine(HeuristicAuthor{})
	cases := []struct {
		prompt, wantType, wantTargetContains string
	}{
		{"monitor https://api.example.com/health", "http", "api.example.com"},
		{"ping 8.8.8.8 every minute", "icmp", "8.8.8.8"},
		// An explicit reachability verb wins over an incidental "site" (agent site),
		// so the IP target stays an ICMP test, not an HTTP one.
		{"ping 9.9.9.9 from every site", "icmp", "9.9.9.9"},
		{"check DNS resolution for example.com", "dns", "example.com"},
		{"tcp connect to db.internal port 5432", "tcp", "db.internal:5432"},
		{"is shop.example.com up?", "http", "shop.example.com"},
		{"check Salesforce login from every branch", "http", "salesforce.com"},
	}
	for _, c := range cases {
		p := mustAuthor(t, e, c.prompt)
		if p.Spec.Type != c.wantType {
			t.Errorf("%q: type = %q, want %q (spec=%+v)", c.prompt, p.Spec.Type, c.wantType, p.Spec)
		}
		if !strings.Contains(p.Spec.Target, c.wantTargetContains) {
			t.Errorf("%q: target = %q, want contains %q", c.prompt, p.Spec.Target, c.wantTargetContains)
		}
		if p.Source != "heuristic" {
			t.Errorf("%q: source = %q, want heuristic", c.prompt, p.Source)
		}
	}
}

func TestHeuristicCannotAuthor(t *testing.T) {
	e := NewEngine(HeuristicAuthor{})
	if _, err := e.Author(context.Background(), "make sure everything is fine"); !errors.Is(err, ErrCannotAuthor) {
		t.Errorf("expected ErrCannotAuthor for a target-less prompt, got %v", err)
	}
}

// mockProposer returns a canned spec — drives the validate-before-surface path.
type mockProposer struct {
	spec testspec.Spec
	err  error
}

func (mockProposer) Name() string { return "mock" }
func (m mockProposer) Propose(context.Context, string) (testspec.Spec, string, error) {
	return m.spec, "because", m.err
}

func TestEngineSchemaValidatesProposals(t *testing.T) {
	// A valid proposal passes through, normalized.
	good := NewEngine(mockProposer{spec: testspec.Spec{Name: "SFDC", Type: "http", Target: "https://login.salesforce.com"}})
	p := mustAuthor(t, good, "check salesforce login")
	if p.Spec.IntervalSeconds != testspec.DefaultIntervalSeconds {
		t.Errorf("proposal not normalized: %+v", p.Spec)
	}

	// An INVALID proposal is rejected (never surfaced) — S26 watch-out.
	bad := NewEngine(mockProposer{spec: testspec.Spec{Name: "x", Type: "telnet", Target: "host"}})
	if _, err := bad.Author(context.Background(), "x"); !errors.Is(err, ErrCannotAuthor) {
		t.Errorf("invalid config should be rejected with ErrCannotAuthor, got %v", err)
	}
}

type fakeCompleter struct {
	out string
	err error
}

func (f fakeCompleter) Complete(context.Context, string, string) (string, error) { return f.out, f.err }

func TestModelAuthorParsesJSON(t *testing.T) {
	c := fakeCompleter{out: "```json\n{\"name\":\"SFDC login\",\"type\":\"http\",\"target\":\"https://login.salesforce.com\"}\n```"}
	e := NewEngine(NewModelAuthor(c, "test-model"))
	p := mustAuthor(t, e, "check salesforce login")
	if p.Spec.Target != "https://login.salesforce.com" || p.Source != "test-model" {
		t.Errorf("model author = %+v source=%s", p.Spec, p.Source)
	}

	// A transport error surfaces as ErrModelUnavailable.
	down := NewEngine(NewModelAuthor(fakeCompleter{err: errors.New("boom")}, "m"))
	if _, err := down.Author(context.Background(), "x"); !errors.Is(err, ErrModelUnavailable) {
		t.Errorf("transport error should be ErrModelUnavailable, got %v", err)
	}
}
