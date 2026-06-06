package ai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// fakeRemoteModel pretends to be a non-loopback HTTP model.
type fakeRemoteModel struct {
	synth    Synthesis
	calls    int
	endpoint string
}

func (f *fakeRemoteModel) Name() string       { return "fake:remote" }
func (f *fakeRemoteModel) RemoteEgress() bool { return true }
func (f *fakeRemoteModel) Endpoint() string   { return f.endpoint }
func (f *fakeRemoteModel) Synthesize(_ context.Context, in SynthesisInput) (Synthesis, error) {
	f.calls++
	if len(in.Evidence) > 0 {
		return Synthesis{
			RootCause:  "x",
			Confidence: ConfidenceMedium,
			Findings:   []Finding{{Statement: "s", Citations: []Citation{{EvidenceID: in.Evidence[0].ID}}}},
		}, nil
	}
	return f.synth, nil
}

func egressPrincipal() *auth.Principal {
	perms := map[string]bool{}
	for _, k := range allReadPerms() {
		perms[k] = true
	}
	return &auth.Principal{TenantID: "t1", UserID: "u1", Permissions: perms}
}

func egressEngine() *Engine {
	return engineWith(fixtureSource{events: []Row{{
		"id": "ev-1", "kind": "incident", "plane": "network",
		"severity": "high", "title": "packet loss spike",
	}}})
}

// U-013 consent gate: a remote model without tenant consent is refused — the
// model is never called.
func TestRemoteModelEgressDeniedWithoutConsent(t *testing.T) {
	m := &fakeRemoteModel{endpoint: "https://api.example/v1"}

	// No policy wired at all: fail closed.
	a := NewAnalyzer(egressEngine(), WithModel(m))
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied with no policy, got %v", err)
	}

	// Policy says no.
	a = NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return false, nil }))
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied with denying policy, got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("remote model was called %d times despite denial", m.calls)
	}
}

// With consent, the call proceeds and exactly one egress audit event records
// tenant, endpoint, model, and the data categories that left.
func TestRemoteModelEgressAllowedIsAudited(t *testing.T) {
	m := &fakeRemoteModel{endpoint: "https://api.example/v1"}
	var events []EgressEvent
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(_ context.Context, tid string) (bool, error) {
			if tid != "t1" {
				t.Errorf("policy consulted for tenant %q", tid)
			}
			return true, nil
		}),
		WithEgressAudit(func(_ context.Context, ev EgressEvent) { events = append(events, ev) }),
	)
	ans, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "did a config change or route change cause this?"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if m.calls != 1 {
		t.Fatalf("model calls = %d, want 1", m.calls)
	}
	if len(events) != 1 {
		t.Fatalf("egress audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.TenantID != "t1" || ev.Endpoint != "https://api.example/v1" || ev.Model != "fake:remote" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.EvidenceCount == 0 || len(ev.Planes) == 0 {
		t.Fatalf("event must carry data categories: %+v", ev)
	}
	_ = ans
}

// The air-gapped builtin path never consults the policy and never audits —
// the local default is untouched (U-013 regression guard).
func TestBuiltinModelNeverConsultsEgress(t *testing.T) {
	a := NewAnalyzer(egressEngine(),
		WithEgressPolicy(func(context.Context, string) (bool, error) {
			t.Fatal("egress policy consulted for the builtin model")
			return false, nil
		}),
		WithEgressAudit(func(context.Context, EgressEvent) {
			t.Fatal("egress audit fired for the builtin model")
		}),
	)
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); err != nil {
		t.Fatalf("builtin path: %v", err)
	}
}

// A loopback HTTP model reports no remote egress; a public one does.
func TestHTTPModelRemoteEgressFlag(t *testing.T) {
	local, err := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: "http://127.0.0.1:11434", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if local.RemoteEgress() {
		t.Fatal("loopback model must not report remote egress")
	}
	remote, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: "https://api.openai.com", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !remote.RemoteEgress() {
		t.Fatal("public endpoint must report remote egress")
	}
	if !strings.Contains(remote.Endpoint(), "api.openai.com") {
		t.Fatalf("endpoint = %q", remote.Endpoint())
	}
}
