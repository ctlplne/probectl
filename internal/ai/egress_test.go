// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	err      error
}

func (f *fakeRemoteModel) Name() string       { return "fake:remote" }
func (f *fakeRemoteModel) RemoteEgress() bool { return true }
func (f *fakeRemoteModel) Endpoint() string   { return f.endpoint }
func (f *fakeRemoteModel) Synthesize(_ context.Context, in SynthesisInput) (Synthesis, error) {
	f.calls++
	if f.err != nil {
		return Synthesis{}, f.err
	}
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
	var events []EgressEvent
	audit := WithEgressAudit(func(_ context.Context, ev EgressEvent) error {
		events = append(events, ev)
		return nil
	})

	// No policy wired at all: fail closed.
	a := NewAnalyzer(egressEngine(), WithModel(m), audit)
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied with no policy, got %v", err)
	}

	// Policy says no.
	a = NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return false, nil }), audit)
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied with denying policy, got %v", err)
	}
	if m.calls != 0 {
		t.Fatalf("remote model was called %d times despite denial", m.calls)
	}
	if len(events) != 2 || !events[0].Denied || !events[1].Denied {
		t.Fatalf("denied external calls must be audited before egress: %+v", events)
	}
	if events[0].DenialReason != "policy_unavailable" || events[1].DenialReason != "consent_missing" {
		t.Fatalf("bounded denial reasons = %+v", events)
	}
}

func TestRemoteModelEgressPolicyErrorFailsClosedAndIsAudited(t *testing.T) {
	m := &fakeRemoteModel{endpoint: "https://api.example/v1"}
	var events []EgressEvent
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return false, errors.New("database unavailable") }),
		WithEgressAudit(func(_ context.Context, ev EgressEvent) error {
			events = append(events, ev)
			return nil
		}),
	)
	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("policy error must fail closed as ErrEgressDenied, got %v", err)
	}
	if m.calls != 0 || len(events) != 1 || !events[0].Denied || events[0].DenialReason != "policy_error" {
		t.Fatalf("policy-error receipt = %+v, model calls = %d", events, m.calls)
	}
}

func TestRemoteRCAFailedAttemptIsAudited(t *testing.T) {
	adapterErr := errors.New("remote adapter unavailable")
	m := &fakeRemoteModel{endpoint: "https://api.example/v1", err: adapterErr}
	var events []EgressEvent
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(_ context.Context, tid string) (bool, error) {
			return tid == "t1", nil
		}),
		WithEgressAudit(func(_ context.Context, ev EgressEvent) error {
			events = append(events, ev)
			return nil
		}),
	)

	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); !errors.Is(err, adapterErr) {
		t.Fatalf("Analyze error = %v, want %v", err, adapterErr)
	}
	if m.calls != 1 {
		t.Fatalf("model calls = %d, want 1", m.calls)
	}
	if len(events) != 1 {
		t.Fatalf("failed remote RCA attempt audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Surface != "rca" || ev.TenantID != "t1" || ev.Endpoint != "https://api.example/v1" || ev.Model != "fake:remote" {
		t.Fatalf("unexpected failed-attempt event: %+v", ev)
	}
	if ev.Denied || ev.EvidenceCount == 0 || len(ev.Planes) == 0 {
		t.Fatalf("authorized event must contain bounded categories without being marked denied: %+v", ev)
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
		WithEgressAudit(func(_ context.Context, ev EgressEvent) error {
			events = append(events, ev)
			return nil
		}),
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
	if ev.Denied {
		t.Fatalf("allowed event marked denied: %+v", ev)
	}
	if ans.Reasoning.Execution != ReasoningExternalAdapter || ans.Reasoning.Adapter != "fake:remote" || ans.Reasoning.EgressConsent != ConsentGranted {
		t.Fatalf("server-reported external reasoning receipt = %+v", ans.Reasoning)
	}
}

func TestRemoteModelAuditSanitizesEndpointProvenance(t *testing.T) {
	const rawEndpoint = "https://audit-user:audit-secret@api.example/v1?api_key=query-secret#fragment-secret"
	m := &fakeRemoteModel{endpoint: rawEndpoint}
	var events []EgressEvent
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return true, nil }),
		WithEgressAudit(func(_ context.Context, ev EgressEvent) error {
			events = append(events, ev)
			return nil
		}),
	)

	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if got := events[0].Endpoint; got != "https://api.example/v1" {
		t.Fatalf("sanitized audit endpoint = %q, want credential-free provenance", got)
	}
	for _, secret := range []string{"audit-user", "audit-secret", "query-secret", "fragment-secret"} {
		if strings.Contains(events[0].Endpoint, secret) {
			t.Fatalf("audit endpoint disclosed %q: %q", secret, events[0].Endpoint)
		}
	}
}

func TestRemoteRCARequiresDurableAuditBeforeDispatch(t *testing.T) {
	m := &fakeRemoteModel{endpoint: "https://api.example/v1"}
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return true, nil }),
	)

	if _, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"}); err == nil {
		t.Fatal("remote RCA proceeded without a durable audit sink")
	}
	if m.calls != 0 {
		t.Fatalf("remote model calls = %d, want 0 when audit is unavailable", m.calls)
	}
}

func TestRemoteRCAAuditWriteFailurePreventsDispatch(t *testing.T) {
	m := &fakeRemoteModel{endpoint: "https://api.example/v1"}
	writeErr := errors.New("immutable store unavailable")
	a := NewAnalyzer(egressEngine(), WithModel(m),
		WithEgressPolicy(func(context.Context, string) (bool, error) { return true, nil }),
		WithEgressAudit(func(context.Context, EgressEvent) error { return writeErr }),
	)

	_, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"})
	if !errors.Is(err, ErrEgressAuditUnavailable) || !errors.Is(err, writeErr) {
		t.Fatalf("Analyze error = %v, want durable audit failure", err)
	}
	if m.calls != 0 {
		t.Fatalf("remote model calls = %d, want 0 after audit write failure", m.calls)
	}
}

// The air-gapped builtin path never consults the policy and never audits —
// the local default is untouched (U-013 regression guard).
func TestBuiltinModelNeverConsultsEgress(t *testing.T) {
	a := NewAnalyzer(egressEngine(),
		WithEgressPolicy(func(context.Context, string) (bool, error) {
			t.Fatal("egress policy consulted for the builtin model")
			return false, nil
		}),
		WithEgressAudit(func(context.Context, EgressEvent) error {
			t.Fatal("egress audit fired for the builtin model")
			return nil
		}),
	)
	ans, err := a.Analyze(context.Background(), egressPrincipal(), Question{Text: "why?"})
	if err != nil {
		t.Fatalf("builtin path: %v", err)
	}
	if ans.Reasoning.Execution != ReasoningBuiltin || ans.Reasoning.Adapter != "builtin" || ans.Reasoning.EgressConsent != ConsentNotRequired {
		t.Fatalf("server-reported builtin reasoning receipt = %+v", ans.Reasoning)
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
