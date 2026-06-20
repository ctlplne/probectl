// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

func allowTenants(allowed ...string) EgressPolicy {
	set := map[string]bool{}
	for _, t := range allowed {
		set[t] = true
	}
	return func(_ context.Context, tenant string) (bool, error) { return set[tenant], nil }
}

// remoteFake is a remote-egressing Completer (the authoring seam).
type remoteFake struct {
	gotUser string
	reply   string
	err     error
}

func (r *remoteFake) Name() string       { return "fake:remote" }
func (r *remoteFake) RemoteEgress() bool { return true }
func (r *remoteFake) Endpoint() string   { return "https://api.example/v1" }
func (r *remoteFake) Complete(_ context.Context, _, user string) (string, error) {
	r.gotUser = user
	return r.reply, r.err
}

// localFake never egresses (loopback model).
type localFake struct{ called bool }

func (l *localFake) Name() string { return "fake:local" }
func (l *localFake) Complete(_ context.Context, _, _ string) (string, error) {
	l.called = true
	return "{}", nil
}

// AIRCA-005: the authoring path is consent-gated like every other external-AI
// egress — no consent, no call; consent, call + audit with surface=author.
func TestGatedCompleterConsentGate(t *testing.T) {
	var audited []EgressEvent
	gate := NewEgressGate(allowTenants("t-yes"), func(_ context.Context, ev EgressEvent) {
		audited = append(audited, ev)
	}, DefaultRedaction)

	inner := &remoteFake{reply: "{}"}
	c := NewGatedCompleter(inner, gate)

	// No principal on ctx → fail closed (no call).
	if _, err := c.Complete(context.Background(), "sys", "user text"); err == nil {
		t.Fatal("egress without an authenticated tenant must be denied")
	}

	// Non-consented tenant → denied, inner never called.
	ctxNo := auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: "t-no"})
	if _, err := c.Complete(ctxNo, "sys", "user text"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("want ErrEgressDenied, got %v", err)
	}
	if inner.gotUser != "" {
		t.Fatal("denied call must never reach the model")
	}

	// Consented tenant → call goes out REDACTED + audited as author surface.
	ctxYes := auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: "t-yes"})
	if _, err := c.Complete(ctxYes, "sys", "probe 10.1.2.3 owned by bob@corp.example token=hunter2secret"); err != nil {
		t.Fatalf("consented call failed: %v", err)
	}
	for _, leak := range []string{"10.1.2.3", "bob@corp.example", "hunter2secret"} {
		if strings.Contains(inner.gotUser, leak) {
			t.Fatalf("unredacted value %q reached the remote model: %q", leak, inner.gotUser)
		}
	}
	if len(audited) != 1 || audited[0].Surface != "author" || audited[0].TenantID != "t-yes" {
		t.Fatalf("authoring egress must audit surface=author: %+v", audited)
	}

	// Local model: exempt — no principal needed, no audit.
	lf := &localFake{}
	lc := NewGatedCompleter(lf, gate)
	if _, err := lc.Complete(context.Background(), "sys", "anything"); err != nil || !lf.called {
		t.Fatalf("local model must pass through ungated: %v", err)
	}
	if len(audited) != 1 {
		t.Fatal("local model must not emit egress audit")
	}
}

// AIRCA-001: the audit records the authorized egress attempt even when the
// provider fails, because the prompt may already have crossed the boundary.
func TestGatedCompleterAuditsFailedRemoteAuthoringAttempt(t *testing.T) {
	var audited []EgressEvent
	gate := NewEgressGate(allowTenants("t-yes"), func(_ context.Context, ev EgressEvent) {
		audited = append(audited, ev)
	}, DefaultRedaction)

	inner := &remoteFake{err: errors.New("provider down")}
	c := NewGatedCompleter(inner, gate)
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: "t-yes"})

	if _, err := c.Complete(ctx, "sys", "probe 10.1.2.3 token=hunter2secret"); err == nil {
		t.Fatal("provider failure must still be returned")
	}
	for _, leak := range []string{"10.1.2.3", "hunter2secret"} {
		if strings.Contains(inner.gotUser, leak) {
			t.Fatalf("unredacted value %q reached the remote model: %q", leak, inner.gotUser)
		}
	}
	if len(audited) != 1 {
		t.Fatalf("failed remote authoring attempt must emit one audit event: %+v", audited)
	}
	ev := audited[0]
	if ev.Surface != "author" || ev.TenantID != "t-yes" || ev.Endpoint != "https://api.example/v1" || ev.Model != "fake:remote" {
		t.Fatalf("unexpected failed-attempt audit event: %+v", ev)
	}
}

// The gate itself fails closed in every degenerate shape.
func TestEgressGateFailsClosed(t *testing.T) {
	cases := map[string]*EgressGate{
		"nil gate":   nil,
		"nil policy": NewEgressGate(nil, nil, DefaultRedaction),
		"policy error": NewEgressGate(func(context.Context, string) (bool, error) {
			return true, errors.New("db down")
		}, nil, DefaultRedaction),
	}
	for name, g := range cases {
		if err := g.Authorize(context.Background(), "t1"); err == nil {
			t.Errorf("%s: must deny", name)
		}
	}
	if err := NewEgressGate(allowTenants("t1"), nil, DefaultRedaction).Authorize(context.Background(), ""); err == nil {
		t.Error("empty tenant must deny")
	}
}

// AIRCA-002: the extended redactor over realistic telemetry — emails, phones,
// MACs, custom patterns; correlation-preserving determinism; existing IP +
// secret behavior intact.
func TestRedactFreeTextPIIRealisticTelemetry(t *testing.T) {
	telemetry := `incident INC-4412: user jane.doe+oncall@corp.example reported VPN drops.
device wifi-ap-7 (mac 00:1A:2B:3C:4D:5E) deauthed client 10.40.2.17 at 14:02.
callback +1 (415) 555-0173 or 415-555-0199; api_key=sk_live_abc123def456
escalation contact ravi@example.net; same AP MAC 00:1A:2B:3C:4D:5E re-flapped.`

	out := redactText(telemetry, DefaultRedaction)

	for _, leak := range []string{
		"jane.doe+oncall@corp.example", "ravi@example.net",
		"00:1A:2B:3C:4D:5E",
		"(415) 555-0173", "415-555-0199",
		"10.40.2.17",
		"sk_live_abc123def456",
	} {
		if strings.Contains(out, leak) {
			t.Errorf("PII/secret %q survived redaction:\n%s", leak, out)
		}
	}
	// Determinism: the repeated MAC masks to the SAME token (correlation survives).
	tok := regexp.MustCompile(`\[mac:[0-9a-f]{32}\]`).FindAllString(out, -1)
	if len(tok) != 2 || tok[0] != tok[1] {
		t.Fatalf("repeated MAC must mask deterministically: %v", tok)
	}
	// Non-PII operational text survives.
	if !strings.Contains(out, "INC-4412") || !strings.Contains(out, "wifi-ap-7") || !strings.Contains(out, "14:02") {
		t.Fatalf("operational context must survive: %s", out)
	}

	// Custom patterns: org-specific identifiers the operator names.
	custom, err := CompileCustomPatterns(`\bEMP-\d{5}\b ;; \bCASE-[A-Z]{2}\d+\b`)
	if err != nil {
		t.Fatal(err)
	}
	pol := DefaultRedaction
	pol.CustomPatterns = custom
	got := redactText("badge EMP-88231 opened CASE-AB1209 for review", pol)
	if strings.Contains(got, "EMP-88231") || strings.Contains(got, "CASE-AB1209") {
		t.Fatalf("custom patterns must mask: %s", got)
	}
	if !strings.Contains(got, "[custom:") {
		t.Fatalf("custom masks must be labeled: %s", got)
	}

	// A bad custom pattern fails closed at compile.
	if _, err := CompileCustomPatterns(`valid.* ;; ([unclosed`); err == nil {
		t.Fatal("bad custom pattern must refuse")
	}
}

// PII masking is policy-controlled but ON in the default remote policy, and
// secrets remain always-on even with everything else off.
func TestRedactPolicyKnobs(t *testing.T) {
	in := "mail bob@x.example pwd=supersecret9 ip 10.0.0.9"
	off := redactText(in, RedactionPolicy{})
	if !strings.Contains(off, "bob@x.example") || !strings.Contains(off, "10.0.0.9") {
		t.Fatal("with all knobs off, only secrets are masked")
	}
	if strings.Contains(off, "supersecret9") {
		t.Fatal("secrets must mask under ANY policy")
	}
}

// The no-client-outside-the-gate gate (Sprint 20 CI check): no file in
// internal/ai (or the analyzer) may dial out except the model adapter and
// the inbound MCP HTTP transport. A new AI integration must go through the
// gate package or fail here.
func TestNoAIClientOutsideGate(t *testing.T) {
	allowed := map[string]bool{
		"model_http.go": true, // THE adapter (redacts + RemoteEgress-reports)
		"mcp/http.go":   true, // inbound transport (serves, never dials AI)
	}
	var offenders []string
	root := "."
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		text := string(src)
		rel := filepath.ToSlash(path)
		if strings.Contains(text, `"net/http"`) && !allowed[rel] {
			offenders = append(offenders, rel+" imports net/http")
		}
		for _, marker := range []string{"api.openai.com", "api.anthropic.com"} {
			if strings.Contains(text, marker) && rel != "model_http.go" {
				offenders = append(offenders, rel+" hardcodes "+marker)
			}
		}
		return nil
	})
	if len(offenders) > 0 {
		t.Fatalf("AI client surface outside the gate/adapter (AIRCA-001 — route through EgressGate):\n%s",
			strings.Join(offenders, "\n"))
	}
}
