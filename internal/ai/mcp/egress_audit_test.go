package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
)

func consentGate(allowed map[string]bool, redact ai.RedactionPolicy) *ai.EgressGate {
	return ai.NewEgressGate(func(_ context.Context, tenant string) (bool, error) {
		return allowed[tenant], nil
	}, nil, redact)
}

func callRPC(t *testing.T, s *Server, p *auth.Principal, tool string) map[string]any {
	t.Helper()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`)
	out := s.Handle(context.Background(), p, raw)
	var resp struct {
		Result map[string]any `json:"result"`
		Error  map[string]any `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("bad rpc response: %v: %s", err, out)
	}
	if resp.Result == nil {
		t.Fatalf("rpc error response: %s", out)
	}
	return resp.Result
}

// AIRCA-001 acceptance: an MCP egress WITHOUT tenant consent is denied (the
// tool never runs, no telemetry leaves) and the denial lands in the audit
// hook; the same call WITH consent succeeds and is audited as allowed.
func TestMCPEgressConsentDeniedAndAudited(t *testing.T) {
	fb := &fakeBackend{}
	var events []CallEvent
	s := New(fb, consentGate(map[string]bool{"t-consented": true}, ai.RedactionPolicy{}),
		WithCallAudit(func(_ context.Context, ev CallEvent) { events = append(events, ev) }))

	deny := &auth.Principal{TenantID: "t-locked", UserID: "u1", Permissions: map[string]bool{"test.read": true}}
	res := callRPC(t, s, deny, "list_tests")
	if res["isError"] != true {
		t.Fatalf("non-consented MCP call must return an error result: %v", res)
	}
	if !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "consent") {
		t.Fatalf("denial must explain consent: %v", res)
	}
	if len(fb.seen()) != 0 {
		t.Fatal("the tool must NOT run for a non-consented tenant — telemetry never even gathered")
	}
	if len(events) != 1 || events[0].Allowed || events[0].Denial != "consent" || events[0].Tool != "list_tests" || events[0].TenantID != "t-locked" {
		t.Fatalf("denial must be audited (who/tool/why): %+v", events)
	}

	allow := &auth.Principal{TenantID: "t-consented", UserID: "u2", Permissions: map[string]bool{"test.read": true}}
	res = callRPC(t, s, allow, "list_tests")
	if res["isError"] == true {
		t.Fatalf("consented call must pass: %v", res)
	}
	if len(events) != 2 || !events[1].Allowed || events[1].UserID != "u2" {
		t.Fatalf("allowed call must be audited too (AIRCA-003): %+v", events)
	}
}

// Every OUTCOME audits — permission and rate denials included (AIRCA-003).
func TestMCPAuditCoversEveryOutcome(t *testing.T) {
	fb := &fakeBackend{}
	var events []CallEvent
	s := New(fb, consentGate(map[string]bool{"t1": true}, ai.RedactionPolicy{}),
		WithRateLimit(1),
		WithCallAudit(func(_ context.Context, ev CallEvent) { events = append(events, ev) }))

	noPerm := &auth.Principal{TenantID: "t1", UserID: "u3", Permissions: map[string]bool{}}
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
	_ = s.Handle(context.Background(), noPerm, raw)
	if len(events) != 1 || events[0].Denial != "permission" {
		t.Fatalf("permission denial must audit: %+v", events)
	}

	ok := &auth.Principal{TenantID: "t1", UserID: "u4", Permissions: map[string]bool{"test.read": true}}
	_ = s.Handle(context.Background(), ok, raw)
	_ = s.Handle(context.Background(), ok, raw) // second call trips the 1/min limiter
	if len(events) != 3 || events[2].Denial != "rate" {
		t.Fatalf("rate denial must audit: %+v", events)
	}
}

// piiBackend overrides one tool to return realistic PII-laden telemetry.
type piiBackend struct{ *fakeBackend }

func (b *piiBackend) ListTests(_ context.Context, _ *auth.Principal) (any, error) {
	return map[string]any{
		"note":    "agent 10.9.8.7 (oncall bob@corp.example) token=verysecret99",
		"healthy": true,
	}, nil
}

// AIRCA-002 at the MCP boundary: tool results are redacted by the gate's
// policy before they reach the external AI client — text AND structured.
func TestMCPToolResultsRedacted(t *testing.T) {
	fb := &piiBackend{fakeBackend: &fakeBackend{}}
	s := New(fb, consentGate(map[string]bool{"t1": true}, ai.DefaultRedaction))
	p := &auth.Principal{TenantID: "t1", Permissions: map[string]bool{"test.read": true}}
	res := callRPC(t, s, p, "list_tests")

	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	structured, _ := json.Marshal(res["structuredContent"])
	for _, leak := range []string{"10.9.8.7", "bob@corp.example", "verysecret99"} {
		if strings.Contains(text, leak) || strings.Contains(string(structured), leak) {
			t.Fatalf("value %q egressed to the MCP client unredacted:\ntext=%s\nstructured=%s", leak, text, structured)
		}
	}
	// Still valid JSON with operational content intact.
	var obj map[string]any
	if err := json.Unmarshal(structured, &obj); err != nil {
		t.Fatalf("redacted structuredContent must stay valid JSON: %v", err)
	}
	if obj["healthy"] != true {
		t.Fatalf("non-sensitive fields must survive: %v", obj)
	}
}
