// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// C8 (U-013) table-driven redaction: IPs, v6, secrets, hostnames-per-policy.
func TestRedactText(t *testing.T) {
	def := DefaultRedaction
	hosts := RedactionPolicy{MaskIPs: true, MaskHostnames: true}
	cases := []struct {
		name string
		in   string
		pol  RedactionPolicy
		gone []string // must NOT appear after redaction
		kept []string // must still appear
	}{
		{"ipv4", "loss between 10.1.2.3 and 192.168.7.9/24 rose", def,
			[]string{"10.1.2.3", "192.168.7.9"}, []string{"loss between", "rose"}},
		{"ipv6", "edge 2001:db8::1 to fe80::aa:bb degraded", def,
			[]string{"2001:db8::1", "fe80::aa:bb"}, []string{"edge", "degraded"}},
		{"mapped v4", "peer ::ffff:10.0.0.7 flapped", def,
			[]string{"10.0.0.7"}, []string{"peer", "flapped"}},
		{"bearer", "header Authorization: Bearer sk-live-abcdef123456789 leaked", def,
			[]string{"sk-live-abcdef123456789"}, []string{"header"}},
		{"kv secret", "config api_key=AKxyzSECRET9 password: hunter22 ok", def,
			[]string{"AKxyzSECRET9", "hunter22"}, []string{"config", "ok"}},
		{"aws key id", "found AKIAIOSFODNN7EXAMPLE in env", def,
			[]string{"AKIAIOSFODNN7EXAMPLE"}, []string{"found", "in env"}},
		{"pem block", "cert -----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY----- end", def,
			[]string{"MIIE"}, []string{"cert", "end"}},
		{"hostnames kept by default", "db-1.internal.example.com slow", def,
			nil, []string{"db-1.internal.example.com", "slow"}},
		{"hostnames masked per policy", "db-1.internal.example.com slow", hosts,
			[]string{"db-1.internal.example.com"}, []string{"slow"}},
		{"ips off", "10.1.2.3 reachable", RedactionPolicy{MaskIPs: false},
			nil, []string{"10.1.2.3", "reachable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactText(tc.in, tc.pol)
			for _, g := range tc.gone {
				if strings.Contains(got, g) {
					t.Errorf("%q still contains %q", got, g)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(got, k) {
					t.Errorf("%q lost %q", got, k)
				}
			}
		})
	}
}

// Stable masking: the same value yields the same token within a tenant
// (correlation survives).
func TestRedactionTokensAreStable(t *testing.T) {
	a := redactText("from 10.0.0.1 to 10.0.0.2 and back to 10.0.0.1", DefaultRedaction)
	first := redactText("10.0.0.1", DefaultRedaction)
	if strings.Count(a, first) != 2 {
		t.Fatalf("same IP should map to the same token twice: %q (token %q)", a, first)
	}
}

// AIRCA-001/RED-004: labels must not be public hashes of low-entropy values.
// An external model that sees [ip:<token>] should not be able to hash a small
// candidate list (for example RFC1918 addresses) and discover the original IP
// unless it also has the deployment's tenant-scoped redaction key.
func TestRedactionTokenDictionaryAttackRequiresTenantKey(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x11}, crypto.KeySize)
	keyB := bytes.Repeat([]byte{0x22}, crypto.KeySize)
	polA := DefaultRedaction
	polA.TokenKey = keyA
	polB := DefaultRedaction
	polB.TokenKey = keyB

	token := redactTextForTenant("10.1.2.3", polA, "tenant-a")
	if !regexp.MustCompile(`^\[ip:[0-9a-f]{32}\]$`).MatchString(token) {
		t.Fatalf("unexpected token shape: %q", token)
	}
	if strings.Contains(token, "10.1.2.3") {
		t.Fatalf("token leaked the raw IP: %q", token)
	}
	if again := redactTextForTenant("10.1.2.3", polA, "tenant-a"); again != token {
		t.Fatalf("same tenant + key + value must be stable: %q != %q", again, token)
	}
	if otherTenant := redactTextForTenant("10.1.2.3", polA, "tenant-b"); otherTenant == token {
		t.Fatalf("same value under another tenant must not match: %q", otherTenant)
	}

	for _, candidate := range []string{"10.1.2.1", "10.1.2.2", "10.1.2.3", "10.1.2.4"} {
		if got := redactTextForTenant(candidate, polB, "tenant-a"); got == token {
			t.Fatalf("wrong key dictionary candidate %q matched token %q", candidate, token)
		}
	}
}

// The evidence passed to the analyzer is never mutated — redaction operates
// on a deep copy (the local pipeline keeps raw values for citations).
func TestRedactSynthesisInputDoesNotMutate(t *testing.T) {
	in := SynthesisInput{
		Question: "why is 10.0.0.1 slow?",
		Evidence: []Evidence{{ID: "E1", Title: "loss at 10.0.0.1", Summary: "token=abc123secret"}},
	}
	out := redactSynthesisInput(in, DefaultRedaction)
	if strings.Contains(out.Question, "10.0.0.1") || strings.Contains(out.Evidence[0].Title, "10.0.0.1") {
		t.Fatal("redacted copy still has the IP")
	}
	if !strings.Contains(in.Question, "10.0.0.1") || !strings.Contains(in.Evidence[0].Title, "10.0.0.1") ||
		!strings.Contains(in.Evidence[0].Summary, "abc123secret") {
		t.Fatal("original input was mutated")
	}
}

func TestRedactAnswerForPersistenceMasksDurableArtifact(t *testing.T) {
	ans := Answer{
		ID:         "ans-1",
		Tenant:     "tenant-a",
		Question:   "why is alice@example.com seeing loss from 10.0.0.1 with token=rawsecret123?",
		RootCause:  "alice@example.com saw 10.0.0.1 fail after password=hunter22 changed",
		Confidence: ConfidenceHigh,
		Findings: []Finding{{
			Statement: "ticket CASE-1234 exposed 10.0.0.1 for alice@example.com",
			Citations: []Citation{{EvidenceID: "E1"}},
		}},
		Evidence: []Evidence{{
			ID:      "E1",
			Title:   "loss at 10.0.0.1 for alice@example.com",
			Summary: "Authorization: Bearer sk-live-abcdef123456789",
			Ref:     "incident://10.0.0.1/alice@example.com",
			Fields: Row{
				"target": "10.0.0.1",
				"owner":  "alice@example.com",
				"nested": map[string]any{"secret": "api_key=rawsecret123"},
			},
		}},
		Model: "builtin",
	}
	pol := DefaultRedaction
	pol.CustomPatterns = []*regexp.Regexp{regexp.MustCompile(`CASE-\d+`)}

	got := RedactAnswerForPersistence(ans, pol, "tenant-a")
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, leaked := range []string{"alice@example.com", "10.0.0.1", "rawsecret123", "hunter22", "sk-live-abcdef123456789", "CASE-1234"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("persisted answer leaked %q: %s", leaked, raw)
		}
	}
	if got.Evidence[0].ID != "E1" || got.Findings[0].Citations[0].EvidenceID != "E1" {
		t.Fatalf("redaction must preserve evidence IDs/citations: %+v", got)
	}
	if !strings.Contains(ans.Question, "alice@example.com") || !strings.Contains(ans.Evidence[0].Title, "10.0.0.1") {
		t.Fatal("redaction mutated the live answer")
	}
}

// capturePrompt runs an httptest OpenAI-shaped server and returns whatever
// user-message content the model receives.
func capturePrompt(t *testing.T, m *HTTPModel) string {
	t.Helper()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		for _, msg := range req.Messages {
			if msg.Role == "user" {
				got = msg.Content
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{
				"content": `{"root_cause":"x","confidence":"low","insufficient_evidence":false,"findings":[{"statement":"s","citations":["E1"]}]}`,
			}}},
		})
	}))
	t.Cleanup(srv.Close)
	m.endpoint = srv.URL
	if _, err := m.Synthesize(context.Background(), SynthesisInput{
		Question: "why is 10.9.8.7 slow?",
		Evidence: []Evidence{{ID: "E1", Title: "loss at 10.9.8.7", Summary: "password=supersecret1"}},
	}); err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	return got
}

// Remote path: the wire prompt is masked. Local (loopback) path: untouched —
// the sovereignty regression guard.
func TestRemotePromptRedactedLocalUntouched(t *testing.T) {
	remote, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: "http://127.0.0.1:1", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	remote.remote = true // force the remote classification onto the test server
	prompt := capturePrompt(t, remote)
	if strings.Contains(prompt, "10.9.8.7") || strings.Contains(prompt, "supersecret1") {
		t.Fatalf("remote prompt leaked raw values: %q", prompt)
	}
	if !strings.Contains(prompt, "E1") {
		t.Fatalf("remote prompt lost evidence ids: %q", prompt)
	}

	local, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: "http://127.0.0.1:1", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if local.remote {
		t.Fatal("loopback endpoint classified remote")
	}
	prompt = capturePrompt(t, local)
	if !strings.Contains(prompt, "10.9.8.7") || !strings.Contains(prompt, "password=supersecret1") {
		t.Fatalf("LOCAL path must be untouched, got %q", prompt)
	}
}
