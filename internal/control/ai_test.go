// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/mcp"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
)

func aiTestReq(method, path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestRemoteAuditorsFailClosedWithoutStore(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := egressAuditor(nil, log)(t.Context(), ai.EgressEvent{
		TenantID: "tenant-a",
		Surface:  "rca",
	}); !errors.Is(err, ai.ErrEgressAuditUnavailable) {
		t.Fatalf("egress auditor error = %v, want %v", err, ai.ErrEgressAuditUnavailable)
	}
	if err := mcpCallAuditor(nil, log)(t.Context(), mcp.CallEvent{
		TenantID: "tenant-a",
		UserID:   "user-a",
		Tool:     "list_tests",
		Allowed:  true,
	}); !errors.Is(err, errMCPCallAuditUnavailable) {
		t.Fatalf("MCP call auditor error = %v, want %v", err, errMCPCallAuditUnavailable)
	}
}

// With no datastore the assistant still answers (the built-in air-gapped model)
// and, finding no evidence, returns an honest insufficient-evidence answer rather
// than a fabricated cause.
func TestHandleAIAskValidationAndAirGappedDefault(t *testing.T) {
	h := testServer(nil).Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/ask", map[string]any{"question": "  "}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty question: status = %d, want 422", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/ask", map[string]any{"question": "why is api.example.com slow?"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("ask: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var ans struct {
		Model                string                 `json:"model"`
		InsufficientEvidence bool                   `json:"insufficient_evidence"`
		ID                   string                 `json:"id"`
		Reasoning            ai.ReasoningProvenance `json:"reasoning"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	if ans.Model != "builtin" {
		t.Errorf("default model = %q, want builtin (air-gapped)", ans.Model)
	}
	if ans.Reasoning.Execution != ai.ReasoningBuiltin || ans.Reasoning.Adapter != "builtin" {
		t.Errorf("server reasoning receipt = %+v, want builtin local/air-gapped", ans.Reasoning)
	}
	if !ans.InsufficientEvidence || ans.ID == "" {
		t.Errorf("no-evidence answer should be insufficient with an id, got %+v", ans)
	}
}

func TestBuildEngineSecondaryPermissionABAC(t *testing.T) {
	const tenantID = "00000000-0000-0000-0000-0000000000a1"
	principal := &auth.Principal{
		TenantID:    tenantID,
		Permissions: map[string]bool{ai.PermMetricsRead: true},
		Attributes:  map[string]string{"department": "contractor"},
	}
	engine := buildEngineWithPolicyLoader(
		&config.Config{AIMaxEvidence: 10},
		nil,
		func(_ context.Context, loadedTenant string) ([]auth.Policy, error) {
			if loadedTenant != tenantID {
				t.Fatalf("policy tenant = %q, want %q", loadedTenant, tenantID)
			}
			return []auth.Policy{{
				Effect:     auth.PolicyDeny,
				Permission: ai.PermMetricsRead,
				Subject:    map[string]string{"department": "contractor"},
				Priority:   100,
				Enabled:    true,
			}}, nil
		},
	)
	if _, err := engine.Query(context.Background(), principal, ai.Query{Domain: ai.DomainMetrics}); !errors.Is(err, ai.ErrForbidden) {
		t.Fatalf("ABAC-denied production engine query = %v, want ErrForbidden", err)
	}

	policyErr := errors.New("policy store unavailable")
	engine = buildEngineWithPolicyLoader(
		&config.Config{AIMaxEvidence: 10},
		nil,
		func(context.Context, string) ([]auth.Policy, error) { return nil, policyErr },
	)
	if _, err := engine.Query(context.Background(), principal, ai.Query{Domain: ai.DomainMetrics}); !errors.Is(err, policyErr) {
		t.Fatalf("policy-load failure = %v, want fail-closed error", err)
	}
}

type aiTestRemoteModel struct {
	calls int
}

func (m *aiTestRemoteModel) Name() string       { return "test-remote" }
func (m *aiTestRemoteModel) RemoteEgress() bool { return true }
func (m *aiTestRemoteModel) Endpoint() string   { return "https://ai.example.test/v1/chat" }
func (m *aiTestRemoteModel) Synthesize(context.Context, ai.SynthesisInput) (ai.Synthesis, error) {
	m.calls++
	return ai.Synthesis{InsufficientEvidence: true}, nil
}

func TestAIAskRemoteEgressDeniedReturnsForbidden(t *testing.T) {
	srv := testServer(nil)
	model := &aiTestRemoteModel{}
	srv.analyzer = ai.NewAnalyzer(
		ai.NewEngine(),
		ai.WithModel(model),
		ai.WithEgressAudit(func(context.Context, ai.EgressEvent) error { return nil }),
	)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/ask", map[string]any{
		"question": "why is checkout slow?",
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ask status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if model.calls != 0 {
		t.Fatalf("remote model was called %d times despite egress denial", model.calls)
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "forbidden" || !strings.Contains(body.Error.Message, "tenant_governance.ai_remote_egress") {
		t.Fatalf("error body = %+v, want consent-oriented forbidden", body.Error)
	}
}

func TestAIAskRejectsScopeInjectionAndInvalidRange(t *testing.T) {
	h := testServer(nil).Handler()
	for name, body := range map[string]map[string]any{
		"tenant subject":   {"question": "what happened?", "subject": map[string]string{"tenant_id": "other"}},
		"evidence subject": {"question": "what happened?", "subject": map[string]string{"evidence_id": "foreign"}},
		"reversed range":   {"question": "what happened?", "range": map[string]string{"start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/ask", body))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAIRemoteEgressAuditDataIncludesSurface(t *testing.T) {
	for _, surface := range []string{"rca", "author", "mcp"} {
		data := aiRemoteEgressAuditData(ai.EgressEvent{
			TenantID:      "tenant-a",
			Endpoint:      "https://ai.example.test/v1/chat",
			Model:         "test-remote",
			Surface:       surface,
			EvidenceCount: 2,
			Planes:        []string{"bgp", "flow"},
		})
		if data["surface"] != surface {
			t.Fatalf("ai.remote_egress audit payload for %s missing surface: %#v", surface, data)
		}
		if data["model"] != "test-remote" || data["evidence_count"] != 2 {
			t.Fatalf("ai.remote_egress audit payload lost model/evidence context: %#v", data)
		}
		if data["allowed"] != true {
			t.Fatalf("successful egress audit must say allowed: %#v", data)
		}
	}
	denied := aiRemoteEgressAuditData(ai.EgressEvent{Denied: true, DenialReason: "consent_missing"})
	if denied["allowed"] != false || denied["denial_reason"] != "consent_missing" {
		t.Fatalf("denied egress audit data = %#v", denied)
	}
}

func TestHandleAIFeedbackValidationAndPersistenceGuard(t *testing.T) {
	h := testServer(nil).Handler()

	// Invalid rating → 422 (validation runs before the persistence check).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/feedback", map[string]any{"answer_id": "a", "rating": "sideways"}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad rating: status = %d, want 422", rec.Code)
	}

	// Valid feedback but no datastore → 503.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/feedback", map[string]any{"answer_id": "ans_1", "rating": "up"}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("feedback without persistence: status = %d, want 503", rec.Code)
	}
}

func TestAIAuditAndPersistenceMinimizeSensitiveText(t *testing.T) {
	srv := testServer(nil)
	srv.cfg.AIRedactIPs = true
	srv.cfg.AIRedactPII = true

	question := "why is alice@example.com losing traffic from 10.0.0.1 with password=hunter22?"
	data := srv.aiAskAuditData(question, &auth.Principal{TenantID: "tenant-a"})
	if got := data["question"].(string); strings.Contains(got, "alice@example.com") ||
		strings.Contains(got, "10.0.0.1") || strings.Contains(got, "hunter22") {
		t.Fatalf("audit question was not minimized: %q", got)
	}
	if data["question_redacted"] != true {
		t.Fatalf("audit data must mark question as redacted: %#v", data)
	}

	req := aiTestReq(http.MethodPost, "/v1/ai/ask", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{TenantID: "tenant-a"}))
	persisted := srv.aiAnswerForPersistence(req, ai.Answer{
		ID:         "ans-1",
		Tenant:     "tenant-a",
		Question:   question,
		RootCause:  "alice@example.com hit 10.0.0.1 after token=rawsecret123 changed",
		Confidence: ai.ConfidenceHigh,
		Findings: []ai.Finding{{
			Statement: "10.0.0.1 is the failing target for alice@example.com",
			Citations: []ai.Citation{{EvidenceID: "E1"}},
		}},
		Evidence: []ai.Evidence{{
			ID:      "E1",
			Title:   "flow from 10.0.0.1",
			Summary: "api_key=rawsecret123",
			Fields:  ai.Row{"target": "10.0.0.1", "owner": "alice@example.com"},
		}},
		Model: "builtin",
	})
	b, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, leaked := range []string{"alice@example.com", "10.0.0.1", "hunter22", "rawsecret123"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("persisted AI answer leaked %q: %s", leaked, raw)
		}
	}
}
