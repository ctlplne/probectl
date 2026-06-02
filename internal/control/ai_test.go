package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func aiTestReq(method, path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
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
		Model                string `json:"model"`
		InsufficientEvidence bool   `json:"insufficient_evidence"`
		ID                   string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	if ans.Model != "builtin" {
		t.Errorf("default model = %q, want builtin (air-gapped)", ans.Model)
	}
	if !ans.InsufficientEvidence || ans.ID == "" {
		t.Errorf("no-evidence answer should be insufficient with an id, got %+v", ans)
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
